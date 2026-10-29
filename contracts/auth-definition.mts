import { canonicalHash } from '../lib/compiler.mjs';

// Reviewed, data-only description of how one provider authenticates accounts.
// A definition never carries credentials and never names code to load: provider
// quirks select a fixed parser by name. Loading a definition is not a grant,
// a registered OAuth client, or certification of any operation.
export type ScopeSeparator = ' ' | ',';
export type TokenResponseFormat = 'oauth2' | 'slack-v2';
export type ClientAuthentication = 'body' | 'basic';
export type ReviewStatus = 'candidate' | 'reviewed';
export type TokenQuirks = Readonly<{
  errorInSuccessBody: boolean; errorCodeField: 'error' | 'error-or-code'; nullRefreshMeansNone: boolean; basicEncoding: 'raw' | 'form-urlencoded';
}>;
export type IdentityRequest = Readonly<{
  url: string; method: 'GET' | 'POST'; headers: Readonly<Record<string, string>>; body: 'none' | 'empty-form';
}>;
/** A body fact: an exact value, or merely a present non-empty value. */
export type IdentityRequirement = Readonly<{ pointer: string; equals: string | number | boolean }> | Readonly<{ pointer: string; present: true }>;
export type IdentityKey = Readonly<{ pointers: readonly string[]; separator: string }>;
export type IdentitySpec = Readonly<{
  request: IdentityRequest;
  require: readonly IdentityRequirement[];
  requireFailure: 'unverifiable' | 'reconnect_required';
  id: Readonly<{ pointers: readonly string[]; separator: string; allowNumbers: boolean }>;
  /** Used only when the primary ID pointers are absent (for example a provider's internal-integration tokens). */
  alternateId: IdentityKey | null;
  displayName: Readonly<{ pointers: readonly string[]; fallback: string }>;
  email: string | null;
  /** userId (F10.9, R5) repeats one part of the account id, so it must read one of the id's pointers. */
  attributes: Readonly<Partial<Record<'workspaceId' | 'workspaceName' | 'userId', string>>>;
}>;
export type AccessProbe = Readonly<{ url: string; method: 'GET' }>;
export type AuthApp = Readonly<{
  appId: string;
  scopes: Readonly<{ read: readonly string[]; write: readonly string[] }>;
  userScopes: Readonly<{ read: readonly string[]; write: readonly string[] }>;
  upgradeScopes: Readonly<{ prefixes: readonly string[]; exact: readonly string[] }>;
  accessProbe: AccessProbe | null;
}>;
export type Revocation = Readonly<{
  url: string; method: 'POST' | 'DELETE'; encoding: 'form' | 'json';
  clientAuthentication: 'none' | ClientAuthentication; tokenParameter: string;
  preferredToken: 'refresh' | 'access'; successStatuses: readonly number[];
  /** What a confirmed call removes: the whole provider grant, or only the presented token. */
  covers: 'grant' | 'token';
  /** Body facts that must also hold, for providers that report failure inside a 2xx response. */
  successRequire: readonly IdentityRequirement[];
  /** Where a person removes the app's authorization at the provider, for a revocation that removes only a token (F10.5, T1). */
  settingsUrl?: string;
}>;
/** Version 2 (F10.2): the scopes of one access level. Optional scopes are asked for at sign-in only under the 'full'
 *  consent policy; an in-context scope only through Add access on the permission rows it names, never at sign-in. */
export type InContextScope = Readonly<{ scope: string; rows: readonly string[] }>;
export type FullLevel = Readonly<{ required: readonly string[]; optional: readonly string[]; inContext: readonly InContextScope[] }>;
export type ReadLevel = Readonly<{ required: readonly string[]; optional: readonly string[] }>;
export type AccessGrant = 'scope' | 'user_scope' | 'pages';
export type AuthAppV2 = Readonly<{
  appId: string;
  accessProbe: AccessProbe | null;
  /** 'pages' is a grant of the pages the user picks (Notion); it carries no scopes. */
  access: Readonly<{ default: 'full'; grant: AccessGrant; levels: Readonly<{ full: FullLevel; read: ReadLevel | null }> }>;
  /** Scopes Fabric never asks for for this app: not at sign-in, not in Add access, not carried into a reconnect. */
  neverRequest: readonly string[];
  /** Page grants only (Notion): the integration capabilities the operator attests the registered app has. */
  attestedCapabilities?: readonly string[];
}>;
export type ConsentMode = 'full' | 'required';
/** One reading of a version 1 or version 2 app entry, so the engine has one code path. */
export type NormalizedAuthApp = Readonly<{
  appId: string; schemaVersion: 1 | 2; accessProbe: AccessProbe | null; grant: AccessGrant; identityScopes: readonly string[];
  levels: Readonly<{ full: FullLevel; read: ReadLevel | null }>;
  neverRequest: readonly string[];
  /** Each parent scope with every scope it grants through any chain (the definition's scopeImplications, closed); empty for version 1. */
  implies: Readonly<Record<string, readonly string[]>>;
  /** Version 1 only: the map-checked Add-access rule. Version 2 apps add only scopes of their full level. */
  upgradeScopes: Readonly<{ prefixes: readonly string[]; exact: readonly string[] }> | null;
}>;
export type AuthDefinition = Readonly<{
  schemaVersion: 1 | 2;
  providerId: string;
  displayName: string;
  reviewStatus: ReviewStatus;
  credentialEnvironment: Readonly<{ clientId: string; clientSecret: string }>;
  authorization: Readonly<{
    url: string; pkce: 'S256' | 'none'; scopeParameter: string; userScopeParameter: string | null;
    /** Verified provider rule for an http://127.0.0.1 callback; 'https-required' needs a hosted callback. */
    loopbackRedirect: 'allowed' | 'unverified' | 'https-required';
    scopeSeparator: ScopeSeparator; identityScopes: readonly string[]; extraParameters: Readonly<Record<string, string>>;
  }>;
  token: Readonly<{
    url: string; encoding: 'form' | 'json'; clientAuthentication: ClientAuthentication; responseFormat: TokenResponseFormat;
    scopeSeparator: ScopeSeparator; acceptedTokenTypes: readonly string[]; reconnectErrors: readonly string[];
    requireExpiry: boolean; maxLifetimeSeconds: number;
    /** Documented deviations from RFC 6749, each opted into per provider and never applied by default. */
    quirks: TokenQuirks;
  }>;
  refresh: Readonly<{ supported: boolean; keepPreviousWhenOmitted: boolean }>;
  revocation: Revocation | null;
  apiHeaders: Readonly<Record<string, string>>;
  identity: IdentitySpec;
  apps: readonly (AuthApp | AuthAppV2)[];
  /** Version 2 only: a parent scope grants its children (GitHub `user` grants `read:user`). */
  scopeImplications?: Readonly<Record<string, readonly string[]>>;
  /** Version 2 only: what sign-in asks for while the provider app is in testing and once it is published. */
  consentPolicy?: Readonly<{ testing: ConsentMode; production: ConsentMode }>;
  /** Version 2 only (F10.21): body facts every 2xx API answer must hold, for a provider that answers its errors with a 2xx (Slack: /ok is true). */
  apiSuccessRequire?: readonly Readonly<{ pointer: string; equals: string | number | boolean }>[];
  /** Version 2 only, optional (F10.17): the lowercase response header in which the provider lists what a token holds (GitHub's
   *  x-oauth-scopes). Fabric reads it to narrow a grant, never to widen one (lib/grant-drift.mjs), and never sends it. */
  grantHeader?: string;
}>;

export class AuthDefinitionError extends Error {
  readonly code = 'invalid_definition';
  constructor(detail: string) { super(`Invalid auth definition: ${detail}.`); this.name = 'AuthDefinitionError'; }
}

const PROVIDER = /^[a-z][a-z0-9-]{1,39}$/;
const APP = /^[a-z][a-z0-9-]{0,63}$/;
const ENV = /^FABRIC_[A-Z0-9_]{1,60}$/;
const PARAMETER = /^[a-z][a-z0-9_]{0,39}$/;
const HEADER = /^[A-Za-z][A-Za-z0-9-]{0,63}$/;
// F10.17: a grant header is a provider's own x- header, in lower case as the network seam names response headers.
const GRANT_HEADER = /^x-[a-z0-9-]{1,62}$/;
const ERROR_CODE = /^[a-z][a-z0-9_]{0,63}$/;
const SCOPE = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$/;
// JSON Pointer subset; prototype-chain segment names are never addressable.
const POINTER = /^(?:\/(?!(?:__proto__|prototype|constructor)(?:\/|$))[A-Za-z0-9_.-]{1,64}){1,6}$/;
const PRINTABLE = /^[^\u0000-\u001f\u007f]{1,200}$/;
const ROW = /^[a-z][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*){1,4}$/;
// The engine owns these values; a definition can never supply or override them.
const RESERVED_PARAMETERS = new Set(['client_id', 'client_secret', 'redirect_uri', 'response_type', 'state', 'scope', 'user_scope', 'code', 'code_challenge', 'code_challenge_method', 'code_verifier', 'grant_type', 'refresh_token', 'access_token', 'nonce']);
const RESERVED_HEADERS = new Set(['authorization', 'cookie', 'host', 'content-length', 'proxy-authorization', 'content-type', 'accept']);
// The only template a definition may use: the operator's public client ID in a revocation path.
const CLIENT_ID_PLACEHOLDER = '{client_id}';

const isRecord = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
function fail(detail: string): never { throw new AuthDefinitionError(detail); }
function shape(value: unknown, keys: readonly string[], where: string): asserts value is Record<string, unknown> {
  if (!isRecord(value)) fail(`${where} must be an object`);
  for (const key of keys) if (!Object.hasOwn(value, key)) fail(`${where}.${key} is required`);
  for (const key of Object.keys(value)) if (!keys.includes(key)) fail(`${where}.${key} is not allowed`);
}
function text(value: unknown, pattern: RegExp, where: string): string {
  if (typeof value !== 'string' || !pattern.test(value)) fail(`${where} is malformed`);
  return value;
}
function bool(value: unknown, where: string): boolean { if (typeof value !== 'boolean') fail(`${where} must be a boolean`); return value; }
function oneOf<T extends string>(value: unknown, allowed: readonly T[], where: string): T {
  if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value)) fail(`${where} must be one of ${allowed.join(', ')}`);
  return value as T;
}
function list(value: unknown, item: (entry: unknown, where: string) => unknown, where: string, max = 32, min = 0): unknown[] {
  if (!Array.isArray(value) || value.length < min || value.length > max) fail(`${where} must be a list of ${min}-${max} entries`);
  const seen = new Set<string>();
  value.forEach((entry, index) => {
    item(entry, `${where}[${index}]`);
    const key = canonicalHash(entry);
    if (seen.has(key)) fail(`${where} contains a duplicate`);
    seen.add(key);
  });
  return value;
}
/** Absolute HTTPS endpoint on the default port with no credentials, query or fragment. */
export function endpoint(value: unknown, where: string): string {
  if (typeof value !== 'string' || value.length > 500) fail(`${where} must be an HTTPS URL`);
  let url: URL;
  try { url = new URL(value); } catch { fail(`${where} must be an HTTPS URL`); }
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.search || url.hash || url.href !== value ||
      url.hostname === 'localhost' || /^[\d.]+$/.test(url.hostname) || url.hostname.startsWith('[') ||
      // Loopback, link-local, private-suffix, trailing-dot and single-label hosts are never public endpoints.
      !url.hostname.includes('.') || url.hostname.endsWith('.') || /\.(?:localhost|local|internal|home|lan|corp|intranet)$/.test(url.hostname)) fail(`${where} must be a public HTTPS URL without credentials, port, query or fragment`);
  return value;
}
function map(value: unknown, keyPattern: RegExp, reserved: Set<string>, where: string, max = 8): Record<string, string> {
  if (!isRecord(value) || Object.keys(value).length > max) fail(`${where} must be an object with at most ${max} entries`);
  for (const [key, entry] of Object.entries(value)) {
    if (!keyPattern.test(key) || reserved.has(key.toLowerCase())) fail(`${where}.${key} is not an allowed name`);
    text(entry, PRINTABLE, `${where}.${key}`);
  }
  return value as Record<string, string>;
}
function scopes(value: unknown, where: string, max = 64): void { list(value, (entry, at) => text(entry, SCOPE, at), where, max); }
function scopePair(value: unknown, where: string): void {
  shape(value, ['read', 'write'], where);
  scopes(value.read, `${where}.read`); scopes(value.write, `${where}.write`);
}
function pointers(value: unknown, where: string, min: number, max: number): void { list(value, (entry, at) => text(entry, POINTER, at), where, max, min); }

function requirements(value: unknown, where: string): void {
  list(value, (entry, at) => {
    if (isRecord(entry) && Object.hasOwn(entry, 'present')) {
      shape(entry, ['pointer', 'present'], at);
      if (entry.present !== true) fail(`${at}.present must be true`);
    } else {
      shape(entry, ['pointer', 'equals'], at);
      if (!['string', 'number', 'boolean'].includes(typeof entry.equals) || (typeof entry.equals === 'string' && !PRINTABLE.test(entry.equals))) fail(`${at}.equals is malformed`);
    }
    text(entry.pointer, POINTER, `${at}.pointer`);
  }, where, 4);
}
function identityKey(value: unknown, where: string): void {
  shape(value, ['pointers', 'separator'], where);
  pointers(value.pointers, `${where}.pointers`, 1, 3);
  if (typeof value.separator !== 'string' || !/^[:|/@-]?$/.test(value.separator)) fail(`${where}.separator is malformed`);
  if ((value.pointers as unknown[]).length > 1 && !value.separator) fail(`${where}.separator is required for composite identities`);
}

function identity(value: unknown, where: string): void {
  shape(value, ['request', 'require', 'requireFailure', 'id', 'alternateId', 'displayName', 'email', 'attributes'], where);
  shape(value.request, ['url', 'method', 'headers', 'body'], `${where}.request`);
  endpoint(value.request.url, `${where}.request.url`);
  oneOf(value.request.method, ['GET', 'POST'], `${where}.request.method`);
  map(value.request.headers, HEADER, RESERVED_HEADERS, `${where}.request.headers`);
  oneOf(value.request.body, ['none', 'empty-form'], `${where}.request.body`);
  if (value.request.method === 'GET' && value.request.body !== 'none') fail(`${where}.request.body must be none for GET`);
  requirements(value.require, `${where}.require`);
  oneOf(value.requireFailure, ['unverifiable', 'reconnect_required'], `${where}.requireFailure`);
  shape(value.id, ['pointers', 'separator', 'allowNumbers'], `${where}.id`);
  pointers(value.id.pointers, `${where}.id.pointers`, 1, 3);
  if (typeof value.id.separator !== 'string' || !/^[:|/@-]?$/.test(value.id.separator)) fail(`${where}.id.separator is malformed`);
  if ((value.id.pointers as unknown[]).length > 1 && !value.id.separator) fail(`${where}.id.separator is required for composite identities`);
  bool(value.id.allowNumbers, `${where}.id.allowNumbers`);
  if (value.alternateId !== null) identityKey(value.alternateId, `${where}.alternateId`);
  shape(value.displayName, ['pointers', 'fallback'], `${where}.displayName`);
  pointers(value.displayName.pointers, `${where}.displayName.pointers`, 0, 4);
  text(value.displayName.fallback, PRINTABLE, `${where}.displayName.fallback`);
  if (value.email !== null) text(value.email, POINTER, `${where}.email`);
  if (!isRecord(value.attributes)) fail(`${where}.attributes must be an object`);
  // F10.9 (R5): userId reads one of the id pointers, and of the alternate id's too when there is one, since that key makes the account
  // id whenever a primary pointer is absent. So whichever key made the account id already carries it.
  const alternate = value.alternateId as IdentityKey | null;
  for (const [key, pointer] of Object.entries(value.attributes)) {
    if (!['workspaceId', 'workspaceName', 'userId'].includes(key)) fail(`${where}.attributes.${key} is not allowed`);
    text(pointer, POINTER, `${where}.attributes.${key}`);
    // F10.9 (R5): the provider's own user id, never anything the account id does not already carry, so bindings can leave it out.
    if (key === 'userId' && !(value.id.pointers as unknown[]).includes(pointer)) fail(`${where}.attributes.userId must read one of the id pointers`);
    if (key === 'userId' && alternate !== null && !(alternate.pointers as readonly unknown[]).includes(pointer)) fail(`${where}.attributes.userId must also read one of the alternate id pointers`);
  }
}

function app(value: unknown, where: string, userScopes: boolean): void {
  shape(value, ['appId', 'scopes', 'userScopes', 'upgradeScopes', 'accessProbe'], where);
  text(value.appId, APP, `${where}.appId`);
  scopePair(value.scopes, `${where}.scopes`); scopePair(value.userScopes, `${where}.userScopes`);
  const user = value.userScopes as { read: unknown[]; write: unknown[] };
  if (!userScopes && (user.read.length || user.write.length)) fail(`${where}.userScopes require authorization.userScopeParameter`);
  shape(value.upgradeScopes, ['prefixes', 'exact'], `${where}.upgradeScopes`);
  list(value.upgradeScopes.prefixes, (entry, at) => { const prefix = text(entry, SCOPE, at); if (prefix.length < 8) fail(`${at} is too broad`); }, `${where}.upgradeScopes.prefixes`, 8);
  scopes(value.upgradeScopes.exact, `${where}.upgradeScopes.exact`, 16);
  accessProbe(value.accessProbe, where);
}

function accessProbe(value: unknown, where: string): void {
  if (value !== null) {
    shape(value, ['url', 'method'], `${where}.accessProbe`);
    if (typeof value.url !== 'string' || value.url.length > 500) fail(`${where}.accessProbe.url is malformed`);
    let url: URL;
    try { url = new URL(value.url); } catch { fail(`${where}.accessProbe.url is malformed`); }
    // A fixed, bounded read probe may carry a query; it never carries credentials.
    endpoint(`${url.origin}${url.pathname}`, `${where}.accessProbe.url`);
    if (url.hash || url.username || url.password || url.href !== value.url) fail(`${where}.accessProbe.url is malformed`);
    oneOf(value.method, ['GET'], `${where}.accessProbe.method`);
  }
}

const scopeList = (value: unknown): string[] => value as string[];
function overlap(a: readonly string[], b: readonly string[]): string | undefined { return a.find(scope => b.includes(scope)); }

/** Version 2 app entry: levels, never-request list and the implication and identity rules that bind them. */
function appV2(value: unknown, where: string, context: { userScopes: boolean; identityScopes: readonly string[]; implications: Readonly<Record<string, readonly string[]>> }): void {
  shape(value, ['appId', 'accessProbe', 'access', 'neverRequest', ...(isRecord(value) && Object.hasOwn(value, 'attestedCapabilities') ? ['attestedCapabilities'] : [])], where);
  text(value.appId, APP, `${where}.appId`);
  accessProbe(value.accessProbe, where);
  shape(value.access, ['default', 'grant', 'levels'], `${where}.access`);
  oneOf(value.access.default, ['full'], `${where}.access.default`);
  const grant = oneOf(value.access.grant, ['scope', 'user_scope', 'pages'], `${where}.access.grant`);
  if (grant === 'user_scope' && !context.userScopes) fail(`${where}.access.grant user_scope requires authorization.userScopeParameter`);
  shape(value.access.levels, ['full', 'read'], `${where}.access.levels`);
  const full = value.access.levels.full, read = value.access.levels.read;
  shape(full, ['required', 'optional', 'inContext'], `${where}.access.levels.full`);
  for (const key of ['required', 'optional'] as const) scopes(full[key], `${where}.access.levels.full.${key}`);
  const appId = value.appId as string;
  list(full.inContext, (entry, at) => {
    shape(entry, ['scope', 'rows'], at);
    text(entry.scope, SCOPE, `${at}.scope`);
    // Rows are this app's permission row ids; a consistency test checks each one exists in catalog/permissions.
    list(entry.rows, (row, rowAt) => { if (typeof text(row, ROW, rowAt) !== 'string' || !(row as string).startsWith(`${appId}.`)) fail(`${rowAt} must name one of ${appId}'s permission rows`); }, `${at}.rows`, 16, 1);
  }, `${where}.access.levels.full.inContext`, 64);
  if (read !== null) {
    shape(read, ['required', 'optional'], `${where}.access.levels.read`);
    for (const key of ['required', 'optional'] as const) scopes(read[key], `${where}.access.levels.read.${key}`);
  }
  scopes(value.neverRequest, `${where}.neverRequest`);
  if (Object.hasOwn(value, 'attestedCapabilities')) {
    if (grant !== 'pages') fail(`${where}.attestedCapabilities belong to a pages grant only`);
    list(value.attestedCapabilities, (entry, at) => text(entry, /^[a-z][a-z_]{0,39}$/, at), `${where}.attestedCapabilities`, 8);
  }
  const required = scopeList(full.required), optional = scopeList(full.optional), never = scopeList(value.neverRequest);
  const inContext = (full.inContext as { scope: string }[]).map(entry => entry.scope);
  if (new Set(inContext).size !== inContext.length) fail(`${where}.access.levels.full.inContext names a scope twice`);
  const readRequired = read === null ? [] : scopeList((read as Record<string, unknown>).required), readOptional = read === null ? [] : scopeList((read as Record<string, unknown>).optional);
  if (grant === 'pages' && (required.length || optional.length || inContext.length || read !== null)) fail(`${where}.access.grant pages carries no scopes and no read level`);
  // A scope grant that asks for nothing could never deliver what "full access" promises; an empty read level likewise.
  if (grant !== 'pages' && !required.length && !optional.length) fail(`${where}.access.levels.full asks for no scope at sign-in`);
  if (read !== null && !readRequired.length) fail(`${where}.access.levels.read needs at least one required scope, or null for no read level`);
  if (overlap(required, optional)) fail(`${where}.access.levels.full lists ${overlap(required, optional)} as both required and optional`);
  // An in-context scope is never asked for at sign-in, at any level.
  if (overlap(inContext, [...required, ...optional, ...readRequired, ...readOptional])) fail(`${where}.access.levels.full.inContext repeats ${overlap(inContext, [...required, ...optional, ...readRequired, ...readOptional])}, which a sign-in asks for`);
  if (overlap(readRequired, readOptional)) fail(`${where}.access.levels.read lists ${overlap(readRequired, readOptional)} as both required and optional`);
  const levels = {full: [...required, ...optional, ...inContext], ...(read === null ? {} : {read: [...readRequired, ...readOptional]})};
  for (const [level, own] of Object.entries(levels)) {
    const never_ = overlap(own, never);
    if (never_) fail(`${where} asks for ${never_} in the ${level} level and also lists it in neverRequest`);
    if (overlap(own, context.identityScopes)) fail(`${where}.access.levels.${level} repeats the identity scope ${overlap(own, context.identityScopes)}`);
    // Every sign-in also asks for the identity scopes, so the implication rules see them as part of each level.
    const members = [...own, ...context.identityScopes];
    for (const parent of members) {
      const grants = context.implications[parent] || [];
      // A parent with something it already grants is a contradiction; a parent that grants a never-requested scope,
      // directly or through a chain, would hand it over anyway.
      if (overlap(grants, members)) fail(`${where}.access.levels.${level} asks for ${parent} and ${overlap(grants, members)}, which ${parent} already grants`);
      if (overlap(grants, never)) fail(`${where}.access.levels.${level} asks for ${parent}, which grants the never-requested ${overlap(grants, never)}`);
    }
  }
  const identityNever = overlap(context.identityScopes, never);
  if (identityNever) fail(`${where}.neverRequest lists the identity scope ${identityNever}, which every sign-in asks for`);
}

/** For each parent, every scope it grants through any chain (its closure), breadth first. Pure: a chain that comes back to its
 *  parent is skipped, and `cycle` (the validator's) hears of it with the scopes passed on the way. */
export function impliedClosure(direct: Readonly<Record<string, readonly string[]>> | undefined, cycle?: (parent: string, through: readonly string[]) => void): Record<string, readonly string[]> {
  const closure: Record<string, readonly string[]> = Object.create(null), rules = direct ?? {};
  for (const parent of Object.keys(rules)) {
    const seen = new Set<string>(), queue: string[] = [...(rules[parent] || [])];
    while (queue.length) {
      const scope = queue.shift() as string;
      if (scope === parent) { cycle?.(parent, [...seen]); continue; }
      if (seen.has(scope)) continue;
      seen.add(scope);
      queue.push(...(Object.hasOwn(rules, scope) ? rules[scope] || [] : []));
    }
    closure[parent] = [...seen];
  }
  return closure;
}

/** Validates scopeImplications and returns, for each parent, every scope it grants through any chain (its closure). */
function implications(value: unknown, where: string): Record<string, readonly string[]> {
  if (!isRecord(value) || Object.keys(value).length > 16) fail(`${where} must be an object with at most 16 entries`);
  for (const [parent, children] of Object.entries(value)) {
    text(parent, SCOPE, `${where} key`);
    scopes(children, `${where}.${parent}`, 8);
    if ((children as unknown[]).length === 0) fail(`${where}.${parent} must name at least one scope`);
  }
  return impliedClosure(value as Record<string, readonly string[]>, (parent, through) => fail(through.length ? `${where}.${parent} grants itself through ${through.join(', ')}` : `${where}.${parent} cannot grant itself`));
}

/** Validates a definition and returns a detached, deeply frozen copy. */
export function validateAuthDefinition(value: unknown): AuthDefinition {
  try { canonicalHash(value); } catch { fail('definition must be plain JSON data'); }
  if (!isRecord(value) || (value.schemaVersion !== 1 && value.schemaVersion !== 2)) fail('definition.schemaVersion must be 1 or 2');
  const v2 = value.schemaVersion === 2, grant = v2 && Object.hasOwn(value, 'grantHeader');
  shape(value, ['schemaVersion', 'providerId', 'displayName', 'reviewStatus', 'credentialEnvironment', 'authorization', 'token', 'refresh', 'revocation', 'apiHeaders', 'identity', 'apps', ...(v2 ? ['scopeImplications', 'consentPolicy'] : []),
    ...(v2 && Object.hasOwn(value, 'apiSuccessRequire') ? ['apiSuccessRequire'] : []), ...(grant ? ['grantHeader'] : [])], 'definition');
  text(value.providerId, PROVIDER, 'definition.providerId');
  text(value.displayName, /^[A-Za-z0-9][A-Za-z0-9 .&'-]{0,59}$/, 'definition.displayName');
  oneOf(value.reviewStatus, ['candidate', 'reviewed'], 'definition.reviewStatus');
  shape(value.credentialEnvironment, ['clientId', 'clientSecret'], 'definition.credentialEnvironment');
  text(value.credentialEnvironment.clientId, ENV, 'definition.credentialEnvironment.clientId');
  text(value.credentialEnvironment.clientSecret, ENV, 'definition.credentialEnvironment.clientSecret');
  // A definition may read only its own provider's client credentials, never another secret.
  const envPrefix = `FABRIC_${(value.providerId as string).toUpperCase().replace(/-/g, '_')}_CLIENT_`;
  if (value.credentialEnvironment.clientId !== `${envPrefix}ID` || value.credentialEnvironment.clientSecret !== `${envPrefix}SECRET`) fail(`definition.credentialEnvironment must be ${envPrefix}ID and ${envPrefix}SECRET`);

  const authorization = value.authorization;
  shape(authorization, ['url', 'pkce', 'scopeParameter', 'userScopeParameter', 'loopbackRedirect', 'scopeSeparator', 'identityScopes', 'extraParameters'], 'definition.authorization');
  oneOf(authorization.loopbackRedirect, ['allowed', 'unverified', 'https-required'], 'definition.authorization.loopbackRedirect');
  endpoint(authorization.url, 'definition.authorization.url');
  oneOf(authorization.pkce, ['S256', 'none'], 'definition.authorization.pkce');
  if (authorization.scopeParameter !== 'scope') fail('definition.authorization.scopeParameter must be scope');
  if (authorization.userScopeParameter !== null && authorization.userScopeParameter !== 'user_scope') fail('definition.authorization.userScopeParameter must be user_scope or null');
  oneOf(authorization.scopeSeparator, [' ', ','], 'definition.authorization.scopeSeparator');
  scopes(authorization.identityScopes, 'definition.authorization.identityScopes', 8);
  map(authorization.extraParameters, PARAMETER, RESERVED_PARAMETERS, 'definition.authorization.extraParameters');

  const token = value.token;
  shape(token, ['url', 'encoding', 'clientAuthentication', 'responseFormat', 'scopeSeparator', 'acceptedTokenTypes', 'reconnectErrors', 'requireExpiry', 'maxLifetimeSeconds', 'quirks'], 'definition.token');
  shape(token.quirks, ['errorInSuccessBody', 'errorCodeField', 'nullRefreshMeansNone', 'basicEncoding'], 'definition.token.quirks');
  bool(token.quirks.errorInSuccessBody, 'definition.token.quirks.errorInSuccessBody');
  oneOf(token.quirks.errorCodeField, ['error', 'error-or-code'], 'definition.token.quirks.errorCodeField');
  bool(token.quirks.nullRefreshMeansNone, 'definition.token.quirks.nullRefreshMeansNone');
  oneOf(token.quirks.basicEncoding, ['raw', 'form-urlencoded'], 'definition.token.quirks.basicEncoding');
  endpoint(token.url, 'definition.token.url');
  oneOf(token.encoding, ['form', 'json'], 'definition.token.encoding');
  oneOf(token.clientAuthentication, ['body', 'basic'], 'definition.token.clientAuthentication');
  oneOf(token.responseFormat, ['oauth2', 'slack-v2'], 'definition.token.responseFormat');
  oneOf(token.scopeSeparator, [' ', ','], 'definition.token.scopeSeparator');
  list(token.acceptedTokenTypes, (entry, at) => text(entry, /^[a-z][a-z_-]{0,19}$/, at), 'definition.token.acceptedTokenTypes', 4, 1);
  list(token.reconnectErrors, (entry, at) => text(entry, ERROR_CODE, at), 'definition.token.reconnectErrors', 12, 1);
  bool(token.requireExpiry, 'definition.token.requireExpiry');
  if (!Number.isSafeInteger(token.maxLifetimeSeconds) || (token.maxLifetimeSeconds as number) < 60 || (token.maxLifetimeSeconds as number) > 31_536_000) fail('definition.token.maxLifetimeSeconds must be 60-31536000');

  shape(value.refresh, ['supported', 'keepPreviousWhenOmitted'], 'definition.refresh');
  bool(value.refresh.supported, 'definition.refresh.supported'); bool(value.refresh.keepPreviousWhenOmitted, 'definition.refresh.keepPreviousWhenOmitted');
  if (!value.refresh.supported && value.refresh.keepPreviousWhenOmitted) fail('definition.refresh.keepPreviousWhenOmitted requires refresh support');

  if (value.revocation !== null) {
    const revocation = value.revocation;
    const settings = isRecord(revocation) && Object.hasOwn(revocation, 'settingsUrl');
    shape(revocation, ['url', 'method', 'encoding', 'clientAuthentication', 'tokenParameter', 'preferredToken', 'successStatuses', 'successRequire', 'covers', ...(settings ? ['settingsUrl'] : [])], 'definition.revocation');
    oneOf(revocation.covers, ['grant', 'token'], 'definition.revocation.covers');
    if (typeof revocation.url !== 'string') fail('definition.revocation.url must be an HTTPS URL');
    const at = revocation.url.indexOf(CLIENT_ID_PLACEHOLDER), pathStart = revocation.url.indexOf('/', 'https://'.length), after = revocation.url[at + CLIENT_ID_PLACEHOLDER.length];
    if (revocation.url.split(CLIENT_ID_PLACEHOLDER).length > 2 || (at !== -1 && (pathStart === -1 || at <= pathStart || revocation.url[at - 1] !== '/' || (after !== undefined && after !== '/')))) fail('definition.revocation.url may contain one {client_id} placeholder as a whole path segment');
    endpoint(revocation.url.replace(CLIENT_ID_PLACEHOLDER, 'client-id'), 'definition.revocation.url');
    oneOf(revocation.method, ['POST', 'DELETE'], 'definition.revocation.method');
    oneOf(revocation.encoding, ['form', 'json'], 'definition.revocation.encoding');
    oneOf(revocation.clientAuthentication, ['none', 'body', 'basic'], 'definition.revocation.clientAuthentication');
    if (!['token', 'access_token'].includes(revocation.tokenParameter as string)) fail('definition.revocation.tokenParameter must be token or access_token');
    oneOf(revocation.preferredToken, ['refresh', 'access'], 'definition.revocation.preferredToken');
    list(revocation.successStatuses, (entry, at) => { if (!Number.isSafeInteger(entry) || (entry as number) < 200 || (entry as number) > 299) fail(`${at} must be a 2xx status`); }, 'definition.revocation.successStatuses', 4, 1);
    requirements(revocation.successRequire, 'definition.revocation.successRequire');
    if (settings) {
      if (typeof revocation.settingsUrl !== 'string' || revocation.settingsUrl.length > 200) fail('definition.revocation.settingsUrl must be an HTTPS URL of at most 200 characters');
      endpoint(revocation.settingsUrl, 'definition.revocation.settingsUrl');
    }
  }
  const apiHeaders = map(value.apiHeaders, HEADER, RESERVED_HEADERS, 'definition.apiHeaders');
  if (grant) {
    const header = text(value.grantHeader, GRANT_HEADER, 'definition.grantHeader');
    // Never a header Fabric sends itself: a reserved one, or one of the definition's own API headers.
    if (RESERVED_HEADERS.has(header) || Object.keys(apiHeaders).some(name => name.toLowerCase() === header)) fail('definition.grantHeader names a header Fabric sends');
  }
  identity(value.identity, 'definition.identity');
  const implied = v2 ? implications(value.scopeImplications, 'definition.scopeImplications') : {};
  if (v2) {
    shape(value.consentPolicy, ['testing', 'production'], 'definition.consentPolicy');
    oneOf(value.consentPolicy.testing, ['full', 'required'], 'definition.consentPolicy.testing');
    oneOf(value.consentPolicy.production, ['full', 'required'], 'definition.consentPolicy.production');
    // F10.21: the facts a provider's 2xx answers must hold, each an exact value (a present fact says nothing about success).
    if (Object.hasOwn(value, 'apiSuccessRequire')) {
      const facts = value.apiSuccessRequire;
      if (!Array.isArray(facts) || !facts.length) fail('definition.apiSuccessRequire must be a list of 1-4 entries');
      requirements(facts, 'definition.apiSuccessRequire');
      if (facts.some(entry => Object.hasOwn(entry as object, 'present'))) fail('definition.apiSuccessRequire entries are {pointer, equals}');
    }
  }
  const appIds = new Set<string>();
  if (v2) list(value.apps, (entry, at) => {
    appV2(entry, at, {userScopes: authorization.userScopeParameter !== null, identityScopes: scopeList(authorization.identityScopes), implications: implied});
    const appId = (entry as { appId: string }).appId;
    if (appIds.has(appId)) fail(`${at}.appId is duplicated`);
    appIds.add(appId);
  }, 'definition.apps', 16, 1);
  else list(value.apps, (entry, at) => {
    app(entry, at, authorization.userScopeParameter !== null);
    const appId = (entry as { appId: string }).appId;
    if (appIds.has(appId)) fail(`${at}.appId is duplicated`);
    appIds.add(appId);
    // One connection stores one credential: a Slack-style exchange may carry a bot
    // and a user token, so an app may request bot scopes or user scopes, not both.
    const pair = entry as { scopes: { read: unknown[]; write: unknown[] }; userScopes: { read: unknown[]; write: unknown[] } };
    if ((pair.scopes.read.length || pair.scopes.write.length) && (pair.userScopes.read.length || pair.userScopes.write.length)) fail(`${at} may request bot scopes or user scopes, not both`);
  }, 'definition.apps', 16, 1);
  if (v2) {
    // T1 across apps (F10.5): a sign-in is refused for any granted scope on any app's never list, so no app's access may ask
    // for, or grant through an implication, a scope another app of the same provider never holds.
    const apps = value.apps as AuthAppV2[];
    apps.forEach((entry, index) => {
      for (const other of apps.filter(item => item !== entry)) {
        const {full, read} = other.access.levels, asked = [...full.required, ...full.optional, ...full.inContext.map(item => item.scope), ...(read ? [...read.required, ...read.optional] : [])];
        const reach = new Set(asked.flatMap(scope => [scope, ...(implied[scope] ?? [])])), clash = entry.neverRequest.find(scope => reach.has(scope));
        if (clash) fail(`definition.apps[${index}].neverRequest lists ${clash}, which the ${other.appId} app's access asks for or grants`);
      }
    });
  }
  return deepFreeze(structuredClone(value)) as unknown as AuthDefinition;
}

/** One reading of either version's app entry. Version 1: its write set is the full level and its read set the read level,
 *  exactly as version 1 code asked for them, so version 1 sign-ins are unchanged (T6). */
export function normalizeAuthApp(definition: AuthDefinition, entry: AuthApp | AuthAppV2): NormalizedAuthApp {
  if (definition.schemaVersion === 2) {
    const app = entry as AuthAppV2;
    return deepFreeze({appId: app.appId, schemaVersion: 2, accessProbe: app.accessProbe, grant: app.access.grant, identityScopes: definition.authorization.identityScopes,
      levels: app.access.levels, neverRequest: app.neverRequest, implies: impliedClosure(definition.scopeImplications), upgradeScopes: null});
  }
  const app = entry as AuthApp, user = definition.authorization.userScopeParameter !== null && (app.userScopes.read.length > 0 || app.userScopes.write.length > 0);
  const pair = user ? app.userScopes : app.scopes;
  return deepFreeze({appId: app.appId, schemaVersion: 1, accessProbe: app.accessProbe, grant: user ? 'user_scope' : 'scope', identityScopes: definition.authorization.identityScopes,
    levels: {full: {required: pair.write, optional: [], inContext: []}, read: {required: pair.read, optional: []}}, neverRequest: [], implies: {}, upgradeScopes: app.upgradeScopes});
}

/** What a grant holds (F10.5): the granted scopes and every scope a granted parent grants, so GitHub's `admin:org` holds
 *  `read:org`. Version 1 implies nothing and reads the grant unchanged. */
export function effectiveScopes(app: NormalizedAuthApp, granted: readonly string[]): string[] {
  if (app.schemaVersion !== 2) return [...granted];
  return [...new Set([...granted, ...granted.flatMap(scope => Object.hasOwn(app.implies, scope) ? app.implies[scope] ?? [] : [])])];
}
/** The granted scopes Fabric never holds (T1): each one on the never list, or granting one through any chain. Sorted, once each. */
export function refusedScopes(neverRequest: readonly string[], implies: Readonly<Record<string, readonly string[]>>, granted: readonly string[]): string[] {
  const never = new Set(neverRequest);
  return [...new Set(granted.filter(scope => never.has(scope) || (Object.hasOwn(implies, scope) && (implies[scope] ?? []).some(child => never.has(child)))))].sort();
}

/** Every scope of a normalized app's full level, in definition order. */
export const fullLevelScopes = (app: NormalizedAuthApp): string[] => [...app.levels.full.required, ...app.levels.full.optional, ...app.levels.full.inContext.map(entry => entry.scope)];
/** The scopes of the level a sign-in asks for: the full level's three lists, or the read level's two. */
export const levelScopes = (app: NormalizedAuthApp, level: 'full' | 'read'): string[] => level === 'full' ? fullLevelScopes(app)
  : app.levels.read ? [...app.levels.read.required, ...app.levels.read.optional] : [];

function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object') { for (const entry of Object.values(value)) deepFreeze(entry); Object.freeze(value); }
  return value;
}

/** Fills the only permitted template, the public client ID in a revocation path. */
export function revocationUrl(definition: AuthDefinition, clientId: string): string | null {
  if (!definition.revocation) return null;
  return definition.revocation.url.replace(CLIENT_ID_PLACEHOLDER, encodeURIComponent(clientId));
}

/** Every origin a definition's lifecycle may contact, derived from its declared endpoints only. */
export function definitionOrigins(definition: AuthDefinition): Readonly<Record<'token' | 'revocation' | 'identity', readonly string[]>> {
  return Object.freeze({
    token: Object.freeze([new URL(definition.token.url).origin]),
    revocation: Object.freeze(definition.revocation ? [new URL(definition.revocation.url.replace(CLIENT_ID_PLACEHOLDER, 'client-id')).origin] : []),
    identity: Object.freeze([new URL(definition.identity.request.url).origin]),
  });
}

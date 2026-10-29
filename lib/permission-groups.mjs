import {readdirSync, readFileSync} from 'node:fs';

// Plain-language permission groups (UI-2, docs/UI-0-SCREEN-CONTRACTS.md section 3.7). Each app
// declares, as reviewed data in catalog/permissions/<appId>.json, the rows an owner sees ("Access
// drafts", "Send emails"), which operations belong to each, and each row's default. The engine
// still decides per operation; a group is a label, a default and a way to set its members together.
const EFFECTS = new Set(['read', 'write', 'delete']);
const MODES = new Set(['allow', 'ask', 'deny']);
const REQUEST = /^(GET|HEAD|POST|PUT|PATCH|DELETE) \/[^\s]{0,500}$/;
const ID = /^[a-z0-9][a-z0-9._-]{0,99}$/;
const RANK = {read: 0, write: 1, delete: 2}, STRICT = {allow: 0, ask: 1, deny: 2};
// F10.3: version 2 rows may also be locked by Fabric, reach other people, or send some bodies to a stricter row. F10.6: they may
// say which scopes their members need, which members can never work through a sign-in or cannot do their job, and what to note. F10.9:
// they may say which writes must carry the content a read returned, and which members' answers can carry a secret.
const VERSION_2 = ['locked', 'audience', 'bodyRoutes', 'scopeSets', 'memberScopeSets', 'unavailable', 'conditions', 'conditionalScopes', 'unsupported', 'bindContent', 'sensitive'];
const FIELDS = new Set(['id', 'label', 'effect', 'defaultMode', 'stayInAccount', 'operations', 'requests', 'scopes', 'reviewedReads', ...VERSION_2]);
const TESTS = ['contains', 'equals', 'present'];
/** F10.9: what a bound write carries: the etag read, the sha read, or the content read, sent again unchanged. */
const BIND_KINDS = Object.freeze(['etag', 'sha', 'resend']);
const scalar = value => value === null || typeof value === 'string' || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value));
/** ASCII-only case folding, as the proxy matcher folds paths. */
const fold = text => text.replace(/[A-Z]/g, char => String.fromCharCode(char.charCodeAt(0) + 32));

function invalid(appId, message) {throw new Error(`Permission groups for ${appId}: ${message}`);}

// Request templates (F08.0a): "METHOD /path" where each segment is a literal, {name} (exactly one segment),
// {name}:verb (one segment ending in a literal custom verb, as Google uses), or {+name} (one or more
// segments, last position only). {+name} marks a parameter the provider documents as spanning segments,
// such as a file path; for the typed operations it reads the same as {name}.
const PARAM = /^\{\+?[A-Za-z_][A-Za-z0-9_.-]{0,63}\}$/;
const PARAM_VERB = /^\{([A-Za-z_][A-Za-z0-9_.-]{0,63})\}(:[A-Za-z][A-Za-z0-9]{0,63})$/;
/** Parses one template; throws on anything outside the grammar (partial-segment parameters, {+x} not last). */
export function parseTemplate(request) {
  if (typeof request !== 'string' || !REQUEST.test(request)) throw new Error(`Template ${request} is not "METHOD /path".`);
  const [method, path] = request.split(' ');
  const raw = path === '/' ? [] : path.slice(1).split('/');
  const segments = raw.map((segment, index) => {
    if (!segment) throw new Error(`Template ${request} has an empty segment.`);
    if (PARAM.test(segment)) {
      const rest = segment.startsWith('{+');
      if (rest && index !== raw.length - 1) throw new Error(`Template ${request} has {+...} before the last segment.`);
      return {kind: rest ? 'rest' : 'param', name: segment.slice(rest ? 2 : 1, -1)};
    }
    const verb = PARAM_VERB.exec(segment);
    if (verb) return {kind: 'verb', name: verb[1], suffix: verb[2]};
    if (/[{}]/.test(segment)) throw new Error(`Template ${request} has a parameter inside a segment.`);
    return {kind: 'literal', value: segment};
  });
  return {method, segments};
}
/** The same template with {+name} read as {name}: how a typed operation's path is compared. */
export const memberKey = request => request.replace(/\{\+/g, '{');
/** Method plus segment shape, ignoring parameter names and ASCII case: two templates with one shape route the same requests. */
export function templateShape(parsed) {
  const fold = text => text.replace(/[A-Z]/g, char => char.toLowerCase());
  return `${parsed.method} /${parsed.segments.map(segment => segment.kind === 'literal' ? fold(segment.value) : segment.kind === 'param' ? '{}' : segment.kind === 'verb' ? `{}${fold(segment.suffix)}` : '{+}').join('/')}`;
}
/** The shape with {+name} read as {name}: two templates with one loose shape in different rows would let the
 *  proxy and a typed operation route the same endpoint to different rows. */
export const looseShape = parsed => templateShape(parsed).replace(/\{\+\}/g, '{}');
const strings = (value, pattern) => Array.isArray(value) && value.length <= 200 && value.every(item => typeof item === 'string' && item.length > 0 && item.length <= 500 && (!pattern || pattern.test(item)));

/** The reference tokens of an RFC 6901 JSON pointer, unescaped, or null when it is not one ('' names the whole value). */
function pointerTokens(pointer) {
  if (typeof pointer !== 'string' || (pointer && (!pointer.startsWith('/') || /~(?![01])/.test(pointer)))) return null;
  return pointer ? pointer.slice(1).split('/').map(token => token.replace(/~1/g, '/').replace(/~0/g, '~')) : [];
}
/** A row's body routes, checked and frozen: each is {member, pointer, to} plus exactly one of contains, equals (a JSON scalar)
 *  or present (true). `member` is a member of the row; `to` is checked once every row is known. */
function bodyRoutesOf(appId, group, operations, requests) {
  if (!Array.isArray(group.bodyRoutes) || !group.bodyRoutes.length || group.bodyRoutes.length > 50) invalid(appId, `${group.id} bodyRoutes lists between 1 and 50 routes.`);
  return Object.freeze(group.bodyRoutes.map(route => {
    const [kind, ...more] = route && typeof route === 'object' && !Array.isArray(route) ? TESTS.filter(key => Object.hasOwn(route, key)) : [];
    if (!kind || more.length || Object.keys(route).sort().join() !== ['member', 'pointer', 'to', kind].sort().join()) invalid(appId, `${group.id} has a body route that is not {member, pointer, to} with exactly one of contains, equals or present.`);
    if (kind === 'present' ? route.present !== true : !scalar(route[kind])) invalid(appId, kind === 'present' ? `${group.id} has a body route whose present must be true.` : `${group.id} has a body route whose ${kind} is not a JSON scalar.`);
    if (typeof route.member !== 'string' || !(operations.includes(route.member) || requests.map(memberKey).includes(memberKey(route.member)))) invalid(appId, `${route.member} has a body route in ${group.id} but is not a member of ${group.id}.`);
    const tokens = pointerTokens(route.pointer);
    if (!tokens?.length || tokens.length > 32 || route.pointer.length > 200 || tokens.some(token => !token || token === '__proto__')) invalid(appId, `${group.id} has a body route whose pointer ${route.pointer} is not a JSON pointer of 1 to 32 non-empty tokens in at most 200 characters.`);
    return Object.freeze({member: route.member, pointer: route.pointer, [kind]: route[kind], to: route.to});
  }));
}

/** Scope alternatives as rows declare them: 1 to 32, OR between them, AND within each, each de-duplicated and sorted. [[]] is
 *  "no scope; the provider decides"; [] says nothing, so it is refused. */
function setsOf(appId, where, value) {
  if (!Array.isArray(value) || !value.length || value.length > 32 || value.some(set => !Array.isArray(set) || set.length > 32 || !strings(set))) invalid(appId, `${where} must list 1 to 32 alternatives, each a list of at most 32 scopes of 1 to 500 characters.`);
  return Object.freeze(value.map(set => Object.freeze([...new Set(set)].sort())));
}
const words = (appId, where, value) => {if (typeof value !== 'string' || !value.trim() || value.length > 200) invalid(appId, `${where} needs a reason of 1 to 200 characters.`); return value;};
/** A row's F10.6 scope data, checked and frozen, each key only when declared. Member-keyed maps name members of the row and are
 *  stored by member key, so {+x} and {x} are one member and every reader looks a member up one way. */
function rowDataOf(appId, group, operations, requests) {
  const keys = requests.map(memberKey), isMember = member => operations.includes(member) || keys.includes(memberKey(member));
  const byMember = (key, read) => {
    const value = group[key];
    if (!value || typeof value !== 'object' || Array.isArray(value) || !Object.keys(value).length) invalid(appId, `${group.id} ${key} must name at least one member.`);
    const out = new Map();
    for (const [member, entry] of Object.entries(value)) {
      if (!isMember(member)) invalid(appId, `${member} is in ${group.id} ${key} but is not a member of ${group.id}.`);
      if (out.has(memberKey(member))) invalid(appId, `${group.id} ${key} names ${memberKey(member)} twice.`);
      out.set(memberKey(member), read(entry, member));
    }
    return Object.freeze(Object.fromEntries(out));
  };
  const scopeSets = group.scopeSets === undefined ? null : setsOf(appId, `${group.id} scopeSets`, group.scopeSets);
  const memberScopeSets = group.memberScopeSets === undefined ? null : byMember('memberScopeSets', (sets, member) => setsOf(appId, `${group.id} memberScopeSets for ${member}`, sets));
  const unavailable = group.unavailable === undefined ? null : byMember('unavailable', (reason, member) => {if (typeof reason !== 'string' || !Object.hasOwn(UNAVAILABLE_REASONS, reason)) invalid(appId, `${group.id} marks ${member} unavailable for an unknown reason.`); return reason;});
  const conditions = group.conditions === undefined ? null : byMember('conditions', (list, member) => {
    if (!Array.isArray(list) || !list.length || list.some(item => typeof item !== 'string' || !Object.hasOwn(CONDITION_WORDS, item))) invalid(appId, `${group.id} conditions for ${member} must be a list drawn from beta and plan-dependent.`);
    return Object.freeze([...new Set(list)].sort());
  });
  const unsupported = group.unsupported === undefined ? null : byMember('unsupported', (reason, member) => words(appId, `${group.id} unsupported for ${member}`, reason));
  let conditionalScopes = null;
  if (group.conditionalScopes !== undefined) {
    const value = group.conditionalScopes, entries = value && typeof value === 'object' && !Array.isArray(value) ? Object.entries(value) : [];
    if (!entries.length || entries.length > 16 || entries.some(([scope]) => !scope || scope.length > 500)) invalid(appId, `${group.id} conditionalScopes must name 1 to 16 scopes of 1 to 500 characters.`);
    if (group.locked !== undefined) invalid(appId, `${group.id} is locked by Fabric, so it has no conditional scopes.`);
    const asked = new Set([...(scopeSets ?? []), ...Object.values(memberScopeSets ?? {})].flat(2));
    for (const [scope, reason] of entries) {
      words(appId, `${group.id} conditionalScopes for ${scope}`, reason);
      if (asked.has(scope)) invalid(appId, `${group.id} lists ${scope} as conditional, but its scope sets already ask for it.`);
    }
    conditionalScopes = Object.freeze(Object.fromEntries(entries));
  }
  for (const member of Object.keys(unavailable ?? {})) if ([unsupported, memberScopeSets, conditions].some(map => map && Object.hasOwn(map, member)))
    invalid(appId, `${member} is unavailable in ${group.id}, so it cannot also be unsupported, have scope sets or carry conditions.`);
  // F10.9 (spec line 749, T5): a write on a member listed here must carry exactly what a prepare step read: the etag in If-Match, or the
  // sha or the raw content at a body pointer. R13 (T8): a member whose answer can carry a credential. Their reader is lib/actions.mjs.
  const bindContent = group.bindContent === undefined ? null : byMember('bindContent', (entry, member) => bindingOf(appId, group, member, entry));
  const sensitive = group.sensitive === undefined ? null : byMember('sensitive', (value, member) => {if (value !== 'secrets') invalid(appId, `${group.id} sensitive for ${member} must be "secrets".`); return value;});
  if ((bindContent || sensitive) && group.locked !== undefined) invalid(appId, `${group.id} is locked by Fabric, so it has no content binding and no sensitive members.`);
  for (const member of [...Object.keys(bindContent ?? {}), ...Object.keys(sensitive ?? {})]) if (unavailable && Object.hasOwn(unavailable, member))
    invalid(appId, `${member} is unavailable in ${group.id}, so it has no content binding and is not marked sensitive.`);
  return {...(scopeSets ? {scopeSets} : {}), ...(memberScopeSets ? {memberScopeSets} : {}), ...(unavailable ? {unavailable} : {}), ...(conditions ? {conditions} : {}),
    ...(conditionalScopes ? {conditionalScopes} : {}), ...(unsupported ? {unsupported} : {}), ...(bindContent ? {bindContent} : {}), ...(sensitive ? {sensitive} : {})};
}
/** F10.9: one member's content binding, checked and frozen: {kind, at}, an etag in header:If-Match, or a sha or the raw content resent at
 *  body:<pointer>, a JSON pointer of 1 to 32 non-empty tokens in at most 200 characters, as body routes take. */
function bindingOf(appId, group, member, entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry) || Object.keys(entry).sort().join() !== 'at,kind' || !BIND_KINDS.includes(entry.kind))
    invalid(appId, `${group.id} bindContent for ${member} must be {kind, at} with kind etag, sha or resend.`);
  const {kind, at} = entry;
  if (kind === 'etag') {
    if (at !== 'header:If-Match') invalid(appId, `${group.id} bindContent for ${member} carries an etag, which goes only in header:If-Match.`);
  } else {
    const pointer = typeof at === 'string' && at.startsWith('body:') ? at.slice(5) : null, tokens = pointerTokens(pointer);
    if (!tokens?.length || tokens.length > 32 || pointer.length > 200 || tokens.some(token => !token || token === '__proto__'))
      invalid(appId, `${group.id} bindContent for ${member} carries a ${kind} at body:<pointer>, a JSON pointer of 1 to 32 non-empty tokens in at most 200 characters.`);
  }
  return Object.freeze({kind, at});
}

/** Validates one app's reviewed group definition and returns it frozen. Defaults follow the product rules:
 *  reads may Allow; a write may Allow only when it stays inside the account and can be undone; deletes never Allow.
 *  Version 2 (F10.3, T4) adds locked rows (Never for every caller), audience rows (never Allow) and body routes (a body
 *  that matches goes to a row at least as strict), and (F10.6, T3) scope data and members marked unavailable or unsupported.
 *  Version 1 output is unchanged; version 2 output has no decorative scopes (F10.7). The output loads again to itself. */
export function validatePermissionGroups(definition) {
  if (!definition || typeof definition !== 'object' || ![1, 2].includes(definition.schemaVersion) || typeof definition.appId !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(definition.appId)) throw new Error('Permission groups need schemaVersion 1 or 2 and an appId.');
  const {appId, schemaVersion} = definition;
  if (!Array.isArray(definition.groups) || !definition.groups.length || definition.groups.length > 40) invalid(appId, 'between 1 and 40 groups are required.');
  const ids = new Set(), members = new Map();
  const groups = definition.groups.map(group => {
    if (!group || typeof group !== 'object') invalid(appId, 'a group must be an object.');
    if (!ID.test(group.id ?? '') || ids.has(group.id)) invalid(appId, `group id ${group.id} is missing, malformed or repeated.`);
    ids.add(group.id);
    for (const key of Object.keys(group)) {
      if (schemaVersion === 1 && VERSION_2.includes(key)) invalid(appId, `${group.id} carries ${key}, which needs schemaVersion 2.`);
      if (schemaVersion === 2 && !FIELDS.has(key)) invalid(appId, `${group.id} has an unknown field ${key}.`);
    }
    if (typeof group.label !== 'string' || !group.label.trim() || group.label.length > 60) invalid(appId, `${group.id} needs a label of at most 60 characters.`);
    if (!EFFECTS.has(group.effect) || !MODES.has(group.defaultMode)) invalid(appId, `${group.id} has an unknown effect or default.`);
    if (group.stayInAccount !== undefined && typeof group.stayInAccount !== 'boolean') invalid(appId, `${group.id} stayInAccount must be a boolean.`);
    if (group.defaultMode === 'allow' && group.effect === 'delete') invalid(appId, `${group.id} deletes, so it can never default to Allow.`);
    if (group.defaultMode === 'allow' && group.effect === 'write' && group.stayInAccount !== true) invalid(appId, `${group.id} changes data outside a reversible, in-account scope, so it cannot default to Allow.`);
    const operations = group.operations ?? [], requests = group.requests ?? [];
    if (!strings(operations) || !strings(requests, REQUEST) || operations.length + requests.length === 0) invalid(appId, `${group.id} needs operations or "METHOD /path" requests.`);
    for (const request of requests) {try {parseTemplate(request);} catch (error) {invalid(appId, error.message);}}
    for (const member of [...operations.map(id => `op:${id}`), ...requests.map(request => `req:${memberKey(request)}`)]) {
      if (members.has(member)) invalid(appId, `${member.slice(member.indexOf(':') + 1)} is in both ${members.get(member)} and ${group.id}.`);
      members.set(member, group.id);
    }
    // F10.7: the decorative list said nothing a reader acts on, and was wrong in places. A version 2 row says what its members need
    // in its scope data, so it refuses the list in any form; a version 1 file keeps it, checked and emitted as before.
    if (schemaVersion === 2 && group.scopes !== undefined) invalid(appId, `${group.id} carries scopes, but scopes is a version 1 field: a version 2 row says what its members need in scopeSets.`);
    if (group.scopes !== undefined && !strings(group.scopes)) invalid(appId, `${group.id} scopes must be strings.`);
    // Members that use a writing HTTP method (POST search, freebusy queries) but were reviewed as read-only.
    // Only a read row may list them, and only its own members; they change the default, nothing else.
    const reviewedReads = group.reviewedReads ?? [];
    if (!strings(reviewedReads)) invalid(appId, `${group.id} reviewedReads must be strings.`);
    if (reviewedReads.length && group.effect !== 'read') invalid(appId, `${group.id} is not a read row, so it cannot mark members as reviewed reads.`);
    for (const member of reviewedReads) if (!operations.includes(member) && !requests.map(memberKey).includes(memberKey(member))) invalid(appId, `${member} is marked as a reviewed read but is not a member of ${group.id}.`);
    // T4: a locked row is Never for every caller and nothing on it can loosen that; a row that reaches other people never runs unattended.
    if (group.locked !== undefined && group.locked !== 'fabric') invalid(appId, `${group.id} locked must be "fabric".`);
    if (group.locked && group.defaultMode !== 'deny') invalid(appId, `${group.id} is locked by Fabric, so it must default to Never.`);
    if (group.locked && (group.stayInAccount === true || reviewedReads.length || group.bodyRoutes !== undefined)) invalid(appId, `${group.id} is locked by Fabric, so it cannot stay in the account, list reviewed reads or route bodies.`);
    if (group.audience !== undefined && typeof group.audience !== 'boolean') invalid(appId, `${group.id} audience must be a boolean.`);
    if (group.audience && group.defaultMode === 'allow') invalid(appId, `${group.id} reaches other people, so it can never default to Allow.`);
    if (group.audience && group.stayInAccount === true) invalid(appId, `${group.id} reaches other people, so it cannot be reviewed as staying inside the account.`);
    const bodyRoutes = group.bodyRoutes === undefined ? null : bodyRoutesOf(appId, group, operations, requests), rowData = rowDataOf(appId, group, operations, requests);
    return Object.freeze({id: group.id, label: group.label.trim(), effect: group.effect, defaultMode: group.defaultMode, stayInAccount: group.stayInAccount === true,
      operations: Object.freeze([...operations]), requests: Object.freeze([...requests]), ...(schemaVersion === 1 ? {scopes: Object.freeze([...(group.scopes || [])])} : {}), reviewedReads: Object.freeze([...reviewedReads]),
      ...(group.locked !== undefined ? {locked: group.locked} : {}), ...(group.audience !== undefined ? {audience: group.audience} : {}), ...rowData, ...(bodyRoutes ? {bodyRoutes} : {})});
  });
  // A body route only ever tightens: its target is locked, or at least as strong in effect and default, and reaches other
  // people (or deletes) when its source reaches other people.
  for (const group of groups) for (const route of group.bodyRoutes ?? []) {
    const target = groups.find(other => other.id === route.to && other !== group);
    if (!target) invalid(appId, `${group.id} routes ${route.member} to ${route.to}, which is not another row of ${appId}.`);
    if (target.locked !== 'fabric' && (RANK[target.effect] < RANK[group.effect] || STRICT[target.defaultMode] < STRICT[group.defaultMode] || (group.audience === true && target.audience !== true && target.effect !== 'delete')))
      invalid(appId, `${group.id} routes ${route.member} to ${target.id}, which is looser: a route goes to a locked row, or to one at least as strong in effect and default that reaches other people when its source does.`);
  }
  // Two templates with the same shape in different groups would make the row a request lands in ambiguous.
  const shapes = new Map();
  for (const group of groups) for (const request of group.requests) {
    const shape = looseShape(parseTemplate(request));
    if (shapes.has(shape) && shapes.get(shape) !== group.id) invalid(appId, `${request} routes the same requests as a template in ${shapes.get(shape)}.`);
    shapes.set(shape, group.id);
  }
  return Object.freeze({schemaVersion, appId, groups: Object.freeze(groups)});
}

/** The reviewed definitions shipped in catalog/permissions, keyed by app. */
export function loadPermissionGroups(directory = new URL('../catalog/permissions/', import.meta.url)) {
  const byApp = new Map();
  let files = [];
  try { files = readdirSync(directory).filter(name => name.endsWith('.json')).sort(); } catch { return byApp; }
  for (const name of files) {
    const definition = validatePermissionGroups(JSON.parse(readFileSync(new URL(name, directory), 'utf8')));
    if (`${definition.appId}.json` !== name || byApp.has(definition.appId)) throw new Error(`Permission groups file ${name} must be named after its appId.`);
    byApp.set(definition.appId, definition);
  }
  return byApp;
}

/** The group an operation of the application map belongs to: by provider method id, or by "METHOD /path". */
export function groupFor(definitions, appId, operation) {
  const definition = definitions?.get(appId);
  if (!definition || !operation) return null;
  const request = typeof operation.method === 'string' && typeof operation.path === 'string' ? memberKey(`${operation.method.toUpperCase()} ${operation.path}`) : null;
  return definition.groups.find(group => group.operations.includes(operation.id) || (request !== null && group.requests.some(member => memberKey(member) === request))) || null;
}

/** F10.6 (T3): why a member can never work through a sign-in, in fixed words; the reason codes are reviewed data. */
export const UNAVAILABLE_REASONS = Object.freeze({
  'service-account-only': 'Google allows this only for a service account acting for a whole domain. A sign-in can never use it.',
  'workspace-cse-only': 'This needs Google Workspace client-side encryption, which a sign-in cannot use.',
  'bot-token-only': 'Slack allows this only with a bot token. Fabric signs in as you.',
  'client-credentials-only': 'Only the app itself can call this, with its own credentials. A sign-in can never use it.',
  'no-oauth-scope': 'No sign-in permission covers this, so a sign-in can never use it.',
  'not-requested': 'Fabric never asks for the permission this needs.',
});
/** F10.7 (decision 6): rows split out of an older row, by app, each with the row its members came from. Gmail's drafts, labels and
 *  filters deletes left "Permanently delete" (Never) for their own row (Ask). A developer's ceiling on the old row also covers the new
 *  one, and a record that followed the old row's Never keeps it as a saved Never (lib/permissions.mjs), so the split loosens no
 *  existing account. */
export const SPLIT_ROWS = Object.freeze({gmail: Object.freeze({'gmail.items.delete': 'gmail.permanent.delete'})});
/** Notes on a member that still runs: shown, never hashed. */
export const CONDITION_WORDS = Object.freeze({beta: 'In beta at the provider. It may change or stop working.', 'plan-dependent': 'Works only on some of the provider\'s plans.'});
/** The member of `group` an application-map operation is: its id when the row lists it, else its request as a member key. */
export function memberOf(group, operation) {
  if (!group || !operation) return null;
  if (group.operations.includes(operation.id)) return operation.id;
  return typeof operation.method === 'string' && typeof operation.path === 'string' ? memberKey(`${operation.method.toUpperCase()} ${operation.path}`) : null;
}
/** One member's row data: its own scope sets, else its row's, else null; and its unavailable reason, unsupported words and conditions.
 *  F10.9: its content binding and its sensitive mark too, each only when its row declares one for it. */
export function memberData(group, member) {
  const key = typeof member === 'string' ? memberKey(member) : null, own = map => key !== null && map && Object.hasOwn(map, key) ? map[key] : null;
  const bindContent = own(group?.bindContent), sensitive = own(group?.sensitive);
  return {scopeSets: own(group?.memberScopeSets) ?? group?.scopeSets ?? null, unavailable: own(group?.unavailable), unsupported: own(group?.unsupported), conditions: own(group?.conditions),
    ...(bindContent ? {bindContent} : {}), ...(sensitive ? {sensitive} : {})};
}

/** The value a JSON pointer names inside a parsed JSON value, or undefined when there is none. Only own properties are read,
 *  and an array only by a canonical index, so `length`, `-` and anything inherited name nothing. */
export function resolvePointer(value, pointer) {
  const tokens = pointerTokens(pointer);
  if (!tokens) return undefined;
  let current = value;
  for (const token of tokens) {
    if (!current || typeof current !== 'object' || (Array.isArray(current) && !/^(0|[1-9]\d*)$/.test(token)) || !Object.hasOwn(current, token)) return undefined;
    current = current[token];
  }
  return current;
}

/** The body routes of a row for one member (an operation id or a request) that a parsed body matches. Strings compare with
 *  ASCII case folding; `contains` reads a scalar as a one-item list; `present` holds for any value, null included. */
export function bodyRouteHits(group, member, body) {
  if (!group?.bodyRoutes?.length || typeof member !== 'string') return [];
  const same = (a, b) => typeof a === 'string' && typeof b === 'string' ? fold(a) === fold(b) : a === b;
  return group.bodyRoutes.filter(route => {
    if (memberKey(route.member) !== memberKey(member)) return false;
    const value = resolvePointer(body, route.pointer);
    if (route.present === true) return value !== undefined;
    if (Object.hasOwn(route, 'equals')) return same(value, route.equals);
    return (Array.isArray(value) ? value : [value]).some(item => same(item, route.contains));
  });
}

/** True when this member of a read row was reviewed as read-only despite a writing HTTP method. */
export function reviewedRead(group, operation) {
  if (!group?.reviewedReads?.length || !operation) return false;
  const request = typeof operation.method === 'string' && typeof operation.path === 'string' ? memberKey(`${operation.method.toUpperCase()} ${operation.path}`) : null;
  return group.reviewedReads.includes(operation.id) || (request !== null && group.reviewedReads.some(member => memberKey(member) === request));
}

export const PERMISSION_GROUPS = loadPermissionGroups();

import {groupFor, parseTemplate, memberKey, bodyRouteHits, memberOf} from './permission-groups.mjs';
import {aliasVariants, templatesFor, matchRequest} from './proxy-match.mjs';
import {proxyBase} from './proxy-request.mjs';

// F10.3 (T4, docs/F10-FIVE-APPS-DEEP.md section F10.3): the row Fabric locks, and the body routes, a typed capability meets.
// A member of the application map is placed by its row. Anything else (a direct import, a model acquisition, a map operation
// in no row) is placed by its request: it meets a template when some request could match both, parameter names ignored and
// the app's path aliases included, so no other spelling of a locked or routed endpoint slips past. Pure: no store, no I/O.
// F10.11 part f: an action answers from its steps' placements, read only through a catalog its caller passes (this module never imports
// one): it is locked when any step's own template meets a locked template, its routes are its steps' routes, and with no catalog every
// lookup answers null, as the action is already unsupported then.
export const LOCK_WORDS = 'Fabric keeps this off: it gives access to other people or services. No setting can turn it on.';
/** An agent's grant or request for a locked operation, refused before any account or hold exists. */
export const AGENT_LOCK_WORDS = 'Fabric never lets agents run this operation: it gives access to other people or services.';
/** Why a typed body a route sends to another row is refused: that row's name, or the lock words when Fabric keeps it off. */
export const routedWords = routed => routed.locked ? LOCK_WORDS : `This change belongs to "${routed.label}". Use that operation instead. Nothing was sent.`;
const RANK = {read: 0, write: 1, delete: 2}, STRICT = {allow: 0, ask: 1, deny: 2};
const fold = text => text.replace(/[A-Z]/g, char => String.fromCharCode(char.charCodeAt(0) + 32));
const READS = new Set(['GET', 'HEAD']);
const effectOf = capability => {const method = String(capability.request?.method).toUpperCase(); return READS.has(method) ? 'read' : method === 'DELETE' ? 'delete' : 'write';};
const prefixes = new Map(), parsed = new WeakMap();

/** The "METHOD /path" of an http capability relative to its app's proxy base, or null. A path segment the template grammar
 *  cannot read becomes a one-segment parameter: broader, so every check against it only ever tightens. */
export function typedRequest(capability, config) {
  const apiBase = config?.apiBase;
  if (typeof apiBase !== 'string') return null;
  if (!prefixes.has(apiBase)) {let prefix = null; try {const base = proxyBase(apiBase); prefix = `${base.origin}${base.basePath}`;} catch {} if (prefixes.size >= 64) prefixes.clear(); prefixes.set(apiBase, prefix);}
  const prefix = prefixes.get(apiBase), url = capability?.request?.url, method = capability?.request?.method?.toUpperCase();
  if (prefix === null || typeof url !== 'string' || typeof method !== 'string' || !url.startsWith(`${prefix}/`)) return null;
  return `${method} /${url.slice(prefix.length + 1).split('?')[0].replace(/%7B/gi, '{').replace(/%7D/gi, '}').split('/').map(segment => /[{}]/.test(segment) && !/^\{\+?[A-Za-z_][A-Za-z0-9_.-]{0,63}\}(?::[A-Za-z][A-Za-z0-9]{0,63})?$/.test(segment) ? '{p}' : segment).join('/')}`;
}

/** True when one segment value could fit both template segments. */
function meets(a, b) {
  if (a.kind === 'param' || b.kind === 'param') return true;
  if (a.kind === 'literal' && b.kind === 'literal') return fold(a.value) === fold(b.value);
  const [verb, other] = a.kind === 'verb' ? [a, b] : [b, a], suffix = fold(verb.suffix);
  return other.kind === 'literal' ? fold(other.value).length > suffix.length && fold(other.value).endsWith(suffix) : fold(other.suffix).endsWith(suffix) || suffix.endsWith(fold(other.suffix));
}
/** True when some request could match both parsed templates: {+x} takes the rest, and an RPC app ignores the method. */
export function templatesMeet(a, b, {style = 'rest'} = {}) {
  if (style !== 'rpc' && a.method !== b.method) return false;
  for (let index = 0; ; index++) {
    const x = a.segments[index], y = b.segments[index];
    if (!x || !y) return !x && !y;
    if (x.kind === 'rest' || y.kind === 'rest') return true;
    if (!meets(x, y)) return false;
  }
}

/** Every request form that reaches a capability: its map operation's and its own URL's, parsed. Empty when none can be read. */
function formsOf(capability, operation, config) {
  const requests = new Set([operation && typeof operation.method === 'string' && typeof operation.path === 'string' ? `${operation.method.toUpperCase()} ${operation.path}` : null, typedRequest(capability, config)]);
  const forms = [];
  for (const request of requests) if (request) try {forms.push(parseTemplate(request));} catch {}
  return forms;
}
/** One member's templates, alias forms included: a request as reviewed, an operation id by its place in the map. Null when the map cannot place it. */
function memberTemplates(group, member, config, operations) {
  let request = member;
  if (group.operations.includes(member)) {
    const operation = operations.find(entry => entry && entry.id === member);
    if (typeof operation?.method !== 'string' || typeof operation.path !== 'string') return null;
    request = `${operation.method.toUpperCase()} ${operation.path}`;
  }
  const aliases = config?.aliases ?? [], key = `${request}\n${JSON.stringify(aliases)}`, cached = parsed.get(group) ?? new Map();
  if (!cached.has(key)) {let value = null; try {value = aliasVariants(request, aliases).map(parseTemplate);} catch {} if (cached.size >= 4096) cached.clear(); cached.set(key, value); parsed.set(group, cached);}
  return cached.get(key);
}
const reaches = (templates, forms, config) => templates.some(template => forms.some(form => templatesMeet(template, form, config ?? {})));

/** F10.11 part f: an action's validated entry, only through the catalog given and only while the capability is that entry's current
 *  definition (catalog.entryOf()). Null for anything else, and for every action when no catalog is given. */
const actionEntry = (catalog, capability) => capability?.driver === 'action' ? catalog?.entryOf?.(capability)?.entry ?? null : null;
/**
 * F10.11 part f: each step of a validated action entry beside its placement, with the step's own request as the file writes it
 * ("METHOD /path", a parameter segment as its own text; null when it cannot be read), and whether it is optional or the resolving write.
 * A choice lookup's request is its source's, or the method and path the map gives its operation.
 */
export function actionSteps(entry, map = null) {
  const own = entry.action, written = new Map(), operations = Array.isArray(map?.operations) ? map.operations : [];
  for (const step of [...(own.resolvedInputs ?? []).flatMap(item => item.schema.steps), ...own.prepare, ...own.perform, ...(own.verify?.requests ?? [])]) written.set(step.id, step);
  return entry.placements.map(placement => {
    const step = written.get(placement.stepId), lookup = step ? null : entry.lookups?.[placement.stepId.replace(/^choice:/, '')] ?? null;
    const operation = lookup && typeof lookup.template !== 'string' ? operations.find(item => item && item.id === lookup.operation) : null;
    const request = step ? `${step.method} ${step.path}` : typeof lookup?.template === 'string' ? lookup.template
      : typeof operation?.method === 'string' && typeof operation.path === 'string' ? `${operation.method.toUpperCase()} ${operation.path}` : null;
    return {placement, request, optional: step?.optional === true, resolves: step?.resolves === true};
  });
}
/** T4 for an action: the locked row one of its steps' own templates meets, read by request shape as an unplaced typed request is. A step
 *  whose template cannot be read meets every locked row; so does a write while the map cannot place a locked operation. */
function actionLock(definitions, configs, capability, map, catalog) {
  const entry = actionEntry(catalog, capability), locked = entry ? definitions?.get(capability.appId)?.groups.filter(group => group.locked === 'fabric') ?? [] : [];
  if (!locked.length) return null;
  const config = configs?.get(capability.appId), operations = Array.isArray(map?.operations) ? map.operations : [], forms = [];
  for (const {request} of actionSteps(entry, map)) {
    try {forms.push(parseTemplate(request));} catch {return locked[0];}
  }
  let unplaced = null;
  for (const row of locked) for (const member of [...row.operations, ...row.requests]) {
    const templates = memberTemplates(row, member, config, operations);
    if (!templates) unplaced ??= row;
    else if (reaches(templates, forms, config)) return row;
  }
  return unplaced && (entry.effect !== 'read' || config?.style === 'rpc') ? unplaced : null;
}

/**
 * The row Fabric locks that this http capability is a member of, or null. A map operation in a row is that row's member; one in
 * no row, and a capability with no map operation, meet a locked row by request shape. A request that cannot be placed at all
 * could be any endpoint of its method: a write or delete is held at the lock, and a read only when a locked member reads or the
 * app is RPC, where the method names no endpoint. So is a write or delete while the map cannot place a locked operation (an app
 * reviewed by operation id). Otherwise reads keep their decision (correction 10): through c3 one typed read held at Never
 * would hold every "Other reads" request of the app, with no setting to undo it.
 */
export function lockedRowOf(definitions, configs, capability, operation = null, map = null, catalog = null) {
  if (capability?.driver === 'action') return actionLock(definitions, configs, capability, map, catalog);
  if (capability?.driver !== 'http') return null;
  const locked = definitions?.get(capability.appId)?.groups.filter(group => group.locked === 'fabric') ?? [];
  if (!locked.length) return null;
  const group = operation ? groupFor(definitions, capability.appId, operation) : null;
  if (group) return group.locked === 'fabric' ? group : null;
  const config = configs?.get(capability.appId), forms = formsOf(capability, operation, config), operations = Array.isArray(map?.operations) ? map.operations : [];
  const held = effectOf(capability) !== 'read' || config?.style === 'rpc';
  let unplaced = null;
  for (const row of locked) for (const member of [...row.operations, ...row.requests]) {
    const templates = memberTemplates(row, member, config, operations);
    if (!templates) unplaced ??= row;
    else if (forms.length ? reaches(templates, forms, config) : held || templates.some(template => READS.has(template.method))) return row;
  }
  return unplaced && held ? unplaced : null;
}

/** The rows with body routes this http capability is a member of, as [{group, member}], found the same two ways. An action's are its
 *  steps': each step's member in the row it was placed from, when that row routes it (F10.11 part f). */
function routedMembers(definitions, configs, capability, operation, map, catalog = null) {
  if (capability?.driver === 'action') {
    const groups = definitions?.get(capability.appId)?.groups ?? [], out = [], seen = new Set();
    for (const placement of actionEntry(catalog, capability)?.placements ?? []) {
      const group = groups.find(item => item.id === (placement.routedFrom?.groupId ?? placement.groupId)), key = `${group?.id}|${typeof placement.member === 'string' ? memberKey(placement.member) : ''}`;
      if (!group?.bodyRoutes?.some(route => typeof placement.member === 'string' && memberKey(route.member) === memberKey(placement.member)) || seen.has(key)) continue;
      seen.add(key);
      out.push({group, member: placement.member});
    }
    return out;
  }
  if (capability?.driver !== 'http') return [];
  const routed = definitions?.get(capability.appId)?.groups.filter(group => group.bodyRoutes?.length) ?? [];
  if (!routed.length) return [];
  const group = operation ? groupFor(definitions, capability.appId, operation) : null;
  if (group) {
    const member = group.operations.includes(operation.id) ? operation.id : memberKey(`${operation.method.toUpperCase()} ${operation.path}`);
    return (group.bodyRoutes ?? []).some(route => memberKey(route.member) === memberKey(member)) ? [{group, member}] : [];
  }
  const config = configs?.get(capability.appId), forms = formsOf(capability, operation, config), operations = Array.isArray(map?.operations) ? map.operations : [], out = [];
  for (const row of routed) for (const member of new Set(row.bodyRoutes.map(route => route.member))) {
    const templates = memberTemplates(row, member, config, operations);
    if (templates && reaches(templates, forms, config)) out.push({group: row, member});
  }
  return out;
}

/** The proxy's templates of one app with the requests already placed against them, kept per reviewed definition and settings unless
 *  the app is reviewed by operation id and so read through the stored map. Null when the templates cannot be built. */
const placing = new WeakMap();
function placer(definition, config, map) {
  const build = () => {let templates = null; try {templates = templatesFor(definition, config, map);} catch {} return templates && {templates, placed: new Map()};};
  if (definition.groups.some(group => group.operations.length)) return build();
  const cached = placing.get(definition) ?? new Map();
  if (!cached.has(config)) {if (cached.size >= 16) cached.clear(); cached.set(config, build()); placing.set(definition, cached);}
  return cached.get(config);
}
/**
 * F10.6 (correction 3): the reviewed row and member an http capability is, as {group, member}, or null. A map operation in a row is
 * that row's member. Anything else is placed by its request as the proxy routes the same request: the most specific reviewed
 * template it fits, alias forms included, where a parameter fits only a parameter. A request that fits none best, or fits a more
 * specific route the provider documents but no row reviews, is in no row. Only row data is placed this way; a lock keeps its own
 * broader reading above, since a lock only ever tightens.
 */
export function rowMemberOf(definitions, configs, capability, operation = null, map = null, catalog = null) {
  if (capability?.driver === 'action') {
    // F10.11 part f: an action is the member its last perform step lands on, read in the row that step was placed from.
    const entry = actionEntry(catalog, capability), last = entry?.action.perform.at(-1)?.id, placement = entry?.placements.find(item => item.phase === 'perform' && item.stepId === last);
    const group = placement ? definitions?.get(capability.appId)?.groups.find(item => item.id === (placement.routedFrom?.groupId ?? placement.groupId)) : null;
    return group && typeof placement.member === 'string' ? {group, member: placement.member} : null;
  }
  if (capability?.driver !== 'http') return null;
  const group = operation ? groupFor(definitions, capability.appId, operation) : null;
  if (group) return {group, member: memberOf(group, operation)};
  const definition = definitions?.get(capability.appId), config = configs?.get(capability.appId), place = definition && config ? placer(definition, config, map) : null;
  if (!place) return null;
  const requests = [operation && typeof operation.method === 'string' && typeof operation.path === 'string' ? `${operation.method.toUpperCase()} ${operation.path}` : null, typedRequest(capability, config)];
  for (const request of requests) {
    if (!request) continue;
    if (!place.placed.has(request)) {
      const [method, path] = request.split(' '), match = matchRequest(place.templates, {method, segments: path === '/' ? [] : path.slice(1).split('/')}, {style: config.style});
      if (place.placed.size >= 4096) place.placed.clear();
      place.placed.set(request, match.kind === 'group' ? {groupId: match.groupId, member: match.member} : null);
    }
    const hit = place.placed.get(request), group = hit ? definition.groups.find(entry => entry.id === hit.groupId) : null;
    if (group) return {group, member: hit.member};
  }
  return null;
}

/** The member's own body routes as sorted text, for its typed binding: a member that gains or changes routes needs fresh consent. */
export function memberRoutes(definitions, configs, capability, operation = null, map = null, catalog = null) {
  return routedMembers(definitions, configs, capability, operation, map, catalog).flatMap(({group, member}) => group.bodyRoutes.filter(route => memberKey(route.member) === memberKey(member)).map(route => {
    const kind = ['contains', 'equals', 'present'].find(key => Object.hasOwn(route, key));
    return `${group.id}|${route.member}|${route.pointer}|${kind}|${JSON.stringify(route[kind])}|${route.to}`;
  })).sort();
}

/** The strictest row the routes of this capability send a parsed body to, as {groupId, label, locked}, or null. */
export function bodyRouteOf(definitions, configs, capability, operation, body, map = null, catalog = null) {
  const groups = definitions?.get(capability?.appId)?.groups ?? [], strictness = group => (group.locked === 'fabric' ? 100 : 0) + RANK[group.effect] * 10 + STRICT[group.defaultMode];
  const targets = routedMembers(definitions, configs, capability, operation, map, catalog).flatMap(({group, member}) => bodyRouteHits(group, member, body)).map(route => groups.find(group => group.id === route.to)).filter(Boolean);
  if (!targets.length) return null;
  const target = targets.reduce((a, b) => strictness(b) > strictness(a) ? b : a);
  return Object.freeze({groupId: target.id, label: target.label, locked: target.locked === 'fabric'});
}

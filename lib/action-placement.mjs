// F10.9 part e (docs/F10.9-BUILD-MAP.md part e; R2, R3 and R7; spec lines 737 and 738): where an action step lands. placeStep() places one
// step of a reviewed action file on a reviewed member of a reviewed row through the proxy's own matcher (lib/proxy-match.mjs), never in
// Other, GraphQL, a row Fabric locks or on a member marked unavailable. It applies the row's body routes to the body's constant skeleton,
// refuses a body whose other parts might hit a route, and gives the step's effect. placeRequest() is the run-time hook F10.11 calls on every
// concrete request. Nothing here reads a store, runs a transform or sends a request.
//
// A body is read through its fact from lib/action-expressions.mjs (part d), which part f computes once per slot with the action's shared
// node budget and hands to placeStep(). The constant parts of the fact (constants, objects and lists built in the file) make the body's
// skeleton; everything else is a value only the run time knows.
import {parseTemplate, memberKey, memberData, bodyRouteHits, UNAVAILABLE_REASONS} from './permission-groups.mjs';
import {templatesFor, matchRequest, routeMatch} from './proxy-match.mjs';
import {normalizePath} from './proxy-request.mjs';
import {scopeSetsOf} from './permissions.mjs';
import {normalizeAuthApp, effectiveScopes, fullLevelScopes} from '../contracts/auth-definition.mts';

const RANK = {read: 0, write: 1, delete: 2};
const stronger = (a, b) => RANK[a] >= RANK[b] ? a : b;
const methodEffect = method => method === 'GET' ? 'read' : method === 'DELETE' ? 'delete' : 'write';
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
const INDEX = /^(?:0|[1-9][0-9]*)$/;
const OTHER_WORDS = Object.freeze({'other-reads': 'Other reads', 'other-changes': 'Other changes', 'other-deletes': 'Other deletes', graphql: 'GraphQL'});
/** ASCII-only case folding, as body routes and the matcher fold. */
const fold = text => text.replace(/[A-Z]/g, char => String.fromCharCode(char.charCodeAt(0) + 32));
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const fail = message => { throw new Error(message); };
/** True for a string that parses as JSON: the only body routeMatch() reads. */
const jsonText = value => { if (typeof value !== 'string') return false; try { JSON.parse(value); return true; } catch { return false; } };

/** What a step is to its action: the phases part f (actions) and part k (trigger polls) place. */
export const PHASES = Object.freeze(['prepare', 'perform', 'verify', 'schema', 'lookup', 'poll', 'seed', 'enrich']);
/** Section 8 (part k; R6): a trigger's register and teardown steps, placed only by placeRegistration(), never by placeStep(). */
export const REGISTRATION_PHASES = Object.freeze(['register', 'teardown']);

/**
 * R2: the reviewed resolving writes, by app, as member keys. A perform step marked `resolves: true` places only on one of these; later
 * perform steps may read its answer, and the action always runs in two phases (part f; F10.11). Slack's conversations.open opens or finds
 * the direct-message channel with a person, idempotently. A new entry is a reviewed code change. lib/actions.mjs reads this list.
 */
export const RESOLVING_WRITES = Object.freeze({slack: Object.freeze(['POST /conversations.open'])});

/**
 * R7: the scopes an app's sign-in holds without and with its optional ones, read through normalizeAuthApp(): `required` is the identity
 * scopes and the full level's required scopes, `optional` every other scope of the full level (optional and in-context), each with what
 * a granted parent grants (effectiveScopes()). A member that needs one of `optional` can be missing while the connection still works.
 */
export function accessOf(definition, appId) {
  const entry = Array.isArray(definition?.apps) ? definition.apps.find(app => app?.appId === appId) : undefined;
  if (!entry) fail(`The ${definition?.providerId} sign-in has no app ${appId}.`);
  const app = normalizeAuthApp(definition, entry), required = [...new Set(effectiveScopes(app, [...app.identityScopes, ...app.levels.full.required]))].sort();
  const optional = [...new Set(effectiveScopes(app, [...app.identityScopes, ...fullLevelScopes(app)]))].filter(scope => !required.includes(scope)).sort();
  return Object.freeze({required: Object.freeze(required), optional: Object.freeze(optional)});
}
/** True when one scope alternative (OR between them, AND within each) is held. */
const holds = (alternatives, scopes) => { const have = new Set(scopes); return alternatives.some(set => set.every(scope => have.has(scope))); };

/** The effect of a placed step (F10.10, I5; replaces R3). A POST counts as a read only when its member is listed in its read row's
 *  reviewedReads, no body route moved it (reviewedRead) and everything it sends is built from reads (fromReads). REST: the strongest of
 *  that, or else the method's effect, its row's and, when a body route moved it, the row it came from. RPC: the row's effect, but any other
 *  POST in a read row is a write. Never the matcher's effect, which reads a reviewed read as a read whatever its body
 *  (lib/proxy-match.mjs:123). */
export function stepEffect(placement, config) {
  const read = placement.method === 'POST' && placement.reviewedRead === true && placement.fromReads === true;
  if (config?.style === 'rpc') return placement.method === 'POST' && placement.rowEffect === 'read' ? (read ? 'read' : 'write') : placement.rowEffect;
  return [read ? 'read' : methodEffect(placement.method), placement.rowEffect, placement.routedFrom?.rowEffect ?? 'read'].reduce(stronger);
}
/** The action's effect: the strongest over its prepare and perform steps on every path. Verify steps never count. Null while any counted
 *  step is unplaced (an app reviewed by operation id without its map). */
export function actionEffect(placements) {
  const counted = placements.filter(placement => placement.phase === 'prepare' || placement.phase === 'perform');
  if (counted.some(placement => placement.unplaced)) return null;
  return counted.reduce((effect, placement) => stronger(effect, placement.effect), 'read');
}

/** The step's own template, checked: one of the proxy's methods, a path relative to the reviewed API base inside its prefixes, plain
 *  segments, and for an RPC app GET or POST on one segment with no query on a POST. */
function shapeOf(step, config, where) {
  const {method, path} = step, request = `${method} ${path}`;
  if (typeof method !== 'string' || !METHODS.has(method)) fail(`${where}: an action step uses GET, POST, PUT, PATCH or DELETE.`);
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')) fail(`${where}: a step path is relative to the app's reviewed API base, never a URL.`);
  let parsed;
  try { parsed = parseTemplate(request); } catch (error) { fail(`${where}: ${request} is not a path template of plain segments (${error.message})`); }
  for (const segment of parsed.segments) {
    const text = segment.kind === 'literal' ? segment.value : segment.kind === 'verb' ? segment.suffix.slice(1) : null;
    let plain = false;
    try { plain = text === null || normalizePath(`/${text}`).segments[0] === text; } catch { plain = false; }
    if (!plain) fail(`${where}: ${request} is not a path template of plain segments: ${text} is not one segment sent exactly as written.`);
  }
  const prefixes = config.pathPrefixes?.length ? config.pathPrefixes : ['/'];
  if (!prefixes.some(prefix => prefix === '/' || path.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`))) fail(`${where}: a step path starts with ${prefixes.join(' or ')}.`);
  if (config.style === 'rpc') {
    if (method !== 'GET' && method !== 'POST') fail(`${where}: an RPC app takes GET or POST only.`);
    if (parsed.segments.length !== 1) fail(`${where}: a method of an RPC app is one path segment, such as /chat.postMessage.`);
    if (method === 'POST' && step.query !== undefined && (!record(step.query) || Object.keys(step.query).length)) fail(`${where}: a POST to an RPC app sends its arguments in the body, never the query.`);
  }
  if (method === 'GET' && step.body !== undefined) fail(`${where}: a GET step has no body.`);
  return parsed;
}
/** The segments matchRequest() reads for a template: a parameter as its own text, which only a parameter or rest segment fits. */
const segmentsOf = path => path === '/' ? [] : path.slice(1).split('/');

/** Literals of the step equal the reviewed template's exactly (matching folds case), and {+x} sits only on a rest segment. */
function strictly(parsed, template, where) {
  const reviewed = parseTemplate(template);
  parsed.segments.forEach((segment, index) => {
    const own = reviewed.segments[Math.min(index, reviewed.segments.length - 1)];
    if (own.kind === 'rest') return;
    if (segment.kind === 'rest') fail(`${where}: {+${segment.name}} spans segments, but the reviewed template ${template} takes one segment there.`);
    if (own.kind === 'literal' && segment.kind === 'literal' && segment.value !== own.value) fail(`${where}: the literal ${segment.value} is written ${own.value} in the reviewed template ${template}: an action step writes it exactly.`);
    if (own.kind === 'verb') {
      const text = segment.kind === 'verb' ? segment.suffix : segment.kind === 'literal' ? segment.value : '';
      if (!text.endsWith(own.suffix)) fail(`${where}: the custom verb ${own.suffix} is written exactly as the reviewed template ${template} writes it.`);
    }
  });
}

// ---- body routes ------------------------------------------------------------------------------------------------------------------
const HIT = 'hit', MISS = 'miss';
const KINDS_BUILT = new Set(['object', 'array', 'each']);
const tokensOf = pointer => pointer ? pointer.slice(1).split('/').map(token => token.replace(/~1/g, '/').replace(/~0/g, '~')) : [];
const pointerOf = tokens => tokens.map(token => `/${token.replace(/~/g, '~0').replace(/\//g, '~1')}`).join('');
/** The closed schema at a pointer's tokens, or {found: false} when the schema cannot hold them. Below an unknown (null) part, found. */
function typeAt(schema, tokens) {
  let current = schema;
  for (const token of tokens) {
    if (current === null || current === undefined) return {found: true};
    if (current.type === 'object' && record(current.properties) && Object.hasOwn(current.properties, token)) current = current.properties[token];
    else if (current.type === 'array' && INDEX.test(token) && Number(token) < (current.maxItems ?? 10_000)) current = current.items ?? null;
    else return {found: false};
  }
  return {found: true};
}
const testOf = route => route.present === true ? 'present' : Object.hasOwn(route, 'equals') ? 'equals' : 'contains';
const valueOf = route => route[testOf(route)];
/** True when an exclusion that survived to a value holds the route's value: the field never equals it, folded as the route folds. A
 *  route's non-string value never equals an excluded field, which is a string or a list of strings (F10.8's checkEntry()). */
function covers(rule, value) {
  if (typeof value !== 'string') return true;
  if (rule.fold === 'ascii') return rule.values.some(item => fold(item) === fold(value));
  return !/[A-Za-z]/.test(value) && rule.values.includes(value);
}

/**
 * The outcome of one body route over the body's fact: HIT or MISS when the skeleton decides it, or a refusal when a value only the run time
 * knows might hit it. `tokens` are the route pointer's tokens below `node`. Objects, lists and {each} built in the file are walked; a
 * {when} at or above the pointer is refused; a constant is read as the proxy reads a body (bodyRouteHits()); any other value passes only
 * when it is a transform result, or a pick of one, whose closed output schema cannot hold the pointer, or, for contains and equals, when
 * an exclusion that survived to it holds the route's value (F10.8 map part m).
 */
function outcome(node, tokens, route, ctx) {
  if (node.kind === 'when') fail(`${ctx.where}: a {when} sits at or above ${route.pointer}, which ${ctx.source.id} routes to ${route.to}: a route reads the body as sent, so nothing at or above a routed pointer is left out.`);
  if (node.kind === 'const') return bodyRouteHits({bodyRoutes: [{...route, pointer: pointerOf(tokens)}]}, route.member, node.value).length ? HIT : MISS;
  const test = testOf(route);
  if (KINDS_BUILT.has(node.kind)) {
    if (!tokens.length) {
      // An object or a list built in the file is present; it never equals a scalar. A list contains the route's value when an item does.
      if (test === 'present') return HIT;
      if (test === 'equals' || node.kind === 'object') return MISS;
      return node.kind === 'array' ? node.items.reduce((found, item) => element(item, route, ctx) === HIT ? HIT : found, MISS)
        : element(node.do, route, ctx) === MISS ? MISS : unsure(route, ctx);
    }
    const [token, ...rest] = tokens;
    if (node.kind === 'object') return node.members.has(token) ? outcome(node.members.get(token), rest, route, ctx) : MISS;
    if (node.kind === 'array') {
      if (node.items.some(item => item.kind === 'when')) fail(`${ctx.where}: a {when} sits at or above ${route.pointer}, which ${ctx.source.id} routes to ${route.to}: a list item left out moves the positions after it.`);
      return INDEX.test(token) && Number(token) < node.items.length ? outcome(node.items[Number(token)], rest, route, ctx) : MISS;
    }
    // One element of an {each}: present only when the list is long enough, so a possible hit there is never certain.
    if (!INDEX.test(token) || Number(token) >= (node.type?.maxItems ?? 0)) return MISS;
    return outcome(node.do, rest, route, ctx) === MISS ? MISS : unsure(route, ctx);
  }
  return leaf(node, tokens, route, ctx);
}
/** True for a transform result, or a pick of one: a value whose closed type is the reviewed output schema of a transform. */
const transformResult = node => node.kind === 'transform' || (node.kind === 'pick' && transformResult(node.of));
/** A value only the run time knows, at or above the route's pointer. Above it, a transform result whose closed output schema has no
 *  field on the pointer's path never hits; an input or step data there is refused, as is anything at the pointer itself unless an
 *  exclusion that survived to it holds the route's value. */
function leaf(node, tokens, route, ctx) {
  if (node.keyed) fail(`${ctx.where}: the body's ${route.pointer} sits at or under an ${node.keyed.form} result, which has no closed schema: no body route may read there.`);
  if (tokens.length && transformResult(node) && node.type && !typeAt(node.type, tokens).found) return MISS;
  const test = testOf(route);
  if (test !== 'present') {
    const at = pointerOf(tokens);
    if (node.excludes.some(rule => rule.pointer === at && covers(rule, valueOf(route)))) return MISS;
  }
  return unsure(route, ctx);
}
/** One element of the list at a contains pointer: does it equal the route's value? */
function element(node, route, ctx) {
  if (node.kind === 'when') return element(node.then, route, ctx) === MISS ? MISS : unsure(route, ctx);
  if (node.kind === 'const') return bodyRouteHits({bodyRoutes: [{...route, pointer: ''}]}, route.member, [node.value]).length ? HIT : MISS;
  if (KINDS_BUILT.has(node.kind)) return MISS;
  if (node.keyed) return MISS;
  return node.excludes.some(rule => rule.pointer === '' && covers(rule, valueOf(route))) ? MISS : unsure(route, ctx);
}
function unsure(route, ctx) {
  const test = testOf(route), words = test === 'present' ? 'be present' : `${test === 'equals' ? 'equal' : 'contain'} ${JSON.stringify(valueOf(route))}`;
  return fail(`${ctx.where}: the body's ${route.pointer} could ${words}, which routes this step from ${ctx.source.id} to ${route.to}, and nothing shows it never does: a value there is a constant, or a transform result whose surviving exclusions or closed output schema rule the route out (spec line 738).`);
}
/** The body as the proxy would read it, from what the file fixes: constants, and objects and lists built in the file. A {when} stands for
 *  its value, an {each} for an empty list, and any other value for an empty object, which equals no scalar and holds no field. Every case
 *  where that stand-in could decide a route differently from the real value is refused by outcome() first. */
function skeleton(node) {
  if (node.kind === 'const') return node.value;
  if (node.kind === 'object') return Object.fromEntries([...node.members].map(([key, member]) => [key, skeleton(member)]));
  if (node.kind === 'array') return node.items.map(skeleton);
  if (node.kind === 'when') return skeleton(node.then);
  if (node.kind === 'each') return [];
  return {};
}

/**
 * Places one action step (part e). `deps`: {definition, config, map, phase, body, access, fromReads, where}. `definition` is the app's
 * validated rows, `config` its validated proxy settings, `map` its stored application map (apps reviewed by operation id), `body` the
 * fact of the step's body (checkExpression() at slot body), `access` the app's accessOf() for optional steps and fallbacks, and
 * `fromReads` true only when the caller has shown that every slot of the step reads only reads (F10.10; lib/action-expressions.mjs
 * readsOnly()), so a caller that leaves it out gets a write. Returns a frozen placement {stepId, phase, method, template, member, groupId,
 * rowEffect, effect, fromReads, reviewedRead, routedFrom, unplaced}: fromReads says what the request reads, effect what the step does. A
 * step of an app whose map lacks a reviewed operation is unplaced: valid in shape, never runnable. Throws an Error that names the step and
 * the rule.
 */
export function placeStep(step, {definition, config, map = null, phase = 'perform', body = null, access = null, fromReads = false, where} = {}) {
  if (!record(step)) fail('An action step is an object.');
  const at = typeof where === 'string' ? where : `step ${step.id}`;
  if (!definition?.groups || !record(config)) fail(`${at}: placing a step needs the app's reviewed rows and proxy settings.`);
  if (!PHASES.includes(phase)) fail(`${at}: a step's phase is one of ${PHASES.slice(0, -1).join(', ')} and ${PHASES.at(-1)}.`);
  for (const [name, words] of [['optional', 'optional is true or absent.'], ['resolves', 'resolves is true or absent.']]) if (step[name] !== undefined && step[name] !== true) fail(`${at}: ${words}`);
  if (step.fallbackFor !== undefined && (typeof step.fallbackFor !== 'string' || !step.fallbackFor || step.fallbackFor.length > 64)) fail(`${at}: fallbackFor names the optional step it stands in for.`);
  if (step.optional === true && step.fallbackFor !== undefined) fail(`${at}: a fallback is never optional itself (R7).`);
  const parsed = shapeOf(step, config, at), request = `${step.method} ${step.path}`;
  const templates = templatesFor(definition, config, map);
  if (!templates) return Object.freeze({stepId: step.id, phase, method: step.method, template: null, member: null, groupId: null, rowEffect: null, effect: null, fromReads: false, reviewedRead: false, routedFrom: null, unplaced: true});
  const match = matchRequest(templates, {method: step.method, segments: segmentsOf(step.path)}, {style: config.style, inheritFamilies: config.inheritFamilies});
  if (match.kind !== 'group') {
    if (match.documented) fail(`${at}: ${request} lands on ${match.documented}, a documented route no row reviews, so it would run in ${OTHER_WORDS[match.kind]}: an action step runs only on a reviewed member of a reviewed row.`);
    fail(`${at}: ${request} lands in ${OTHER_WORDS[match.kind]}: an action step runs only on a reviewed member of a reviewed row.`);
  }
  if (match.ambiguous) fail(`${at}: ${request} matches templates of two rows equally well, so the row it lands in is ambiguous.`);
  const reviewedMethod = parseTemplate(match.template).method;
  if (reviewedMethod !== step.method) fail(`${at}: ${request} lands on ${match.template}: an RPC app is matched by path alone, so a step uses its member's own method, ${reviewedMethod}.`);
  strictly(parsed, match.template, at);
  const source = definition.groups.find(group => group.id === match.groupId);
  if (source.locked === 'fabric') fail(`${at}: ${request} lands in ${source.label}, a row Fabric locks: no action step ever runs there (T4).`);
  const data = memberData(source, match.member);
  if (data.unavailable) fail(`${at}: ${request} lands on ${match.member}, which is unavailable: ${UNAVAILABLE_REASONS[data.unavailable]}`);
  if (step.resolves === true && !(RESOLVING_WRITES[definition.appId] ?? []).includes(match.member)) {
    fail(`${at}: resolves: true is allowed only on a reviewed resolving write (RESOLVING_WRITES), and ${match.member} of ${definition.appId} is not one (R2).`);
  }
  // Body routes (F10.3; spec line 738): the skeleton decides each route of the member, or the step is refused; then the proxy's own move.
  let routed = match;
  const routes = (source.bodyRoutes ?? []).filter(route => memberKey(route.member) === memberKey(match.member));
  if (step.body !== undefined && routes.length) {
    if (!body || !(body.sources instanceof Set)) fail(`${at}: placing a step whose member has body routes needs the fact of its body (checkExpression() at slot body).`);
    for (const route of routes) outcome(body, tokensOf(route.pointer), route, {where: at, source});
    routed = routeMatch(definition, match, {body: JSON.stringify(skeleton(body))}, {style: config.style});
  }
  const target = definition.groups.find(group => group.id === routed.groupId), routedFrom = routed.routedFrom ? Object.freeze({groupId: source.id, member: match.member, rowEffect: source.effect}) : null;
  if (routedFrom && target.locked === 'fabric') fail(`${at}: the body routes this step to ${target.label}, a row Fabric locks: no action step ever runs there (T4).`);
  const reviewedRead = !routedFrom && source.effect === 'read' && source.reviewedReads.some(read => memberKey(read) === memberKey(match.member));
  const placement = {stepId: step.id, phase, method: step.method, template: match.template, member: match.member, groupId: target.id, rowEffect: target.effect, effect: null, fromReads: fromReads === true, reviewedRead, routedFrom, unplaced: false};
  placement.effect = stepEffect(placement, config);
  // R7: an optional step is a read whose member needs a scope beyond the sign-in's required ones; its fallback is a read that needs only those.
  if (step.optional === true || step.fallbackFor !== undefined) {
    if (placement.effect !== 'read') fail(`${at}: ${step.optional === true ? 'a write is never optional (R7).' : 'a fallback is a read (R7).'}`);
    if (!access || !Array.isArray(access.required) || !Array.isArray(access.optional)) fail(`${at}: an optional step or a fallback needs the app's reviewed sign-in, which says which scopes are optional (R7).`);
    const operation = Array.isArray(map?.operations) ? map.operations.find(entry => entry?.id === match.member) : undefined;
    const {scopeSets} = scopeSetsOf(operation, data);
    if (!scopeSets.length) fail(`${at}: ${match.member} says nothing about the scopes it needs, so nothing shows whether it needs an optional one (R7).`);
    const withRequired = holds(scopeSets, access.required);
    if (step.optional === true && withRequired) fail(`${at}: an optional step reads a member that needs a scope the sign-in holds beyond its required ones, and ${match.member} needs none (R7).`);
    if (step.optional === true && !holds(scopeSets, [...access.required, ...access.optional])) {
      fail(`${at}: an optional step reads a member the sign-in can hold once its optional scopes are granted, and ${match.member} needs a scope the sign-in never asks for (R7).`);
    }
    if (step.fallbackFor !== undefined && !withRequired) fail(`${at}: a fallback runs when an optional scope is missing, so it needs only the sign-in's required scopes, and ${match.member} needs more (R7).`);
  }
  return Object.freeze(placement);
}

/**
 * Part k (section 8; R6): places a trigger's register or teardown step. Such a step runs only on a reviewed registration member, which
 * sits in its app's locked row: the one carve-out from spec line 737, made by member and never by row. `members` are the member keys
 * lib/triggers.mjs's REGISTRATION_MEMBERS allows for this phase and app; every other member, locked or not, is refused, and so is any
 * request that lands in Other or GraphQL. deps: {definition, config, map, phase, members, where}. Returns a frozen placement as
 * placeStep() does, unplaced when the app is reviewed by operation id and has no map. Only Fabric's engine runs these steps (I07).
 */
export function placeRegistration(step, {definition, config, map = null, phase, members = [], where} = {}) {
  if (!record(step)) fail('A registration step is an object.');
  const at = typeof where === 'string' ? where : `step ${step.id}`;
  if (!definition?.groups || !record(config)) fail(`${at}: placing a step needs the app's reviewed rows and proxy settings.`);
  if (!REGISTRATION_PHASES.includes(phase)) fail(`${at}: a registration step's phase is register or teardown.`);
  const parsed = shapeOf(step, config, at), request = `${step.method} ${step.path}`;
  const templates = templatesFor(definition, config, map);
  if (!templates) return Object.freeze({stepId: step.id, phase, method: step.method, template: null, member: null, groupId: null, rowEffect: null, effect: null, fromReads: false, reviewedRead: false, routedFrom: null, unplaced: true});
  const match = matchRequest(templates, {method: step.method, segments: segmentsOf(step.path)}, {style: config.style, inheritFamilies: config.inheritFamilies});
  if (match.kind !== 'group' || !members.includes(memberKey(match.member))) {
    const landed = match.kind === 'group' ? `lands on ${match.member}` : `lands in ${OTHER_WORDS[match.kind]}`;
    const allowed = members.length ? members.length === 1 ? members[0] : `${members.slice(0, -1).join(', ')} or ${members.at(-1)}` : null;
    fail(`${at}: ${request} ${landed}, which is not a reviewed ${phase} member: ${allowed ? `a trigger's ${phase} step runs only on ${allowed}` : `${definition.appId} has none`} (R6, T4).`);
  }
  if (match.ambiguous) fail(`${at}: ${request} matches templates of two rows equally well, so the row it lands in is ambiguous.`);
  const reviewedMethod = parseTemplate(match.template).method;
  if (reviewedMethod !== step.method) fail(`${at}: ${request} lands on ${match.template}: an RPC app is matched by path alone, so a step uses its member's own method, ${reviewedMethod}.`);
  strictly(parsed, match.template, at);
  const row = definition.groups.find(group => group.id === match.groupId);
  if (row.locked !== 'fabric') fail(`${at}: ${match.member} is a registration member, which sits in its app's locked row, and ${row.id} is not locked (R6).`);
  if (memberData(row, match.member).unavailable) fail(`${at}: ${request} lands on ${match.member}, which is unavailable.`);
  const placement = {stepId: step.id, phase, method: step.method, template: match.template, member: match.member, groupId: row.id, rowEffect: row.effect, effect: null, fromReads: false, reviewedRead: false, routedFrom: null, unplaced: false};
  placement.effect = stepEffect(placement, config);
  return Object.freeze(placement);
}

/**
 * The run-time hook (F10.11; open question 19): places one concrete canonical request ({method, segments, body}, as the proxy normalizer
 * gives them) again and refuses it unless it lands on the step's own reviewed member in the step's own row. A literal sibling such as
 * GitHub's issues/events, or a body that would route the request elsewhere, refuses the job before anything is sent. Returns the match.
 */
export function placeRequest(placement, request, {definition, config, map = null, where = 'request'} = {}) {
  if (!placement || placement.unplaced) fail(`${where}: this step is unplaced: its app is reviewed by operation id and has no stored map holding every reviewed operation.`);
  if (!record(request) || !Array.isArray(request.segments)) fail(`${where}: a request is {method, segments, body} as the proxy normalizer gives it.`);
  // routeMatch() reads a body only as JSON text and passes anything else through unrouted, so this hook refuses what it cannot read.
  if (request.body !== undefined && request.body !== null && !jsonText(request.body)) fail(`${where}: a request body is the JSON text the proxy normalizer gives, so its body routes can be read: nothing is sent.`);
  if (request.method !== placement.method) fail(`${where}: the request uses ${request.method}, but the step's reviewed member is sent with ${placement.method}: nothing is sent.`);
  const templates = templatesFor(definition, config, map);
  if (!templates) fail(`${where}: this step is unplaced: its app is reviewed by operation id and has no stored map holding every reviewed operation.`);
  const match = matchRequest(templates, {method: request.method, segments: request.segments}, {style: config.style, inheritFamilies: config.inheritFamilies});
  const routed = routeMatch(definition, match, {body: request.body}, {style: config.style});
  const landed = routed.kind === 'group' ? `lands on ${routed.member} in ${routed.groupId}` : `lands in ${OTHER_WORDS[routed.kind]}`;
  if (routed.kind !== 'group' || routed.ambiguous || routed.member !== placement.member || routed.groupId !== placement.groupId) {
    fail(`${where}: the request ${landed}, not on the step's reviewed member ${placement.member} in ${placement.groupId}: nothing is sent.`);
  }
  return routed;
}

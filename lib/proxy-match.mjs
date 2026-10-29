import {parseTemplate, templateShape, looseShape, memberKey, bodyRouteHits} from './permission-groups.mjs';

// F08.0a: which permission row a proxy request lands in (docs/F08.0-GOVERNED-PROXY.md section 4). Every
// canonical request maps to exactly one row: a reviewed group, or "Other reads", "Other changes",
// "Other deletes" or GraphQL. The decision layer (F08.0b) applies the owner's modes and clamps.
const RANK = {read: 0, write: 1, delete: 2}, STRICT = {allow: 0, ask: 1, deny: 2};
const stronger = (a, b) => RANK[a] >= RANK[b] ? a : b;
const methodEffect = method => method === 'GET' ? 'read' : method === 'DELETE' ? 'delete' : 'write';
/** ASCII-only case folding: a Unicode lookalike (the Kelvin sign, the long s) never folds into a literal. */
const fold = text => text.replace(/[A-Z]/g, char => String.fromCharCode(char.charCodeAt(0) + 32));

/**
 * The templates an app's proxy requests are matched against, each tagged with its group:
 * - REST and RPC apps: the reviewed `requests` of each group, plus alias routes generated from reviewed
 *   prefixes (GitHub's /repositories/{id}/... mirrors /repos/{owner}/{repo}/...);
 * - apps reviewed by operation id (Google): the stored application map's method and path for each member.
 * - `documented`: the provider's own list of routes ("METHOD /path"). A documented route the catalog does not
 *   list becomes an unreviewed template, so a broad reviewed template such as GET /user/{account_id} can never
 *   capture GET /user/emails: the more specific documented route wins and sends the request to "Other".
 * Returns null when an app reviewed by operation id has no stored map, or a map without every reviewed
 * operation, or with a path that cannot be parsed: its Never rows could not be enforced (proxy_unavailable).
 * Throws when a reviewed template cannot be parsed or when, for an RPC app, one path is under two methods.
 */
export function templatesFor(definition, {style = 'rest', aliases = [], documented = []} = {}, applicationMap = null) {
  if (!definition) return null;
  const templates = [];
  const add = (group, request, member) => {
    const parsed = parseTemplate(request);
    templates.push({groupId: group.id, label: group.label, effect: group.effect, request, member: memberKey(member), method: parsed.method, segments: parsed.segments, shape: templateShape(parsed),
      reviewedRead: group.reviewedReads.some(read => memberKey(read) === memberKey(member)), locked: group.locked === 'fabric'});
  };
  const byOperation = definition.groups.some(group => group.operations.length);
  if (byOperation) {
    const operations = Array.isArray(applicationMap?.operations) ? applicationMap.operations : null;
    if (!operations) return null;
    for (const group of definition.groups) for (const id of group.operations) {
      const operation = operations.find(op => op.id === id);
      if (!operation || typeof operation.method !== 'string' || typeof operation.path !== 'string') return null;
      try {add(group, `${operation.method.toUpperCase()} ${operation.path}`, id);} catch {return null;}
    }
  }
  for (const group of definition.groups) for (const request of group.requests) {
    add(group, request, request);
    for (const {from, to} of aliases) {
      const [method, path] = request.split(' ');
      if (path === from || path.startsWith(`${from}/`)) add(group, `${method} ${to}${path.slice(from.length)}`, request);
    }
  }
  const reviewed = new Set(templates.map(template => looseShape(template)));
  for (const route of documented) {
    let parsed;
    try {parsed = parseTemplate(route);} catch {continue;}
    if (reviewed.has(looseShape(parsed))) continue;
    templates.push({groupId: null, label: null, effect: null, request: route, method: parsed.method, segments: parsed.segments, shape: templateShape(parsed), reviewedRead: false, unreviewed: true});
  }
  if (style === 'rpc') {
    const methods = new Map();
    for (const template of templates) {
      const path = template.shape.slice(template.shape.indexOf(' ') + 1);
      if (methods.has(path) && methods.get(path) !== template.method) throw new Error(`${path} is listed under two methods; an RPC app is matched by path alone.`);
      methods.set(path, template.method);
    }
  }
  return Object.freeze(templates);
}

/** True when one decoded segment fits one template segment (a {+x} is handled by the caller). */
function fits(part, segment) {
  if (part.kind === 'literal') return fold(part.value) === fold(segment);
  if (part.kind === 'verb') return segment.length > part.suffix.length && fold(segment).endsWith(fold(part.suffix));
  return true;
}
/** The match score of one template against decoded segments, or null when it does not match.
 *  Literal 3, {x}:verb 2, {x} 1, {+x} 0: the most specific template wins. */
function score(template, segments) {
  const scores = [];
  for (let index = 0; index < template.segments.length; index++) {
    const part = template.segments[index];
    if (part.kind === 'rest') return index < segments.length ? [...scores, 0] : null;
    if (index >= segments.length || !fits(part, segments[index])) return null;
    scores.push({literal: 3, verb: 2, param: 1}[part.kind]);
  }
  return template.segments.length === segments.length ? scores : null;
}
/** True when a parsed template routes this canonical request (RPC apps ignore the method). */
export function fitsTemplate(template, {method, segments}, {style = 'rest'} = {}) {
  return (style === 'rpc' || template.method === method) && score(template, segments) !== null;
}
/** A "METHOD /path" template plus the alias routes that reach the same endpoint. */
export function aliasVariants(request, aliases = []) {
  const [method, path] = request.split(' ');
  return [request, ...aliases.filter(({from}) => path === from || path.startsWith(`${from}/`)).map(({from, to}) => `${method} ${to}${path.slice(from.length)}`)];
}
const compare = (a, b) => {for (let i = 0; i < Math.max(a.length, b.length); i++) {const d = (a[i] ?? -1) - (b[i] ?? -1); if (d) return d;} return 0;};
/** True when the template matches a leading part of the segments (same method), so its row can pass on a Never. */
function prefixOf(template, segments) {
  if (template.unreviewed || template.segments.length >= segments.length || template.segments.some(part => part.kind === 'rest')) return false;
  return template.segments.every((part, index) => fits(part, segments[index]));
}

/**
 * The row one canonical request lands in. REST apps match on method and path; RPC apps on the path alone,
 * so a GET cannot move a write method out of its row. The effect is never weaker than the row's.
 * Unmatched requests, and requests whose most specific match is a documented route the catalog does not
 * review, go to the "Other" rows; `inheritFrom` lists the rows whose Never they must respect. For an RPC app
 * that is a method whose name is a dot-prefix of the request's, or any method of a reviewed family
 * (`inheritFamilies`, such as admin or oauth).
 */
export function matchRequest(templates, {method, segments}, {style = 'rest', inheritFamilies = []} = {}) {
  const candidates = templates.filter(template => style === 'rpc' || template.method === method);
  let best = null, bestScore = null, tied = [];
  for (const template of candidates) {
    const result = score(template, segments);
    if (!result) continue;
    const order = bestScore ? compare(result, bestScore) : 1;
    if (order > 0) {best = template; bestScore = result; tied = [template];}
    else if (order === 0) tied.push(template);
  }
  if (best && !best.unreviewed) {
    // The validator makes exact ties between groups impossible; if one happens anyway, a row Fabric locks wins, then the strictest effect.
    const groups = [...new Set(tied.map(template => template.groupId))];
    const chosen = groups.length > 1 ? tied.reduce((a, b) => Boolean(a.locked) !== Boolean(b.locked) ? (b.locked ? b : a) : RANK[b.effect] > RANK[a.effect] ? b : a) : best;
    const effect = style === 'rpc' ? chosen.effect : chosen.reviewedRead ? 'read' : stronger(methodEffect(method), chosen.effect);
    return Object.freeze({kind: 'group', groupId: chosen.groupId, label: chosen.label, template: chosen.request, member: chosen.member, effect, reviewedRead: style !== 'rpc' && chosen.reviewedRead, ambiguous: groups.length > 1, inheritFrom: Object.freeze([])});
  }
  const last = segments.at(-1);
  const graphql = style !== 'rpc' && last !== undefined && fold(last) === 'graphql';
  const families = new Set(inheritFamilies.map(fold)), name = segments.length === 1 ? fold(segments[0]) : null;
  const inheritFrom = [...new Set(templates.filter(template => !template.unreviewed && (style === 'rpc'
    ? name !== null && template.segments.length === 1 && template.segments[0].kind === 'literal'
      && (name.startsWith(`${fold(template.segments[0].value)}.`) || (families.has(name.split('.')[0]) && fold(template.segments[0].value).split('.')[0] === name.split('.')[0]))
    : template.method === method && prefixOf(template, segments))).map(template => template.groupId))];
  const kind = graphql ? 'graphql' : style === 'rpc' ? 'other-changes' : method === 'GET' ? 'other-reads' : method === 'DELETE' ? 'other-deletes' : 'other-changes';
  const effect = graphql ? 'write' : style === 'rpc' ? 'write' : methodEffect(method);
  return Object.freeze({kind, groupId: null, label: null, template: null, effect, reviewedRead: false, ambiguous: false, inheritFrom: Object.freeze(inheritFrom),
    documented: best?.unreviewed ? best.request : null});
}

/**
 * F10.3: a reviewed match whose row routes some bodies of its member elsewhere, moved to the strictest row the body is routed
 * to. Only the canonical wire is read, never the caller's object. The routed match keeps its template and member, takes the
 * target's row and label and an effect never weaker than either, and says where it came from; a miss is the same match.
 */
export function routeMatch(definition, match, request, {style = 'rest'} = {}) {
  if (match?.kind !== 'group' || style === 'rpc' || typeof request?.body !== 'string') return match;
  const groups = definition?.groups ?? [], source = groups.find(group => group.id === match.groupId);
  if (!source?.bodyRoutes?.length) return match;
  let body;
  try {body = JSON.parse(request.body);} catch {return match;}
  const targets = bodyRouteHits(source, match.member, body).map(route => groups.find(group => group.id === route.to)).filter(Boolean);
  if (!targets.length) return match;
  const strictness = group => (group.locked === 'fabric' ? 100 : 0) + RANK[group.effect] * 10 + STRICT[group.defaultMode];
  const target = targets.reduce((a, b) => strictness(b) > strictness(a) ? b : a);
  return Object.freeze({...match, groupId: target.id, label: target.label, effect: stronger(match.effect, target.effect), reviewedRead: false, inheritFrom: Object.freeze([]),
    routedFrom: Object.freeze({groupId: source.id, member: match.member})});
}

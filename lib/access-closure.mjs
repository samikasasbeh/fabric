// F10.1 access closure (five apps deep). For one app and one set of granted scopes: which permission rows work, which
// members still lack a scope and which alternatives would cover them, which granted scopes no row member uses, and
// which members can never work because every alternative needs a scope Fabric must not request. Pure and offline: the
// operations' scope alternatives come from the application map (or a fixture of it) and the rows' own scope data,
// nothing is fetched. F10.6: a member its row marks unavailable says why apart, and a row Fabric locks justifies nothing.
// F10.7: a sign-in is read through normalizeAuthApp(), so version 2 levels and never lists count.
import {memberKey, memberData} from './permission-groups.mjs';
import {normalizeAuthApp, levelScopes} from '../contracts/auth-definition.mts';

const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const unique = list => [...new Set(list)].sort();

/** Scope alternatives of one operation: OR between groups, AND within a group (the same reading as permissions.mjs). */
export function alternativesOf(operation) {
  if (Array.isArray(operation?.scopeSets) && operation.scopeSets.length) return operation.scopeSets.map(group => unique(group));
  if (Array.isArray(operation?.requiredScopes) && operation.requiredScopes.length) return operation.requiredScopes.map(scope => [scope]);
  return [];
}

/** Operations keyed by id from Google-style "method id to accepted scopes" data: any one listed scope is enough. */
export function operationsFromScopeLists(methods) {
  return new Map(Object.entries(methods).map(([id, scopes]) => [id, {id, scopeSets: scopes.map(scope => [scope])}]));
}

/** A row's members: its typed operation ids, then its reviewed "METHOD /path" proxy requests, each by its one member key ({+x} is {x}). */
export const membersOf = group => [...new Set([...(group.operations || []), ...(group.requests || [])].map(memberKey))];

/** F10.6: every row member's scope alternatives, keyed by member key: Discovery's facts ("method id to accepted scopes") wherever
 *  they name any, else the row's own sets for the member (memberData()), else none, as decisions read them. */
export function operationsFromRows(groups, methods = null) {
  const operations = new Map();
  for (const group of groups) for (const member of membersOf(group)) {
    const facts = methods && Object.hasOwn(methods, member) && Array.isArray(methods[member]) ? methods[member] : [], {scopeSets} = memberData(group, member);
    operations.set(member, facts.length ? {id: member, scopeSets: facts.map(scope => [scope])} : Array.isArray(scopeSets) ? {id: member, scopeSets: scopeSets.map(set => [...set])} : {id: member});
  }
  return operations;
}

/** Every row member with no scope data, for apps whose members carry none yet: reported as noScopes, never guessed. */
export function unscopedOperations(groups) {
  return new Map(groups.flatMap(membersOf).map(id => [id, {id}]));
}

/**
 * Coverage of every row for a granted scope set. F10.6 (T3): a member its row marks unavailable is listed under `unavailable` with its
 * reason, and its scopes are not used. A row Fabric locks is measured as before, but its scopes justify nothing (its status is
 * `locked`). A row's conditional scopes are used. Every member is read by its member key.
 * @param {{groups: readonly any[], operations: Map<string, any>, granted: readonly string[], identityScopes?: readonly string[], neverRequest?: readonly string[]}} input
 */
export function rowCoverage({groups, operations, granted, identityScopes = [], neverRequest = []}) {
  if (!Array.isArray(groups) || !(operations instanceof Map) || !Array.isArray(granted)) throw new Error('Access closure needs groups, an operation map and a granted scope list.');
  const have = new Set(granted), never = new Set(neverRequest), used = new Set();
  const rows = groups.map(group => {
    const row = {id: group.id, label: group.label, effect: group.effect, defaultMode: group.defaultMode, total: 0, covered: 0, missing: [], cannotWork: [], unmapped: [], noScopes: [], unavailable: []};
    const locked = group.locked === 'fabric', marked = new Map(record(group.unavailable) ? Object.entries(group.unavailable).map(([member, reason]) => [memberKey(member), reason]) : []);
    if (!locked && record(group.conditionalScopes)) for (const scope of Object.keys(group.conditionalScopes)) used.add(scope);
    for (const id of membersOf(group)) {
      row.total++;
      if (marked.has(id)) { row.unavailable.push({member: id, reason: marked.get(id)}); continue; }
      const operation = operations.get(id);
      if (!operation) { row.unmapped.push(id); continue; }
      const alternatives = alternativesOf(operation);
      if (!locked) for (const scope of alternatives.flat()) used.add(scope);
      if (!alternatives.length) { row.noScopes.push(id); continue; }
      if (alternatives.some(alternative => alternative.every(scope => have.has(scope)))) { row.covered++; continue; }
      const possible = alternatives.filter(alternative => !alternative.some(scope => never.has(scope)));
      if (!possible.length) row.cannotWork.push({member: id, alternatives});
      else row.missing.push({member: id, alternatives: possible});
    }
    // A row whose members carry no scope data is unknown, not blocked: nothing says it fails. Members that say why they can never
    // work are not counted either way.
    const counted = row.total - row.unavailable.length;
    row.status = locked ? 'locked' : row.total && !counted ? 'unavailable' : counted && row.covered === counted ? 'works' : row.covered ? 'partial' : counted && row.noScopes.length === counted ? 'unknown' : 'blocked';
    return row;
  });
  const identity = new Set(identityScopes), count = status => rows.filter(row => row.status === status).length;
  const unjustified = unique(granted.filter(scope => !identity.has(scope) && !used.has(scope)));
  const summary = {rows: rows.length, works: count('works'), partial: count('partial'), blocked: count('blocked'), unknown: count('unknown'), locked: count('locked'), unavailable: count('unavailable'),
    members: rows.reduce((sum, row) => sum + row.total, 0), coveredMembers: rows.reduce((sum, row) => sum + row.covered, 0), unavailableMembers: rows.reduce((sum, row) => sum + row.unavailable.length, 0)};
  return {granted: unique(granted), rows, unjustified, summary};
}

/**
 * The scopes a reviewed auth definition requests for one app at one level, identity scopes included, read through normalizeAuthApp().
 * Version 2: `full` is the whole full level (required, optional and in-context scopes) and `read` the read level, where the app has
 * one; `write` is a version 1 word and is refused. Version 1 keeps `read` and `write`, and reads `full` as `write`.
 */
export function grantedFor(definition, appId, level) {
  const entry = definition?.apps?.find(item => item.appId === appId);
  if (!entry) throw new Error(`No ${level} scope set for ${appId}.`);
  const app = normalizeAuthApp(definition, entry), v2 = app.schemaVersion === 2;
  if (v2 && level === 'write') throw new Error(`No write scope set for ${appId}: a version 2 sign-in definition calls it full.`);
  const name = level === 'write' ? 'full' : level;
  if (name !== 'full' && name !== 'read') throw new Error(`No ${level} scope set for ${appId}.`);
  if (name === 'read' && !app.levels.read) throw new Error(`No read scope set for ${appId}: its sign-in has no read level.`);
  return unique([...app.identityScopes, ...levelScopes(app, name)]);
}

/** One app's never-request list, read through normalizeAuthApp(): a version 1 app has none. */
function neverListOf(definition, appId) {
  const entry = definition?.apps?.find(item => item.appId === appId);
  if (!entry) throw new Error(`No sign-in for ${appId} in the ${definition?.providerId} definition.`);
  return normalizeAuthApp(definition, entry).neverRequest;
}

/** One app's closure at one level (or for an explicit scope list): the report the five-apps track drives to zero gaps. Without
 *  `neverRequest`, the app's own never list applies (F10.7). */
export function closure({definition, appId, level, scopes, groups, operations, neverRequest}) {
  const granted = scopes ? unique([...(definition.authorization?.identityScopes || []), ...scopes]) : grantedFor(definition, appId, level);
  return {appId, level: scopes ? 'custom' : level, ...rowCoverage({groups, operations, granted, identityScopes: definition.authorization?.identityScopes || [], neverRequest: neverRequest ?? neverListOf(definition, appId)})};
}

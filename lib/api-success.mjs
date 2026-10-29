// F10.21 part 1 a and b (docs/F10.21-BUILD-MAP.md part 1 a and b; spec lines 274, 1209-1212 and 1228): a provider that answers its own
// errors with HTTP 200 (Slack: {ok: false, error}) declares apiSuccessRequire in its reviewed auth definition, and every 2xx answer of
// that app must hold those facts to count as a success. The proxy (lib/proxy-runtime.mjs), the action runtime (lib/actions-runtime.mjs)
// and the action validator (lib/actions.mjs) read the rule here, through one function. apiRuleOf() reads it from the reviewed definitions
// (lib/providers/definitions.mjs), never from a runtime's injectable provider list, so a stub can never drop it; a definition a caller
// passes may only add a rule for an app that has none. narrowOnMissingScope() turns Slack's missing_scope into what a narrower refresh
// does today: the account record loses the scopes Slack named, and one grant_narrowed notice says so, so the rows that need them read
// "Needs more access".
import {definitionFor, reviewedProviderIds} from './providers/definitions.mjs';
import {normalizeAuthApp, fullLevelScopes} from '../contracts/auth-definition.mts';
import {raise, scopesSubject} from './connection-notices.mjs';

/** A provider error code Fabric repeats: 1 to 64 of a to z, 0 to 9 and _. Anything else is read as `unknown`. */
const ERROR_CODE = /^[a-z0-9_]{1,64}$/;
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const deepFreeze = value => { if (value !== null && typeof value === 'object') { Object.freeze(value); for (const item of Object.values(value)) deepFreeze(item); } return value; };
/** The value at a JSON pointer, own properties only; undefined when there is none. */
function at(value, pointer) {
  let current = value;
  for (const token of pointer.slice(1).split('/').map(part => part.replace(/~1/g, '/').replace(/~0/g, '~'))) {
    if (!record(current) || !Object.hasOwn(current, token)) return undefined;
    current = current[token];
  }
  return current;
}

let shipped = null;
/** The reviewed definition that serves each app, read once from catalog/auth. */
function shippedDefinitions() {
  if (!shipped) {
    shipped = new Map();
    for (const providerId of reviewedProviderIds()) for (const app of definitionFor(providerId).apps) shipped.set(app.appId, definitionFor(providerId));
  }
  return shipped;
}
/** A definition's rule for one of its apps: {require, scopes} (the app's full level, which needed and provided are read against), or null. */
function ruleIn(definition, appId) {
  const facts = definition?.apiSuccessRequire, app = Array.isArray(definition?.apps) ? definition.apps.find(item => item?.appId === appId) : null;
  if (!Array.isArray(facts) || !facts.length || !app) return null;
  return deepFreeze({require: facts.map(({pointer, equals}) => ({pointer, equals})), scopes: fullLevelScopes(normalizeAuthApp(definition, app))});
}

/**
 * The success rule of an app: the reviewed definition's when it sets one, so nothing a caller passes can drop it; otherwise the rule of
 * `definition` (a test app's reviewed sign-in, given by the action catalog or the provider list), or null when neither sets one.
 */
export function apiRuleOf(appId, definition = null) {
  return ruleIn(shippedDefinitions().get(appId) ?? null, appId) ?? ruleIn(definition, appId);
}

/** A comma list of scope names a provider sent, kept only where the name is one of the app's own. */
function scopeList(value, scopes) {
  if (typeof value !== 'string') return null;
  return [...new Set(value.split(',').map(item => item.trim()).filter(item => scopes.includes(item)))];
}

/**
 * The rule held against one 2xx answer's body: {state, error, needed, provided}. `ok` when every fact holds; `refused` when a fact is
 * present with another value (the provider said it did not do it); `unknown` when a fact is absent or the body is not a JSON object.
 * `error` is the provider's /error of a refusal when it is a plain code, else `unknown`, and null when the state is ok. `needed` and `provided` are
 * Slack's missing_scope fields, split on commas and kept only where a name is one of the app's scopes (provided null when Slack sent none).
 */
export function apiVerdict(rule, body) {
  let state = 'ok';
  for (const {pointer, equals} of rule.require) {
    const value = record(body) ? at(body, pointer) : undefined;
    if (value === undefined) { if (state === 'ok') state = 'unknown'; }
    else if (value !== equals) state = 'refused';
  }
  if (state === 'ok') return {state, error: null, needed: [], provided: null};
  const error = state === 'refused' && typeof body.error === 'string' && ERROR_CODE.test(body.error) ? body.error : 'unknown';
  return {state, error, needed: (record(body) ? scopeList(body.needed, rule.scopes) : null) ?? [], provided: record(body) ? scopeList(body.provided, rule.scopes) : null};
}

/** What a job keeps of a refusal: the provider's code, and the scopes it needs when it said so. */
export const providerDetails = verdict => ({providerError: verdict.error, ...(verdict.error === 'missing_scope' && verdict.needed.length ? {needed: [...verdict.needed]} : {})});

/**
 * Part b: after a job's final state is written, a missing_scope answer narrows the account to what the provider says it holds. Only the
 * scopes the record holds that the provider names in `needed` and leaves out of `provided` are taken away; nothing narrows when it sent no
 * `provided`, and nothing is ever added. When some are taken: the record's scopes lose them, one grant_narrowed notice is raised for that
 * set (a second failure finds them gone and raises none), and connection.narrowed is audited. Returns the scopes taken away.
 */
export function narrowOnMissingScope(runtime, connectionId, verdict) {
  if (verdict?.error !== 'missing_scope' || !Array.isArray(verdict.provided)) return [];
  const {store} = runtime, connection = store.get('connections', connectionId);
  if (!connection || !Array.isArray(connection.scopes)) return [];
  const lost = connection.scopes.filter(scope => verdict.needed.includes(scope) && !verdict.provided.includes(scope));
  if (!lost.length) return [];
  const narrowed = {...connection, scopes: connection.scopes.filter(scope => !lost.includes(scope)), updatedAt: new Date(runtime.clock()).toISOString()};
  store.put('connections', narrowed);
  raise(store, {connection: narrowed, kind: 'grant_narrowed', subjectKey: scopesSubject(lost), now: runtime.clock()});
  store.audit({type: 'connection.narrowed', connectionId, appId: connection.appId, reason: 'missing_scope', count: lost.length});
  return lost;
}

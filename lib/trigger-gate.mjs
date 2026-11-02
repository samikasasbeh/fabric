// Iteration 9 part 2a (docs/I07-BUILD-MAP.md section 2.5): the one gate every watch goes through. It runs at subscribe, at approval, at Resume, before
// credentials (a refresh is a network call), after credentials, before every page and enrich request, after the last answer and on every events.list.
// It does no network and no write, so it is safe on every read. It answers {ok: true}, a pause {ok: false, reason, detail?} from the closed list
// of lib/trigger-rules.mjs, or a skip {ok: false, skip: true, detail}. A skip is not a pause: an account that must reconnect has not changed
// authority (spec line 1810), and nothing can be sent while it holds. So a poll ends with nothing stored and backs off, events.list serves what was
// gathered lawfully, and a subscribe, an approval or a Resume refuses. Steps 3 to 8 still run after a skip, and a failure there wins over it, so a row
// at Never still pauses a watch and withholds its events while the account needs reconnecting. This file sits outside the action wall: it reaches
// a trigger only through runtime.actions, the catalog the server was given, which is null only when it would not load. The engine holds that case
// itself, since a local fault is no reason to pause anything (part 2c).
import {canonicalHash} from './compiler.mjs';
import {backgroundAllowed} from './app-detail.mjs';
import {ownedBy, ownershipOf} from './tenant/deployment.mjs';
import {SLACK_HISTORY_TRIGGERS} from './trigger-rules.mjs';

/** Gate step 2: a failed renewal, which backs off and is never a change of authority. */
const WAITING = new Set(['unavailable', 'reconnect_required']);
/** Gate step 7: the authority fields a change of account moves, and those a change of what was approved moves. */
const ACCOUNT_FIELDS = ['identityId', 'bindingHash', 'connectionGeneration'], APPROVED_FIELDS = ['triggerId', 'argsHash', 'policyHash', 'policyRevision'];
const pause = (reason, detail) => ({ok: false, reason, ...(detail ? {detail} : {})});

/** What a subscription's `argsHash` holds. Key order never moves it. */
export const argsHashOf = args => canonicalHash({kind: 'fabric-trigger-args', args});
/**
 * The authority a subscription is approved under, from its current decision (permissions.triggerDecision()): an approval and a Resume store this, and
 * gate step 7 compares it. It holds the identity's id alone, and no cursor, so a rename or a cursor move can never look like a change of authority.
 */
export function authorityOf(subscription, connection, decision) {
  const {bindingHash, policyHash, connectionGeneration, policyRevision} = decision;
  return {triggerId: subscription.triggerId, bindingHash, policyHash, identityId: connection.identity?.id ?? null, argsHash: argsHashOf(subscription.args),
    ...(connectionGeneration === undefined ? {} : {connectionGeneration}), ...(policyRevision === undefined ? {} : {policyRevision})};
}

/** Gate step 3: a tenant record with no owner is never usable; the owner's own Fabric has one owner. */
function owned(connection, subscription, deployment) {
  try { return ownedBy(connection, ownershipOf(subscription, deployment), deployment); } catch { return false; }
}
/** Whether a catalog item may run: placed, its code at its pins, and active, or a candidate only in a certification Fabric. So a candidate's lens on a shared feed sends nothing (I8). */
export function runnable(runtime, item) {
  return !item.entry.unplaced && runtime.actions.pinned(item) && (item.status === 'active' || runtime.permissions.certification === true);
}
/** Gate step 4: the catalog's item for this subscription when it may run. */
function currentItem(runtime, subscription) {
  const item = runtime.actions?.triggerOf?.(subscription.triggerId);
  return item && item.appId === subscription.appId && runnable(runtime, item) ? item : null;
}
/** Gate step 8: a client that is gone, revoked or past its time ends its watches. */
export function clientActive(runtime, clientId) {
  const client = runtime.store.get('clientGrants', clientId);
  return client?.status === 'active' && Date.parse(client.expiresAt) > runtime.clock();
}

/**
 * Section 2.5's eight steps, in order. `memo` is one tick's (permissions.triggerDecision()). `resume` is true only at the owner's Resume: it skips step 7,
 * since Resume checks the owner's digest against current values and rewrites `authority` in the same write. Step 7 is also skipped before approval,
 * when there is no authority yet, and nowhere else: an approved record with none fails it.
 */
export function gate(runtime, subscription, {memo = new Map(), resume = false} = {}) {
  const {store, permissions, deployment} = runtime;
  if (!backgroundAllowed(store, subscription.connectionId)) return pause('background_off');
  const connection = store.get('connections', subscription.connectionId);
  if (!connection || connection.appId !== subscription.appId || connection.driver !== 'http') return pause('account_changed');
  const waiting = WAITING.has(connection.status);
  if (!waiting && connection.status !== 'ready') return pause('account_changed');
  if (!owned(connection, subscription, deployment)) return pause('account_changed');
  const item = currentItem(runtime, subscription);
  if (!item) return pause('definition_changed');
  if (SLACK_HISTORY_TRIGGERS.includes(`${item.appId}.${item.entry.key}`) && runtime.slackDistribution === 'distributed') return pause('provider_refused', 'distributed');
  const decision = permissions.triggerDecision(connection, item.entry, {memo});
  if (decision.mode !== 'allow') return pause('permission_changed');
  if (['missing', 'unavailable'].includes(decision.access)) return pause('access_missing');
  if (!resume && subscription.status !== 'awaiting_approval') {
    const current = authorityOf(subscription, connection, decision), differs = field => subscription.authority?.[field] !== current[field];
    if (ACCOUNT_FIELDS.some(differs)) return pause('account_changed');
    if (APPROVED_FIELDS.some(differs)) return pause('permission_changed');
  }
  if (!clientActive(runtime, subscription.clientId)) return pause('client_ended');
  return waiting ? {ok: false, skip: true, detail: connection.status} : {ok: true};
}

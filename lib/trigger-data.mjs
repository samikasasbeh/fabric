// Iteration 9, part 1b (docs/I07-BUILD-MAP.md; default 12): what a disconnect does to the watches on an account. ConnectionManager.revoke() is the one
// choke point, so every way out of an account reaches this file. Each watch that was waiting on the account or reading it pauses with a reason, and
// everything the watches gathered goes: feeds with their cursors, runs, seen rows and events. The app page's "Fabric no longer holds this account's
// access" stays true. Plain imports only: the action modules stay behind their wall, and this file runs no trigger code.
import {where} from './retention.mjs';
import {pauseTimes} from './trigger-rules.mjs';

/** A subscription in one of these still waits on or reads the account. Any other keeps its status, and a paused one keeps its own reason. */
const STANDING = new Set(['awaiting_approval', 'starting', 'active']);

/** Pauses the account's standing subscriptions and erases its trigger data. `now` is epoch milliseconds. A pause is a change of standing, not a poll, so each writes one audit row, with ids only. */
export function forgetTriggers(store, connectionId, now) {
  const at = new Date(now).toISOString();
  for (const subscription of where(store, 'subscriptions', 'connectionId', connectionId)) {
    if (!STANDING.has(subscription.status)) continue;
    store.put('subscriptions', {...subscription, status: 'paused', reason: 'account_changed', revision: subscription.revision + 1, ...pauseTimes(subscription, (subscription.feeds ?? []).map(id => store.get('triggerFeeds', id)), at), updatedAt: at});
    store.audit({type: 'trigger.paused', subscriptionId: subscription.id, connectionId, appId: subscription.appId, reason: 'account_changed'});
  }
  for (const collection of ['triggerFeeds', 'triggerRuns']) for (const {id} of where(store, collection, 'connectionId', connectionId)) store.delete(collection, id);
  if (typeof store.deleteConnectionTriggerData === 'function') store.deleteConnectionTriggerData(connectionId);
}

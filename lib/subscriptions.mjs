// Iteration 9 parts 3a to 3d (docs/I07-BUILD-MAP.md step 3): what an agent does with a watch through fabric/0.1: triggers.list, triggers.subscribe, triggers.unsubscribe and
// events.list, and what the owner decides: approve, decline, pause, resume and remove. A subscription is a record, not a job: a job is a thing sent to a provider, and approving a
// watch sends nothing. So nothing in this file sends a request. The engine (lib/trigger-engine.mjs) reads, and every check of authority goes through the one gate (lib/trigger-gate.mjs).
//
// It is injected as ContinuationService is, and it works on a plain store as on a designated one: a default Fabric is plain, and a designated-only feature would mean no owner
// on a default run could use a watch. permissions.triggerDecision() holds generation and policy revision only when designated, so nothing here asks which store it has.
// This file sits outside the action wall: it reaches a trigger only through runtime.actions, the catalog the server was given, and a null catalog offers nothing and pauses nothing.
import {randomUUID} from 'node:crypto';
import {canonicalHash, validateInput} from './compiler.mjs';
import {callCard} from './cards.mjs';
import {where} from './retention.mjs';
import {taskTitle} from './runtime.mjs';
import {intervalOf} from './trigger-engine.mjs';
import {argsHashOf, authorityOf, clientActive, gate, runnable} from './trigger-gate.mjs';
import {pauseTimes, subscribeRefusal} from './trigger-rules.mjs';

/** The caps are spec line 1813's and the handoff limits of lib/continuations.mjs. Four waits a client is spec line 1816's. */
const APPROVAL_MS = 30 * 60_000, PER_ACCOUNT = 20, WAITING_PER_CLIENT = 10, WAITING_IN_ALL = 50, WAITS_PER_CLIENT = 4, DEFAULT_LIMIT = 50, MOST_LIMIT = 100, MOST_WAIT_SECONDS = 25;
/** Section 2.1: a live subscription reads. Only the caps and the same-args check also count one waiting or paused. */
const LIVE = new Set(['starting', 'active']), STANDING = new Set([...LIVE, 'awaiting_approval', 'paused']);
/** Gate step 2: an account that cannot be read now. Its watch waits, and its Watches row says the account needs reconnecting. */
const RECONNECTING = new Set(['unavailable', 'reconnect_required']);
/** Part 3b: what an event of a watch that failed the gate shows, so the cursor still moves and nothing leaks after a Never. */
const WITHHELD = Object.freeze({id: null, occurredAt: null, fields: null, summary: Object.freeze([]), withheld: true});
/** Why a subscribe was refused, by the gate's reason. A skip reads `reconnect`, since nothing new starts on an account that cannot be read. */
const REFUSED = Object.freeze({
  background_off: 'Background sync is off for this account, so it cannot be watched.',
  permission_changed: 'A permission this watch reads is not set to Allow, so it cannot run in the background.',
  access_missing: 'This account lacks the access this watch needs.',
  account_changed: 'This account cannot be watched: it changed, was disconnected, or is not an API account.',
  client_ended: 'This agent\'s access has ended.',
  definition_changed: 'This watch is not available now.',
  provider_refused: 'The provider refuses this watch here.',
  reconnect: 'This account needs reconnecting before it can be watched.',
});
function fail(code, message) { throw Object.assign(new Error(message), {code}); }
const iso = time => new Date(time).toISOString();
const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const named = value => typeof value === 'string' && value.length > 0 && value.length <= 256 && !/[\u0000-\u001f\u007f]/.test(value);
const whole = (value, least, most) => Number.isSafeInteger(value) && value >= least && value <= most;
function closed(params, allowed) {
  if (!isRecord(params) || Object.keys(params).some(key => !allowed.includes(key))) fail('invalid_request', 'Unexpected request fields.');
}
/** The accounts a client holds: those its grant names, through a binding or a proxy entry. No new grant field: the approval is the grant. */
const heldBy = client => [...new Set([...client.bindings, ...(client.proxy ?? [])].map(item => item.connectionId))];
/** A subscription as the gate reads it before approval: gate step 7 is keyed on this status, so it asks for no authority. */
const draftOf = (client, item, connectionId, args = {}) => ({clientId: client.id, appId: item.appId, triggerId: item.entry.id, connectionId, args, status: 'awaiting_approval'});

/** What a decision answers: the record's standing, never its authority or its arguments. */
const answerOf = ({id, status, reason, updatedAt}) => ({id, status, ...(reason ? {reason} : {}), updatedAt});

/**
 * What the owner's approval binds (part 3c), from the current decision of permissions.triggerDecision(): the exact watch, the account, and the policy of each row it reads. It reads
 * current values, so a row moved between the view and the approval gives another digest. It holds the generation on a designated store only, as the decision does.
 */
export function approvalDigest(subscription, connection, {rows, connectionGeneration}) {
  const {id, revision, triggerId, connectionId, argsHash} = subscription;
  return canonicalHash({kind: 'subscription-approval', id, revision, triggerId, connectionId, identityId: connection.identity?.id ?? null, argsHash,
    rows: rows.map(({row, policyHash}) => ({row, policyHash})),
    ...(connectionGeneration === undefined ? {} : {connectionGeneration})});
}

export class SubscriptionService {
  constructor({store, runtime, protocol, triggers, clock = runtime.clock, origin, appName = id => id}) {
    Object.assign(this, {store, runtime, protocol, triggers, clock, origin, appName, closed: false});
    /** Client id to the wake function of each of its open waits. Fabric holds no read position, so this is all a wait leaves in memory. */
    this.waiters = new Map();
  }

  // ---- what is offered ----------------------------------------------------------------------------------------------------------------------

  /** The catalog's items this Fabric may run. runnable() is the status half of gate step 4, so the list and the gate cannot disagree: a candidate is never offered, outside a certification Fabric (I8). */
  #listed() {
    const catalog = this.runtime.actions;
    return catalog?.triggers ? [...catalog.triggers.values()].filter(item => runnable(this.runtime, item)) : [];
  }
  /** Whether this client could start this trigger now, on any account it holds. The owner's rows decide, so it says why not. */
  #availability(client, item, connectionIds, memo) {
    if (!connectionIds.length) return {status: 'unavailable', reason: 'no_account'};
    const answers = connectionIds.map(connectionId => gate(this.runtime, draftOf(client, item, connectionId), {memo}));
    return answers.some(answer => answer.ok) ? {status: 'available'} : {status: 'unavailable', reason: answers[0].reason ?? 'reconnect'};
  }
  /** The owner's words for the rows a trigger reads, as capabilities.list names them. */
  #labels(appId, {rows}) {
    const {groups} = this.runtime.permissions.groups.get(appId);
    return rows.map(row => groups.find(group => group.id === row).label);
  }
  /** One entry per trigger, not per account. It lists no cursor, identity or provider value. */
  #offer(client, item, held, memo) {
    const {appId, entry: {id, trigger}} = item, {name, description, inputSchema, choices, event, retention} = trigger;
    const connectionIds = held.filter(connectionId => this.store.get('connections', connectionId)?.appId === appId);
    return {id, appId, name, description, inputSchema, ...(choices ? {choices: choices.map(({input, dependsOn = []}) => ({input, dependsOn: [...dependsOn]}))} : {}), eventFields: Object.keys(event.fields), intervalSeconds: intervalOf(trigger), retention,
      rows: this.#labels(appId, trigger), connectionIds, ...this.#availability(client, item, connectionIds, memo)};
  }
  /**
   * A watch's check as part 3d's fixed states name it, or null for a record that reads nothing, since a request waiting for its approval or a closed one has no check to report. It reads this
   * record, its own count in each feed's last run, and the check times and wait of its feeds and account. A run's `items` and `skipped` are feed-wide, across every watch on the feed, so `health` reads neither.
   */
  health(subscription) {
    const {store} = this, {status, reason, detail, feeds: ids = [], id} = subscription;
    if (!LIVE.has(status) && status !== 'paused') return null;
    const runs = ids.map(feedId => store.get('triggerRuns', feedId)?.runs.at(-1)).filter(Boolean), lastCheckedAt = runs.length ? iso(Math.min(...runs.map(run => run.at))) : null;
    if (status === 'paused') return {state: reason, lastCheckedAt, ...(detail ? {errorCode: detail} : {})};
    const now = this.clock(), feeds = ids.map(feedId => store.get('triggerFeeds', feedId)).filter(Boolean), events = runs.reduce((sum, run) => sum + (run.events[id] ?? 0), 0);
    const waiting = feeds.some(feed => feed.wait?.until > now), failing = feeds.some(feed => feed.failures > 0);
    const state = RECONNECTING.has(store.get('connections', subscription.connectionId)?.status) ? 'reconnect' : waiting ? 'waiting' : failing ? 'failing' : feeds.some(feed => feed.behind) ? 'behind' : status === 'starting' ? 'starting' : events ? 'found' : 'quiet';
    const code = waiting || failing ? runs.find(run => run.code)?.code : undefined, nextOf = feed => Math.max(feed.nextPollAt, feed.wait?.until ?? 0, feed.notBefore ?? 0);
    return {state, lastCheckedAt, ...(feeds.length ? {nextCheckAt: iso(Math.min(...feeds.map(nextOf)))} : {}), ...(state === 'found' ? {events} : {}), ...(code ? {errorCode: code} : {})};
  }
  /** Where the owner approves a waiting request. It carries nothing and grants nothing. */
  #approval({id, status, approvalExpiresAt}) {
    return status === 'awaiting_approval' ? {approval: {url: `${new URL(this.origin).origin}/approve/${id}`, expiresAt: approvalExpiresAt}} : {};
  }
  /** triggers.list: this client's own records only, so no agent reads another's watches through a shared feed. */
  list(client) {
    const held = heldBy(client), memo = new Map();
    return {triggers: this.#listed().map(item => this.#offer(client, item, held, memo)),
      subscriptions: where(this.store, 'subscriptions', 'clientId', client.id).map(stored => {
        const subscription = this.touch(stored), {id, triggerId, connectionId, status, reason, createdAt, updatedAt} = subscription;
        return {id, triggerId, connectionId, status, ...(reason ? {reason} : {}), createdAt, updatedAt, ...this.#approval(subscription), health: this.health(subscription)};
      })};
  }

  // ---- changes of standing ------------------------------------------------------------------------------------------------------------------

  /** Each change of standing writes one audit row with ids only, never args. Polls write none. */
  #audit(type, {id, clientId, connectionId, appId, triggerId}, fields = {}) {
    this.store.audit({type, subscriptionId: id, clientId, connectionId, appId, triggerId, ...fields});
  }
  #expire(subscription, fields = {}) {
    const expired = this.store.put('subscriptions', {...subscription, status: 'expired', ...fields, updatedAt: iso(this.clock())});
    this.#audit('trigger.expired', expired);
    return expired;
  }
  /** Applies expiry lazily on every read that needs it, as ContinuationService.touch() does. The audit row lands on the transition. events.list has no call here: a request that is waiting has no events. */
  touch(subscription) {
    return subscription.status === 'awaiting_approval' && this.clock() >= Date.parse(subscription.approvalExpiresAt) ? this.#expire(subscription) : subscription;
  }
  /** A paused watch has no poll to find its client's end, so a revoke or the owner's list closes it, as the engine closes a live one: it can never resume, and nothing can read what it gathered. */
  #closeEnded({detail: _detail, ...subscription}) {
    const closed = this.store.put('subscriptions', {...subscription, reason: 'client_ended', updatedAt: iso(this.clock())});
    this.#audit('trigger.paused', closed, {reason: 'client_ended'});
    this.triggers.letGo(closed);
    return this.store.get('subscriptions', closed.id);
  }
  #settleClient(subscription) {
    return subscription.status === 'paused' && subscription.reason !== 'client_ended' && !clientActive(this.runtime, subscription.clientId) ? this.#closeEnded(subscription) : subscription;
  }
  /** A revoked client's waiting requests and paused watches close here, and its waits end at once. An active watch pauses through the gate at its next poll, as any other change of authority does. */
  cancelForClient(clientId) {
    for (const subscription of where(this.store, 'subscriptions', 'clientId', clientId)) { if (subscription.status === 'awaiting_approval') this.#expire(subscription, {reason: 'client_ended'}); else this.#settleClient(subscription); }
    this.notify(clientId);
  }

  // ---- triggers.subscribe ---------------------------------------------------------------------------------------------------------------------

  /** A record as the agent reads it. A waiting one carries its link and card. Only a state a card knows has one, so a live watch has none. */
  #view(client, subscription) {
    const {id, status, reason, triggerId, connectionId, appId, triggerKey, createdAt, updatedAt} = subscription, approval = this.#approval(subscription);
    const view = {id, status, ...(reason ? {reason} : {}), triggerId, connectionId, createdAt, updatedAt, approvalRequired: status === 'awaiting_approval', ...approval};
    try {
      const operationName = this.runtime.actions?.triggerOf?.(triggerId)?.entry.trigger.name ?? triggerKey;
      return {...view, card: callCard(view, {requesterName: client.name, appId, appName: this.appName(appId), operationName, effect: 'read', origin: this.origin, now: this.clock()})};
    } catch { return view; }
  }
  #remember(client, requestId, key, requestHash, subscriptionId) {
    this.store.put('protocolRequests', {id: key, clientId: client.id, requestId, requestHash, subscriptionId, status: 'recorded', createdAt: iso(this.clock())});
  }
  #replay(client, previous, requestHash) {
    if (previous.requestHash !== requestHash) fail('idempotency_conflict', 'This request id was already used with different arguments.');
    const subscription = this.store.get('subscriptions', previous.subscriptionId);
    if (subscription?.clientId !== client.id) fail('outcome_unknown', 'The earlier request cannot be replayed safely. List the triggers before issuing a new request.');
    return this.#view(client, this.touch(subscription));
  }
  /** The record this client already holds for this watch, in any state that still waits, reads or can come back. */
  #holding(client, triggerId, connectionId, argsHash) {
    return where(this.store, 'subscriptions', 'clientId', client.id).map(stored => this.touch(stored))
      .find(item => STANDING.has(item.status) && item.triggerId === triggerId && item.connectionId === connectionId && item.argsHash === argsHash);
  }
  /** The caps, asked again at approval (part 3c), where `leaving` is the record being approved: it counts as room for itself, or the 20th watch on an account would refuse itself. Expiry applies first, so a request past its time does not count. */
  #assertRoom(client, connectionId, leaving) {
    const others = stored => stored.id !== leaving, standing = where(this.store, 'subscriptions', 'connectionId', connectionId).filter(others).map(stored => this.touch(stored)).filter(item => STANDING.has(item.status) && item.reason !== 'client_ended');
    if (standing.length >= PER_ACCOUNT) fail('subscription_limit', `This account already has ${PER_ACCOUNT} watches. Remove one before asking for another.`);
    const waiting = where(this.store, 'subscriptions', 'status', 'awaiting_approval').filter(others).map(stored => this.touch(stored)).filter(item => item.status === 'awaiting_approval');
    if (waiting.length >= WAITING_IN_ALL || waiting.filter(item => item.clientId === client.id).length >= WAITING_PER_CLIENT) fail('pending_limit', 'Too many watches are waiting for the owner. Try again after they are handled.');
  }
  /** The gate where something new would start. A skip refuses too, since nothing new starts on an account that cannot be read. */
  #pass(subscription, options) {
    const answer = gate(this.runtime, subscription, options);
    if (!answer.ok) fail('permission_denied', REFUSED[answer.skip ? 'reconnect' : answer.reason]);
  }
  /**
   * triggers.subscribe, in part 3a's order. Everything before the write is a read, so refused bytes store nothing, and a refused request id stays free. The same-args check sits before the gate, not
   * after it: an agent holding a paused watch gets that record and its reason back, even when the gate would refuse a new one. So the promise that an agent loop cannot stack approvals has no exception.
   * The record is written before its request row: after a crash between the two, the same request finds it through the same-args check.
   */
  subscribe(client, requestId, params) {
    closed(params, ['triggerId', 'connectionId', 'args', 'task']);
    const {triggerId, connectionId, args: given = {}} = params, task = taskTitle(params.task);
    if (!named(triggerId) || !named(connectionId) || !isRecord(given)) fail('invalid_request', 'Choose a trigger, a granted account and its arguments.');
    const {store, runtime} = this, connection = store.get('connections', connectionId);
    if (!connection || !heldBy(client).includes(connectionId)) fail('permission_denied', 'This account was not granted to this client.');
    const key = canonicalHash({clientId: client.id, requestId}), requestHash = canonicalHash({method: 'triggers.subscribe', params}), previous = store.get('protocolRequests', key);
    if (previous) return this.#replay(client, previous, requestHash);
    const item = runtime.actions?.triggerOf?.(triggerId);
    if (!item || !runnable(runtime, item)) fail('not_found', 'This trigger is not offered. List the triggers again.');
    const {entry, appId} = item;
    // The schema is closed, so a cursor is refused as any extra key is (spec line 1786).
    try { validateInput(entry.trigger.inputSchema, given); } catch (error) { fail('invalid_request', error.message); }
    const args = runtime.actions.normalizeArgs(entry, given), each = entry.trigger.resource.each;
    // The format sets no minItems, and a watch with no feed could never leave `starting`.
    if (each && !args[each.slice(1)].length) fail('invalid_request', 'Name at least one thing to watch.');
    const refused = subscribeRefusal(appId, entry.key, args, {scopes: runtime.permissions.grantedScopes(connection), slackDistribution: runtime.slackDistribution});
    if (refused) fail('invalid_request', refused.words);
    const argsHash = argsHashOf(args), held = this.#holding(client, triggerId, connectionId, argsHash);
    if (held) { this.#remember(client, requestId, key, requestHash, held.id); return this.#view(client, held); }
    this.#pass(draftOf(client, item, connectionId, args));
    this.#assertRoom(client, connectionId);
    const now = this.clock(), at = iso(now), id = randomUUID(), draft = {id, clientId: client.id, appId, triggerId, triggerKey: entry.key, connectionId, args, argsHash, ...(task ? {task: {title: task}} : {}), revision: 1, status: 'awaiting_approval'};
    const stored = store.put('subscriptions', {...draft, approvalDigest: approvalDigest(draft, connection, runtime.permissions.triggerDecision(connection, entry)), approvalExpiresAt: iso(Math.min(now + APPROVAL_MS, Date.parse(client.expiresAt))),
      feeds: [], pending: [], createdAt: at, updatedAt: at});
    this.#audit('trigger.requested', stored);
    this.#remember(client, requestId, key, requestHash, id);
    return this.#view(client, stored);
  }

  // ---- triggers.unsubscribe -------------------------------------------------------------------------------------------------------------------

  /** An agent may always remove its own watch. A foreign id answers as an unknown one. Polling registered nothing, so there is no provider teardown. */
  unsubscribe(client, params) {
    closed(params, ['subscriptionId']);
    if (!named(params.subscriptionId)) fail('invalid_request', 'Name the subscription to remove.');
    const {store} = this, subscription = store.get('subscriptions', params.subscriptionId);
    if (subscription?.clientId !== client.id) fail('not_found', 'Subscription not found.');
    return this.#view(client, this.#remove(subscription));
  }
  /** Removes a watch for good, for its agent or its owner. Its events and its share of the feeds go. The record stays, so the owner can still see that an agent held this watch and who allowed it. */
  #remove(subscription) {
    const {store} = this;
    if (subscription.status === 'removed') return subscription;
    const removed = store.put('subscriptions', {...subscription, status: 'removed', updatedAt: iso(this.clock())});
    store.deleteSubscriptionEvents(removed.id);
    this.triggers.detach(removed);
    this.#audit('trigger.removed', removed);
    return store.get('subscriptions', removed.id);
  }

  // ---- what the owner sees and decides (parts 3c and 3d) -----------------------------------------------------------------------------------------

  /** A record for the owner's pages, with expiry applied, or null when this Fabric has none. */
  record(id) {
    const stored = this.store.get('subscriptions', id);
    return stored ? this.touch(stored) : null;
  }
  /** What the Activity page lists: every record that waits or stands, with expiry and a client's end applied. It reads by status, so the closed records nothing prunes cost it nothing. */
  ownerList() {
    return [...STANDING].flatMap(status => where(this.store, 'subscriptions', 'status', status)).map(stored => this.#settleClient(this.touch(stored))).filter(item => STANDING.has(item.status));
  }
  /** How many requests wait for the owner. A status read writes nothing, so a lapsed request is left for the next touch and simply not counted. */
  pendingCount() {
    const now = this.clock();
    return where(this.store, 'subscriptions', 'status', 'awaiting_approval').filter(item => now < Date.parse(item.approvalExpiresAt)).length;
  }
  /** The account and the current decision a digest is read from, once the gate has said both stand. */
  #decision({connectionId, triggerId}) {
    const connection = this.store.get('connections', connectionId);
    return {connection, decision: this.runtime.permissions.triggerDecision(connection, this.runtime.actions.triggerOf(triggerId).entry)};
  }
  /**
   * What the owner's card and Watches row show of one watch, as raw values for lib/ui-contracts.mjs, which holds no store. All of it is Fabric's or the reviewed file's: `health` and `skipped`
   * are counts and fixed states, and nothing a provider sent is here. `skipped` is the feed-wide count health() leaves out for an agent, and the owner may see it: the most any run Fabric still
   * keeps could not read, not the last run's, or a real item lost would leave the row one interval later, and not their sum, since a list that shows an item every poll counts it every poll. `digest` is computed now, so a
   * row moved after the view gives another one and the decision refuses. It is null with no trigger or no account, since there is then nothing to bind. `resumable` says the gate would pass.
   */
  ownerFacts(subscription) {
    const {store, runtime} = this, {appId, triggerId, connectionId, feeds = [], status} = subscription, item = runtime.actions?.triggerOf?.(triggerId), {entry} = item?.appId === appId ? item : {};
    const skipped = feeds.reduce((sum, feedId) => sum + Math.max(0, ...(store.get('triggerRuns', feedId)?.runs ?? []).map(run => run.skipped)), 0), facts = {health: this.health(subscription), skipped, trigger: null, digest: null, resumable: false};
    if (!entry) return facts;
    const {name, description, event: {fields, summary}, retention} = entry.trigger, connection = store.get('connections', connectionId);
    const trigger = {name, description, rows: this.#labels(appId, entry.trigger), fields: Object.keys(fields), summary: summary.map(({label, truncate}) => ({label, ...(truncate === undefined ? {} : {truncate})})), intervalSeconds: intervalOf(entry.trigger), retention};
    if (!connection) return {...facts, trigger};
    return {...facts, trigger, digest: approvalDigest(subscription, connection, runtime.permissions.triggerDecision(connection, entry)), resumable: status === 'paused' && Boolean(subscription.approvedAt) && gate(runtime, subscription, {resume: true}).ok};
  }
  /** Who decides. A plain store passes no principal, and a designated one holds its exact owner. It runs first, so a stranger learns nothing of a record. */
  #owner(principal) {
    return this.store.authorityEnabled ? this.runtime.assertOwner(principal) : null;
  }
  #found(id) {
    return this.record(id) ?? fail('not_found', 'This watch is not in this Fabric.');
  }
  /** The owner saw this digest. It must be the one true now, so a row or an account that moved after the view refuses, and the page reads the watch again. */
  #assertSeen(subscription, connection, decision, digest) {
    if (typeof digest !== 'string' || digest !== approvalDigest(subscription, connection, decision)) fail('digest_mismatch', 'This watch changed after the page was read. Read it again.');
  }
  /**
   * Part 3c: the gate, the caps and the digest, in that order, then the one write that starts a watch and its one audit row. attach() answers a record at `paused` when it refuses, and never
   * throws, so the answer reads what it wrote. An approval sends nothing: the engine's next tick reads the feed.
   */
  approve(id, digest, principal) {
    const approver = this.#owner(principal), subscription = this.#found(id);
    if (subscription.status === 'expired') fail('approval_expired', 'This approval expired. The agent can ask again.');
    if (subscription.status !== 'awaiting_approval') fail('not_awaiting_approval', 'This watch is not awaiting approval.');
    this.#pass(subscription);
    this.#assertRoom({id: subscription.clientId}, subscription.connectionId, subscription.id);
    const {connection, decision} = this.#decision(subscription), at = iso(this.clock());
    this.#assertSeen(subscription, connection, decision, digest);
    const approved = this.store.put('subscriptions', {...subscription, status: 'starting', authority: authorityOf(subscription, connection, decision), approvalDigest: digest, approvedAt: at, ...(approver ? {approvedBy: approver} : {}), updatedAt: at});
    this.#audit('trigger.approved', approved);
    return answerOf(this.triggers.attach(approved));
  }
  decline(id, principal) {
    this.#owner(principal);
    const subscription = this.#found(id);
    if (subscription.status !== 'awaiting_approval') fail('not_awaiting_approval', 'This watch is not awaiting approval.');
    const declined = this.store.put('subscriptions', {...subscription, status: 'declined', updatedAt: iso(this.clock())});
    this.#audit('trigger.declined', declined);
    return answerOf(declined);
  }
  /**
   * Part 3d: the owner's Pause, as the engine's own: it writes pauseTimes(), or the gap a Resume owes would be shorter than the one this pause made. Fabric never resumes it. A watch the gate
   * paused keeps its own reason, since that is what the owner has to fix. Only the engine writes a feed, so this touches none, and a poll in flight reads the record again before it stores.
   */
  pause(id, principal) {
    this.#owner(principal);
    const {store} = this, subscription = this.#found(id), at = iso(this.clock());
    if (subscription.status === 'paused') return answerOf(subscription);
    if (!LIVE.has(subscription.status)) fail('not_running', 'This watch is not running.');
    const paused = store.put('subscriptions', {...subscription, status: 'paused', reason: 'owner_paused', revision: subscription.revision + 1, ...pauseTimes(subscription, subscription.feeds.map(feedId => store.get('triggerFeeds', feedId)), at), updatedAt: at});
    this.#audit('trigger.paused', paused, {reason: 'owner_paused'});
    return answerOf(paused);
  }
  /**
   * Part 3d: the gate with its authority step skipped, then the digest, so a Resume doubles as a new approval: what changed is what the owner has just seen. It rewrites `authority` from current
   * values in the write that makes the record `starting`, so no gate ever reads the one without the other. That write raises `revision`, which resume() leaves alone at `starting`. A request that a
   * disconnect paused before anyone approved it has no approval to renew, and a Resume would start a watch whose card the owner never saw, so it refuses.
   */
  resume(id, digest, principal) {
    this.#owner(principal);
    const subscription = this.#found(id);
    if (subscription.status !== 'paused') fail('not_paused', 'This watch is not paused.');
    if (!subscription.approvedAt) fail('never_approved', 'This request was never approved, so there is nothing to resume. Remove it, and the agent can ask again.');
    this.#pass(subscription, {resume: true});
    const {connection, decision} = this.#decision(subscription);
    this.#assertSeen(subscription, connection, decision, digest);
    const started = this.store.put('subscriptions', {...subscription, status: 'starting', revision: subscription.revision + 1, authority: authorityOf(subscription, connection, decision), approvalDigest: digest, updatedAt: iso(this.clock())});
    this.#audit('trigger.resumed', started);
    return answerOf(this.triggers.resume(started));
  }
  remove(id, principal) {
    this.#owner(principal);
    return answerOf(this.#remove(this.#found(id)));
  }

  // ---- events.list ----------------------------------------------------------------------------------------------------------------------------

  /**
   * A watch's standing for this read. A skip counts as passing: no provider call happens and the events were gathered lawfully. A record that went withholds, and so does a watch its owner paused, since
   * the card says Fabric tells the agent what it finds until the owner pauses or removes it, and the gate reads no status. A pause nobody chose, such as a provider's refusal, withholds nothing.
   */
  #readable(id, memo) {
    const subscription = this.store.get('subscriptions', id), stopped = !subscription || (subscription.status === 'paused' && subscription.reason === 'owner_paused');
    const answer = stopped ? {ok: false} : gate(this.runtime, subscription, {memo});
    return {subscription, open: answer.ok || answer.skip === true};
  }
  /** One page: rows by primary key, each watch in it gated once, and `trimmed` counting exactly what retention or the 1,000 cap took, since a client's numbers are contiguous. */
  #page(client, after, limit) {
    const {store} = this, rows = store.listEvents(client.id, after, limit), latest = store.latestSequence(client.id), memo = new Map(), watches = new Map();
    const events = rows.map(({sequence, subscriptionId, connectionId, kind, createdAt, payload: {id, occurredAt, fields, summary}}) => {
      if (!watches.has(subscriptionId)) watches.set(subscriptionId, this.#readable(subscriptionId, memo));
      const {subscription, open} = watches.get(subscriptionId);
      return {sequence, subscriptionId, triggerId: subscription?.triggerId ?? null, connectionId, type: kind, ...(open ? {id, occurredAt, fields, summary} : WITHHELD), detectedAt: iso(createdAt)};
    });
    const next = rows.at(-1)?.sequence ?? Math.max(after, latest);
    return {events, next, latest, trimmed: next - after - rows.length};
  }
  /** Ends at a wake or at the timer, whichever is first. It takes a slot before it starts, and its timer keeps no process alive. */
  #wait(clientId, seconds) {
    const held = this.waiters.get(clientId) ?? new Set();
    if (held.size >= WAITS_PER_CLIENT) fail('wait_limit', `This agent already has ${WAITS_PER_CLIENT} waits open. Wait for one to end.`);
    this.waiters.set(clientId, held);
    return new Promise(resolve => {
      const wake = () => {
        clearTimeout(timer);
        held.delete(wake);
        if (!held.size) this.waiters.delete(clientId);
        resolve();
      };
      const timer = setTimeout(wake, seconds * 1000);
      timer.unref();
      held.add(wake);
    });
  }
  /**
   * events.list. It reads, and when there is nothing to give and something to wait for, it waits for notify() or the timer and reads once more. A client that went during the wait gets `unauthorized`,
   * never data. It writes no document, no audit row and no request row, as calls.get does, and it never calls Store.list: a page goes through the table's primary key.
   */
  async events(client, params) {
    closed(params, ['after', 'limit', 'waitSeconds']);
    const {after = 0, limit = DEFAULT_LIMIT, waitSeconds = 0} = params;
    if (!whole(after, 0, Number.MAX_SAFE_INTEGER) || !whole(limit, 1, MOST_LIMIT) || !whole(waitSeconds, 0, MOST_WAIT_SECONDS)) fail('invalid_request', `after is a whole number from 0, limit 1 to ${MOST_LIMIT} and waitSeconds 0 to ${MOST_WAIT_SECONDS}.`);
    const first = this.#page(client, after, limit);
    if (first.events.length || first.latest > after || !waitSeconds || this.closed || !where(this.store, 'subscriptions', 'clientId', client.id).some(item => LIVE.has(item.status))) return first;
    await this.#wait(client.id, waitSeconds);
    this.protocol.activeClient(client.id);
    return this.#page(client, after, limit);
  }
  /** Wakes every wait of this client. The engine calls it after a poll has landed. */
  notify(clientId) {
    for (const wake of [...(this.waiters.get(clientId) ?? [])]) wake();
  }
  /** Wakes every wait and lets no new one start, or server.close() would hang for up to 25 seconds. */
  close() {
    this.closed = true;
    for (const clientId of [...this.waiters.keys()]) this.notify(clientId);
  }
}

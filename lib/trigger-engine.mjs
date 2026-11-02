// Iteration 9 part 2c (docs/I07-BUILD-MAP.md step 2; sections 2.1 to 2.5): the scheduler. It finds which feeds are due, runs one poll of each through
// runtime.actions.runPoll(), serially, and stores what each returned, in the order section 2.4 names: gate, credentials, gate, requests, gate, events and seen rows,
// the cursor, the run. A poll is no job: it writes no audit row, nothing can dispatch it, and only a change of standing, such as a pause, writes one.
//
// This file sits outside the action wall: it reaches a trigger only through runtime.actions, the catalog the server was given. That catalog is null only when
// it would not load, which is a local fault and no reason to pause anything, so then nothing polls and nothing is written. Only this file writes a feed. Each write
// after an await reads its document again, so a pause during an await is never overwritten, and a subscription or a feed that went during it stays gone.
import {canonicalHash} from './compiler.mjs';
import {where} from './retention.mjs';
import {gate, runnable} from './trigger-gate.mjs';
import {BUDGETS, gapPayload, pauseTimes, placeLostAt, retentionMs} from './trigger-rules.mjs';

const POLLS_A_TICK = 5, TICK_MS = 30_000, TICK_EVERY_MS = 1000, RUNS_KEPT = 50, MINUTE_MS = 60_000, MOST_CURSOR = 2048;
/** The cursors a provider can tell Fabric it has lost, so the only ones ageCursor() has any reason to write. */
const STALE_KINDS = new Set(['history-id@1', 'sync-token@1']);
/** A subscription keeps a lens alive and is read in these. Section 2.1: one waiting for approval, or paused, sends no read. */
const LIVE = new Set(['starting', 'active']);
/** A subscription in one of these still holds its feeds: a paused one comes back to them. */
const HOLDS = new Set([...LIVE, 'paused']);
/** attach() and resume() take a watch from these: an approval leaves it at `starting`, and a Resume finds it `paused`, or `starting` if the owner's route wrote that first. */
const RESUMABLE = new Set(['paused', 'starting']);
const FEED_FIELDS = ['cursors', 'page', 'floor', 'draining', 'budgetStops', 'recordFailures', 'unreadTo', 'notBefore', 'baselined', 'lastGoodAt'];
/** Outcomes that failed: nothing new was reached, and the feed backs off. */
const FAILED = new Set(['limited', 'backoff', 'skipped', 'scope_missing']);
/** Section 2.4: a missing_scope answer pauses here. No gate can say so: Slack's history row opens on any of four scopes, so losing one leaves it reading as granted. */
const SCOPE_GONE = Object.freeze({reason: 'access_missing', detail: 'missing_scope'});
/** RFC 3339, from a time in milliseconds or a stored time. */
const iso = time => new Date(time).toISOString();
const fieldsOf = result => Object.fromEntries(FEED_FIELDS.map(name => [name, result[name]]));
/** A run's count of events by watch, for those that were stored. */
const counted = rows => { const events = {}; for (const row of rows) if (row.kind === 'trigger.event') events[row.subscriptionId] = (events[row.subscriptionId] ?? 0) + 1; return events; };
const feedIdOf = (connectionId, pollHash, resource, epoch) => canonicalHash({kind: 'fabric-trigger-feed', connectionId, pollHash, resource, epoch}).slice(0, 32);
/** A trigger's resource values for these args: one list by index for each feed, as triggerPollHash() numbers them. */
const resourcesOf = ({resource}, args) => Array.isArray(resource) ? [resource.map(name => args[name])] : args[resource.each.slice(1)].map(value => [value]);
const stepsOf = ({poll}) => [...poll.source.steps, ...(poll.seed ? [poll.seed.step] : []), ...(poll.enrich?.steps ?? [])];
const onHistory = item => item.entry.trigger.poll.cursors.some(cursor => cursor.kind === 'history-id@1');
/** Section 2.4: how often a trigger may run. A polling trigger takes the greatest of its numbers, and one on its fallback takes its poll's. */
export const intervalOf = ({delivery, poll}) => delivery.method === 'polling' ? Math.max(delivery.intervalSeconds.default, delivery.intervalSeconds.min, poll.minIntervalSeconds) : poll.minIntervalSeconds;

export class TriggerEngine {
  constructor({store, runtime, clock = runtime.clock, random = Math.random, certification = false, budgets = BUDGETS, windows}) {
    Object.assign(this, {store, runtime, clock, random, certification, budgets, windows, buckets: new Map(), rates: new Map(), busy: false, stopped: false, timer: null, running: Promise.resolve()});
    this.notify = () => {};
  }
  /** The catalog's items this feed may run on: a candidate's lens sends nothing, outside a certification Fabric. */
  #itemsOf(feed) {
    return this.runtime.actions.triggersOnPoll(feed.appId, feed.pollHash).filter(item => runnable(this.runtime, item));
  }
  #lensOf(subscription) {
    const item = this.runtime.actions.triggerOf(subscription.triggerId);
    return item ? this.runtime.actions.triggerLens(item.entry, subscription.args) : null;
  }
  #liveOn(feed) {
    return where(this.store, 'subscriptions', 'connectionId', feed.connectionId).filter(subscription => LIVE.has(subscription.status) && subscription.feeds?.includes(feed.id));
  }
  /** A pause is a change of standing, so it writes one audit row, with ids only. It keeps what the gap a Resume owes needs. */
  #pause(subscription, {reason, detail}) {
    const current = this.store.get('subscriptions', subscription.id), at = iso(this.clock());
    if (!LIVE.has(current?.status)) return;
    this.store.put('subscriptions', {...current, status: 'paused', reason, ...(detail ? {detail} : {}), revision: current.revision + 1, ...pauseTimes(current, (current.feeds ?? []).map(id => this.store.get('triggerFeeds', id)), at), updatedAt: at});
    this.store.audit({type: 'trigger.paused', subscriptionId: current.id, connectionId: current.connectionId, appId: current.appId, reason});
    if (reason === 'client_ended') this.letGo(current);
  }
  /**
   * A client's end is final: a grant never comes back, so this watch can never resume, and nothing can read what it gathered. So its events and its share of its feeds go now, as a disconnect's do.
   * The record stays, so the owner can still see that this agent held a watch.
   */
  letGo(subscription) {
    this.store.deleteSubscriptionEvents(subscription.id);
    this.detach(subscription);
  }
  /** The Slack methods a feed's steps name, as a wait names them. */
  #methodsOf(feed) {
    return [...new Set(this.runtime.actions.triggersOnPoll(feed.appId, feed.pollHash).flatMap(item => stepsOf(item.entry.trigger).map(step => step.path.slice(1))))];
  }
  /** What a feed's requests count against, each as [key, requests a minute]: its connection, or for Slack its workspace and each method, as Slack counts. */
  #bucketsOf(feed) {
    const rule = Object.hasOwn(this.budgets, feed.appId) ? this.budgets[feed.appId] : null;
    if (!rule) return [];
    if (!rule.methods) return [[feed.connectionId, rule.perMinute]];
    const {identity} = this.store.get('connections', feed.connectionId) ?? {}, workspace = identity?.workspaceId ?? String(identity?.id).split(':')[0];
    return this.#methodsOf(feed).filter(method => Object.hasOwn(rule.methods, method)).map(method => [`${workspace}:${method}`, rule.methods[method]]);
  }
  /** A bucket as of now: it fills evenly over a minute, up to one minute's requests. A poll can take it below zero, and then it owes. */
  #bucket(key, perMinute, now) {
    const held = this.buckets.get(key) ?? {tokens: perMinute, at: now}, bucket = {tokens: Math.min(perMinute, held.tokens + (now - held.at) * perMinute / 60_000), at: now};
    this.buckets.set(key, bucket);
    return bucket;
  }
  #room(feed, now) {
    const rate = this.rates.get(feed.connectionId);
    if (rate && now < rate.until && rate.remaining < this.budgets[feed.appId]?.keepRemaining) return false;
    return this.#bucketsOf(feed).every(([key, perMinute]) => this.#bucket(key, perMinute, now).tokens >= 1);
  }
  #spend(feed, requests, now) {
    for (const [key, perMinute] of this.#bucketsOf(feed)) this.#bucket(key, perMinute, now).tokens -= requests;
  }
  /** The feeds a tick may start: due, oldest first, at most POLLS_A_TICK. One with an empty bucket stays due, is marked behind and takes no slot, so Fabric never claims an interval it is not keeping. */
  #chosen(now) {
    const {store} = this, ready = store.list('triggerFeeds').filter(feed => feed.nextPollAt <= now && (feed.wait?.until ?? 0) <= now && (feed.notBefore ?? 0) <= now);
    if (!ready.length) return [];
    const watched = new Set(store.list('subscriptions').filter(subscription => LIVE.has(subscription.status)).flatMap(subscription => subscription.feeds ?? [])), chosen = [];
    for (const feed of ready.filter(candidate => watched.has(candidate.id)).sort((a, b) => a.nextPollAt - b.nextPollAt)) {
      if (!this.#room(feed, now)) { if (!feed.behind) store.put('triggerFeeds', {...feed, behind: true}); continue; }
      if (chosen.length === POLLS_A_TICK) continue;
      this.#spend(feed, 1, now);
      chosen.push(feed);
    }
    return chosen;
  }
  #record(feed, run) {
    const held = this.store.get('triggerRuns', feed.id)?.runs ?? [];
    this.store.put('triggerRuns', {id: feed.id, connectionId: feed.connectionId, runs: [...held, run].slice(-RUNS_KEPT)});
  }
  #wake(added) {
    for (const clientId of Object.keys(added)) this.notify(clientId);
  }
  /** Stores one gap for each of these watches, as a poll stores its own: a replay computes the same key, so it lands once. */
  #gap(feed, items, subscriptions, reason, from) {
    const now = this.clock(), payload = gapPayload(reason, iso(from), iso(now)), kept = Math.max(...items.map(item => retentionMs(item.entry.trigger.retention)));
    this.#wake(this.store.appendPoll({feedId: feed.id, events: subscriptions.map(subscription => ({clientId: subscription.clientId, subscriptionId: subscription.id, dedupeKey: payload.id, connectionId: feed.connectionId,
      userRecordId: subscription.userRecordId ?? null, kind: 'trigger.gap', createdAt: now, expiresAt: now + kept, payload}))}).added);
  }
  /**
   * Section 2.3: a poll that reached the live edge takes its feed off the pending list of each watch in `listed`, the list read before its first request, so a poll already in flight
   * never counts. One with none left stores its one gap if it was resumed, then turns active. Each is read again here, so a watch that went during the await stays gone.
   */
  #settle(feed, items, listed) {
    const {store} = this, at = iso(this.clock());
    for (const {id, revision} of listed) {
      const current = store.get('subscriptions', id);
      if (current?.status !== 'starting' || current.revision !== revision || !current.pending.includes(feed.id)) continue;
      const pending = current.pending.filter(other => other !== feed.id), {pausedAt, heardTo, ...rest} = current;
      if (pending.length) { store.put('subscriptions', {...current, pending, updatedAt: at}); continue; }
      if (pausedAt) this.#gap(feed, items, [current], 'resume', heardTo ?? pausedAt);
      store.put('subscriptions', {...rest, pending, status: 'active', updatedAt: at});
    }
  }
  /** Gates each watch, pausing those that fail. A skip pauses nothing: it ends the poll. Answers who may read on, and a skip if there was one: a feed has one account, so any skip says the same. */
  #gated(subscriptions, memo) {
    const open = [];
    let skip = null;
    for (const subscription of subscriptions) {
      const answer = gate(this.runtime, subscription, {memo});
      if (answer.ok) open.push(subscription);
      else if (answer.skip) skip = answer;
      else this.#pause(subscription, answer);
    }
    return {open, skip};
  }
  /** runPoll()'s gate. It reads the watches again each time and writes nothing, so a row saved mid-poll is seen at the next request: the last gate of #poll says why, and pauses. */
  #authority(feed, memo) {
    return (_item, lens) => {
      const answers = this.#liveOn(feed).filter(subscription => lens === undefined || this.#lensOf(subscription) === lens).map(subscription => gate(this.runtime, subscription, {memo}));
      return answers.find(answer => answer.skip) ?? {ok: answers.some(answer => answer.ok)};
    };
  }
  /** Upward only, at most a quarter, so no floor is ever crossed. */
  #jittered(seconds) {
    return Math.round(seconds * 1000 * (1 + this.random() * 0.25));
  }
  /** When a feed that failed runs again: min(3600, interval * 2^failures) seconds, or later if a wait says so. A provider's wait counts in full, past that hour. */
  #resumesAt(interval, failures, wait) {
    return Math.max(wait?.until ?? 0, this.clock() + this.#jittered(Math.min(3600, interval * 2 ** failures)));
  }
  /** A limit is per token, or for Slack per method, so one answer holds every feed it covers. */
  #hold(feed, wait, until) {
    for (const other of where(this.store, 'triggerFeeds', 'connectionId', feed.connectionId)) {
      if (wait.method === undefined || this.#methodsOf(other).includes(wait.method)) this.store.put('triggerFeeds', {...other, wait: {until: Math.max(until, other.wait?.until ?? 0), reason: wait.reason}});
    }
  }
  /**
   * Section 2.4's order, from the last answer on: the last gate, events and seen rows, the cursor, the run, then what follows from them. With no live watch left, or a gate that
   * skipped, nothing is stored and the cursor stays. A feed that went during the await stays gone, and one a Resume started over keeps its fresh start.
   */
  #store(id, {feed, items, interval, listed, memo}, result) {
    const {store} = this, current = store.get('triggerFeeds', id), now = this.clock();
    this.#spend(feed, Math.max(0, result.run.requests - 1), now);
    if (result.rate) this.rates.set(feed.connectionId, {remaining: result.rate.remaining, until: result.rate.resetAt ?? now + MINUTE_MS});
    if (!current || (feed.baselined && !current.baselined)) return;
    // The provider said the scope is gone. The row may still read as granted, and a narrowing may have moved the account's generation, which the gate would call a change of account.
    if (result.outcome === 'scope_missing') for (const subscription of this.#liveOn(current)) this.#pause(subscription, SCOPE_GONE);
    const last = this.#gated(this.#liveOn(current), memo), discard = !last.open.length, failed = last.skip !== null || FAILED.has(result.outcome);
    // A client's end takes a feed with its last watch, and what went stays gone.
    if (!store.get('triggerFeeds', id)) return;
    const kept = new Set(last.open.map(subscription => subscription.id)), events = discard ? [] : result.events.filter(row => kept.has(row.subscriptionId));
    const {added, overLimit} = discard ? {added: {}, overLimit: []} : store.appendPoll({feedId: id, seen: result.seen, seenLimits: result.seenLimits, events});
    const stops = discard ? [] : [...result.lensPauses, ...overLimit.map(({lens}) => ({lens, code: 'seen_limit', reason: 'too_many_items'}))];
    const watching = lens => last.open.filter(subscription => this.#lensOf(subscription) === lens), dropped = stops.map(stop => stop.lens).filter(lens => !watching(lens).length);
    // A Resume started this feed over, so the other watches lost what its silent baseline just marked as seen. Their gap ends here, with that baseline.
    const told = !discard && result.reachedEdge && (current.lostFrom ?? null) !== null;
    if (told) this.#gap(current, items, last.open.filter(subscription => subscription.status === 'active' || !subscription.pending.includes(id)), 'resync', current.lostFrom);
    // A lens that stops here read less than this poll stored for the others, so it pauses before the feed says the present was reached: its gap starts at its own last read.
    for (const {lens, code, reason} of stops) for (const subscription of watching(lens)) this.#pause(subscription, {reason, detail: code});
    const failures = failed ? current.failures + 1 : 0, onward = !discard && result.onward === true, resumesAt = failed ? this.#resumesAt(interval, failures, result.wait) : null;
    store.put('triggerFeeds', {...current, ...(discard ? {notBefore: result.notBefore} : fieldsOf(result)), ...(told ? {lostFrom: null} : {}), failures, wait: null, lenses: current.lenses.filter(lens => !dropped.includes(lens)),
      ...(failed ? {nextPollAt: resumesAt} : onward ? {nextPollAt: this.clock()} : {}), ...(!discard && result.pause?.reason === 'cursor_invalid' ? {cursorInvalid: true} : {}), ...(!discard && result.reachedEdge ? {readAt: result.run.at} : {})});
    for (const lens of dropped) store.deleteLensSeen(id, lens);
    this.#record(current, {...result.run, ...(discard ? {outcome: last.skip ? 'skipped' : 'withheld', ...(last.skip ? {code: last.skip.detail} : {})} : {}), events: counted(events)});
    if (result.wait) this.#hold(current, result.wait, resumesAt);
    if (discard) return;
    if (result.pause) for (const subscription of last.open) this.#pause(subscription, result.pause);
    if (result.reachedEdge) this.#settle(current, items, listed);
    this.#wake(added);
  }
  /** Section 2.2: a lens this poll will not read writes no rows, so later it could not tell new from old. It leaves the feed with its rows, and its next watch takes the next epoch. A history item never repeats, so a history feed keeps it. */
  #dropUnread(feed, items, open) {
    if (onHistory(items[0])) return feed;
    const read = new Set([...items.flatMap(item => item.entry.trigger.poll.enrich ? [] : item.lenses), ...open.map(subscription => this.#lensOf(subscription))]), unread = feed.lenses.filter(lens => !read.has(lens));
    if (!unread.length) return feed;
    for (const lens of unread) this.store.deleteLensSeen(feed.id, lens);
    return this.store.put('triggerFeeds', {...feed, lenses: feed.lenses.filter(lens => read.has(lens))});
  }
  /** One poll of one feed. A feed's next time is written before the first await, so a night asleep coalesces into one run. */
  async #poll(id, {memo, deadline}) {
    const {store, runtime} = this, read = store.get('triggerFeeds', id);
    if (!read) return;
    const items = this.#itemsOf(read), now = this.clock(), interval = Math.max(0, ...items.map(item => intervalOf(item.entry.trigger)));
    const {behind: _caught, ...rest} = read, feed = store.put('triggerFeeds', {...rest, nextPollAt: now + this.#jittered(interval)}), listed = this.#liveOn(feed), first = this.#gated(listed, memo);
    if (first.skip) {
      const failures = feed.failures + 1;
      store.put('triggerFeeds', {...feed, failures, nextPollAt: this.#resumesAt(interval, failures)});
      this.#record(feed, {at: now, outcome: 'skipped', status: null, requests: 0, items: 0, skipped: 0, events: {}, code: first.skip.detail});
      return;
    }
    if (!first.open.length) return;
    const tracked = this.#dropUnread(feed, items, first.open);
    const result = await runtime.actions.runPoll({runtime, feed: tracked, entries: items, subscriptions: first.open, memo, authority: this.#authority(tracked, memo), deadline, windows: this.windows});
    this.#store(id, {feed: tracked, items, interval, listed, memo}, result);
  }
  async #round() {
    const started = this.clock(), memo = new Map();
    for (const feed of this.#chosen(started)) {
      if (this.stopped || this.clock() - started >= TICK_MS) break;
      // A limit answer earlier in this round holds every feed it covers, and a poll now would send past the wait and clear it.
      if ((this.store.get('triggerFeeds', feed.id)?.wait?.until ?? 0) > this.clock()) continue;
      // One feed's local fault leaves the rest: it runs again at its next time, and what it stored replays.
      try { await this.#poll(feed.id, {memo, deadline: started + TICK_MS}); } catch {}
    }
  }
  /** Polls run one at a time, whoever asks. */
  #turn(work) {
    const turn = this.running.then(work);
    this.running = turn.catch(() => {});
    return turn;
  }
  /** One round of due feeds. Its own flag keeps a slow round from stacking up behind the timer. */
  async tick() {
    if (this.busy || !this.runtime.actions) return;
    this.busy = true;
    try { await this.#turn(() => this.#round()); } finally { this.busy = false; }
  }
  /** The feed of this poll and resource that tracks this lens: the lowest epoch that does, and a new one when none does. A running history feed takes the lens in. */
  #feedFor(item, lens, resource, connectionId) {
    const {store} = this, {pollHash, appId} = item, now = this.clock(), history = onHistory(item);
    for (let epoch = 0; ; epoch++) {
      const id = feedIdOf(connectionId, pollHash, resource, epoch), feed = store.get('triggerFeeds', id);
      if (!feed) {
        const unwatched = this.#itemsOf({appId, pollHash}).flatMap(other => other.entry.trigger.poll.enrich && !history ? [] : other.lenses);
        store.put('triggerFeeds', {id, appId, connectionId, pollHash, resource, epoch, lenses: [...new Set([...unwatched, lens])], cursors: {}, page: null, baselined: false, floor: null, draining: false, budgetStops: 0, recordFailures: 0,
          lastGoodAt: null, nextPollAt: now, notBefore: null, failures: 0, wait: null, createdAt: iso(now)});
        return id;
      }
      if (feed.lenses.includes(lens) || history) {
        store.put('triggerFeeds', {...feed, lenses: [...new Set([...feed.lenses, lens])], nextPollAt: Math.min(feed.nextPollAt, now)});
        return id;
      }
    }
  }
  /**
   * Finds or makes the feeds of a watch, one per resource value, marks them due and lists them as pending: it turns active when each has finished a poll that started after this. So a backlog
   * never replays. A poll that reads an input outside its resource is refused here: two watches with different values would share one request, and only one of them would be read.
   */
  attach(subscription) {
    const {store} = this, catalog = this.runtime.actions, current = store.get('subscriptions', subscription.id);
    if (!catalog || !RESUMABLE.has(current?.status)) return current;
    const item = catalog.triggerOf(current.triggerId);
    if (!item || catalog.triggerPollInputs(item.entry).length) {
      this.#pause(current, {reason: 'definition_changed', ...(item ? {detail: 'poll_input'} : {})});
      return store.get('subscriptions', current.id);
    }
    const lens = this.#lensOf(current), feeds = resourcesOf(item.entry.trigger, current.args).map(resource => this.#feedFor(item, lens, resource, current.connectionId)), {reason: _reason, detail: _detail, ...rest} = current;
    this.#release(current, (current.feeds ?? []).filter(id => !feeds.includes(id)));
    return store.put('subscriptions', {...rest, status: 'starting', feeds, pending: feeds, revision: current.status === 'paused' ? current.revision + 1 : current.revision, updatedAt: iso(this.clock())});
  }
  /**
   * A feed that lost its place starts again from now, once. Its baseline is silent, so any other watch that hears of it is owed a gap, stored when that baseline ends, or what it marks as seen would fall
   * after the gap. A feed that did not lose its place is left as it is.
   */
  #startOver(id) {
    const {store} = this, read = store.get('triggerFeeds', id);
    if (!read?.cursorInvalid) return;
    const {cursorInvalid: _lost, ...feed} = read;
    store.put('triggerFeeds', {...feed, lostFrom: placeLostAt(feed) ?? feed.createdAt, cursors: {}, page: null, floor: null, baselined: false, draining: false, budgetStops: 0, recordFailures: 0});
  }
  /** The engine's half of Resume: as attach(), keeping `pausedAt` for the gap this watch is owed when it reaches the present. The owner's route has checked the gate and rewritten `authority`. */
  resume(subscription) {
    const current = this.store.get('subscriptions', subscription.id);
    if (!current || !RESUMABLE.has(current.status)) return current;
    if (this.runtime.actions) for (const id of current.feeds ?? []) this.#startOver(id);
    return this.attach(current);
  }
  /** Of the feeds a watch left, one no other watch holds goes with its runs and seen rows, and one a disconnect already took is simply not there. */
  #release(subscription, ids) {
    const {store} = this, holders = where(store, 'subscriptions', 'connectionId', subscription.connectionId).filter(other => other.id !== subscription.id && HOLDS.has(other.status));
    for (const id of ids) {
      if (holders.some(other => other.feeds?.includes(id))) continue;
      store.delete('triggerFeeds', id);
      store.delete('triggerRuns', id);
      store.deleteFeedSeen(id);
    }
  }
  /** Takes a watch off its feeds. */
  detach(subscription) {
    const {store} = this;
    this.#release(subscription, subscription.feeds ?? []);
    const current = store.get('subscriptions', subscription.id);
    if (current) store.put('subscriptions', {...current, feeds: [], pending: []});
  }
  /** Sleeps through a provider's wait and its x-poll-interval floor. */
  async #waitOut(id) {
    for (;;) {
      const feed = this.store.get('triggerFeeds', id), left = Math.max(feed?.wait?.until ?? 0, feed?.notBefore ?? 0) - this.clock();
      if (left <= 0) return;
      await this.runtime.wait(left);
    }
  }
  /** For the live harness: one poll of each of a watch's feeds now, on the same path, so it ignores nextPollAt and never the gate, a wait or a floor. It answers the watch as it stands. */
  async pollNow(subscriptionId) {
    const {store} = this, subscription = store.get('subscriptions', subscriptionId);
    if (!subscription || !this.runtime.actions) return subscription;
    for (const id of subscription.feeds ?? []) {
      await this.#waitOut(id);
      await this.#turn(() => this.#poll(id, {memo: new Map()}));
    }
    return store.get('subscriptions', subscriptionId);
  }
  /**
   * For the live harness alone, in a certification Fabric: writes a stale value over a running watch's sync or history cursor, so a live test can prove a resync that a provider gives no other way to reach (TG7, and
   * Calendar's if its probe allows). It is the one code that writes a cursor by hand. Nothing an agent can call reaches it, no server route names it, and it takes its turn, so no poll is in flight. Any stored page goes too, or
   * the next poll would read on from there and never send the value. It answers the watch as it stands.
   */
  async ageCursor(subscriptionId, value) {
    if (this.certification !== true) throw new Error('Only a certification Fabric can age a cursor.');
    if (typeof value !== 'string' || !value || value.length > MOST_CURSOR) throw new Error('A cursor value is text of 1 to 2,048 characters.');
    return this.#turn(() => {
      const {store} = this, subscription = store.get('subscriptions', subscriptionId);
      if (subscription?.status !== 'active') throw new Error('This watch is not running.');
      const cursor = this.runtime.actions.triggerOf(subscription.triggerId).entry.trigger.poll.cursors.find(item => STALE_KINDS.has(item.kind));
      if (!cursor) throw new Error('This watch has no cursor a stale value can age.');
      for (const id of subscription.feeds) {
        const feed = store.get('triggerFeeds', id);
        store.put('triggerFeeds', {...feed, cursors: {...feed.cursors, [cursor.name]: value}, page: null});
      }
      return store.get('subscriptions', subscriptionId);
    });
  }
  /** A one-second timer that keeps nothing alive, and one tick now. A certification Fabric runs neither: its guard refuses a tick between tests, so it polls through pollNow() alone. */
  start() {
    if (this.certification) return;
    this.timer = setInterval(() => this.tick().catch(() => {}), TICK_EVERY_MS);
    this.timer.unref();
    this.tick().catch(() => {});
  }
  /** Ends the timer and waits for the running poll, so the store closes under nothing. */
  async stop() {
    clearInterval(this.timer);
    this.timer = null;
    this.stopped = true;
    await this.running;
  }
}

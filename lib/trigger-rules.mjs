// Iteration 9 part 2a (docs/I07-BUILD-MAP.md step 2; sections 2.4, 2.5 and 9): the fixed facts of the poll engine, as data. The closed list of
// pause reasons, how to read a limit answer, which Slack errors pause, which snapshots are windows, what each provider's requests may cost
// and what a subscribe refuses before it stores anything. This file imports nothing, so code on both sides of the action wall can read it. It
// reads no store or clock and sends no request: subscribeRefusal() takes only the arguments and what Fabric already holds, so no provider
// request happens before approval. A new entry is a reviewed code change.

/** Section 2.5: why a subscription pauses. A pause never resumes on its own (spec line 1794), and a skip is not a pause. */
export const PAUSE_REASONS = Object.freeze(['owner_paused', 'background_off', 'permission_changed', 'access_missing', 'account_changed', 'client_ended', 'definition_changed', 'provider_refused', 'too_many_items', 'cursor_invalid']);

/**
 * How each app says a 403 is a limit and not a refusal, since a limit waits and a refusal pauses. Google names `reasons` or a `domain` in its error
 * shape ({error: {errors: [{reason, domain}]}}). GitHub spends its primary limit down to the `remaining` header at 0, and its secondary limit
 * has no header of its own, only `words`. A 403 alone is never enough: an app that is not listed never answers a limit with one.
 */
export const LIMITS = Object.freeze({
  gmail: Object.freeze({reasons: Object.freeze(['dailyLimitExceeded', 'userRateLimitExceeded', 'rateLimitExceeded'])}),
  'google-calendar': Object.freeze({domains: Object.freeze(['usageLimits'])}),
  github: Object.freeze({remaining: 'x-ratelimit-remaining', words: Object.freeze(['secondary rate limit'])}),
});
/** True when `answer` ({status, headers, data}) is a 403 its app's LIMITS read as a limit. A 429 or a 529 needs no table. */
export function limitAnswer(appId, answer) {
  const rule = Object.hasOwn(LIMITS, appId) ? LIMITS[appId] : null;
  if (!rule || answer?.status !== 403) return false;
  const errors = answer.data?.error?.errors, listed = Array.isArray(errors) ? errors : [], message = answer.data?.message;
  return listed.some(item => rule.reasons?.includes(item?.reason) || rule.domains?.includes(item?.domain))
    || (rule.remaining !== undefined && answer.headers?.[rule.remaining] === '0')
    || (typeof message === 'string' && rule.words?.some(words => message.toLowerCase().includes(words)) === true);
}

/** Section 2.4: the Slack `ok: false` errors that pause `provider_refused`, each with its code as the detail. */
export const PAUSE_ERRORS = Object.freeze(['channel_not_found', 'not_in_channel', 'thread_not_found', 'method_deprecated', 'deprecated_endpoint', 'token_revoked', 'account_inactive', 'ekm_access_denied']);

/** Section 2.4: the codes that say a retry will not help, whichever status carries them. Notion's page names the code and no status, so a 429 holding it must still pause, and never wait. */
export const REFUSED_CODES = Object.freeze({notion: Object.freeze(['public_api_request_blocked'])});
/** The code of an answer its app's REFUSED_CODES lists, or null. */
export function refusedCode(appId, answer) {
  const code = answer?.data?.code;
  return Object.hasOwn(REFUSED_CODES, appId) && REFUSED_CODES[appId].includes(code) ? code : null;
}

/**
 * Section 2.4: the snapshots that read a window of the provider's list, by <appId>.<key>, so old items leave it on their own. `seconds` is a fixed
 * reach, `minutesInput` an input that sets one, and an entry with neither has no set reach. A snapshot not listed reads a whole list.
 */
export const WINDOWS = Object.freeze({
  'gmail.new-email-matching-search': Object.freeze({seconds: 604_800}),
  'google-calendar.starting-soon': Object.freeze({minutesInput: 'leadMinutes'}),
  'github.push': Object.freeze({}),
  'github.workflow-run-finished': Object.freeze({}),
  'github.release-published': Object.freeze({}),
  'slack.mention-search': Object.freeze({}),
  'slack.reaction-recent': Object.freeze({}),
});
/** The window of one trigger with one subscription's `args`, as {seconds}, null seconds when it has no set reach; null when it is no window. */
export function windowOf(appId, key, args = {}) {
  const name = `${appId}.${key}`;
  if (!Object.hasOwn(WINDOWS, name)) return null;
  const {seconds = null, minutesInput} = WINDOWS[name];
  return {seconds: minutesInput ? args[minutesInput] * 60 : seconds};
}

/**
 * Part 2a: requests a minute, half of what each provider allows, since actions share its limit (recommendation 9 is still undecided). Per connection,
 * and for Slack per workspace and method, as Slack counts. `keepRemaining`: no poll while GitHub's own count is under this. Fabric holds these
 * in memory, and an empty bucket leaves a feed due and marks it behind: it never claims an interval it is not keeping.
 */
export const BUDGETS = Object.freeze({
  gmail: Object.freeze({perMinute: 60}),
  'google-calendar': Object.freeze({perMinute: 120}),
  github: Object.freeze({perMinute: 60, keepRemaining: 500}),
  notion: Object.freeze({perMinute: 90}),
  slack: Object.freeze({methods: Object.freeze({'conversations.history': 25, 'conversations.replies': 25, 'search.messages': 10, 'users.conversations': 25})}),
});

/** The fixed line of each gap. Nothing in a gap comes from a provider. */
const GAP_WORDS = Object.freeze({
  resync: 'Fabric lost its place in this list and found it again. Changes in this time were not read.',
  resume: 'This watch was paused. Changes in this time were not read.',
  bound: 'More changed at once than one check can read. Older changes in this time were not read.',
  stall: 'Fabric could not read past one place in this list. What it skipped was not read.',
  overflow: 'Everything in this list was new at once, so Fabric marked it as read and reported none of it.',
  window: 'Fabric was away for longer than this list reaches back. Changes in this time were not read.',
});
/**
 * Section 2.2: a gap's event, read on both sides of the action wall: a poll builds most of them, and only the scheduler knows when a watch was
 * paused. Its id is its dedupe key, `gap|<reason>|<range start>`, so a replay stores nothing twice and a later gap gets a new key.
 */
export const gapPayload = (reason, from, to) => ({type: 'trigger.gap', id: `gap|${reason}|${from}`, occurredAt: to, fields: {from, to, reason}, summary: [{label: 'Gap', value: GAP_WORDS[reason]}]});
/**
 * What a pause stores for the gap a Resume owes, from the watch and its feeds. `pausedAt` is the first pause, so a watch paused again before it reached the present keeps one gap over the whole range.
 * `heardTo` is when those feeds last reached the present, the one read longest ago deciding: a pause is found at a poll, so what was written since that read was never read, and the gap starts there.
 */
export function pauseTimes(subscription, feeds, at) {
  const reads = feeds.map(feed => feed?.readAt).filter(Number.isFinite);
  return {pausedAt: subscription.pausedAt ?? at, heardTo: subscription.pausedAt ? subscription.heardTo : reads.length ? Math.min(...reads) : undefined};
}
/**
 * Where the gap of a lost place starts: when its feed last reached the present. `lastGoodAt` moves with each step of a drain, so alone it would start the gap after what the drain had not reached.
 * The time is in milliseconds, or null for a feed never read.
 */
export const placeLostAt = ({lastGoodAt = null, readAt = null}) => lastGoodAt !== null && readAt !== null ? Math.min(lastGoodAt, readAt) : lastGoodAt ?? readAt;
/** How long a trigger's `retention` keeps an event, in milliseconds. */
export const retentionMs = ({days, hours}) => days !== undefined ? days * 86_400_000 : hours * 3_600_000;

/** Gate step 5: the triggers that read conversations.history or conversations.replies, which Slack holds to one read a minute for a distributed app (spec line 1808). */
export const SLACK_HISTORY_TRIGGERS = Object.freeze(['slack.new-message', 'slack.new-dm', 'slack.thread-reply', 'slack.reaction-recent', 'slack.file-shared']);

const CALENDAR_ACLS = 'https://www.googleapis.com/auth/calendar.acls';
/** `starting-soon`'s interval in seconds, as its block declares it: a lead under twice this could pass between two polls. */
const STARTING_SOON_SECONDS = 120;
const SLACK_CHANNEL = /^[CG][A-Z0-9]{8,20}$/, SLACK_DIRECT = /^D[A-Z0-9]{8,20}$/;
const REFUSALS = Object.freeze({
  distributed: 'Slack holds this app to one history or thread read a minute in each workspace, because it is distributed outside the Slack Marketplace, so it cannot keep this watch.',
  channel_id: 'Give each conversation as its Slack id, such as C0123456789, or D0123456789 for a direct message.',
  empty_search: 'Say what to search for: an empty search matches every email.',
  primary_calendar: 'Give the calendar\'s own id from List my calendars, not primary: both name one calendar, and one change would reach you twice.',
  lead_too_short: `Ask for a lead of at least ${STARTING_SOON_SECONDS * 2 / 60} minutes, twice how often Fabric checks, or a meeting could start between two checks.`,
  needs_access: 'This watch reads who a calendar is shared with, and this account has not allowed that. Use Add access on the account first.',
});
const refusal = reason => ({reason, words: REFUSALS[reason]});
/** The conversation ids a Slack trigger's arguments name, and what each must fit. Arguments that name none give none. */
function slackIds(key, args) {
  if (key === 'new-dm') return {ids: args.conversations ?? [], shape: SLACK_DIRECT};
  return {ids: key === 'thread-reply' ? (args.threads ?? []).map(thread => thread.channel) : args.channels ?? [], shape: SLACK_CHANNEL};
}

/**
 * What a subscribe refuses from its own values, before it stores anything: {reason, words}, or null. `args` already fit the trigger's closed
 * input schema, which has no `pattern` and no `minProperties`. `facts` is what Fabric holds with no network: {scopes, slackDistribution}. A reader's
 * calendar is not refused here, since Fabric stores no access role: it pauses `provider_refused` at its first poll (default 45).
 */
export function subscribeRefusal(appId, key, args, {scopes = [], slackDistribution = 'internal'} = {}) {
  if (appId === 'slack') {
    if (slackDistribution === 'distributed' && SLACK_HISTORY_TRIGGERS.includes(`slack.${key}`)) return refusal('distributed');
    const {ids, shape} = slackIds(key, args);
    return ids.every(id => shape.test(id)) ? null : refusal('channel_id');
  }
  if (appId === 'gmail') return key === 'new-email-matching-search' && !Object.keys(args.search ?? {}).length ? refusal('empty_search') : null;
  if (appId === 'google-calendar') {
    if (args.calendarId === 'primary') return refusal('primary_calendar');
    if (key === 'starting-soon' && args.leadMinutes * 60 < STARTING_SOON_SECONDS * 2) return refusal('lead_too_short');
    if (key === 'calendar-sharing-changed' && !scopes.includes(CALENDAR_ACLS)) return refusal('needs_access');
  }
  return null;
}

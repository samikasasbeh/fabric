// F10.21 part 1 f (docs/F10.21-BUILD-MAP.md part 1 f): a Slack simulator for the Slack actions' tests. It is written from Slack's Web API
// reference (docs.slack.dev, the method pages named below, read for this step) and from this comment, and it imports only node built-ins:
// never lib/, catalog/, Slack's action file, rows or proxy settings, so an action bug and a simulator bug cannot cancel out. Test data only:
// nothing in lib/ imports it, and nothing here calls Slack.
//
// The service: https://slack.com/api/<method> (ORIGIN and BASE). One workspace (T0FABRIC1, domain fabric-test) and one user token, the
// owner's. A method takes its arguments from the query of a GET or from the JSON body of a POST; Slack accepts either for every method used
// here. Fabric sends only JSON, so a POST body that is not application/json answers invalid_form_data (Slack would take a form; the
// simulator refuses it so a form never slips through). Every answer is HTTP 200 JSON, {ok: true, ...} or {ok: false, error}, except a
// rate limit (below). Order of checks: the bearer token (none: not_authed; another: invalid_auth), a `token` argument anywhere in the query
// or the body (token_argument, the simulator's own guard: Fabric reserves the name and never sends it; the call is recorded with
// tokenArgument true), the body's type, the method (unknown_method), its scopes, then its own rules. A method whose scope the token lacks
// answers missing_scope with `needed` (the scope) and `provided` (the token's scopes, comma-joined, in the order given), from this table,
// copied from each method's reference page (user tokens):
//   users.conversations       channels:read, groups:read, im:read or mpim:read for each type asked (public_channel, private_channel, im, mpim)
//   conversations.info        the read scope of the channel's type
//   conversations.history,    the history scope of the channel's type: channels:history (C), groups:history (G), im:history (D)
//   conversations.replies
//   chat.getPermalink, chat.scheduledMessages.list   none
//   search.messages           search:read
//   users.list, users.info    users:read (an email shows only with users:read.email too)
//   users.lookupByEmail       users:read.email
//   users.profile.get / .set  users.profile:read / users.profile:write
//   chat.postMessage, chat.update, chat.scheduleMessage, chat.deleteScheduledMessage   chat:write
//   reactions.add, reactions.remove / reactions.get   reactions:write / reactions:read
//   conversations.open        im:write (one person; a group DM, mpim:write, is not simulated)
//   canvases.getContent       canvases:read
// Every POST method used here accepts application/json by its reference page: chat.postMessage, chat.update, chat.scheduleMessage,
// chat.deleteScheduledMessage, reactions.add, reactions.remove, users.profile.set, conversations.open and canvases.getContent (open
// question 14 of the build map).
//
// Data: the owner (U0OWNER01), Ada Lovelace (U0ADA0001), Grace Hopper (U0GRACE01), a bot (U0BOT0001) and a deleted user (U0GONE001);
// #general (C0GENERAL1, the owner, Ada and Grace), #fabric-test (C0FABTEST1, the owner and Ada), a private channel G0PRIVATE1 (the owner),
// #others (C0OTHERS01, public, without the owner), an archived #old-news (C0ARCHIVE1, the owner) and a private G0SECRET01 without the owner;
// the owner's self-DM D0OWNER01; a canvas F0CANVAS01. #fabric-test holds the two synthetic messages ("[SYNTHETIC] Fabric message 1" by the
// owner, two hours before the clock's start, and "... message 2" by Ada, one hour before; their ts are `synthetic`), and #general a
// thread: "Welcome to #general" by Ada with two replies. IDS names every id.
//
// Messages, as the reference pages document them:
// - A ts is "<seconds>.<6 digits>", taken from the clock, unique and increasing. Lists order ts as numbers (BigInt), never as text, so
//   999999999.999999 is older than 1000000000.000000. A ts is always a string.
// - conversations.history: top-level messages (a thread's replies stay out), newest first; oldest, latest (exclusive unless inclusive) and
//   limit (1 to 999, default 100); cursor pages, with has_more and response_metadata.next_cursor ('' on the last page). A user token reads a
//   public channel it is not in; a private one it is not in answers channel_not_found. A parent carries thread_ts and reply_count.
// - conversations.replies: ts names the parent or any reply; the answer is the parent, then the replies oldest first. oldest, latest and
//   inclusive cut every message of the thread, the parent included (the reference: "the earliest messages in the time range are returned
//   first"); limit and cursor page. A ts that names no message answers thread_not_found. A reply carries thread_ts and parent_user_id.
// - chat.postMessage: channel is a channel or DM id (a user id posts into the DM with that person, as Slack does); text up to 40,000
//   characters (msg_too_long beyond), required unless blocks or attachments are given (no_text). channel_not_found, not_in_channel (a public
//   channel the owner is not in), is_archived. thread_ts must name a top-level message of the channel: none answers thread_not_found, and
//   a reply's ts cannot_reply_to_message (the reference: "use the parent's ts, not a reply's"; both words are the simulator's reading).
//   The text is stored exactly as sent. A post notifies people for each unescaped <!channel>, <!here>, <!everyone> or <@U...>; with
//   parse full, or link_names true, a plain @channel, @here or @everyone notifies too. Escaped text (&lt;!channel&gt;) notifies nobody.
// - chat.update: only the owner's own message (cant_update_message, nothing changed), message_not_found, edit_window_closed after
//   closeEditWindow(); text up to 4,000 characters (the method's own msg_too_long rule); text without blocks drops the blocks (the
//   reference), attachments stay unless [] (removed) or a new list (replaced). The message is marked edited.
// - chat.scheduleMessage: post_at is whole Unix seconds (a JSON integer or a string of digits; anything else invalid_time), after now
//   (time_in_past) and at most 120 days ahead (time_too_far beyond; exactly 120 days is taken). Answers scheduled_message_id (Q...) and
//   post_at. A message is listed by chat.scheduledMessages.list until it is deleted or due; once due it posts, as the owner, on the next
//   call. chat.deleteScheduledMessage answers invalid_scheduled_message_id for an id it does not hold in that channel, a second delete, or a
//   message due within 60 seconds (the reference).
// - reactions.add / reactions.remove take {channel, timestamp, name}: a known emoji name (no colons, lower case; a skin tone
//   ::skin-tone-2 to -6 may follow), else invalid_name; message_not_found; already_reacted and no_reaction change nothing. reactions.get
//   answers {type: 'message', channel, message: {..., reactions: [{name, users, count}]}}: count is everyone, users at most three (the
//   caller first) unless full, then everyone in the order they reacted.
// - conversations.open {users}: one person, the same D id every time (D followed by the user id without its U); the owner's own id opens
//   the self-DM. user_not_found, user_disabled (a deleted user), users_list_not_supplied; more than one person, or a channel to resume,
//   answers not_simulated. return_im true adds no_op, already_open and the channel's is_im and user.
// - users.list pages by cursor (limit 1 to 1,000; without one, everyone); users.info; users.lookupByEmail (any case; a deleted user or an
//   unknown address answers users_not_found). users.profile.get answers the owner's profile; a status whose expiration has passed reads
//   cleared. users.profile.set takes {profile} with status_text (up to 100 characters, else too_long), status_emoji (:name:, else
//   invalid_emoji_not_allowed) and status_expiration (whole seconds, 0 for never, else invalid_profile) only; any other field answers
//   not_simulated; `user` other than the owner answers not_admin; clearing one of the two text fields alone answers
//   must_clear_both_status_text_and_status_emoji. No profile is invalid_profile.
// - search.messages {query, count (1 to 100, default 20), page (1 to 100), sort (score or timestamp), sort_dir}: the query is read as
//   quoted phrases (each must appear, in order, any case), in:<#C...>, from:<@U...>, after:YYYY-MM-DD and before:YYYY-MM-DD (UTC days, the
//   day itself excluded) and bare words (each must appear). Only conversations the owner can read are searched. Matches carry channel {id,
//   name}, ts, user, username, text and permalink; paging {count, total, page, pages}. An empty query is no_query.
// - users.conversations {types (default public_channel), exclude_archived, limit, cursor}: the conversations the owner is in.
//   conversations.info {channel, include_num_members}. chat.getPermalink {channel, message_ts}: https://fabric-test.slack.com/archives/
//   <channel>/p<ts digits>, with ?thread_ts=<parent>&cid=<channel> for a reply. canvases.getContent {canvas_id, content_type}: the
//   markdown, in one string; canvas_not_found; html is not simulated.
// - rateLimit: true is Slack's limit for apps distributed outside the Marketplace: a second conversations.history, or a second
//   conversations.replies, within 60 seconds in the workspace answers HTTP 429 with Retry-After (the seconds left) and {ok: false, error:
//   'ratelimited'}, changing nothing. Each method is limited apart.
//
// The network contract is lib/network.mjs's seam: `request` takes its options and answers {status, headers, data}. Refused before
// sending, with sent false: a URL that is not https on 443 or carries credentials, an origin outside allowedOrigins or not Slack's, an
// unsupported method or response handling, an unsafe header, a body that is not a string or Buffer, a body over 1 MiB. After sending, with
// sent true: an answer over maxBytes, and drop(). A path on Slack's origin outside /api answers 404. Only the response headers asked for
// come back (the seam's default list when none are named).
//
// Every request that reaches the simulator is recorded in `calls`, without its Authorization header: {method, name (the Slack method, or
// null), url, query, headers, body, write, status, error, tokenArgument?}. writes() and reads() are the calls to write and read methods;
// state() is a copy of the state; notifications() the people Slack would have pinged. Switches, each for the next call to one method
// unless {times} says how many: fail(name, {status?, headers?, data}) answers that instead and changes nothing; drop(name) applies the call,
// then throws as a lost answer; swallow(name) answers as if applied but changes nothing; oversize(name, bytes) pads the answer;
// hold(name) returns {reached, release()}. Test data, never recorded as calls: seed(channel, {ts?, user?, text, threadTs?}) and
// post(channel, {user, text, threadTs?}) add someone's message and give its ts; edit(channel, ts, text) changes one; react(channel, ts,
// name, user) adds someone else's reaction; revokeScope(scope) takes a scope from the token; closeEditWindow() closes every edit;
// addPerson({id, name, realName, displayName?, email?, isBot?, deleted?}) and addChannel({id, name}) add a person and a public channel
// the owner is in (step 21 part 2).
import {Buffer} from 'node:buffer';

export const ORIGIN = 'https://slack.com';
export const BASE = `${ORIGIN}/api`;
/** Every id of the simulated workspace. */
export const IDS = Object.freeze({team: 'T0FABRIC1', owner: 'U0OWNER01', ada: 'U0ADA0001', grace: 'U0GRACE01', bot: 'U0BOT0001', gone: 'U0GONE001',
  general: 'C0GENERAL1', fabricTest: 'C0FABTEST1', private: 'G0PRIVATE1', others: 'C0OTHERS01', archived: 'C0ARCHIVE1', secret: 'G0SECRET01', selfDm: 'D0OWNER01',
  canvas: 'F0CANVAS01'});
const DOMAIN = 'fabric-test';
const DEFAULT_RESPONSE_HEADERS = ['content-type', 'etag', 'retry-after', 'x-ratelimit-remaining'];
const UNSAFE_HEADER = /^(host|connection|transfer-encoding|content-length|upgrade|proxy-.*|forwarded|x-forwarded-.*)$/i;
const DAY_SECONDS = 86_400, PACED = new Set(['conversations.history', 'conversations.replies']), PACE_MS = 60_000;
// Standard emoji names the simulator knows (a sample of Slack's list, enough for the actions' tests); a skin tone may follow some.
const EMOJI = new Set(['thumbsup', '+1', 'thumbsdown', '-1', 'white_check_mark', 'heavy_check_mark', 'x', 'eyes', 'tada', 'heart', 'rocket', 'raised_hands', 'smile', 'joy',
  'wave', 'pray', 'clap', 'fire', 'coffee', 'train', 'calendar', 'memo', 'hourglass']);
const STATUS_EMOJI = /^:[a-z0-9_+'-]{1,100}(?:::skin-tone-[2-6])?:$/;
const WRITES = new Set(['chat.postMessage', 'chat.update', 'chat.scheduleMessage', 'chat.deleteScheduledMessage', 'reactions.add', 'reactions.remove', 'conversations.open', 'users.profile.set']);
const READS = new Set(['users.conversations', 'conversations.info', 'conversations.history', 'conversations.replies', 'chat.getPermalink', 'chat.scheduledMessages.list', 'search.messages',
  'users.list', 'users.info', 'users.lookupByEmail', 'users.profile.get', 'reactions.get', 'canvases.getContent']);
const READ_SCOPE = {C: 'channels:read', G: 'groups:read', D: 'im:read'}, HISTORY_SCOPE = {C: 'channels:history', G: 'groups:history', D: 'im:history'};
const TYPE_SCOPE = {public_channel: 'channels:read', private_channel: 'groups:read', im: 'im:read', mpim: 'mpim:read'};
const FIXED_SCOPE = {'search.messages': 'search:read', 'users.list': 'users:read', 'users.info': 'users:read', 'users.lookupByEmail': 'users:read.email', 'users.profile.get': 'users.profile:read',
  'users.profile.set': 'users.profile:write', 'chat.postMessage': 'chat:write', 'chat.update': 'chat:write', 'chat.scheduleMessage': 'chat:write', 'chat.deleteScheduledMessage': 'chat:write',
  'reactions.add': 'reactions:write', 'reactions.remove': 'reactions:write', 'reactions.get': 'reactions:read', 'conversations.open': 'im:write', 'canvases.getContent': 'canvases:read'};

const notSent = message => Object.assign(new Error(message), {sent: false});
const lost = message => Object.assign(new Error(message), {sent: true});
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const done = (data = {}) => ({status: 200, data: {ok: true, ...data}});
const no = error => ({status: 200, data: {ok: false, error}});
/** A ts as one number of microseconds, so lists order it as Slack does. */
const tsKey = ts => { const [seconds, micros] = String(ts).split('.'); return BigInt(seconds) * 1_000_000n + BigInt((micros ?? '').padEnd(6, '0').slice(0, 6) || '0'); };
const TS = /^[0-9]{1,12}\.[0-9]{6}$/;
const newestFirst = (a, b) => (tsKey(a.ts) < tsKey(b.ts) ? 1 : tsKey(a.ts) > tsKey(b.ts) ? -1 : 0);
const oldestFirst = (a, b) => -newestFirst(a, b);
const truthy = value => value === true || value === 'true' || value === 1 || value === '1';
/** A whole number from a JSON number or a string of digits; null for anything else. */
const whole = value => Number.isSafeInteger(value) ? value : typeof value === 'string' && /^-?[0-9]{1,15}$/.test(value) ? Number(value) : null;
const cursorOf = index => Buffer.from(`next:${index}`).toString('base64');
function startOf(cursor) {
  if (cursor === undefined || cursor === '') return 0;
  const match = /^next:([0-9]{1,6})$/.exec(Buffer.from(String(cursor), 'base64').toString('utf8'));
  return match ? Number(match[1]) : null;
}
/** One page of a list: {items, next} with next '' on the last page, or null for a cursor this list never gave. */
function pageOf(list, {cursor, limit}) {
  const start = startOf(cursor);
  if (start === null || start > list.length) return null;
  const end = limit === null ? list.length : start + limit;
  return {items: list.slice(start, end), next: end < list.length ? cursorOf(end) : ''};
}
/** True when a `token` argument sits anywhere in the arguments. */
const holdsToken = value => Array.isArray(value) ? value.some(holdsToken) : record(value) && Object.entries(value).some(([key, item]) => key === 'token' || holdsToken(item));
const dayStart = day => { const match = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/.exec(day); return match ? Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3])) / 1000 : null; };

function person(id, name, realName, display, email, extra = {}) {
  return {id, team_id: IDS.team, name, real_name: realName, deleted: false, is_bot: false, profile: {real_name: realName, display_name: display, email, status_text: '', status_emoji: '', status_expiration: 0}, ...extra};
}
function initialState(owner, start) {
  const people = [person(owner.id, owner.name, 'Fabric Owner', 'owner', 'owner@example.com'), person(IDS.ada, 'ada', 'Ada Lovelace', 'ada', 'ada@example.com'),
    person(IDS.grace, 'grace', 'Grace Hopper', 'grace', 'grace@example.com'), person(IDS.bot, 'fabric-bot', 'Fabric Bot', 'fabric-bot', undefined, {is_bot: true}),
    person(IDS.gone, 'gone', 'Former Member', 'gone', 'gone@example.com', {deleted: true})];
  const channel = (id, name, members, extra = {}) => ({id, name, is_private: id.startsWith('G'), is_im: false, is_archived: false, members, messages: [], ...extra});
  return {
    team: {id: owner.teamId, domain: DOMAIN}, owner: owner.id, people,
    channels: Object.fromEntries([channel(IDS.general, 'general', [owner.id, IDS.ada, IDS.grace]), channel(IDS.fabricTest, 'fabric-test', [owner.id, IDS.ada]),
      channel(IDS.private, 'fabric-private', [owner.id]), channel(IDS.others, 'others', [IDS.ada]), channel(IDS.archived, 'old-news', [owner.id], {is_archived: true}),
      channel(IDS.secret, 'secret', [IDS.ada]), channel(IDS.selfDm, owner.id, [owner.id], {is_im: true, user: owner.id})].map(item => [item.id, item])),
    scheduled: [], canvases: {[IDS.canvas]: {id: IDS.canvas, title: '[SYNTHETIC] Fabric canvas', content: '# [SYNTHETIC] Fabric canvas\n\nA canvas Fabric reads in its tests.\n'}},
    notifications: [], editWindowOpen: true, created: start,
  };
}

export class SlackSimulator {
  /** clock() gives the time ts values and statuses read; token is the bearer token; owner {id, teamId, name}; scopes the token's scopes. */
  constructor({clock = () => Date.parse('2026-10-26T15:00:00.000Z'), token = 'xoxp-slack-simulator-token', owner = {id: IDS.owner, teamId: IDS.team, name: 'owner'}, scopes = [], rateLimit = false} = {}) {
    this.clock = clock;
    this.token = token;
    this.scopes = [...scopes];
    this.rateLimit = rateLimit === true;
    this.calls = [];
    this.switches = new Map();
    this.holds = new Map();
    this.paced = new Map();
    this.lastTs = 0n;
    this.scheduledCount = 0;
    this.data = initialState({id: owner.id, teamId: owner.teamId, name: owner.name}, clock());
    const start = clock();
    this.seed(IDS.general, {ts: this.#tsAt(start - DAY_SECONDS * 1000), user: IDS.ada, text: 'Welcome to #general'});
    const welcome = this.data.channels[IDS.general].messages[0].ts;
    this.seed(IDS.general, {ts: this.#tsAt(start - DAY_SECONDS * 1000 + 60_000), user: IDS.grace, text: 'Thanks', threadTs: welcome});
    this.seed(IDS.general, {ts: this.#tsAt(start - DAY_SECONDS * 1000 + 120_000), user: owner.id, text: 'Hello', threadTs: welcome});
    this.synthetic = Object.freeze({one: this.seed(IDS.fabricTest, {ts: this.#tsAt(start - 7_200_000), user: owner.id, text: '[SYNTHETIC] Fabric message 1'}),
      two: this.seed(IDS.fabricTest, {ts: this.#tsAt(start - 3_600_000), user: IDS.ada, text: '[SYNTHETIC] Fabric message 2'})});
    this.request = this.request.bind(this);
  }
  state() { return structuredClone(this.data); }
  writes() { return this.calls.filter(call => call.write); }
  reads() { return this.calls.filter(call => call.name !== null && READS.has(call.name)); }
  notifications() { return structuredClone(this.data.notifications); }
  revokeScope(scope) { this.scopes = this.scopes.filter(item => item !== scope); return this; }
  closeEditWindow() { this.data.editWindowOpen = false; return this; }
  #switch(kind, name, extra = {}, {times = 1} = {}) {
    if (!Number.isSafeInteger(times) && times !== Infinity) throw new Error('times is a whole number or Infinity.');
    this.switches.set(name, {kind, left: times, ...extra});
    return this;
  }
  fail(name, answer, options) { return this.#switch('fail', name, {answer: structuredClone(answer)}, options); }
  drop(name, options) { return this.#switch('drop', name, {}, options); }
  swallow(name, options) { return this.#switch('swallow', name, {}, options); }
  oversize(name, bytes, options) { return this.#switch('oversize', name, {bytes}, options); }
  hold(name) {
    let reach, release;
    const reached = new Promise(resolve => { reach = resolve; }), released = new Promise(resolve => { release = resolve; });
    this.holds.set(name, {reached, released, reach, release: () => { this.holds.delete(name); release(); }});
    return {reached, release: this.holds.get(name).release};
  }
  #take(name) {
    const entry = this.switches.get(name);
    if (!entry) return null;
    if (--entry.left <= 0) this.switches.delete(name);
    return entry;
  }

  // ---- test data ------------------------------------------------------------------------------------------------------------------------
  /** A ts for a moment, unique and later than every ts made before it. */
  #tsAt(ms) {
    let key = BigInt(Math.floor(ms)) * 1000n;
    if (key <= this.lastTs) key = this.lastTs + 1n;
    this.lastTs = key;
    return `${key / 1_000_000n}.${String(key % 1_000_000n).padStart(6, '0')}`;
  }
  #nextTs() { return this.#tsAt(this.clock()); }
  /** Adds a message to a channel without a call; a given ts is used as it is. Returns its ts. */
  seed(channel, {ts, user = IDS.ada, text, threadTs} = {}) {
    const target = this.data.channels[channel];
    if (!target) throw new Error(`No channel ${channel}.`);
    const stamp = ts ?? this.#nextTs();
    if (!TS.test(stamp)) throw new Error('A ts is <seconds>.<6 digits>.');
    if (tsKey(stamp) > this.lastTs) this.lastTs = tsKey(stamp);
    target.messages.push({type: 'message', ts: stamp, user, text, reactions: [], ...(threadTs ? {thread_ts: threadTs} : {})});
    return stamp;
  }
  /** Someone else posts now. */
  post(channel, {user, text, threadTs} = {}) { return this.seed(channel, {user, text, threadTs}); }
  /** Someone (or Slack) changes a message's text. */
  edit(channel, ts, text) { const message = this.#message(this.data, channel, ts); if (!message) throw new Error('No such message.'); message.text = text; message.edited = {user: message.user, ts: this.#nextTs()}; return this; }
  /** Someone else reacts. */
  react(channel, ts, name, user) {
    const message = this.#message(this.data, channel, ts);
    if (!message) throw new Error('No such message.');
    const reaction = message.reactions.find(item => item.name === name) ?? (message.reactions.push({name, users: []}), message.reactions.at(-1));
    if (!reaction.users.includes(user)) reaction.users.push(user);
    return this;
  }
  #message(state, channel, ts) { return state.channels[channel]?.messages.find(item => item.ts === ts) ?? null; }
  /** Someone joins the workspace (F10.21 part 2: a second person with the same name). */
  addPerson({id, name, realName, displayName = name, email, isBot = false, deleted = false}) {
    if (this.data.people.some(item => item.id === id)) throw new Error(`${id} is taken.`);
    this.data.people.push(person(id, name, realName, displayName, email, {is_bot: isBot, deleted}));
    return this;
  }
  /** A public channel the owner is in (F10.21 part 2: more conversations than one page holds). */
  addChannel({id, name}) {
    if (this.data.channels[id]) throw new Error(`${id} is taken.`);
    this.data.channels[id] = {id, name, is_private: false, is_im: false, is_archived: false, members: [this.data.owner], messages: []};
    return this;
  }

  // ---- the methods ----------------------------------------------------------------------------------------------------------------------
  #person(state, id) { return state.people.find(item => item.id === id) ?? null; }
  #canRead(state, channel) { return channel.members.includes(state.owner) || (!channel.is_private && !channel.is_im); }
  /** Channel arguments that name a user post to the DM with that person, as Slack does for chat.postMessage. */
  #channelArg(state, value) {
    if (typeof value === 'string' && /^[UW]/.test(value) && this.#person(state, value)) return this.#dm(state, value);
    return state.channels[value] ?? null;
  }
  #dm(state, user) {
    const id = user === state.owner ? IDS.selfDm : `D${user.slice(1)}`;
    state.channels[id] ??= {id, name: user, is_private: true, is_im: true, is_archived: false, user, members: [state.owner, user], messages: []};
    return state.channels[id];
  }
  #shown(message, channel) {
    const replies = channel.messages.filter(item => item.thread_ts === message.ts && item.ts !== message.ts);
    const parent = message.thread_ts && message.thread_ts !== message.ts ? channel.messages.find(item => item.ts === message.thread_ts) : null;
    return {type: 'message', user: message.user, text: message.text, ts: message.ts,
      ...(replies.length ? {thread_ts: message.ts, reply_count: replies.length, latest_reply: replies.sort(oldestFirst).at(-1).ts} : {}),
      ...(parent ? {thread_ts: parent.ts, parent_user_id: parent.user} : {}), ...(message.edited ? {edited: message.edited} : {}),
      ...(message.reactions.length ? {reactions: message.reactions.map(item => ({name: item.name, users: [...item.users], count: item.users.length}))} : {})};
  }
  #permalink(state, channel, message) {
    const digits = message.ts.replace('.', '');
    const thread = message.thread_ts && message.thread_ts !== message.ts ? `?thread_ts=${message.thread_ts}&cid=${channel.id}` : '';
    return `https://${state.team.domain}.slack.com/archives/${channel.id}/p${digits}${thread}`;
  }
  #window(list, args) {
    const inclusive = truthy(args.inclusive), oldest = args.oldest !== undefined ? tsKey(args.oldest) : null, latest = args.latest !== undefined ? tsKey(args.latest) : null;
    return list.filter(item => {
      const key = tsKey(item.ts);
      return (oldest === null || (inclusive ? key >= oldest : key > oldest)) && (latest === null || (inclusive ? key <= latest : key < latest));
    });
  }
  #limit(value, max, fallback) { if (value === undefined) return fallback; const limit = whole(value); return limit !== null && limit >= 1 && limit <= max ? limit : undefined; }
  /** Posts every scheduled message whose time has come. */
  #deliver(state) {
    const now = Math.floor(this.clock() / 1000);
    for (const item of state.scheduled.filter(entry => entry.post_at <= now)) {
      state.scheduled.splice(state.scheduled.indexOf(item), 1);
      state.channels[item.channel_id].messages.push({type: 'message', ts: this.#nextTs(), user: state.owner, text: item.text, reactions: []});
    }
  }
  #notify(state, channel, ts, text, {parse, linkNames}) {
    for (const match of text.matchAll(/<!(channel|here|everyone)(?:\|[^>]*)?>|<@([UW][A-Z0-9]{2,20})(?:\|[^>]*)?>/g)) {
      state.notifications.push(match[1] ? {kind: match[1], channel, ts} : {kind: 'user', channel, ts, user: match[2]});
    }
    if (parse === 'full' || linkNames === true) for (const match of text.matchAll(/(?:^|[^<!@\w])@(channel|here|everyone)\b/g)) state.notifications.push({kind: match[1], channel, ts});
  }

  #methods = {
    'users.conversations': ({state, args}) => {
      const types = String(args.types ?? 'public_channel').split(','), limit = this.#limit(args.limit, 999, 100);
      if (limit === undefined || types.some(type => !TYPE_SCOPE[type])) return no(limit === undefined ? 'invalid_limit' : 'invalid_types');
      const kind = channel => channel.is_im ? 'im' : channel.is_private ? 'private_channel' : 'public_channel';
      const list = Object.values(state.channels).filter(channel => channel.members.includes(state.owner) && types.includes(kind(channel)) && !(truthy(args.exclude_archived) && channel.is_archived));
      const page = pageOf(list, {cursor: args.cursor, limit});
      if (!page) return no('invalid_cursor');
      return done({channels: page.items.map(channel => ({id: channel.id, name: channel.name, is_channel: !channel.is_private && !channel.is_im, is_group: channel.is_private && !channel.is_im,
        is_im: channel.is_im, is_mpim: false, is_private: channel.is_private, is_archived: channel.is_archived, ...(channel.is_im ? {user: channel.user} : {})})), response_metadata: {next_cursor: page.next}});
    },
    'conversations.info': ({state, args}) => {
      const channel = state.channels[args.channel];
      if (!channel || !this.#canRead(state, channel)) return no('channel_not_found');
      return done({channel: {id: channel.id, name: channel.name, is_channel: !channel.is_private && !channel.is_im, is_private: channel.is_private, is_im: channel.is_im, is_archived: channel.is_archived,
        is_member: channel.members.includes(state.owner), ...(channel.is_im ? {user: channel.user} : {}), ...(truthy(args.include_num_members) ? {num_members: channel.members.length} : {})}});
    },
    'conversations.history': ({state, args}) => {
      const channel = state.channels[args.channel], limit = this.#limit(args.limit, 999, 100);
      if (!channel || !this.#canRead(state, channel)) return no('channel_not_found');
      if (limit === undefined) return no('invalid_limit');
      const top = this.#window(channel.messages.filter(item => !item.thread_ts || item.thread_ts === item.ts), args).sort(newestFirst);
      const page = pageOf(top, {cursor: args.cursor, limit});
      if (!page) return no('invalid_cursor');
      return done({messages: page.items.map(item => this.#shown(item, channel)), has_more: page.next !== '', pin_count: 0, response_metadata: {next_cursor: page.next}});
    },
    'conversations.replies': ({state, args}) => {
      const channel = state.channels[args.channel], limit = this.#limit(args.limit, 1000, 1000);
      if (!channel || !this.#canRead(state, channel)) return no('channel_not_found');
      if (limit === undefined) return no('invalid_limit');
      const named = typeof args.ts === 'string' ? channel.messages.find(item => item.ts === args.ts) : null;
      if (!named) return no('thread_not_found');
      const root = named.thread_ts && named.thread_ts !== named.ts ? channel.messages.find(item => item.ts === named.thread_ts) : named;
      const thread = [root, ...channel.messages.filter(item => item.thread_ts === root.ts && item.ts !== root.ts).sort(oldestFirst)];
      const page = pageOf(this.#window(thread, args), {cursor: args.cursor, limit});
      if (!page) return no('invalid_cursor');
      return done({messages: page.items.map(item => this.#shown(item, channel)), has_more: page.next !== '', response_metadata: {next_cursor: page.next}});
    },
    'chat.getPermalink': ({state, args}) => {
      const channel = state.channels[args.channel];
      if (!channel || !this.#canRead(state, channel)) return no('channel_not_found');
      const message = channel.messages.find(item => item.ts === args.message_ts);
      return message ? done({channel: channel.id, permalink: this.#permalink(state, channel, message)}) : no('message_not_found');
    },
    'chat.scheduledMessages.list': ({state, args}) => {
      if (args.channel !== undefined && !state.channels[args.channel]) return no('invalid_channel');
      const list = state.scheduled.filter(item => args.channel === undefined || item.channel_id === args.channel);
      return done({scheduled_messages: list.map(item => ({id: item.id, channel_id: item.channel_id, post_at: item.post_at, date_created: item.date_created, text: item.text})), response_metadata: {next_cursor: ''}});
    },
    'search.messages': ({state, args}) => {
      const query = typeof args.query === 'string' ? args.query.trim() : '';
      if (!query) return no('no_query');
      const count = this.#limit(args.count, 100, 20), pageNumber = this.#limit(args.page, 100, 1);
      if (count === undefined || pageNumber === undefined) return no('invalid_arguments');
      const parsed = parseQuery(query);
      if (!parsed) return no('invalid_arguments');
      const fold = text => text.toLowerCase();
      const matches = [];
      for (const channel of Object.values(state.channels)) {
        if (!this.#canRead(state, channel) || (parsed.in && channel.id !== parsed.in)) continue;
        for (const message of channel.messages) {
          const seconds = Number(tsKey(message.ts) / 1_000_000n), text = fold(message.text);
          if ((parsed.from && message.user !== parsed.from) || (parsed.after !== null && seconds < parsed.after + DAY_SECONDS) || (parsed.before !== null && seconds >= parsed.before)) continue;
          if (!parsed.phrases.every(phrase => text.includes(fold(phrase))) || !parsed.words.every(word => text.includes(fold(word)))) continue;
          matches.push({type: 'message', channel: {id: channel.id, name: channel.name}, ts: message.ts, user: message.user, username: this.#person(state, message.user)?.name ?? '',
            text: message.text, permalink: this.#permalink(state, channel, message)});
        }
      }
      matches.sort(newestFirst);
      if ((args.sort === 'timestamp' && args.sort_dir === 'asc')) matches.reverse();
      const pages = Math.max(1, Math.ceil(matches.length / count)), start = (pageNumber - 1) * count;
      return done({query, messages: {matches: matches.slice(start, start + count), paging: {count, total: matches.length, page: pageNumber, pages}, total: matches.length}});
    },
    'users.list': ({state, args}) => {
      const limit = this.#limit(args.limit, 1000, null);
      if (limit === undefined) return no('invalid_limit');
      const page = pageOf(state.people, {cursor: args.cursor, limit});
      if (!page) return no('invalid_cursor');
      return done({members: page.items.map(item => this.#user(item)), response_metadata: {next_cursor: page.next}});
    },
    'users.info': ({state, args}) => { const found = this.#person(state, args.user); return found ? done({user: this.#user(found)}) : no('user_not_found'); },
    'users.lookupByEmail': ({state, args}) => {
      const wanted = typeof args.email === 'string' ? args.email.toLowerCase() : null;
      const found = state.people.find(item => !item.deleted && typeof item.profile.email === 'string' && item.profile.email.toLowerCase() === wanted);
      return found ? done({user: this.#user(found)}) : no('users_not_found');
    },
    'users.profile.get': ({state, args}) => {
      const found = this.#person(state, args.user ?? state.owner);
      if (!found) return no('user_not_found');
      this.#expire(found);
      return done({profile: this.#profile(found)});
    },
    'users.profile.set': ({state, args}) => {
      if (args.user !== undefined && args.user !== state.owner) return no('not_admin');
      const profile = args.profile;
      if (!record(profile)) return no('invalid_profile');
      if (Object.keys(profile).some(key => !['status_text', 'status_emoji', 'status_expiration'].includes(key))) return no('not_simulated');
      if (profile.status_text !== undefined && (typeof profile.status_text !== 'string' || [...profile.status_text].length > 100)) return no('too_long');
      const clears = ['status_text', 'status_emoji'].filter(key => profile[key] === ''), sets = ['status_text', 'status_emoji'].filter(key => profile[key] !== undefined && profile[key] !== '');
      if (clears.length === 1 && sets.length === 0 && Object.keys(profile).filter(key => key !== 'status_expiration').length === 1) return no('must_clear_both_status_text_and_status_emoji');
      if (profile.status_emoji !== undefined && profile.status_emoji !== '' && !(typeof profile.status_emoji === 'string' && STATUS_EMOJI.test(profile.status_emoji))) return no('invalid_emoji_not_allowed');
      if (profile.status_expiration !== undefined && (whole(profile.status_expiration) === null || whole(profile.status_expiration) < 0)) return no('invalid_profile');
      const owner = this.#person(state, state.owner);
      for (const key of ['status_text', 'status_emoji']) if (profile[key] !== undefined) owner.profile[key] = profile[key];
      if (profile.status_expiration !== undefined) owner.profile.status_expiration = whole(profile.status_expiration);
      return done({profile: this.#profile(owner), username: owner.name});
    },
    'chat.postMessage': ({state, args}) => {
      const channel = this.#channelArg(state, args.channel);
      if (!channel || !this.#canRead(state, channel)) return no('channel_not_found');
      if (!channel.members.includes(state.owner)) return no('not_in_channel');
      if (channel.is_archived) return no('is_archived');
      const text = args.text;
      if ((typeof text !== 'string' || text === '') && !Array.isArray(args.blocks) && !Array.isArray(args.attachments)) return no('no_text');
      if (typeof text === 'string' && text.length > 40_000) return no('msg_too_long');
      if (args.thread_ts !== undefined) {
        const parent = channel.messages.find(item => item.ts === args.thread_ts);
        if (!parent) return no('thread_not_found');
        if (parent.thread_ts && parent.thread_ts !== parent.ts) return no('cannot_reply_to_message');
      }
      const ts = this.#nextTs(), message = {type: 'message', ts, user: state.owner, text: typeof text === 'string' ? text : '', reactions: [],
        ...(args.thread_ts !== undefined ? {thread_ts: args.thread_ts} : {}), ...(Array.isArray(args.blocks) ? {blocks: structuredClone(args.blocks)} : {}),
        ...(Array.isArray(args.attachments) && args.attachments.length ? {attachments: structuredClone(args.attachments)} : {}), ...(truthy(args.reply_broadcast) ? {reply_broadcast: true} : {})};
      channel.messages.push(message);
      this.#notify(state, channel.id, ts, message.text, {parse: args.parse, linkNames: args.link_names === true || args.link_names === 'true' || args.link_names === 1});
      return done({channel: channel.id, ts, message: {type: 'message', user: state.owner, text: message.text, ts, ...(message.thread_ts ? {thread_ts: message.thread_ts} : {})}});
    },
    'chat.update': ({state, args}) => {
      const channel = state.channels[args.channel];
      if (!channel || !this.#canRead(state, channel)) return no('channel_not_found');
      const message = channel.messages.find(item => item.ts === args.ts);
      if (!message) return no('message_not_found');
      if (message.user !== state.owner) return no('cant_update_message');
      if (!state.editWindowOpen) return no('edit_window_closed');
      const text = args.text;
      if ((typeof text !== 'string' || text === '') && !Array.isArray(args.blocks) && !Array.isArray(args.attachments)) return no('no_text');
      if (typeof text === 'string' && text.length > 4000) return no('msg_too_long');
      if (typeof text === 'string') message.text = text;
      if (Array.isArray(args.blocks)) { if (args.blocks.length) message.blocks = structuredClone(args.blocks); else delete message.blocks; }
      else if (typeof text === 'string') delete message.blocks;
      if (Array.isArray(args.attachments)) { if (args.attachments.length) message.attachments = structuredClone(args.attachments); else delete message.attachments; }
      message.edited = {user: state.owner, ts: this.#nextTs()};
      return done({channel: channel.id, ts: message.ts, text: message.text, message: {text: message.text, user: message.user}});
    },
    'chat.scheduleMessage': ({state, args}) => {
      const channel = this.#channelArg(state, args.channel);
      if (!channel || !this.#canRead(state, channel)) return no('channel_not_found');
      if (!channel.members.includes(state.owner)) return no('not_in_channel');
      if (channel.is_archived) return no('is_archived');
      const postAt = whole(args.post_at), now = Math.floor(this.clock() / 1000);
      if (postAt === null) return no('invalid_time');
      if (postAt <= now) return no('time_in_past');
      if (postAt > now + 120 * DAY_SECONDS) return no('time_too_far');
      if (typeof args.text !== 'string' || args.text === '') return no('no_text');
      if (args.text.length > 40_000) return no('msg_too_long');
      const id = `Q${String(++this.scheduledCount).padStart(9, '0')}`;
      state.scheduled.push({id, channel_id: channel.id, post_at: postAt, date_created: now, text: args.text});
      return done({channel: channel.id, scheduled_message_id: id, post_at: postAt, message: {type: 'message', user: state.owner, text: args.text}});
    },
    'chat.deleteScheduledMessage': ({state, args}) => {
      const item = state.scheduled.find(entry => entry.id === args.scheduled_message_id && entry.channel_id === args.channel);
      if (!state.channels[args.channel]) return no('channel_not_found');
      if (!item || item.post_at - Math.floor(this.clock() / 1000) <= 60) return no('invalid_scheduled_message_id');
      state.scheduled.splice(state.scheduled.indexOf(item), 1);
      return done();
    },
    'reactions.add': ({state, args}) => this.#reaction(state, args, true),
    'reactions.remove': ({state, args}) => this.#reaction(state, args, false),
    'reactions.get': ({state, args}) => {
      const channel = state.channels[args.channel];
      if (!channel || !this.#canRead(state, channel)) return no('channel_not_found');
      const message = channel.messages.find(item => item.ts === args.timestamp);
      if (!message) return no('message_not_found');
      const full = truthy(args.full), shown = this.#shown(message, channel);
      const reactions = message.reactions.map(item => {
        const users = full ? [...item.users] : [...(item.users.includes(state.owner) ? [state.owner] : []), ...item.users.filter(user => user !== state.owner)].slice(0, 3);
        return {name: item.name, users, count: item.users.length};
      });
      return done({type: 'message', channel: channel.id, message: {...shown, ...(reactions.length ? {reactions} : {}), permalink: this.#permalink(state, channel, message)}});
    },
    'conversations.open': ({state, args}) => {
      if (args.channel !== undefined) return no('not_simulated');
      if (typeof args.users !== 'string' || args.users === '') return no('users_list_not_supplied');
      if (args.users.includes(',')) return no('not_simulated');
      const found = this.#person(state, args.users);
      if (!found) return no('user_not_found');
      if (found.deleted) return no('user_disabled');
      const id = found.id === state.owner ? IDS.selfDm : `D${found.id.slice(1)}`, already = Boolean(state.channels[id]), dm = this.#dm(state, found.id);
      return done(truthy(args.return_im) ? {no_op: already, already_open: already, channel: {id: dm.id, is_im: true, user: found.id}} : {channel: {id: dm.id}});
    },
    'canvases.getContent': ({state, args}) => {
      const canvas = state.canvases[args.canvas_id];
      if (!canvas) return no('canvas_not_found');
      if (args.content_type !== undefined && args.content_type !== 'markdown') return no('not_simulated');
      return done({content: canvas.content});
    },
  };
  #user(found) {
    const {email, ...profile} = found.profile;
    return {...structuredClone(found), profile: {...structuredClone(profile), ...(email !== undefined && this.scopes.includes('users:read.email') ? {email} : {})}};
  }
  #profile(found) { return this.#user(found).profile; }
  #expire(found) {
    const until = found.profile.status_expiration;
    if (until > 0 && until <= Math.floor(this.clock() / 1000)) Object.assign(found.profile, {status_text: '', status_emoji: '', status_expiration: 0});
  }
  #reaction(state, args, add) {
    const channel = state.channels[args.channel];
    if (!channel || !this.#canRead(state, channel)) return no('channel_not_found');
    const message = channel.messages.find(item => item.ts === args.timestamp);
    if (!message) return no('message_not_found');
    const name = typeof args.name === 'string' ? args.name : '', [base, tone] = name.split('::');
    if (!EMOJI.has(base) || (tone !== undefined && !/^skin-tone-[2-6]$/.test(tone))) return no('invalid_name');
    const reaction = message.reactions.find(item => item.name === name);
    if (add) {
      if (reaction?.users.includes(state.owner)) return no('already_reacted');
      if (reaction) reaction.users.push(state.owner); else message.reactions.push({name, users: [state.owner]});
      return done();
    }
    if (!reaction?.users.includes(state.owner)) return no('no_reaction');
    reaction.users = reaction.users.filter(user => user !== state.owner);
    if (!reaction.users.length) message.reactions.splice(message.reactions.indexOf(reaction), 1);
    return done();
  }
  /** The scope a call needs, or null for none. The history and read scopes depend on the channel's type; an unknown channel needs none here. */
  #needs(state, name, args) {
    if (FIXED_SCOPE[name]) return FIXED_SCOPE[name];
    if (name === 'users.conversations') return String(args.types ?? 'public_channel').split(',').map(type => TYPE_SCOPE[type]).find(scope => scope && !this.scopes.includes(scope)) ?? null;
    const kind = typeof args.channel === 'string' ? args.channel[0] : null;
    if (name === 'conversations.info' && state.channels[args.channel]) return READ_SCOPE[kind] ?? null;
    if (PACED.has(name) && state.channels[args.channel]) return HISTORY_SCOPE[kind] ?? null;
    return null;
  }

  async request({url, method = 'GET', headers = {}, body, allowedOrigins, maxBytes = 2 * 1024 * 1024, responseType = 'json', redirect = 'error', responseHeaders = DEFAULT_RESPONSE_HEADERS, timeoutMs = 15000}) {
    let target;
    try { target = new URL(url); } catch { throw notSent('Invalid request URL.'); }
    if (target.protocol !== 'https:' || target.username || target.password || target.hash || (target.port && target.port !== '443')) throw notSent('Only credential-free HTTPS URLs on port 443 are allowed.');
    if (!Array.isArray(allowedOrigins) || !allowedOrigins.includes(target.origin)) throw notSent('Request origin is outside the connection grant.');
    if (!['json', 'buffer'].includes(responseType) || !['error', 'report'].includes(redirect) || !Array.isArray(responseHeaders)) throw notSent('Unsupported response handling.');
    if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000 || !Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 10 * 1024 * 1024) throw notSent('Invalid request limits.');
    if (!/^(GET|POST)$/.test(method)) throw notSent('Unsupported HTTP method.');
    const lower = {};
    for (const [name, value] of Object.entries(headers)) {
      if (UNSAFE_HEADER.test(name) || !/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(name) || typeof value !== 'string' || /[\r\n]/.test(value)) throw notSent('Unsafe request header.');
      lower[name.toLowerCase()] = value;
    }
    if (body !== undefined && !(typeof body === 'string' || Buffer.isBuffer(body))) throw notSent('Request body must be serialized.');
    if (body !== undefined && Buffer.byteLength(body) > 1024 * 1024) throw notSent('Request body is too large.');
    if (target.origin !== ORIGIN) throw notSent('Provider DNS lookup failed or timed out.');
    // Sent from here on: the call is recorded, without its Authorization header.
    const name = /^\/api\/([a-zA-Z.]+)$/.exec(target.pathname)?.[1] ?? null, text = body === undefined ? undefined : Buffer.isBuffer(body) ? body.toString('utf8') : body;
    const json = /^application\/json\b/i.test(lower['content-type'] ?? '');
    let parsed = null;
    if (text !== undefined) { try { parsed = JSON.parse(text); } catch { parsed = text; } }
    const query = Object.fromEntries(target.searchParams);
    const {authorization, ...kept} = lower;
    const call = {method, name, url: target.href, query, headers: kept, body: parsed, write: WRITES.has(name), status: null, error: null};
    this.calls.push(call);
    const gate = name ? this.holds.get(name) : null;
    if (gate) { gate.reach(); await gate.released; }
    const answer = this.#answer({call, name, method, authorization, query, parsed, text, json});
    call.status = answer.status;
    call.error = answer.data?.ok === false ? answer.data.error : null;
    const headersOut = Object.fromEntries(Object.entries(answer.headers ?? {}).map(([key, value]) => [key.toLowerCase(), String(value)]));
    const bytes = answer.data === null || answer.data === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(answer.data), 'utf8');
    if (answer.lost) throw lost('Provider connection failed.');
    if (bytes.length > maxBytes) throw lost('Provider response exceeded the size limit.');
    if (bytes.length) headersOut['content-type'] ??= 'application/json; charset=utf-8';
    const shown = {};
    for (const key of responseHeaders) if (headersOut[key] !== undefined) shown[key] = headersOut[key];
    return {status: answer.status, headers: shown, data: responseType === 'buffer' ? bytes : bytes.length ? JSON.parse(bytes.toString('utf8')) : null};
  }
  #answer({call, name, method, authorization, query, parsed, text, json}) {
    if (name === null) return {status: 404, data: {ok: false, error: 'not_found'}};
    if (!authorization) return no('not_authed');
    if (authorization !== `Bearer ${this.token}`) return no('invalid_auth');
    if (holdsToken(query) || holdsToken(parsed)) { call.tokenArgument = true; return no('token_argument'); }
    if (method === 'POST' && text !== undefined && (!json || !record(parsed))) return no('invalid_form_data');
    const handle = this.#methods[name];
    if (!handle) return no('unknown_method');
    const args = method === 'GET' ? query : record(parsed) ? parsed : {};
    const needed = this.#needs(this.data, name, args);
    if (needed && !this.scopes.includes(needed)) return {status: 200, data: {ok: false, error: 'missing_scope', needed, provided: this.scopes.join(',')}};
    if (this.rateLimit && PACED.has(name)) {
      const last = this.paced.get(name), now = this.clock();
      if (last !== undefined && now - last < PACE_MS) return {status: 429, headers: {'retry-after': String(Math.ceil((last + PACE_MS - now) / 1000))}, data: {ok: false, error: 'ratelimited'}};
      this.paced.set(name, now);
    }
    this.#deliver(this.data);
    const chosen = this.#take(name);
    if (chosen?.kind === 'fail') return {status: chosen.answer.status ?? 200, headers: chosen.answer.headers ?? {}, data: structuredClone(chosen.answer.data)};
    const state = chosen?.kind === 'swallow' ? structuredClone(this.data) : this.data;
    let answer = handle({state, args});
    if (chosen?.kind === 'drop') answer = {...answer, lost: true};
    if (chosen?.kind === 'oversize') answer = {...answer, data: {...answer.data, padding: 'x'.repeat(Math.max(0, chosen.bytes))}};
    return answer;
  }
}

/** A search query read as phrases, words, in:, from:, after: and before:; null for one this simulator does not read. */
function parseQuery(query) {
  const out = {phrases: [], words: [], in: null, from: null, after: null, before: null};
  const tokens = query.match(/"[^"]*"|\S+/g) ?? [];
  for (const token of tokens) {
    let match;
    if (token.startsWith('"')) { if (token.length < 2 || !token.endsWith('"')) return null; out.phrases.push(token.slice(1, -1)); }
    else if ((match = /^in:<#([CGD][A-Z0-9]{2,20})(?:\|[^>]*)?>$/.exec(token))) out.in = match[1];
    else if ((match = /^from:<@([UW][A-Z0-9]{2,20})(?:\|[^>]*)?>$/.exec(token))) out.from = match[1];
    else if ((match = /^(after|before):([0-9]{4}-[0-9]{2}-[0-9]{2})$/.exec(token))) { const start = dayStart(match[2]); if (start === null) return null; out[match[1]] = start; }
    else out.words.push(token);
  }
  return out;
}

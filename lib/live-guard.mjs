// F10.12 part 1 (docs/F10.12-BUILD-MAP.md part 1): the live guard. A certification Fabric (lib/certification.mjs) sends every outgoing
// request through wrap(), so the guard reads the exact bytes at the network seam and refuses anything outside the owner's test areas before
// it leaves the machine: a refusal is `action_refused` with details {reason: 'live_guard', rule} and `sent: false`, so a job it stops ends
// "failed, nothing changed". Sign-in traffic passes at any time and is never traced. Everything else passes only inside a test, only on a
// method and path the app's allowlist names, and only with synthetic text. Counters, created ids and the trace live in a file beside the run
// state, so a restart keeps them. Only the harness imports this file; nothing in server.mjs does.
import {createHmac, randomBytes} from 'node:crypto';
import {chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync} from 'node:fs';
import path from 'node:path';
import {definitionFor, reviewedProviderIds} from './providers/definitions.mjs';
import {INTROSPECTION} from './providers/oauth2.mjs';

/** The caps of one run. */
export const LIMITS = Object.freeze({testWrites: 12, runWrites: 120, calendars: 2, githubHourly: 5, githubTokens: 10});
/** The one guest a live test may invite, the one sharing rule it may read or remove, and the row whose one-time Ask deletes a calendar. */
export const GUEST = 'fabric-guest@example.com';
export const SHARE_RULE = 'user:fabric-share@example.com';
export const PERMANENT_DELETE = 'google-calendar.permanent.delete';
/** The recorded value (scripts/live-certify.mjs --record) that names C9's invitation on the owner's primary calendar. */
export const C9_EVENT = 'c9Event';
/** The recorded name of the run calendar a read probe lists (docs/I07-BUILD-MAP.md part 3g). */
export const LEFTOVER_CALENDAR = 'leftoverCalendar';
/** Iteration 9 part 9b: the recorded name of the second test account, the one other guest TC-guest invites. */
export const SECOND_GUEST = 'secondGuest';
/** Iteration 9 part 9b: the two tests of an event about to start (TC-soon). `starting-soon` reads only the next minutes, which the run window of days 7 to 13 can never hold. */
export const SOON_TESTS = Object.freeze(['TC-soon-watch', 'TC-soon']);
/** Iteration 9 part 9b: the one column T6 adds and removes. */
export const PROBE_COLUMN = '[SYNTHETIC] Fabric trigger probe';
const HOUR = 60 * 60_000, SOON_BACK = 5 * 60_000, RUN_ID = /^[A-Z2-7]{8}$/, TEST_ID = /^[A-Za-z][A-Za-z0-9-]{0,15}$/, ROW_ID = /^[a-z0-9][a-z0-9.-]{0,127}$/;
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** The fixed words of every refusal, by rule. Each ends "Nothing was sent." and names no value it refused. */
export const GUARD_WORDS = Object.freeze({
  revocation: 'A live test run never asks a provider to revoke access. Nothing was sent.',
  origin: 'This address is outside what the live tests of this app may reach. Nothing was sent.',
  outside_test: 'Only sign-in may reach a provider outside a live test. Nothing was sent.',
  no_rule: 'This app has no live-test rules yet, so the harness sends nothing to it. Nothing was sent.',
  not_allowlisted: 'This method and path are not on the live tests\' list for this app. Nothing was sent.',
  body: 'This request body is not one the live tests send. Nothing was sent.',
  test_cap: 'A live test may send at most 12 changes. Nothing was sent.',
  run_cap: 'A live run may send at most 120 changes. Nothing was sent.',
  text: 'Every text a live test writes starts with [SYNTHETIC] Fabric, then this test and this run. Nothing was sent.',
  owner_unset: 'The run\'s owner, time zone and date are not set yet. Nothing was sent.',
  recipient: 'A live test sends email only to the account\'s own address. Nothing was sent.',
  draft: 'A live test sends or changes only a draft this run created, with its whole message. Nothing was sent.',
  repository: 'A live test reaches only the sandbox repository samikasasbeh/fabric-sandbox-test. Nothing was sent.',
  repository_admin: 'A live test never touches collaborators, hooks, keys, transfers, forks, secrets, environments or invitations. Nothing was sent.',
  notifications: 'Every Calendar change in a live test carries sendUpdates=none and never sends notifications. Nothing was sent.',
  window: 'Every date in a live test falls from day 7 to day 13 after the run date, in your time zone. Nothing was sent.',
  recurrence: 'A repeating event in a live test repeats daily or weekly, 1 to 3 times, in its own time zone, with nothing else in its rule. Nothing was sent.',
  calendar: 'A live test changes only the two calendars this run created. Nothing was sent.',
  calendar_cap: 'A live run creates at most two calendars. Nothing was sent.',
  primary: 'Your own calendar is off limits, except the one recorded invitation and your answer to it. Nothing was sent.',
  guest: 'A live test invites only fabric-guest@example.com, or the second test account you recorded. Nothing was sent.',
  one_time_ask: 'A calendar is deleted only during the one-time Ask on "Permanently delete calendars or clear all events". Nothing was sent.',
  sharing: 'A live test reads or removes only the fabric-share@example.com rule of a calendar this run created. Nothing was sent.',
  locked: 'Fabric never sends a request that gives access to other people or services. Nothing was sent.',
  mailbox: 'A live test reaches only the mail this run sent, what its synthetic search found and what you recorded for it. Nothing was sent.',
  label: 'A live test uses only the labels this run created, and INBOX, UNREAD, STARRED and IMPORTANT. Nothing was sent.',
  vacation: 'A live test turns the vacation reply off, or on for your contacts only, with nothing else in it. Nothing was sent.',
  filter: 'A live test makes only one filter: mail from synthetic-sender@example.invalid gets one label this run created. Nothing was sent.',
  invalid: 'Fabric could not check this request against the live-test rules. Nothing was sent.',
  github_hourly: 'GitHub allows only a few sign-ins an hour, and 5 happened here in the last hour. Wait before signing in again. Nothing was sent.',
  github_elsewhere: 'Say how many GitHub tokens for these permissions are live elsewhere before signing in. Nothing was sent.',
  github_tokens: 'This sign-in would make 10 live GitHub tokens for these permissions, and GitHub revokes the oldest past 10. Remove an older authorization first. Nothing was sent.',
  notion_area: 'A live test changes only pages A and B, the recorded row and data source, and the pages and discussions this run made. Nothing was sent.',
  // F10.19 and F10.17 share it: Notion's row and GitHub's.
  comment_delete: 'A comment is deleted only during the one-time Ask on its app\'s permanent delete row ("Permanently delete comments and views" on Notion, "Permanently delete repos, comments, releases and gists" on GitHub), and on Notion only one this run made. Nothing was sent.',
  // F10.21 part 2: Slack's test areas (step 22).
  slack_channel: 'A live test writes to Slack only in the recorded #fabric-test channel or your own direct message, and replies only in the recorded synthetic thread. Nothing was sent.',
  slack_message: 'A live test edits only a message this run posted, and cancels only a message this run scheduled. Nothing was sent.',
  slack_dm: 'A live test opens a direct message only with yourself. Nothing was sent.',
  slack_reaction: 'A live test reacts only with white_check_mark. Nothing was sent.',
  slack_schedule: 'A live test schedules a message at most one day ahead. Nothing was sent.',
  slack_status: 'A live test sets only a synthetic status that clears within an hour, or clears your status. Nothing was sent.',
  slack_delete: 'A live test never deletes a Slack message. Nothing was sent.',
  // F10.17: GitHub's test areas (step 18).
  branch: 'A live test creates, writes, opens a pull request from and deletes only this run\'s own branches, and a pull request or a run goes only into main or one of them. Nothing was sent.',
  merge: 'A live test merges only a pull request this run opened into one of its own branches. Nothing was sent.',
  label: 'A live test adds or removes only the label fabric-test, one at a time. Nothing was sent.',
  review: 'A live test reviews only with COMMENT. Nothing was sent.',
  workflow: 'A live test runs only the workflow fabric-synthetic.yml, with no inputs. Nothing was sent.',
  // Iteration 9 part 9b: what the trigger plans send that no action plan does.
  soon: 'In the one test of an event about to start, an event on a run calendar starts within the hour and ends within two, with no guest and no repeat, and a list holds both its bounds within that hour. Nothing was sent.',
  release: 'A live test publishes only a prerelease of this run\'s own branch, never a draft and never a full release. Nothing was sent.',
  notion_column: 'A live test adds or removes only the column [SYNTHETIC] Fabric trigger probe, as text, on the recorded data source. Nothing was sent.',
  slack_mention: 'A live test mentions only you, once, in the one test that asks for it, and no other text holds a Slack mention or link. Nothing was sent.',
});

// ---- small readers -------------------------------------------------------------------------------------------------------------------
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const keysOf = value => Object.keys(value).sort().join();
const lower = value => typeof value === 'string' ? value.toLowerCase() : null;
const EMAIL = /^[^\s@]+@[^\s@]+$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
/** A refusal inside a rule: thrown, and turned into the verdict by check(). Rule sets other than the shipped ones use it too. */
export function refuseRequest(rule) { throw Object.assign(new Error(GUARD_WORDS[rule] ?? GUARD_WORDS.invalid), {guardRule: rule}); }
const no = refuseRequest;
/** 8 random base32 characters. */
export function newRunId() { return [...randomBytes(8)].map(byte => BASE32[byte & 31]).join(''); }
/** The guard's run file and the folder's sign-in log. */
export const guardFile = (folder, appId, runId) => path.join(folder, 'live-certify', `${appId}-${runId}.guard.json`);
export const signInFile = folder => path.join(folder, 'live-certify', 'sign-ins.json');

// ---- dates in the owner's zone, from Intl alone --------------------------------------------------------------------------------------
const formats = new Map();
function zoneFormat(zone) {
  if (!formats.has(zone)) formats.set(zone, new Intl.DateTimeFormat('en-US', {timeZone: zone, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit'}));
  return formats.get(zone);
}
/** True for an IANA zone name Intl knows (never an offset). */
export function validZone(zone) {
  if (typeof zone !== 'string' || !/^(?:UTC|[A-Za-z_]+(?:\/[A-Za-z0-9_+-]+)+)$/.test(zone)) return false;
  try { zoneFormat(zone); return true; } catch { return false; }
}
/** The wall time of an instant in a zone. */
function wallOf(ms, zone) {
  const parts = Object.fromEntries(zoneFormat(zone).formatToParts(new Date(ms)).map(part => [part.type, part.value]));
  return {date: `${parts.year}-${parts.month}-${parts.day}`, hour: Number(parts.hour) % 24, minute: Number(parts.minute), second: Number(parts.second), millisecond: ((ms % 1000) + 1000) % 1000};
}
const utcOfWall = (date, {hour = 0, minute = 0, second = 0, millisecond = 0} = {}) => { const [y, m, d] = date.split('-').map(Number); return Date.UTC(y, m - 1, d, hour, minute, second, millisecond); };
/** How far a zone's wall clock is ahead of UTC at an instant. Exported for the plan placeholders of lib/live-certify.mjs (F10.12 part 2). */
export const offsetAt = (ms, zone) => { const wall = wallOf(ms, zone); return utcOfWall(wall.date, wall) - ms; };
/** The instant of a wall time in a zone: the offset is read at a first guess and again where that guess lands. */
export function zonedInstant(date, time, zone) {
  const wall = utcOfWall(date, time);
  return wall - offsetAt(wall - offsetAt(wall, zone), zone);
}
export function validDate(date) {
  if (typeof date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return false;
  return new Date(utcOfWall(date)).toISOString().slice(0, 10) === date;
}
/** A YYYY-MM-DD date some whole days later. */
export const addDays = (date, days) => new Date(utcOfWall(date) + days * 86_400_000).toISOString().slice(0, 10);
const MIDNIGHT = Object.freeze({hour: 0, minute: 0, second: 0});
/** The run window: from day 7 at 00:00 to (not including) day 14 at 00:00 after the run date, in the owner's zone. */
function windowOf(owner) {
  const at = date => zonedInstant(date, MIDNIGHT, owner.timeZone);
  const firstDay = addDays(owner.runDate, 7), lastDay = addDays(owner.runDate, 13), endDay = addDays(owner.runDate, 14);
  return {firstDay, lastDay, endDay, start: at(firstDay), end: at(endDay)};
}
const inWindow = (view, ms) => Number.isFinite(ms) && ms >= view.window.start && ms < view.window.end;

// ---- the shared checks a rule set uses -----------------------------------------------------------------------------------------------
const marker = view => `[SYNTHETIC] Fabric ${view.test} ${view.runId}`;
/** True when the text starts with this test's and this run's marker, followed by nothing or a space. */
export function synthetic(view, text) {
  if (typeof text !== 'string') return false;
  const prefix = marker(view);
  return text.startsWith(prefix) && (text.length === prefix.length || /\s/.test(text[prefix.length]));
}
const needText = (view, value) => { if (!synthetic(view, value)) no('text'); };
const needOwner = view => { if (!view.owner) no('owner_unset'); };
/** An RFC 3339 instant with its offset, inside the run window. */
function instant(view, value) {
  needOwner(view);
  if (typeof value !== 'string' || !RFC3339.test(value) || !inWindow(view, Date.parse(value))) no('window');
  return Date.parse(value);
}
/** A start or end of an event: a dateTime with its offset, or an all-day date (an end may be day 14, which is exclusive). */
function when(view, value, field) {
  needOwner(view);
  if (!record(value) || Object.hasOwn(value, 'date') === Object.hasOwn(value, 'dateTime')) no('window');
  if (Object.hasOwn(value, 'timeZone') && !validZone(value.timeZone)) no('body');
  if (Object.hasOwn(value, 'dateTime')) return instant(view, value.dateTime);
  if (!validDate(value.date) || value.date < view.window.firstDay || value.date > (field === 'end' ? view.window.endDay : view.window.lastDay)) no('window');
}
/** A recurrence: one RRULE, FREQ DAILY or WEEKLY, COUNT 1 to 3, nothing else, every occurrence inside the window in the event's own zone. */
function recurrence(view, body) {
  const rules = body.recurrence;
  if (!Array.isArray(rules) || rules.length !== 1 || typeof rules[0] !== 'string' || !rules[0].startsWith('RRULE:')) no('recurrence');
  const parts = new Map();
  for (const part of rules[0].slice('RRULE:'.length).split(';')) {
    const [name, value, ...extra] = part.split('=');
    if (!name || value === undefined || extra.length || parts.has(name.toUpperCase())) no('recurrence');
    parts.set(name.toUpperCase(), value.toUpperCase());
  }
  if ([...parts.keys()].some(name => !['FREQ', 'COUNT'].includes(name)) || !['DAILY', 'WEEKLY'].includes(parts.get('FREQ')) || !/^[1-3]$/.test(parts.get('COUNT') ?? '')) no('recurrence');
  if (!record(body.start) || !record(body.end)) no('recurrence');
  const step = parts.get('FREQ') === 'WEEKLY' ? 7 : 1, count = Number(parts.get('COUNT'));
  for (let index = 1; index < count; index++) for (const field of ['start', 'end']) occurrence(view, body[field], field, index * step);
}
/** One later occurrence of a start or end: its wall time moves by whole days in the event's zone, as Google expands it. */
function occurrence(view, value, field, days) {
  if (Object.hasOwn(value, 'date')) { when(view, {date: addDays(value.date, days)}, field); return; }
  if (!validZone(value.timeZone)) no('recurrence');
  const wall = wallOf(Date.parse(value.dateTime), value.timeZone);
  if (!inWindow(view, zonedInstant(addDays(wall.date, days), wall, value.timeZone))) no('window');
}
/** Every guest is fabric-guest@example.com, the recorded second account, the owner's own entry, or a calendar this run created (its organizer entry). */
function guests(view, list) {
  if (!Array.isArray(list)) no('guest');
  for (const entry of list) {
    const email = record(entry) ? lower(entry.email) : null;
    if (email === GUEST) continue;
    if (email && email === lower(view.recorded[SECOND_GUEST])) continue;
    if (email && view.owner && email === view.owner.email) continue;
    if (email && view.calendars.some(id => id.toLowerCase() === email)) continue;
    no('guest');
  }
}

// ---- paths -----------------------------------------------------------------------------------------------------------------------------
/** A path pattern: literal segments, ':name' for one segment, '+name' for the rest (one or more). */
const pattern = text => text === '' ? [] : text.split('/');
function matchPath(parts, segments) {
  const params = {};
  for (const [index, part] of parts.entries()) {
    if (part.startsWith('+')) { if (segments.length <= index) return null; params[part.slice(1)] = segments.slice(index).join('/'); return params; }
    if (index >= segments.length) return null;
    if (part.startsWith(':')) params[part.slice(1)] = segments[index];
    else if (part !== segments[index]) return null;
  }
  return parts.length === segments.length ? params : null;
}
/** The first entry of a table whose method and path both fit the request. */
function routeOf(table, request) {
  for (const entry of table) {
    if (entry.method !== request.method) continue;
    const params = matchPath(entry.parts, request.segments);
    if (params) return {entry, params};
  }
  return null;
}
const table = rows => rows.map(([method, route, handle]) => ({method, parts: pattern(route), handle}));
/** F10.12 part 2: a rule set's method and path pairs, below its base, as checkPlan() (lib/live-certify.mjs) compares each write placement. */
const allowlistOf = (rows, prefix = []) => Object.freeze(rows.map(entry => Object.freeze({method: entry.method, path: [...prefix, ...entry.parts].join('/')})));
const READ = Object.freeze({write: false});

// ---- Google Calendar: the full set step 14 needs ----------------------------------------------------------------------------------------
const TEXT_FIELDS = ['summary', 'description', 'location'];
const RESPONSES = new Set(['accepted', 'tentative', 'declined']);
const FREE_BUSY_KEYS = new Set(['timeMin', 'timeMax', 'timeZone', 'items']);
// The locked row's members ("Give access to other people or services"), refused by name even on a run calendar.
const CALENDAR_LOCKED = table([['POST', 'calendars/:any/events/watch'], ['POST', 'users/me/calendarList/watch'], ['POST', 'users/me/settings/watch'], ['POST', 'calendars/:any/acl/watch'],
  ['POST', 'channels/stop'], ['POST', 'calendars/:any/acl'], ['PATCH', 'calendars/:any/acl/:rule'], ['PUT', 'calendars/:any/acl/:rule'], ['POST', 'calendars/:any/transferOwnership']]);
/** Which calendar an id names: one this run created, the owner's primary (by name or the owner's own address), or another. */
function kindOf(view, id) {
  if (typeof id !== 'string' || !id) return 'other';
  if (view.calendars.includes(id)) return 'run';
  if (id === 'primary' || (view.owner && id.toLowerCase() === view.owner.email)) return 'primary';
  return 'other';
}
/** A calendar this run created; the primary calendar and any other are refused under their own rule. */
function runOnly(view, id) {
  const kind = kindOf(view, id);
  if (kind === 'primary') no('primary');
  if (kind !== 'run') no('calendar');
}
function notifications(query) {
  if (query.get('sendUpdates') !== 'none') no('notifications');
  if (query.has('sendNotifications') && query.get('sendNotifications') !== 'false') no('notifications');
}
function eventBody(view, body) {
  if (!record(body)) no('body');
  for (const field of TEXT_FIELDS) if (Object.hasOwn(body, field)) needText(view, body[field]);
  for (const field of ['start', 'end', 'originalStartTime']) if (Object.hasOwn(body, field)) when(view, body[field], field);
  if (Object.hasOwn(body, 'recurrence')) recurrence(view, body);
  if (Object.hasOwn(body, 'attendees')) guests(view, body.attendees);
}
/** C9: on the primary calendar, only the recorded event and only the owner's own answer, with attendeesOmitted. */
function invitationAnswer(view, request, eventId) {
  needOwner(view);
  if (request.method !== 'PATCH' || typeof view.recorded[C9_EVENT] !== 'string' || eventId !== view.recorded[C9_EVENT]) no('primary');
  notifications(request.query);
  const body = request.body;
  if (!record(body)) no('primary');
  if (keysOf(body) !== 'attendees,attendeesOmitted') no('primary');
  if (body.attendeesOmitted !== true || !Array.isArray(body.attendees) || body.attendees.length !== 1) no('primary');
  const [entry] = body.attendees;
  if (!record(entry) || keysOf(entry) !== 'email,responseStatus' || lower(entry.email) !== view.owner.email || !RESPONSES.has(entry.responseStatus)) no('primary');
  return {write: true};
}
const changeEvent = (request, view, {cal, event}) => {
  const kind = kindOf(view, cal);
  if (kind === 'primary') return invitationAnswer(view, request, event);
  runOnly(view, cal);
  notifications(request.query);
  eventBody(view, request.body);
  return {write: true};
};
const soonTest = view => SOON_TESTS.includes(view.test);
const listEvents = (request, view, {cal}) => {
  const {query} = request;
  // Iteration 9 part 3g: probes P2 and P3 read a calendar an earlier run left, since a probe makes none. Only the one the owner recorded, only this list, and with no bound, which is what a sync read sends.
  if (kindOf(view, cal) === 'other' && cal === view.recorded[LEFTOVER_CALENDAR] && !query.has('timeMin') && !query.has('timeMax')) return READ;
  if (kindOf(view, cal) === 'primary') {
    if (!(query.get('q') ?? '').startsWith('[SYNTHETIC]') || !query.has('timeMin') || !query.has('timeMax')) no('primary');
  } else runOnly(view, cal);
  if (soonTest(view) && kindOf(view, cal) === 'run') { soonList(view, query); return READ; }
  for (const bound of ['timeMin', 'timeMax']) if (query.has(bound)) instant(view, query.get(bound));
  return READ;
};
/** Iteration 9 part 9b, TC-soon: in its two tests a list of a run calendar holds both bounds inside the hour around now, a few minutes back at most, since a poll builds its bounds a moment before the guard reads them. */
function soonList(view, query) {
  const [from, to] = ['timeMin', 'timeMax'].map(name => query.get(name));
  if (![from, to].every(value => typeof value === 'string' && RFC3339.test(value))) no('soon');
  if (!(Date.parse(from) >= view.now - SOON_BACK && Date.parse(to) >= view.now && Date.parse(to) <= view.now + HOUR)) no('soon');
}
/** Iteration 9 part 9b, TC-soon: `starting-soon` needs an event about to start, so here one starts within the hour and ends within two, with no guest and no repeat. Every other rule of an event holds. */
function soonEvent(view, body) {
  if (!record(body)) no('body');
  if (['attendees', 'recurrence', 'originalStartTime'].some(field => Object.hasOwn(body, field))) no('soon');
  for (const field of TEXT_FIELDS) if (Object.hasOwn(body, field)) needText(view, body[field]);
  const [start, end] = [body.start, body.end].map(value => record(value) && typeof value.dateTime === 'string' && RFC3339.test(value.dateTime) ? Date.parse(value.dateTime) : NaN);
  for (const value of [body.start, body.end]) if (record(value) && Object.hasOwn(value, 'timeZone') && !validZone(value.timeZone)) no('body');
  if (!(start > view.now && start <= view.now + HOUR && end > start && end <= view.now + 2 * HOUR)) no('soon');
}
const CALENDAR_ROUTES = table([
  ['POST', 'calendars', (request, view) => {
    const body = request.body;
    if (!record(body)) no('body');
    for (const field of TEXT_FIELDS) if (Object.hasOwn(body, field) || field === 'summary') needText(view, body[field]);
    if (Object.hasOwn(body, 'timeZone') && !validZone(body.timeZone)) no('body');
    if (view.calendarsMade >= LIMITS.calendars) no('calendar_cap');
    return {write: true, creates: 'calendar', calendar: true};
  }],
  ['DELETE', 'calendars/:cal', (request, view, {cal}) => {
    runOnly(view, cal);
    if (view.oneTimeAsk !== PERMANENT_DELETE) no('one_time_ask');
    return {write: true};
  }],
  ['POST', 'calendars/:cal/events', (request, view, {cal}) => { runOnly(view, cal); notifications(request.query); (soonTest(view) ? soonEvent : eventBody)(view, request.body); return {write: true, creates: 'event'}; }],
  ['POST', 'calendars/:cal/events/quickAdd', (request, view, {cal}) => {
    runOnly(view, cal);
    notifications(request.query);
    if (request.body !== null) no('body');
    const words = request.query.get('text');
    needText(view, words);
    if (words.includes('@')) no('guest');
    needOwner(view);
    const dates = words.match(/\d{4}-\d{2}-\d{2}/g) ?? [];
    if (!dates.length || dates.some(date => !validDate(date) || date < view.window.firstDay || date > view.window.lastDay)) no('window');
    return {write: true, creates: 'event'};
  }],
  ['PATCH', 'calendars/:cal/events/:event', changeEvent],
  ['PUT', 'calendars/:cal/events/:event', changeEvent],
  ['DELETE', 'calendars/:cal/events/:event', (request, view, {cal}) => { runOnly(view, cal); notifications(request.query); return {write: true}; }],
  ['POST', 'calendars/:cal/events/:event/move', (request, view, {cal}) => {
    runOnly(view, cal);
    notifications(request.query);
    if (request.body !== null) no('body');
    if (kindOf(view, request.query.get('destination')) !== 'run') no('calendar');
    return {write: true};
  }],
  ['DELETE', 'calendars/:cal/acl/:rule', (request, view, {cal, rule}) => { runOnly(view, cal); if (rule !== SHARE_RULE) no('sharing'); return {write: true}; }],
  ['POST', 'freeBusy', (request, view) => {
    const body = request.body;
    if (!record(body) || Object.keys(body).some(key => !FREE_BUSY_KEYS.has(key)) || !Array.isArray(body.items) || !body.items.length || body.items.length > 20) no('body');
    if (Object.hasOwn(body, 'timeZone') && !validZone(body.timeZone)) no('body');
    instant(view, body.timeMin);
    instant(view, body.timeMax);
    for (const item of body.items) { if (!record(item) || keysOf(item) !== 'id') no('body'); runOnly(view, item.id); }
    return READ;
  }],
  ['GET', 'users/me/calendarList', () => READ],
  ['GET', 'users/me/calendarList/:cal', (request, view, {cal}) => { if (kindOf(view, cal) === 'other') no('calendar'); return READ; }],
  ['GET', 'users/me/settings/timezone', () => READ],
  ['GET', 'calendars/:cal', (request, view, {cal}) => { runOnly(view, cal); return READ; }],
  ['GET', 'calendars/:cal/events', listEvents],
  ['GET', 'calendars/:cal/events/:event', (request, view, {cal, event}) => {
    if (kindOf(view, cal) === 'primary') { if (typeof view.recorded[C9_EVENT] !== 'string' || event !== view.recorded[C9_EVENT]) no('primary'); return READ; }
    runOnly(view, cal);
    return READ;
  }],
  ['GET', 'calendars/:cal/events/:event/instances', (request, view, {cal}) => { runOnly(view, cal); return READ; }],
  ['GET', 'calendars/:cal/acl', (request, view, {cal}) => { runOnly(view, cal); return READ; }],
  ['GET', 'calendars/:cal/acl/:rule', (request, view, {cal, rule}) => { runOnly(view, cal); if (rule !== SHARE_RULE) no('sharing'); return READ; }],
]);
const CALENDAR = Object.freeze({appId: 'google-calendar', base: 'https://www.googleapis.com/calendar/v3', allowlist: allowlistOf(CALENDAR_ROUTES), route(request, view) {
  if (routeOf(CALENDAR_LOCKED, request)) no('locked');
  const match = routeOf(CALENDAR_ROUTES, request);
  if (!match) no('not_allowlisted');
  return match.entry.handle(request, view, match.params);
}});

// ---- Gmail: what G0 to G10 send (step 15), and nothing more -----------------------------------------------------------------------------
// Every header that names a recipient or a place replies and receipts go.
const ADDRESS_HEADERS = new Set(['to', 'cc', 'bcc', 'reply-to', 'resent-to', 'resent-cc', 'resent-bcc', 'resent-reply-to', 'mail-followup-to', 'mail-reply-to', 'followup-to',
  'disposition-notification-to', 'return-receipt-to']);
const ENCODED_WORD = /=\?([^?\s]+)\?([BbQq])\?([^?\s]*)\?=/g;
/** RFC 2047: encoded words decoded, adjacent ones joined without the space between them. An encoding Fabric cannot read is refused. */
function decodeWords(value, rule) {
  const joined = value.replace(/(=\?[^?\s]+\?[BbQq]\?[^?\s]*\?=)\s+(?==\?[^?\s]+\?[BbQq]\?[^?\s]*\?=)/g, '$1');
  return joined.replace(ENCODED_WORD, (_, charset, encoding, data) => {
    const name = charset.toLowerCase().split('*')[0];
    const bytes = encoding.toUpperCase() === 'B' ? Buffer.from(data, 'base64') : Buffer.from(data.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (__, hex) => String.fromCharCode(parseInt(hex, 16))), 'latin1');
    if (name === 'utf-8' || name === 'us-ascii') return bytes.toString('utf8');
    if (name === 'iso-8859-1' || name === 'latin1') return bytes.toString('latin1');
    return no(rule);
  });
}
/** Every address in a header is the owner's own, and no @ stands outside one. */
function recipients(view, value) {
  const addresses = value.match(/[^\s<>,;:"()[\]@]+@[^\s<>,;:"()[\]@]+/g) ?? [];
  if (addresses.length !== (value.match(/@/g) ?? []).length || addresses.some(address => address.toLowerCase() !== view.owner.email)) no('recipient');
}
/** A raw message: every address header (each instance, unfolded and decoded) names only the owner, and every Subject is synthetic. */
function message(view, raw) {
  if (typeof raw !== 'string' || !raw || raw.length > 4_000_000 || !/^[A-Za-z0-9_\-+/]+={0,2}$/.test(raw)) no('body');
  needOwner(view);
  const text = Buffer.from(raw.replace(/\+/g, '-').replace(/\//g, '_'), 'base64url').toString('utf8'), end = text.search(/\r?\n\r?\n/);
  // F10.12 check: in the headers a line breaks only as CRLF or LF, and no other control character stands, so no mail parser can split a
  // header the guard read whole (a lone CR once hid a Bcc inside the Subject).
  if (/\r(?!\n)|[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u2028\u2029]/.test(end === -1 ? text : text.slice(0, end))) no('body');
  const unfolded = (end === -1 ? text : text.slice(0, end)).replace(/\r?\n[ \t]+/g, ' ');
  const headers = unfolded.split(/\r?\n/).filter(line => line.length).map(line => {
    const colon = line.indexOf(':');
    if (colon < 1) no('body');
    return {name: line.slice(0, colon).trim().toLowerCase(), value: line.slice(colon + 1).trim()};
  });
  for (const header of headers.filter(item => ADDRESS_HEADERS.has(item.name))) recipients(view, decodeWords(header.value, 'recipient'));
  const subjects = headers.filter(item => item.name === 'subject');
  if (!subjects.length) no('text');
  for (const subject of subjects) subjectText(view, decodeWords(subject.value, 'text'));
}
/** F10.15 part 2: a Subject is this test's synthetic text, or a reply's as rfc5322.replyHeaders@1 writes it: "Re:" and the synthetic text of
 *  a test of this run, the subject of the message it replies to (G4 replies to G3's email). */
function subjectText(view, value) {
  const reply = /^re:[ \t]*/i.exec(value);
  if (!reply) return needText(view, value);
  const match = /^\[SYNTHETIC\] Fabric [A-Za-z][A-Za-z0-9-]{0,15} (\S+)(?:\s|$)/.exec(value.slice(reply[0].length));
  if (!match || match[1] !== view.runId) no('text');
}
const MESSAGE_KEYS = new Set(['raw', 'threadId']), LABEL_KEYS = new Set(['name', 'labelListVisibility', 'messageListVisibility', 'color']);
const ownDraft = (view, id) => { if (typeof id !== 'string' || !view.drafts.includes(id)) no('draft'); };
/** A draft's body: its whole message, as raw. */
function draftMessage(view, body) {
  if (!record(body) || Object.keys(body).some(key => !['id', 'message'].includes(key))) no('body');
  if (!record(body.message) || typeof body.message.raw !== 'string') no('draft');
  if (Object.keys(body.message).some(key => !MESSAGE_KEYS.has(key))) no('body');
  message(view, body.message.raw);
  sendThread(view, body.message);
}
/** F10.15: the recorded values (scripts/live-certify.mjs --record) that name the read pass's message and conversation and the owner's hand draft. */
export const READ_MESSAGE = 'readMessage', READ_THREAD = 'readThread', HAND_DRAFT = 'handDraft';
/** The one sender a live test's filter names. */
export const SYNTHETIC_SENDER = 'synthetic-sender@example.invalid';
/** The system labels a live test may add or remove: TRASH and SPAM go only through the trash routes, SENT and DRAFT never. */
const OPEN_LABELS = new Set(['INBOX', 'UNREAD', 'STARRED', 'IMPORTANT']);
// The locked row's settings ("Give access to other people or services"), refused by name with every method below them, as watch and stop are.
const GMAIL_LOCKED_SETTINGS = new Set(['sendAs', 'forwardingAddresses', 'delegates', 'autoForwarding']);
const lockedGmail = ({segments}) => (segments.length === 1 && ['watch', 'stop'].includes(segments[0])) || (segments[0] === 'settings' && GMAIL_LOCKED_SETTINGS.has(segments[1]));
const HISTORY_PARAMETERS = new Set(['startHistoryId', 'maxResults', 'pageToken']);
const WEEK_TERM = 'newer_than:7d', SEARCH_PARAMETERS = new Set(['q', 'maxResults', 'pageToken']), SEARCH_OPERATORS = new Set(['from', 'to', 'subject', 'label', 'has', 'after', 'before']);
const BATCH_KEYS = new Set(['ids', 'addLabelIds', 'removeLabelIds']), MODIFY_KEYS = new Set(['addLabelIds', 'removeLabelIds']);
const VACATION_ON = 'enableAutoReply,endTime,responseBodyPlainText,responseSubject,restrictToContacts,startTime';
/** A threadId in a message to send or draft names a thread this run made. */
const sendThread = (view, body) => { if (Object.hasOwn(body, 'threadId') && !view.threads.includes(body.threadId)) no('mailbox'); };
/** Messages and threads a change reaches: only ones this run made. */
const runMessages = (view, ids) => { if (!Array.isArray(ids) || !ids.length || ids.some(id => !view.messages.includes(id))) no('mailbox'); };
const runThread = (view, id) => { if (!view.threads.includes(id)) no('mailbox'); };
/** What a read reaches: what this run made, what its synthetic search listed, or the one the owner recorded for it. */
function readable(view, kind, id) {
  const found = kind === 'message' ? view.messages.includes(id) || view.listedMessages.includes(id) || id === view.recorded[READ_MESSAGE]
    : kind === 'thread' ? view.threads.includes(id) || view.listedThreads.includes(id) || id === view.recorded[READ_THREAD]
    : view.drafts.includes(id) || id === view.recorded[HAND_DRAFT];
  if (!found) no('mailbox');
}
/** A search within synthetic mail only: Fabric's query form (text.gmailQuery@1) with a quoted phrase starting "[SYNTHETIC] Fabric", as the words or the
 *  subject, and nothing that widens it: no OR, group, negated phrase, bare word or other operator, and no parameter but q, maxResults and pageToken. */
function syntheticSearch(query) {
  if ([...query.keys()].some(name => !SEARCH_PARAMETERS.has(name))) no('mailbox');
  let rest = query.get('q') ?? '', synthetic = false;
  while (rest) {
    // Iteration 9 part 9b: the term below reads no underscore, so this one literal is taken whole. It can only narrow a search, and no search passes without its synthetic term.
    if (rest === WEEK_TERM || rest.startsWith(`${WEEK_TERM} `)) { rest = rest.slice(WEEK_TERM.length + 1); continue; }
    const match = /^(-?)(?:([a-z]+):)?("[^"]*"|[^\s"(){}]+)(?: |$)/.exec(rest);
    if (!match || (match[2] !== undefined && !SEARCH_OPERATORS.has(match[2]))) no('mailbox');
    const [whole, minus, operator, value] = match, quoted = value.startsWith('"'), flag = operator === 'has' && value === 'attachment';
    const seconds = (operator === 'after' || operator === 'before') && /^[0-9]{1,12}$/.test(value);
    if ((minus && !flag) || (quoted ? ['has', 'after', 'before'].includes(operator) : !flag && !seconds)) no('mailbox');
    if (!minus && quoted && (operator === undefined || operator === 'subject') && value.startsWith('"[SYNTHETIC] Fabric')) synthetic = true;
    rest = rest.slice(whole.length);
  }
  if (!synthetic) no('mailbox');
}
/** The labels a modify adds or removes: each one this run created, or INBOX, UNREAD, STARRED or IMPORTANT. */
function modifyLabels(view, body) {
  for (const list of [body.addLabelIds, body.removeLabelIds]) {
    if (list !== undefined && (!Array.isArray(list) || list.some(id => !OPEN_LABELS.has(id) && !view.labels.includes(id)))) no('label');
  }
}
/** The vacation reply: off ({enableAutoReply: false} alone), or on for contacts only with a synthetic subject and text and both times (epoch
 *  milliseconds, as text) inside the run's days 7 to 13. */
function gmailVacation(view, body) {
  if (!record(body)) no('vacation');
  if (keysOf(body) === 'enableAutoReply' && body.enableAutoReply === false) return;
  if (keysOf(body) !== VACATION_ON || body.enableAutoReply !== true || body.restrictToContacts !== true) no('vacation');
  if (![body.startTime, body.endTime].every(time => typeof time === 'string' && /^[0-9]{1,16}$/.test(time))) no('vacation');
  needText(view, body.responseSubject);
  needText(view, body.responseBodyPlainText);
  needOwner(view);
  for (const time of [body.startTime, body.endTime]) if (!inWindow(view, Number(time))) no('window');
}
/** The one filter: exactly {criteria: {from: the synthetic sender}, action: {addLabelIds: [a label this run created]}}, so it never forwards. */
function gmailFilter(view, body) {
  if (!record(body) || keysOf(body) !== 'action,criteria' || !record(body.criteria) || keysOf(body.criteria) !== 'from' || body.criteria.from !== SYNTHETIC_SENDER) no('filter');
  if (!record(body.action) || keysOf(body.action) !== 'addLabelIds' || !Array.isArray(body.action.addLabelIds) || body.action.addLabelIds.length !== 1) no('filter');
  if (!view.labels.includes(body.action.addLabelIds[0])) no('label');
}
const trashMessage = (request, view, {id}) => { runMessages(view, [id]); if (request.body !== null) no('body'); return {write: true}; };
const trashThread = (request, view, {id}) => { runThread(view, id); if (request.body !== null) no('body'); return {write: true}; };
const GMAIL_ROUTES = table([
  ['POST', 'messages/send', (request, view) => {
    const body = request.body;
    if (!record(body) || Object.keys(body).some(key => !MESSAGE_KEYS.has(key))) no('body');
    message(view, body.raw);
    sendThread(view, body);
    return {write: true, creates: 'message'};
  }],
  ['POST', 'drafts', (request, view) => { if (Object.hasOwn(request.body ?? {}, 'id')) no('body'); draftMessage(view, request.body); return {write: true, creates: 'draft'}; }],
  ['PUT', 'drafts/:draft', (request, view, {draft}) => {
    if (draft !== view.recorded[HAND_DRAFT]) ownDraft(view, draft);
    if (record(request.body) && Object.hasOwn(request.body, 'id') && request.body.id !== draft) no('draft');
    draftMessage(view, request.body);
    return {write: true};
  }],
  ['POST', 'drafts/send', (request, view) => { ownDraft(view, request.body?.id); draftMessage(view, request.body); return {write: true, creates: 'message'}; }],
  ['POST', 'labels', (request, view) => {
    const body = request.body;
    if (!record(body) || Object.keys(body).some(key => !LABEL_KEYS.has(key))) no('body');
    needText(view, body.name);
    return {write: true, creates: 'label'};
  }],
  ['POST', 'messages/batchModify', (request, view) => {
    const body = request.body;
    if (!record(body) || Object.keys(body).some(key => !BATCH_KEYS.has(key))) no('body');
    runMessages(view, body.ids);
    modifyLabels(view, body);
    return {write: true};
  }],
  ['POST', 'threads/:id/modify', (request, view, {id}) => {
    runThread(view, id);
    if (!record(request.body) || Object.keys(request.body).some(key => !MODIFY_KEYS.has(key))) no('body');
    modifyLabels(view, request.body);
    return {write: true};
  }],
  ['POST', 'messages/:id/trash', trashMessage],
  ['POST', 'messages/:id/untrash', trashMessage],
  ['POST', 'threads/:id/trash', trashThread],
  ['POST', 'threads/:id/untrash', trashThread],
  ['PUT', 'settings/vacation', (request, view) => { gmailVacation(view, request.body); return {write: true}; }],
  ['POST', 'settings/filters', (request, view) => { gmailFilter(view, request.body); return {write: true, creates: 'filter'}; }],
  ['GET', 'messages', request => { syntheticSearch(request.query); return {write: false, lists: true}; }],
  ['GET', 'messages/:id', (request, view, {id}) => { readable(view, 'message', id); return READ; }],
  ['GET', 'threads/:id', (request, view, {id}) => { readable(view, 'thread', id); return READ; }],
  ['GET', 'drafts/:draft', (request, view, {draft}) => { readable(view, 'draft', draft); return READ; }],
  ['GET', 'labels', () => READ],
  ['GET', 'labels/:label', (request, view, {label}) => { if (!view.labels.includes(label)) no('label'); return READ; }],
  ['GET', 'settings/vacation', () => READ],
  ['GET', 'settings/filters/:filter', (request, view, {filter}) => { if (!view.filters.includes(filter)) no('filter'); return READ; }],
  ['GET', 'profile', () => READ],
  // Iteration 9 (docs/I07-BUILD-MAP.md parts 3g and 9b): it lists every id in the mailbox, so its answer reaches no read: only a search's does, and readable() stays strict.
  ['GET', 'history', request => { if ([...request.query.keys()].some(name => !HISTORY_PARAMETERS.has(name))) no('mailbox'); return READ; }],
]);
// F10.15: Find emails and Reply read metadataHeaders repeated, as the proxy's array parameters send them; any other query name occurs once.
const GMAIL = Object.freeze({appId: 'gmail', base: 'https://gmail.googleapis.com/gmail/v1/users/me', allowlist: allowlistOf(GMAIL_ROUTES), repeatable: Object.freeze(['metadataHeaders']), route(request, view) {
  if (lockedGmail(request)) no('locked');
  const match = routeOf(GMAIL_ROUTES, request);
  if (!match) no('not_allowlisted');
  return match.entry.handle(request, view, match.params);
}});

// ---- GitHub: the sandbox repository, narrowed to step 17's placements (docs/F10.17-BUILD-MAP.md part 2) ------------------------------------
// Reads: anything in the sandbox but its admin paths, and outside it exactly GET /user, /user/repos, /gists, /user/orgs and a search whose
// q holds the sandbox qualifier and no other repository, organization or user. Writes: the 15 actions' write placements and the plan's two
// proxied writes (a comment delete in the one-time Ask on "Permanently delete ...", a run branch's delete in the ask step), each only on
// this run's branches fabric/test-<runId> or fabric/test-<runId>-<suffix>, with synthetic text wherever text is sent.
const SANDBOX = Object.freeze(['repos', 'samikasasbeh', 'fabric-sandbox-test']);
const SANDBOX_QUALIFIER = 'repo:samikasasbeh/fabric-sandbox-test';
const GITHUB_ADMIN = new Set(['collaborators', 'hooks', 'keys', 'transfer', 'forks', 'secrets', 'environments', 'invitations']);
const GITHUB_DELETE_ROW = 'github.permanent.delete', GITHUB_LABEL = 'fabric-test', GITHUB_WORKFLOW = 'fabric-synthetic.yml';
/** True for this run's own branch: fabric/test-<runId>, or with -<suffix> of 1 to 16 lowercase letters or digits ($branch). */
function runBranch(view, name) {
  const own = `fabric/test-${view.runId}`;
  return typeof name === 'string' && (name === own || (name.startsWith(`${own}-`) && /^[a-z0-9]{1,16}$/.test(name.slice(own.length + 1))));
}
const needBranch = (view, name) => { if (!runBranch(view, name)) no('branch'); };
/** A body that is an object holding only the named fields. */
function fields(body, allowed) {
  if (!record(body) || Object.keys(body).some(key => !allowed.includes(key))) no('body');
  return body;
}
/** Each named field that is present is synthetic text. */
const texts = (view, body, names) => { for (const name of names) if (Object.hasOwn(body, name)) needText(view, body[name]); };
/** A search: its q holds the sandbox qualifier as a qualifier, and no other repository, organization, user or owner qualifier. */
function sandboxSearch(request) {
  const q = request.query.get('q');
  if (typeof q !== 'string') no('repository');
  const tokens = (q.match(/"[^"]*"|\S+/g) ?? []).filter(token => !token.startsWith('"'));
  if (!tokens.includes(SANDBOX_QUALIFIER) || tokens.some(token => /^(repo|org|user|owner):/i.test(token) && token !== SANDBOX_QUALIFIER)) no('repository');
  return READ;
}
// Iteration 9 (docs/I07-BUILD-MAP.md parts 3g and 9b): notifications reads the inbox, so a run counts sandbox events only.
const GITHUB_OUTSIDE = table([['GET', 'user', () => READ], ['GET', 'user/repos', () => READ], ['GET', 'gists', () => READ], ['GET', 'user/orgs', () => READ], ['GET', 'search/issues', sandboxSearch], ['GET', 'notifications', () => READ]]);
const GITHUB_ROUTES = table([
  // A new issue names no label but fabric-test: GitHub creates a label a new issue names that the repository lacks.
  ['POST', 'issues', (request, view) => {
    const body = fields(request.body, ['title', 'body', 'labels']);
    if (Object.hasOwn(body, 'labels') && JSON.stringify(body.labels) !== JSON.stringify([GITHUB_LABEL])) no('label');
    texts(view, body, ['title', 'body']);
    needText(view, body.title);
    return {write: true};
  }],
  // H3's undo restores issue B's recorded title byte for byte: on that one issue, that one title passes.
  ['PATCH', 'issues/:number', (request, view, {number}) => {
    const body = fields(request.body, ['title', 'body', 'state', 'state_reason']);
    const restore = number === view.recorded.issueB && typeof view.recorded.issueBTitle === 'string' && body.title === view.recorded.issueBTitle;
    texts(view, body, restore ? ['body'] : ['title', 'body']);
    return {write: true};
  }],
  ['POST', 'issues/:number/comments', (request, view) => { needText(view, fields(request.body, ['body']).body); return {write: true}; }],
  // Iteration 9 part 9b, TH8: no action publishes a release, so this one ask does: a prerelease of a run branch, whose tag is that name, so it never moves `latest` and names no tag of the repository's own.
  ['POST', 'releases', (request, view) => {
    const body = fields(request.body, ['tag_name', 'target_commitish', 'name', 'draft', 'prerelease']);
    needBranch(view, body.tag_name);
    needBranch(view, body.target_commitish);
    needText(view, body.name);
    if (body.draft !== false || body.prerelease !== true) no('release');
    return {write: true};
  }],
  ['DELETE', 'issues/comments/:id', (request, view) => { if (view.oneTimeAsk !== GITHUB_DELETE_ROW) no('comment_delete'); return {write: true}; }],
  ['POST', 'issues/:number/labels', request => {
    const labels = fields(request.body, ['labels']).labels;
    if (!Array.isArray(labels) || labels.length !== 1 || labels[0] !== GITHUB_LABEL) no('label');
    return {write: true};
  }],
  ['DELETE', 'issues/:number/labels/:name', (request, view, {name}) => { if (name !== GITHUB_LABEL) no('label'); return {write: true}; }],
  ['POST', 'git/refs', (request, view) => {
    const body = fields(request.body, ['ref', 'sha']);
    if (typeof body.ref !== 'string' || !body.ref.startsWith('refs/heads/')) no('branch');
    needBranch(view, body.ref.slice('refs/heads/'.length));
    return {write: true};
  }],
  ['DELETE', 'git/refs/+ref', (request, view, {ref}) => { if (!ref.startsWith('heads/')) no('branch'); needBranch(view, ref.slice('heads/'.length)); return {write: true}; }],
  ['PUT', 'contents/+path', (request, view) => {
    const body = fields(request.body, ['message', 'content', 'sha', 'branch']);
    needBranch(view, body.branch);
    needText(view, body.message);
    return {write: true};
  }],
  // A pull opens from a run branch into main or a run branch; one into a run branch is recorded by its number, so this run can merge it.
  ['POST', 'pulls', (request, view) => {
    const body = fields(request.body, ['title', 'head', 'base', 'draft', 'body']);
    needBranch(view, body.head);
    if (body.base !== 'main') needBranch(view, body.base);
    texts(view, body, ['title', 'body']);
    needText(view, body.title);
    return {write: true, ...(body.base !== 'main' ? {creates: 'pull'} : {})};
  }],
  ['POST', 'pulls/:number/reviews', (request, view) => {
    const body = fields(request.body, ['event', 'commit_id', 'body']);
    if (body.event !== 'COMMENT') no('review');
    needText(view, body.body);
    return {write: true};
  }],
  ['PUT', 'pulls/:number/merge', (request, view, {number}) => {
    if (!view.pulls.includes(number)) no('merge');
    texts(view, fields(request.body, ['sha', 'merge_method', 'commit_title', 'commit_message']), ['commit_title', 'commit_message']);
    return {write: true};
  }],
  ['POST', 'actions/workflows/:workflow/dispatches', (request, view, {workflow}) => {
    if (workflow !== GITHUB_WORKFLOW) no('workflow');
    const body = fields(request.body, ['ref', 'inputs', 'return_run_details']);
    if (body.ref !== 'main') needBranch(view, body.ref);
    if (body.inputs !== undefined && !(record(body.inputs) && Object.keys(body.inputs).length === 0)) no('workflow');
    // Asking GitHub for the new run's id (run-workflow reads the run back by it) is the one other field a dispatch may carry.
    if (body.return_run_details !== undefined && body.return_run_details !== true) no('workflow');
    return {write: true};
  }],
]);
const GITHUB = Object.freeze({appId: 'github', base: 'https://api.github.com',
  allowlist: Object.freeze([...allowlistOf(GITHUB_ROUTES, SANDBOX), ...allowlistOf(table([['GET', ''], ['GET', '+rest']]), SANDBOX), ...allowlistOf(GITHUB_OUTSIDE)]),
  route(request, view) {
    const inSandbox = SANDBOX.every((part, index) => request.segments[index] === part);
    if (!inSandbox) {
      const outside = routeOf(GITHUB_OUTSIDE, request);
      if (!outside) no('repository');
      return outside.entry.handle(request, view, outside.params);
    }
    const rest = request.segments.slice(SANDBOX.length);
    if (rest.some(part => GITHUB_ADMIN.has(part))) no('repository_admin');
    if (request.method === 'GET') return READ;
    const match = routeOf(GITHUB_ROUTES, {...request, segments: rest});
    if (!match) no('not_allowlisted');
    // Every create is recorded by the id GitHub answers, as step 12 records it: the evidence's created identity, and what a stopped run
    // left in place. A pull into one of this run's branches is recorded as a pull, by its number too, so only it can be merged.
    const verdict = match.entry.handle(request, view, match.params);
    return request.method === 'POST' && verdict.creates === undefined ? {...verdict, creates: 'item'} : verdict;
  }});

// ---- Notion: the test area of N0 to N11 (F10.19 part 2) ---------------------------------------------------------------------------------
/** The row whose one-time Ask deletes the run's comments (N11). */
export const NOTION_PERMANENT_DELETE = 'notion.permanent.delete';
const NOTION_ID = /^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i;
/** A Notion id in one form, lowercase with no hyphens, as a link or the API writes it; anything else is null. */
const notionId = value => typeof value === 'string' && NOTION_ID.test(value) ? value.replace(/-/g, '').toLowerCase() : null;
/** The recorded values (scripts/live-certify.mjs --record) of these names, and what this run made of a kind, as ids. */
const recordedIds = (view, names) => names.map(name => notionId(view.recorded[name])).filter(Boolean);
const madeIds = (view, kind) => view.made.filter(item => item.kind === kind).map(item => notionId(item.id)).filter(Boolean);
const oneOf = (value, ids) => { const id = notionId(value); return id !== null && ids.includes(id); };
/** A page a test may change: A, B, row 1 or a page this run made. */
const areaPage = (view, id) => { if (!oneOf(id, [...recordedIds(view, ['pageA', 'pageB', 'row1']), ...madeIds(view, 'page')])) no('notion_area'); };
/** A page a test may move or trash: only one this run made. */
const madePage = (view, id) => { if (!oneOf(id, madeIds(view, 'page'))) no('notion_area'); };
/** An object holding no member but these. */
const closed = (value, allowed) => { if (!record(value) || Object.keys(value).some(key => !allowed.includes(key))) no('body'); };
/** Rich text a test writes: text pieces only (never a mention, an equation or a link), their contents joined starting with the marker. */
function richText(view, list) {
  if (!Array.isArray(list) || !list.length) no('body');
  for (const piece of list) {
    closed(piece, ['type', 'text']);
    if (piece.type !== undefined && piece.type !== 'text') no('body');
    closed(piece.text, ['content']);
    if (typeof piece.text.content !== 'string') no('body');
  }
  needText(view, list.map(piece => piece.text.content).join(''));
}
/** Markdown a test writes: it starts with the marker and holds no tag (a mention, a page or a database). */
const markdownText = (view, value) => { needText(view, value); if (value.includes('<')) no('body'); };
/** Property values: a title or text written with the marker, or a plain value; never people, files or relations, which reach others. */
const PLAIN_VALUES = new Set(['number', 'checkbox', 'select', 'status', 'multi_select', 'date', 'url', 'email', 'phone_number']);
function propertyValues(view, values) {
  if (!record(values) || !Object.keys(values).length) no('body');
  for (const value of Object.values(values)) {
    if (!record(value) || Object.keys(value).length !== 1) no('body');
    const [type] = Object.keys(value);
    if (type === 'title' || type === 'rich_text') richText(view, value[type]);
    else if (!PLAIN_VALUES.has(type)) no('body');
  }
}
/** A page's parent: A or B by page id, or the recorded data source; `rows` allows the data source. */
function parentOf(view, parent, {rows}) {
  if (!record(parent)) no('body');
  if (rows && Object.hasOwn(parent, 'data_source_id')) {
    closed(parent, ['type', 'data_source_id']);
    if ((parent.type ?? 'data_source_id') !== 'data_source_id') no('body');
    if (!oneOf(parent.data_source_id, recordedIds(view, ['dataSource']))) no('notion_area');
    return;
  }
  closed(parent, ['type', 'page_id']);
  if ((parent.type ?? 'page_id') !== 'page_id' || !Object.hasOwn(parent, 'page_id')) no('body');
  if (!oneOf(parent.page_id, recordedIds(view, ['pageA', 'pageB']))) no('notion_area');
}
const NOTION_ROUTES = table([
  ['GET', '+rest', () => READ],
  ['POST', 'search', () => READ],
  ['POST', 'data_sources/:source/query', () => READ],
  // Iteration 9 part 9b, T6: one column of plain text, by its fixed name, added and taken away on the recorded data source. A schema's other columns are the owner's.
  ['PATCH', 'data_sources/:source', (request, view, {source}) => {
    if (!oneOf(source, recordedIds(view, ['dataSource']))) no('notion_area');
    const body = request.body;
    closed(body, ['properties']);
    const named = record(body.properties) ? Object.keys(body.properties) : [], value = named[0] === PROBE_COLUMN ? body.properties[PROBE_COLUMN] : undefined;
    if (named.length !== 1 || !(value === null || (record(value) && keysOf(value) === 'rich_text' && record(value.rich_text) && !Object.keys(value.rich_text).length))) no('notion_column');
    return {write: true};
  }],
  ['POST', 'pages', (request, view) => {
    const body = request.body;
    closed(body, ['parent', 'properties', 'markdown']);
    parentOf(view, body.parent, {rows: true});
    propertyValues(view, body.properties);
    if (Object.hasOwn(body, 'markdown')) markdownText(view, body.markdown);
    return {write: true, creates: 'page'};
  }],
  ['PATCH', 'pages/:page', (request, view, {page}) => {
    areaPage(view, page);
    const body = request.body;
    closed(body, ['properties', 'in_trash']);
    if (!Object.keys(body).length || (Object.hasOwn(body, 'in_trash') && body.in_trash !== false)) no('body');
    if (Object.hasOwn(body, 'properties')) propertyValues(view, body.properties);
    return {write: true};
  }],
  ['PATCH', 'pages/:page/markdown', (request, view, {page}) => {
    areaPage(view, page);
    const body = request.body;
    if (!record(body) || !['insert_content', 'update_content'].includes(body.type)) no('body');
    closed(body, ['type', body.type]);
    if (body.type === 'insert_content') {
      closed(body.insert_content, ['content']);
      markdownText(view, body.insert_content.content);
      return {write: true};
    }
    closed(body.update_content, ['content_updates']);
    const updates = body.update_content.content_updates;
    if (!Array.isArray(updates) || updates.length !== 1) no('body');
    closed(updates[0], ['old_str', 'new_str']);
    if (typeof updates[0].old_str !== 'string' || !updates[0].old_str || typeof updates[0].new_str !== 'string') no('body');
    // An empty replacement removes a marker an earlier step added.
    if (updates[0].new_str !== '') markdownText(view, updates[0].new_str);
    return {write: true};
  }],
  ['POST', 'pages/:page/move', (request, view, {page}) => {
    madePage(view, page);
    closed(request.body, ['parent']);
    parentOf(view, request.body.parent, {rows: false});
    return {write: true};
  }],
  ['DELETE', 'blocks/:block', (request, view, {block}) => { madePage(view, block); return {write: true}; }],
  ['POST', 'comments', (request, view) => {
    const body = request.body;
    closed(body, ['parent', 'discussion_id', 'rich_text']);
    if (Object.hasOwn(body, 'parent') === Object.hasOwn(body, 'discussion_id')) no('body');
    if (Object.hasOwn(body, 'parent')) {
      closed(body.parent, ['type', 'page_id']);
      if ((body.parent.type ?? 'page_id') !== 'page_id' || !oneOf(body.parent.page_id, recordedIds(view, ['pageA']))) no('notion_area');
    } else if (!oneOf(body.discussion_id, madeIds(view, 'discussion'))) no('notion_area');
    richText(view, body.rich_text);
    return {write: true, creates: 'comment', also: {kind: 'discussion', field: 'discussion_id'}};
  }],
  ['DELETE', 'comments/:comment', (request, view, {comment}) => {
    if (view.oneTimeAsk !== NOTION_PERMANENT_DELETE || !oneOf(comment, madeIds(view, 'comment'))) no('comment_delete');
    return {write: true};
  }],
]);
const NOTION = Object.freeze({appId: 'notion', base: 'https://api.notion.com/v1', allowlist: allowlistOf(NOTION_ROUTES), route(request, view) {
  const match = routeOf(NOTION_ROUTES, request);
  if (!match) no('not_allowlisted');
  return match.entry.handle(request, view, match.params);
}});

// ---- An app with no rules yet: every request is refused ------------------------------------------------------------------------------
const nothing = (appId, base) => Object.freeze({appId, base, allowlist: Object.freeze([]), route: () => no('no_rule')});

// ---- Slack: the test areas of step 22 (docs/F10.21-BUILD-MAP.md part 2) ----------------------------------------------------------------
// Writes go only to the recorded #fabric-test channel or the owner's self-DM, with synthetic text that Slack reads for no mention or link;
// a reply only in the recorded synthetic thread; an edit only of a message this run posted; a reaction only white_check_mark; a direct
// message only opened with the owner; a schedule at most a day ahead, cancelled only by its own id; a status only synthetic and clearing
// within an hour, or the clear form. chat.delete is never sent. Every value the rules compare with is one Muse recorded.
// F10.21 check: Slack reads a GET's query as the arguments of any method, writes included (its Web API basics page), so a GET is never a
// read by its verb: it passes only for the read methods the actions, their readbacks and the plan send, in any channel. A write carries its
// arguments in its JSON body only, and Slack would read a query beside it too, so a write with any query is refused.
const SLACK_READS = new Set(['auth.test', 'chat.getPermalink', 'chat.scheduledMessages.list', 'conversations.history', 'conversations.info', 'conversations.replies', 'reactions.get',
  'search.messages', 'users.conversations', 'users.info', 'users.list', 'users.lookupByEmail', 'users.profile.get']);
const SLACK_POST = new Set(['channel', 'text', 'parse', 'link_names', 'unfurl_links', 'unfurl_media', 'thread_ts', 'reply_broadcast']);
const SLACK_UPDATE = new Set(['channel', 'ts', 'text', 'attachments', 'parse', 'link_names']);
const SLACK_SCHEDULE = new Set(['channel', 'text', 'post_at', 'parse', 'link_names', 'unfurl_links', 'unfurl_media']);
const SLACK_REACTION = new Set(['channel', 'timestamp', 'name']);
const MENTION_TEST = 'TR3', SLACK_STATUS_EMOJI = /^:[a-z0-9_+'-]{1,100}(?:::skin-tone-[2-6])?:$/;
/** The body as an object of known keys only. */
function slackBody(request, keys) {
  if (!record(request.body) || Object.keys(request.body).some(key => !keys.has(key))) no('body');
  return request.body;
}
/** #fabric-test or the owner's self-DM, as recorded. */
function slackChannel(view, channel) {
  if (typeof channel !== 'string' || ![view.recorded.fabricTest, view.recorded.selfDm].includes(channel)) no('slack_channel');
}
/** Text Slack reads for no mention and no link (parse none, link_names false), and synthetic. */
function slackText(view, body, mentions = false) {
  if (body.parse !== 'none' || body.link_names !== false) no('body');
  needText(view, body.text);
  // Iteration 9 part 9b: Slack reads <...> as a mention or a link whatever `parse` says, so no text holds one but TR3's post of the owner's own member id, which `mention-search` needs.
  if (body.text.includes('<') && !(mentions && ownerMention(view, body.text))) no('slack_mention');
}
/** The one mention a live test sends: in TR3 alone, this test's marker, then the owner, and nothing else. */
const ownerMention = (view, text) => view.test === MENTION_TEST && typeof view.recorded.ownerUser === 'string' && text === `${marker(view)} <@${view.recorded.ownerUser}>`;
const noUnfurl = body => { if (body.unfurl_links !== false || body.unfurl_media !== false) no('body'); };
/** Read a canvas: a reviewed read sent as a POST. */
const slackRead = () => READ;
const SLACK_ROUTES = table([
  ['POST', 'chat.postMessage', (request, view) => {
    const body = slackBody(request, SLACK_POST);
    slackChannel(view, body.channel);
    slackText(view, body, true);
    noUnfurl(body);
    if (Object.hasOwn(body, 'reply_broadcast') && body.reply_broadcast !== false) no('body');
    if (Object.hasOwn(body, 'thread_ts') && body.thread_ts !== view.recorded.synthetic1) no('slack_channel');
    return {write: true, creates: 'slack-message', createdKey: 'ts'};
  }],
  ['POST', 'chat.update', (request, view) => {
    const body = slackBody(request, SLACK_UPDATE);
    slackChannel(view, body.channel);
    if (!view.posted.includes(body.ts)) no('slack_message');
    if (Object.hasOwn(body, 'attachments') && !(Array.isArray(body.attachments) && body.attachments.length === 0)) no('body');
    slackText(view, body);
    return {write: true};
  }],
  ['POST', 'chat.scheduleMessage', (request, view) => {
    const body = slackBody(request, SLACK_SCHEDULE);
    slackChannel(view, body.channel);
    slackText(view, body);
    noUnfurl(body);
    if (!Number.isSafeInteger(body.post_at) || body.post_at * 1000 <= view.now || body.post_at * 1000 > view.now + 24 * HOUR) no('slack_schedule');
    return {write: true, creates: 'slack-scheduled', createdKey: 'scheduled_message_id'};
  }],
  ['POST', 'chat.deleteScheduledMessage', (request, view) => {
    const body = slackBody(request, new Set(['channel', 'scheduled_message_id']));
    slackChannel(view, body.channel);
    if (!view.scheduled.includes(body.scheduled_message_id)) no('slack_message');
    return {write: true};
  }],
  ...['reactions.add', 'reactions.remove'].map(name => ['POST', name, (request, view) => {
    const body = slackBody(request, SLACK_REACTION);
    slackChannel(view, body.channel);
    if (typeof body.timestamp !== 'string' || body.name !== 'white_check_mark') no('slack_reaction');
    return {write: true};
  }]),
  ['POST', 'conversations.open', (request, view) => {
    if (!record(request.body) || keysOf(request.body) !== 'users' || request.body.users !== view.recorded.ownerUser) no('slack_dm');
    return {write: true};
  }],
  ['POST', 'users.profile.set', (request, view) => {
    const body = request.body, profile = record(body) ? body.profile : null;
    if (!record(body) || keysOf(body) !== 'profile' || !record(profile) || keysOf(profile) !== 'status_emoji,status_expiration,status_text') no('slack_status');
    if (profile.status_text === '' && profile.status_emoji === '' && profile.status_expiration === 0) return {write: true};
    const until = profile.status_expiration;
    if (!Number.isSafeInteger(until) || until * 1000 <= view.now || until * 1000 > view.now + HOUR || typeof profile.status_emoji !== 'string' || !SLACK_STATUS_EMOJI.test(profile.status_emoji)) no('slack_status');
    needText(view, profile.status_text);
    return {write: true};
  }],
  ['POST', 'canvases.getContent', slackRead],
]);
const SLACK = Object.freeze({appId: 'slack', base: 'https://slack.com/api', allowlist: allowlistOf(SLACK_ROUTES), route(request, view) {
  if (request.segments.join('/') === 'chat.delete') no('slack_delete');
  if (request.method === 'GET') {
    if (request.segments.length !== 1 || !SLACK_READS.has(request.segments[0])) no('not_allowlisted');
    return READ;
  }
  if ([...request.query.keys()].length > 0) no('body');
  const match = routeOf(SLACK_ROUTES, request);
  if (!match) no('not_allowlisted');
  if (match.entry.handle !== slackRead) needOwner(view);
  return match.entry.handle(request, view, match.params);
}});
/** The shipped rule sets, by app. A guard for an app with none refuses everything but sign-in. */
export const RULES = Object.freeze({'google-calendar': CALENDAR, gmail: GMAIL, github: GITHUB, notion: NOTION, slack: SLACK});

// ---- sign-in and revocation, from the reviewed definitions -----------------------------------------------------------------------------
const APPS = JSON.parse(readFileSync(new URL('../catalog/apps.json', import.meta.url), 'utf8'));
/** Sign-in traffic: each reviewed definition's token, identity and probe URLs, and each Google app's Discovery document, by method and URL. */
const SIGN_IN = new Set();
/** Revocation: each reviewed definition's revocation URL, {client_id} standing for one path segment. */
const REVOCATIONS = [];
for (const providerId of reviewedProviderIds()) {
  const definition = definitionFor(providerId);
  SIGN_IN.add(`POST ${new URL(definition.token.url).href}`);
  SIGN_IN.add(`${definition.identity.request.method} ${new URL(definition.identity.request.url).href}`);
  for (const app of definition.apps) if (app.accessProbe?.url) SIGN_IN.add(`GET ${new URL(app.accessProbe.url).href}`);
  if (definition.revocation?.url) {
    const template = new URL(definition.revocation.url.replace('{client_id}', 'CLIENT_ID_SEGMENT'));
    REVOCATIONS.push({origin: template.origin, segments: template.pathname.split('/').map(part => part === 'CLIENT_ID_SEGMENT' ? null : part)});
  }
}
for (const app of APPS) if (app.discovery?.kind === 'google-discovery') SIGN_IN.add(`GET ${new URL(app.discovery.url).href}`);
// F10.19: a token introspection (Notion's, run once before N0) is sign-in traffic: client-authenticated, never traced.
for (const url of Object.values(INTROSPECTION)) SIGN_IN.add(`POST ${new URL(url).href}`);
const revocation = url => REVOCATIONS.some(item => {
  const segments = url.pathname.split('/');
  return item.origin === url.origin && item.segments.length === segments.length && item.segments.every((part, index) => part === null ? segments[index].length > 0 : part === segments[index]);
});

// ---- the guard ----------------------------------------------------------------------------------------------------------------------
function freshState(appId, runId) { return {schemaVersion: 1, appId, runId, owner: null, writes: 0, testWrites: {}, calendarsMade: 0, created: [], trace: []}; }
/** The run file a guard with this run id wrote, or a fresh state; a file of another shape refuses to start, so no cap resets silently. */
function readGuardState(file, appId, runId) {
  if (!existsSync(file)) return freshState(appId, runId);
  const state = JSON.parse(readFileSync(file, 'utf8'));
  if (!record(state) || state.schemaVersion !== 1 || state.appId !== appId || state.runId !== runId || !Number.isSafeInteger(state.writes) || !record(state.testWrites)
    || !Number.isSafeInteger(state.calendarsMade) || !Array.isArray(state.created) || !Array.isArray(state.trace)) throw new Error('The guard file of this run is not one the live guard wrote.');
  return state;
}
function readSignIns(file) {
  if (!existsSync(file)) return {schemaVersion: 1, signIns: []};
  const book = JSON.parse(readFileSync(file, 'utf8'));
  if (!record(book) || book.schemaVersion !== 1 || !Array.isArray(book.signIns)) throw new Error('The sign-in log of this folder is not one the live guard wrote.');
  return book;
}
/** Writes a file the owner alone can read, whole or not at all. */
function writeSecret(file, value) {
  const next = `${file}.${process.pid}.tmp`;
  writeFileSync(next, `${JSON.stringify(value, null, 1)}\n`, {mode: 0o600});
  chmodSync(next, 0o600);
  renameSync(next, file);
}
const scopeSet = scopes => [...new Set((Array.isArray(scopes) ? scopes : []).map(String))].sort();
/** The id a create answered, at `key` (Slack answers a message's ts and a scheduled message's scheduled_message_id, F10.21). */
const createdId = (data, key = 'id') => record(data) && ((typeof data[key] === 'string' && data[key].length > 0 && data[key].length <= 1024) || Number.isSafeInteger(data[key])) ? String(data[key]) : null;

/**
 * The live guard of one run of one app. `key` is the run's in-memory HMAC key (the one the evidence uses), `folder` the certification
 * folder, `rules` the rule sets by app (RULES by default). Returns {appId, runId, wrap, check, begin, end, beginOneTimeAsk, endOneTimeAsk,
 * setOwner, setElsewhere, signIn, trace, created, counts}.
 */
export function createGuard({appId, runId, folder, clock = Date.now, key, rules = RULES}) {
  if (typeof appId !== 'string' || !/^[a-z][a-z0-9-]{1,63}$/.test(appId)) throw new Error('The live guard needs an app id.');
  if (typeof runId !== 'string' || !RUN_ID.test(runId)) throw new Error('A run id is 8 base32 characters.');
  if (typeof folder !== 'string' || !path.isAbsolute(folder)) throw new Error('The live-test folder must be an absolute path.');
  if (!(key instanceof Uint8Array) || key.length < 32) throw new Error('The run key is at least 32 random bytes, kept in memory only.');
  if (typeof clock !== 'function' || !record(rules)) throw new Error('The live guard needs a clock and its rule sets.');
  const own = Buffer.from(key), directory = path.join(folder, 'live-certify'), file = guardFile(folder, appId, runId), signInPath = signInFile(folder);
  mkdirSync(directory, {recursive: true, mode: 0o700});
  chmodSync(directory, 0o700);
  const state = readGuardState(file, appId, runId);
  const save = () => writeSecret(file, state);
  const rule = Object.hasOwn(rules, appId) ? rules[appId] : null;
  const base = rule ? new URL(rule.base) : null, basePath = base ? base.pathname.replace(/\/$/, '') : '';
  let test = null, oneTimeAsk = null, signIns = null;
  const elsewhere = new Map();
  // F10.15: what a synthetic Gmail search listed, which a read may reach. Kept in memory only: after a restart a read of it is refused until a
  // search lists it again, never the other way round.
  const listed = {messages: new Set(), threads: new Set()};
  const made = kind => state.created.filter(item => item.kind === kind).map(item => item.id);
  const mac = value => createHmac('sha256', own).update(value).digest('hex');
  const bodyDigest = body => body === undefined || body === null ? null : mac(body);
  const identityOf = id => EMAIL.test(id) ? `hmac:${mac(id).slice(0, 32)}` : id;
  const refusal = rule => ({allowed: false, rule, words: GUARD_WORDS[rule] ?? GUARD_WORDS.invalid});
  const view = () => {
    const owner = state.owner;
    return Object.freeze({appId, runId, test, owner, recorded: owner?.recorded ?? {}, window: owner ? windowOf(owner) : null, oneTimeAsk, calendarsMade: state.calendarsMade,
      calendars: state.created.filter(item => item.kind === 'calendar').map(item => item.id), drafts: state.created.filter(item => item.kind === 'draft').map(item => item.id),
      made: Object.freeze(state.created.map(item => Object.freeze({id: item.id, kind: item.kind}))),
      // F10.21: Slack's messages and scheduled messages this run made, and the guard's clock for Slack's windows.
      posted: state.created.filter(item => item.kind === 'slack-message').map(item => item.id), scheduled: state.created.filter(item => item.kind === 'slack-scheduled').map(item => item.id), now: clock(),
      // F10.15: Gmail's messages, threads, labels and filters this run made, and what a synthetic search listed.
      messages: made('message'), threads: made('thread'), labels: made('label'), filters: made('filter'), listedMessages: [...listed.messages], listedThreads: [...listed.threads],
      // F10.17: the pull requests this run opened, by number, which a merge path names.
      pulls: state.created.filter(item => item.kind === 'pull' && typeof item.number === 'string').map(item => item.number)});
  };
  /** The request as a rule reads it: method, the decoded segments below the app's base, the query and the parsed body. */
  function parse(url, options) {
    const method = String(options.method ?? 'GET').toUpperCase();
    if (url.origin !== base.origin || !(url.pathname === basePath || url.pathname.startsWith(`${basePath}/`))) return refusal('origin');
    const rest = url.pathname.slice(basePath.length + 1), segments = [];
    for (const raw of rest === '' ? [] : rest.split('/')) {
      let segment;
      try { segment = decodeURIComponent(raw); } catch { return refusal('not_allowlisted'); }
      if (!segment || segment === '.' || segment === '..' || /[/\\]/.test(segment)) return refusal('not_allowlisted');
      segments.push(segment);
    }
    const names = [...url.searchParams.keys()], repeatable = Array.isArray(rule.repeatable) ? rule.repeatable : [];
    if (names.some((name, index) => names.indexOf(name) !== index && !repeatable.includes(name))) return refusal('not_allowlisted');
    const raw = options.body === undefined || options.body === null ? null : Buffer.isBuffer(options.body) ? options.body.toString('utf8') : String(options.body);
    let body = null;
    if (raw !== null && raw !== '') { try { body = JSON.parse(raw); } catch { return refusal('body'); } }
    if (body !== null && ['GET', 'DELETE'].includes(method)) return refusal('body');
    return {method, segments, query: url.searchParams, body};
  }
  /** Pure over the guard's state: the verdict on one request, {allowed, kind, write, ...} or {allowed: false, rule, words}. */
  function check(options) {
    let url;
    try { url = new URL(options?.url); } catch { return refusal('origin'); }
    if (url.protocol !== 'https:' || url.username || url.password || url.hash) return refusal('origin');
    const method = String(options.method ?? 'GET').toUpperCase();
    if (revocation(url)) return refusal('revocation');
    if (SIGN_IN.has(`${method} ${url.href}`)) return {allowed: true, kind: 'signin', write: false, method};
    if (test === null) return refusal('outside_test');
    if (!rule) return refusal('no_rule');
    const request = parse(url, options);
    if (request.allowed === false) return request;
    let verdict;
    try { verdict = rule.route(request, view()); }
    catch (error) { return refusal(typeof error?.guardRule === 'string' ? error.guardRule : 'invalid'); }
    if (!record(verdict) || typeof verdict.write !== 'boolean') return refusal('invalid');
    if (verdict.write && (state.testWrites[test] ?? 0) >= LIMITS.testWrites) return refusal('test_cap');
    if (verdict.write && state.writes >= LIMITS.runWrites) return refusal('run_cap');
    return {allowed: true, kind: verdict.write ? 'write' : 'read', write: verdict.write, method, ...(verdict.creates ? {creates: verdict.creates, ...(verdict.createdKey ? {createdKey: verdict.createdKey} : {})} : {}), ...(verdict.calendar ? {calendar: true} : {}),
      ...(verdict.creates && record(verdict.also) ? {also: {kind: String(verdict.also.kind), field: String(verdict.also.field)}} : {}), ...(verdict.lists ? {lists: true} : {})};
  }
  /** The requester: check() first; a refusal never reaches `inner`. Counters are saved before the send and the trace before the answer returns. */
  function wrap(inner) {
    if (typeof inner !== 'function') throw new Error('The live guard wraps a requester function.');
    return async function guarded(options) {
      const verdict = check(options);
      if (!verdict.allowed) throw Object.assign(new Error(verdict.words), {sent: false, code: 'action_refused', details: {reason: 'live_guard', rule: verdict.rule}});
      if (verdict.kind === 'signin') return inner(options);
      const active = test, entry = {test: active, method: verdict.method, path: new URL(options.url).pathname, bodyHmac: bodyDigest(options.body), status: null, identity: null};
      if (verdict.write) { state.writes++; state.testWrites[active] = (state.testWrites[active] ?? 0) + 1; }
      if (verdict.calendar) state.calendarsMade++;
      save();
      let response;
      try { response = await inner(options); }
      catch (error) { state.trace.push(entry); save(); throw error; }
      entry.status = Number.isSafeInteger(response?.status) ? response.status : null;
      const id = verdict.creates && entry.status >= 200 && entry.status < 300 ? createdId(response?.data, verdict.createdKey) : null;
      // F10.17: a GitHub pull request is also recorded by its number, which its merge path names.
      const number = verdict.creates === 'pull' && Number.isSafeInteger(response?.data?.number) ? {number: String(response.data.number)} : {};
      if (id !== null) { state.created.push({id, test: active, kind: verdict.creates, ...number}); entry.identity = identityOf(id); }
      // F10.19: what the answer names beside it (a new comment's discussion), once, so a later reply may name it.
      const also = id !== null && verdict.also ? createdId({id: response.data[verdict.also.field]}) : null;
      if (also !== null && !state.created.some(item => item.kind === verdict.also.kind && item.id === also)) state.created.push({id: also, test: active, kind: verdict.also.kind});
      // F10.15: a sent message's thread is the run's own too, once; a synthetic search's answer is what a read may reach of the mailbox.
      const thread = id !== null && verdict.creates === 'message' ? createdId({id: response?.data?.threadId}) : null;
      if (thread !== null && !made('thread').includes(thread)) state.created.push({id: thread, test: active, kind: 'thread'});
      if (verdict.lists && entry.status >= 200 && entry.status < 300) {
        for (const item of Array.isArray(response?.data?.messages) ? response.data.messages : []) {
          const found = createdId(item), inThread = record(item) ? createdId({id: item.threadId}) : null;
          if (found !== null) listed.messages.add(found);
          if (inThread !== null) listed.threads.add(inThread);
        }
      }
      state.trace.push(entry);
      save();
      return response;
    };
  }
  return Object.freeze({appId, runId, check, wrap,
    begin(id) {
      if (typeof id !== 'string' || !TEST_ID.test(id)) throw new Error('A test id is a short name such as C2.');
      if (test !== null) throw new Error('A test is already running: end it first.');
      test = id;
    },
    end() { test = null; oneTimeAsk = null; },
    beginOneTimeAsk(row) {
      if (test === null) throw new Error('A one-time Ask runs inside a test.');
      if (typeof row !== 'string' || !ROW_ID.test(row)) throw new Error('A one-time Ask names its row by id.');
      oneTimeAsk = row;
    },
    endOneTimeAsk() { oneTimeAsk = null; },
    /** The owner's address, time zone and run date, and the values recorded before the run. Fixed for the run once set. */
    setOwner({email, timeZone, runDate, recorded = {}} = {}) {
      if (typeof email !== 'string' || !EMAIL.test(email) || email.length > 320) throw new Error('The owner\'s address must be an email address.');
      if (!validZone(timeZone)) throw new Error('The owner\'s time zone must be an IANA time zone name.');
      if (!validDate(runDate)) throw new Error('The run date must be a real date, YYYY-MM-DD.');
      if (!record(recorded) || Object.keys(recorded).length > 20 || Object.entries(recorded).some(([name, value]) => !/^[A-Za-z][A-Za-z0-9]{0,39}$/.test(name) || typeof value !== 'string' || !value || value.length > 1024)) {
        throw new Error('Recorded values are named text values.');
      }
      const owner = {email: email.toLowerCase(), timeZone, runDate, recorded: {...recorded}};
      if (state.owner && JSON.stringify(state.owner) !== JSON.stringify(owner)) throw new Error('The run\'s owner, time zone, date and recorded values are fixed for this run.');
      state.owner = owner;
      save();
    },
    /** A copy of the run's owner as setOwner() fixed it (read back from the run's file on a resume), or null before. */
    owner() { return state.owner ? {...state.owner, recorded: {...state.owner.recorded}} : null; },
    /** The live tokens of this provider and scope set Muse counted elsewhere (S7.13's paper log), asked before a connect link. */
    setElsewhere(providerId, scopes, count) {
      if (typeof providerId !== 'string' || !Number.isSafeInteger(count) || count < 0 || count > 100) throw new Error('Give the number of live tokens elsewhere as a whole number.');
      elsewhere.set(`${providerId} ${scopeSet(scopes).join(' ')}`, count);
    },
    /** Before a sign-in URL is made: GitHub's counts from the folder's file log, read on every call; other providers are not counted. */
    signIn(providerId, scopes) {
      if (providerId !== 'github') return;
      const set = scopeSet(scopes), now = clock(), refused = rule => Object.assign(new Error(GUARD_WORDS[rule]), {code: 'rate_limited', details: {reason: 'live_guard', rule}});
      signIns = readSignIns(signInPath);
      const github = signIns.signIns.filter(entry => entry.providerId === 'github');
      if (github.filter(entry => now - Date.parse(entry.at) < HOUR).length >= LIMITS.githubHourly) throw refused('github_hourly');
      const counted = elsewhere.get(`github ${set.join(' ')}`);
      if (counted === undefined) throw refused('github_elsewhere');
      const lifetime = github.filter(entry => Array.isArray(entry.scopes) && entry.scopes.join(' ') === set.join(' ')).length;
      if (lifetime + counted + 1 >= LIMITS.githubTokens) throw refused('github_tokens');
      signIns.signIns.push({providerId, scopes: set, at: new Date(now).toISOString()});
      writeSecret(signInPath, signIns);
    },
    /** The logged requests of one test: method, path, body HMAC, provider status and created identity. Never a header or a body. */
    trace(id) { return state.trace.filter(entry => entry.test === id).map(({test: _, ...entry}) => ({...entry})); },
    created() { return state.created.map(item => ({...item})); },
    counts() { return {writes: state.writes, testWrites: {...state.testWrites}, calendarsMade: state.calendarsMade}; },
  });
}

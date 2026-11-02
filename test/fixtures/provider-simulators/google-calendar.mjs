// F10.13 part 1 (docs/F10.13-BUILD-MAP.md part 1): a Google Calendar simulator for the Calendar actions' tests. It is written from Google's
// Calendar API v3 reference (the Discovery document and the Calendar guides) and from this comment, and it imports only node built-ins:
// never lib/, catalog/, Calendar's action file or the scope facts fixture, so an action bug and a simulator bug cannot cancel out. Test
// data only: nothing in lib/ imports it, and nothing here calls Google.
//
// The service: https://www.googleapis.com/calendar/v3 (ORIGIN and BASE). One account, the owner {email, zone}: its primary calendar has the
// owner's address as its id and the owner's zone, and "primary" names it in every path. Routes (named "METHOD /template" below the base,
// as the switches take them), each with the scopes the Discovery document lists for it:
//   GET    /users/me/calendarList                     list entries, 100 a page (maxResults 1 to 250, pageToken)
//   GET    /users/me/calendarList/{calendarId}        one entry; "primary" resolves
//   GET    /users/me/settings/{setting}               only "timezone" ({value: the owner's zone}); any other setting answers 404
//   GET    /calendars/{calendarId}/events             list (below); GET .../events/{eventId} one event or one instance
//   POST   /calendars/{calendarId}/events             insert; POST .../events/quickAdd?text quick add
//   PATCH  /calendars/{calendarId}/events/{eventId}   patch; PUT the same path is update; DELETE the same path deletes
//   POST   /calendars/{calendarId}/events/{eventId}/move?destination
//   POST   /freeBusy                                  a read: it changes nothing and is recorded as one
//   POST   /calendars, GET /calendars/{calendarId}, DELETE /calendars/{calendarId}
//   GET    /calendars/{calendarId}/acl                list rules, 100 a page (maxResults 1 to 250, pageToken), a writer or an owner only
//   GET    /calendars/{calendarId}/acl/{ruleId}, DELETE /calendars/{calendarId}/acl/{ruleId}
// Scopes whose grant depends on the object (calendar.app.created, calendar.events.owned and their read twins, calendar.events.freebusy,
// calendar.events.public.readonly) are left out of the table: a token holding only those is refused, stricter than Google, never looser.
//
// Errors use Google's shape {error: {code, message, errors: [{domain, reason, message}]}}. Without "Authorization: Bearer <token>" every
// route answers 401 (reason authError, status UNAUTHENTICATED); a route whose scopes the token lacks answers 403 insufficientPermissions
// (status PERMISSION_DENIED); an unknown route, calendar, event or rule answers 404 notFound. Nothing a refused request names changes.
//
// Events, as Google documents them:
// - Insert takes start and end, each {dateTime} or {date} and never both, the two of the same form, with an optional IANA timeZone. A
//   dateTime is RFC 3339; without an offset it needs timeZone and is read as wall time there. The end must be after the start: an all-day
//   end is exclusive, so an end equal to the start answers 400 timeRangeEmpty. A recurring timed event needs timeZone on start and end
//   (else 400 "Missing time zone definition for start time." or "... end time."). Recurrence is one RRULE line with FREQ=DAILY or WEEKLY
//   and COUNT, UNTIL, INTERVAL and BYDAY (plain weekdays); any other recur part, value or line answers 400, so no test trusts an expansion
//   the simulator cannot do. Each version of an event has an etag field and the same ETag header, and every change moves it. The
//   organizer is the calendar (the owner on the primary calendar, else the calendar with its summary as displayName), the creator the
//   owner, eventType "default" unless seed() sets another. Ids are base32hex. Fields not named here are ignored, as read-only ones are.
// - Times are shown in the calendar's zone, or the timeZone a get or list names; start and end keep their own timeZone field. An offset of
//   zero is written Z.
// - Meet: conferenceData.createRequest is read only with conferenceDataVersion=1 (with 0 or none it is ignored, as documented). Its
//   conferenceSolutionKey type must be hangoutsMeet. The conference has status success, an id derived from the requestId and the order
//   it was made in, and a hangoutLink; a requestId seen before creates no second conference: the event gets the one already made.
// - Quick add: Google does not document its parser, so this grammar is the simulator's own: "<title> on YYYY-MM-DD at H[:MM]am|pm to
//   H[:MM]am|pm", in the calendar's zone. Any other text becomes a one-hour event at the next whole hour, with the text as its title.
// - List: singleEvents=true expands a series into instances in the event's own zone, so 10:00 stays 10:00 across a daylight-saving
//   change; an instance id is "<eventId>_<start in UTC, YYYYMMDDTHHMMSSZ>" (or "_YYYYMMDD" all day) with recurringEventId and
//   originalStartTime. Without singleEvents a series is listed once. orderBy=startTime without singleEvents=true answers 400. timeMin
//   bounds an event's end and timeMax its start, both exclusive (an all-day event spans its days in the calendar's zone). q matches every
//   word, in any case, in the summary, description, location or an attendee's email. maxResults (1 to 2,500, default 250) and pageToken
//   page. maxAttendees on a get or list keeps only the caller's own entry when there are more, with attendeesOmitted. Cancelled events
//   are left out unless showDeleted=true: then a cancelled event is listed, and with singleEvents=true a cancelled series is its
//   occurrences, never the series itself. An invitation hidden from the calendar is left out unless showHiddenInvitations=true. All event
//   types are listed.
// - Get: a deleted event answers 200 with status cancelled, or 404 or 410 under deletedAs(status).
// - Patch and update (PUT): an If-Match that is not the current etag answers 412 conditionNotMet and changes nothing; with none the
//   change applies (Google does not require it). Patch replaces each top-level field it names (null clears one); update replaces the whole
//   event and needs start and end. attendees replaces the list (an entry without responseStatus keeps the one it had); with
//   attendeesOmitted: true only the listed attendees change. A caller who is not the organizer (an invitation) may change only their own
//   responseStatus, else 403 forbiddenForNonOrganizer.
// - sendUpdates, on insert, quick add, patch, update, delete and move, must be all, externalOnly or none (else 400 invalidParameter);
//   none or no value emails nobody. all records one notification per guest (not the owner, not the organizer); externalOnly only guests
//   outside the owner's domain. A guest's own answer, with all or externalOnly, notifies the organizer.
// - Move: the destination must be a calendar the owner can write (403 requiredAccessLevel, or 404); only a default event moves (else 400
//   eventTypeRestriction and it stays); a moved event keeps its id and gets the destination as organizer. Only the organizer moves it.
//   The move answers with one etag and the event then reads back with a newer one, as Google does (live run TOQJPGEU, C8).
// - Delete: 204; a second delete answers 410 deleted, and a deleted series cancels the occurrences written apart from it.
// - One occurrence: a write on an instance id makes an exception, an item with that id, recurringEventId and originalStartTime, which takes
//   that occurrence's place in every list. A move of an instance answers 400 cannotChangeOrganizerOfInstance.
// - POST /freeBusy {timeMin, timeMax, timeZone?, items}: {kind, timeMin, timeMax, calendars: {<id as asked>: {busy}}} from opaque,
//   confirmed events, instances expanded, clipped to the window and merged; times in UTC, or in timeZone. A calendar the owner does not
//   have gets {errors: [{domain: 'global', reason: 'notFound'}], busy: []}.
// - Calendars: insert (summary required; id c_<64 hex>@group.calendar.google.com; the owner's zone unless timeZone; an owner list entry
//   and the owner's own ACL rule), get, and delete (the primary answers 400 cannotDeletePrimaryCalendar; only an owner deletes, else 403
//   forbidden; its events and rules go with it). ACL: get and delete of user:<email> rules; a deleted rule answers 404; only the
//   calendar's owner deletes one (else 403 forbidden).
//
// Change feeds (the Calendar sync guide): events.list with none of the eight parameters refused beside a sync token, calendarList.list and
// acl.list each read one log, per calendar for events and rules, and one for the list. The log holds an item's newest change, so a delta shows
// each item once in its current state, in the order it last moved. A list with no token is a full read and leaves out what has gone. Its last
// page carries nextSyncToken and any other page nextPageToken, never both, and an empty delta still answers a token. A token is opaque and
// binds its feed and the whole query but syncToken and pageToken. An old token stays good until expireToken(), so a poll can be replayed.
//   400 a refused parameter beside a token, showDeleted=false or showHidden=false beside one, a query that differs from the token's, a damaged token
//   410 a token expireToken() ended, with Google's body: domain calendar, reason fullSyncRequired, location syncToken. It is unconnected to age
// A cancelled item stays in the log. The organizer's copy keeps its details. Any other copy, and the entry a move leaves on its source
// calendar, holds its id and status alone, and a cancelled occurrence holds those with recurringEventId and originalStartTime. A move also
// writes the event on its destination, with the same id. A removed rule reads role none, and a removed list entry deleted: true.
//
// The fields parameter is a partial response on any route, applied to a 2xx answer: a,b(c,d),e/f and *. A mask that does not parse, or that
// names no field of an events list, answers 400 invalidParameter and changes nothing.
//
// The network contract is lib/network.mjs's seam: `request` takes its options and answers {status, headers, data}. Refused before
// sending, with sent false: a URL that is not https on 443 or carries credentials, an origin outside allowedOrigins or not Google's, an
// unsupported method or response handling, an unsafe header, a body that is not a string or Buffer, a body over 1 MiB. After sending,
// with sent true: an answer over maxBytes, and drop(). A path on Google's origin outside the base answers 404. Only the response headers
// asked for come back (the seam's default list when none are named).
//
// Every request that reaches the simulator is recorded in `calls`, without its Authorization header: {method, origin, path (below the
// base), route, query, headers, body, write, status}. writes() and reads() are the calls to write and read routes; state() is a copy of
// the state; notifications() the emails Google would have sent. Switches, each for the next call to one route unless {times} says how
// many: fail(route, {status, headers?, data?}) answers that instead and changes nothing; drop(route) applies the call, then throws as a
// lost answer; swallow(route) answers as if applied but changes nothing; oversize(route, bytes) pads the answer; hold(route) returns
// {reached, release()}. Test data: touch(calendarId, eventId) is someone else changing the event (its etag moves); invite(event) adds an
// event another account organizes on the primary calendar, with the owner as a guest; seed(calendarId, event, {eventType}) inserts one
// unrecorded; addCalendar(entry) gives the owner another account's calendar at an access role; share(calendarId, email, role) adds a rule;
// deletedAs(200 | 404 | 410) sets how a deleted event reads back. For the feeds: invite({calendarId, hidden}) puts an invitation on any calendar;
// guestResponds(calendarId, eventId, email, status) is a guest answering, and moves the etag and updated; setReminders(calendarId, eventId,
// reminders) moves the etag and not updated; share() and sharePublic() add rules and unshare() removes one; hideCalendar(), recolor() and
// leaveCalendar() change the owner's list, and changeRole() moves the owner's access with no entry in the list's sync feed; expireToken(calendarId, {feed}) ends a feed's tokens; shortPage(n) makes the next page of a feed hold
// n items and a next page, n = 0 for an empty one; redeliver(n) repeats the last n items in the next delta; rateLimit(route, {status, times})
// answers Google's usageLimits refusal, at 403 or 429, with no Retry-After.
import {createHash} from 'node:crypto';

export const ORIGIN = 'https://www.googleapis.com';
export const BASE = `${ORIGIN}/calendar/v3`;
const BASE_PATH = '/calendar/v3';
const DEFAULT_RESPONSE_HEADERS = ['content-type', 'etag', 'retry-after', 'x-ratelimit-remaining'];
const UNSAFE_HEADER = /^(host|connection|transfer-encoding|content-length|upgrade|proxy-.*|forwarded|x-forwarded-.*)$/i;
const AUTH = 'https://www.googleapis.com/auth/';
const scopes = (...names) => names.map(name => `${AUTH}${name}`);
const EVENTS_READ = scopes('calendar', 'calendar.events', 'calendar.events.readonly', 'calendar.readonly');
const EVENTS_WRITE = scopes('calendar', 'calendar.events');
const SEND_UPDATES = new Set(['all', 'externalOnly', 'none']);
const RESPONSES = new Set(['needsAction', 'declined', 'tentative', 'accepted']);
const WRITERS = new Set(['owner', 'writer']);
const DAYS = ['MO', 'TU', 'WE', 'TH', 'FR', 'SA', 'SU'];
const DAY_MS = 86_400_000, HOUR_MS = 3_600_000;
/** How many instances one series yields at most, and how many days its expansion walks. */
const MAX_INSTANCES = 730, MAX_DAYS = 7320;
const EMAIL = /^[^\s@]+@[^\s@]+$/;
/** The parameters Google refuses beside a sync token, on events.list and on calendarList.list. */
const NOT_BESIDE_TOKEN = Object.freeze(['iCalUID', 'orderBy', 'privateExtendedProperty', 'q', 'sharedExtendedProperty', 'timeMin', 'timeMax', 'updatedMin']);
const LIST_NOT_BESIDE_TOKEN = Object.freeze(['minAccessRole', 'showOwnOrganizationOnly']);
const namesOf = text => Object.fromEntries(text.split(' ').map(name => [name, true]));
/** The fields a mask on an events list may name. Below these, a mask reads what is there. */
const EVENT_LIST_FIELDS = Object.freeze({...namesOf('kind etag summary description updated timeZone accessRole defaultReminders nextPageToken nextSyncToken'),
  items: namesOf('kind etag id status htmlLink created updated summary description location creator organizer start end recurrence recurringEventId originalStartTime transparency iCalUID attendees attendeesOmitted hangoutLink conferenceData eventType reminders')});

const notSent = message => Object.assign(new Error(message), {sent: false});
const lost = message => Object.assign(new Error(message), {sent: true});
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const hex = text => createHash('sha256').update(text).digest('hex');
const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
const STATUS = {401: 'UNAUTHENTICATED', 403: 'PERMISSION_DENIED'};
const googleError = (code, reason, message, {domain = 'global', status = false, ...where} = {}) =>
  ({status: code, data: {error: {code, message, errors: [{domain, reason, message, ...where}], ...(status ? {status: STATUS[code]} : {})}}});
/** A refusal a handler throws: the Google error it answers with. Handlers check everything before they change anything. */
class Refusal extends Error { constructor(answer) { super(answer.data.error.message); this.answer = answer; } }
const refuse = (code, reason, message, extra) => { throw new Refusal(googleError(code, reason, message, extra)); };
const notFound = () => refuse(404, 'notFound', 'Not Found');
const ok = (data, headers = {}) => ({status: 200, headers, data});
const newLog = () => ({at: 0, epoch: 0, items: {}, gone: {}});
/** What a query says apart from where it stands: the part a sync token binds. */
const bindingOf = query => hex(canonical([...query].filter(([name]) => !['syncToken', 'pageToken'].includes(name)).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))).slice(0, 16);

// ---- partial responses -----------------------------------------------------------------------------------------------------------------
/** A fields mask as a tree: each name maps to true or the tree below it. A mask that does not parse answers 400. */
function maskOf(text) {
  let at = 0;
  const bad = () => refuse(400, 'invalidParameter', `Invalid field selection ${text.slice(0, 64)}`, {locationType: 'parameter', location: 'fields'});
  const name = () => {
    const match = /^(?:\*|[A-Za-z][A-Za-z0-9_]*)/.exec(text.slice(at));
    if (!match) bad();
    at += match[0].length;
    return match[0];
  };
  const selection = () => {
    const tree = {};
    for (;;) {
      let node = tree, part = name();
      while (text[at] === '/') {
        at++;
        node = node[part] = record(node[part]) ? node[part] : {};
        part = name();
      }
      if (text[at] === '(') {
        at++;
        node[part] = selection();
        if (text[at++] !== ')') bad();
      } else node[part] = true;
      if (text[at] !== ',') return tree;
      at++;
    }
  };
  const tree = selection();
  if (at !== text.length) bad();
  return tree;
}
/** Refuses a name a mask reads that the answer's fields do not hold, as far down as `known` says. */
function checkMask(tree, known, text) {
  for (const [name, below] of Object.entries(tree)) {
    if (name === '*') continue;
    if (!Object.hasOwn(known, name)) refuse(400, 'invalidParameter', `Invalid field selection ${name}`, {locationType: 'parameter', location: 'fields'});
    if (record(known[name]) && record(below)) checkMask(below, known[name], text);
  }
}
/** An answer with only what a mask names. */
function masked(value, tree) {
  if (tree === true || tree['*'] || value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(item => masked(item, tree));
  return Object.fromEntries(Object.entries(value).filter(([name]) => Object.hasOwn(tree, name)).map(([name, item]) => [name, masked(item, tree[name])]));
}

// ---- time ------------------------------------------------------------------------------------------------------------------------------
const FORMATS = new Map();
/** The wall time of an instant in a zone. */
function wallOf(ms, zone) {
  let format = FORMATS.get(zone);
  if (!format) {
    format = new Intl.DateTimeFormat('en-US', {timeZone: zone, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit'});
    FORMATS.set(zone, format);
  }
  const parts = Object.fromEntries(format.formatToParts(new Date(ms)).map(part => [part.type, part.value]));
  return {year: Number(parts.year), month: Number(parts.month), day: Number(parts.day), hour: Number(parts.hour) % 24, minute: Number(parts.minute), second: Number(parts.second)};
}
/** The zone's offset from UTC at an instant, in minutes. */
function offsetOf(ms, zone) {
  const whole = Math.floor(ms / 1000) * 1000, wall = wallOf(whole, zone);
  return Math.round((Date.UTC(wall.year, wall.month - 1, wall.day, wall.hour, wall.minute, wall.second) - whole) / 60_000);
}
/** The instant a wall time names in a zone. */
function instantOf({year, month, day, hour = 0, minute = 0, second = 0}, zone) {
  const guess = Date.UTC(year, month - 1, day, hour, minute, second), first = guess - offsetOf(guess, zone) * 60_000;
  return guess - offsetOf(first, zone) * 60_000;
}
const pad = (value, size = 2) => String(value).padStart(size, '0');
const dateText = ({year, month, day}) => `${pad(year, 4)}-${pad(month)}-${pad(day)}`;
/** RFC 3339 in a zone, the offset Z when it is zero. */
function formatInstant(ms, zone) {
  const wall = wallOf(ms, zone), offset = offsetOf(ms, zone), size = Math.abs(offset);
  return `${dateText(wall)}T${pad(wall.hour)}:${pad(wall.minute)}:${pad(wall.second)}${offset === 0 ? 'Z' : `${offset < 0 ? '-' : '+'}${pad(Math.floor(size / 60))}:${pad(size % 60)}`}`;
}
const iso = ms => new Date(ms).toISOString();
function validZone(zone) {
  if (typeof zone !== 'string' || !/^[A-Za-z][A-Za-z0-9_+-]*(\/[A-Za-z0-9_+-]+)*$/.test(zone)) return false;
  try { new Intl.DateTimeFormat('en-US', {timeZone: zone}); return true; } catch { return false; }
}
/** A YYYY-MM-DD date's parts, or null when it is not a real date. */
function dateParts(text) {
  const match = typeof text === 'string' ? /^(\d{4})-(\d{2})-(\d{2})$/.exec(text) : null;
  if (!match) return null;
  const [year, month, day] = match.slice(1).map(Number), ms = Date.UTC(year, month - 1, day);
  const back = new Date(ms);
  return back.getUTCFullYear() === year && back.getUTCMonth() === month - 1 && back.getUTCDate() === day ? {year, month, day} : null;
}
const addDays = (date, days) => dateText((ms => ({year: ms.getUTCFullYear(), month: ms.getUTCMonth() + 1, day: ms.getUTCDate()}))(new Date(Date.parse(`${date}T00:00:00Z`) + days * DAY_MS)));
const daysBetween = (from, to) => Math.round((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / DAY_MS);
const weekdayOf = date => DAYS[(new Date(`${date}T00:00:00Z`).getUTCDay() + 6) % 7];
/**
 * An RFC 3339 date-time as an instant. With no offset it is wall time in `zone`, and without a zone it is refused (null), as it is when a
 * part is out of range. `needOffset` refuses one with no offset whatever the zone (timeMin, timeMax, freeBusy).
 */
function parseDateTime(text, zone, {needOffset = false} = {}) {
  const match = typeof text === 'string' ? /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})?$/i.exec(text) : null;
  if (!match) return null;
  const date = dateParts(`${match[1]}-${match[2]}-${match[3]}`), [hour, minute, second] = [match[4], match[5], match[6]].map(Number);
  if (!date || hour > 23 || minute > 59 || second > 59) return null;
  const fraction = match[7] ? Math.floor(Number(`0${match[7]}`) * 1000) : 0;
  if (match[8]) {
    const offset = /^z$/i.test(match[8]) ? 0 : (match[8][0] === '-' ? -1 : 1) * (Number(match[8].slice(1, 3)) * 60 + Number(match[8].slice(4, 6)));
    return Date.UTC(date.year, date.month - 1, date.day, hour, minute, second, fraction) - offset * 60_000;
  }
  if (needOffset || !validZone(zone)) return null;
  return instantOf({...date, hour, minute, second}, zone) + fraction;
}
const utcStamp = ms => iso(ms).replace(/[-:]/g, '').replace(/\.\d{3}/, '');

// ---- recurrence ------------------------------------------------------------------------------------------------------------------------
/** The one RRULE line a series may carry, parsed; null for no recurrence. Anything the simulator cannot expand answers 400. */
function ruleOf(recurrence) {
  if (recurrence === undefined || recurrence === null || (Array.isArray(recurrence) && recurrence.length === 0)) return null;
  const bad = () => refuse(400, 'invalid', 'Invalid recurrence rule.');
  if (!Array.isArray(recurrence) || recurrence.length !== 1 || typeof recurrence[0] !== 'string') bad();
  const match = /^RRULE:(.+)$/.exec(recurrence[0]);
  if (!match) bad();
  const rule = {interval: 1}, seen = new Set();
  for (const part of match[1].split(';')) {
    const [key, value, ...rest] = part.split('=');
    if (rest.length || !value || seen.has(key)) bad();
    seen.add(key);
    if (key === 'FREQ') { if (!['DAILY', 'WEEKLY'].includes(value)) bad(); rule.freq = value; }
    else if (key === 'COUNT') { if (!/^[1-9][0-9]{0,3}$/.test(value)) bad(); rule.count = Number(value); }
    else if (key === 'INTERVAL') { if (!/^[1-9][0-9]{0,2}$/.test(value)) bad(); rule.interval = Number(value); }
    else if (key === 'UNTIL') {
      const until = /^(\d{4})(\d{2})(\d{2})(?:T(\d{2})(\d{2})(\d{2})Z)?$/.exec(value), date = until ? dateParts(`${until[1]}-${until[2]}-${until[3]}`) : null;
      if (!date) bad();
      rule.until = {date: dateText(date), ms: until[4] === undefined ? null : Date.UTC(date.year, date.month - 1, date.day, Number(until[4]), Number(until[5]), Number(until[6]))};
    } else if (key === 'BYDAY') {
      const days = value.split(',');
      if (days.some(day => !DAYS.includes(day)) || new Set(days).size !== days.length) bad();
      rule.byday = days;
    } else bad();
  }
  if (!rule.freq || (rule.count && rule.until)) bad();
  return rule;
}
/** The starts of a series, in order, expanded in the event's own zone: {date, ms} (ms null all day), stopping before `before`. */
function startsOf(event, before = Infinity) {
  const rule = event.rule, timed = event.start.kind === 'dateTime', zone = timed ? event.start.timeZone : null;
  const wall = timed ? wallOf(event.start.ms, zone) : null, first = timed ? dateText(wall) : event.start.date, monday = addDays(first, -DAYS.indexOf(weekdayOf(first)));
  const starts = [];
  for (let offset = 0; offset < MAX_DAYS && starts.length < MAX_INSTANCES; offset++) {
    const date = addDays(first, offset), weekday = weekdayOf(date);
    const fits = rule.freq === 'DAILY' ? offset % rule.interval === 0 && (!rule.byday || rule.byday.includes(weekday))
      : Math.floor(daysBetween(monday, date) / 7) % rule.interval === 0 && (rule.byday ? rule.byday.includes(weekday) : weekday === weekdayOf(first));
    if (!fits) continue;
    const ms = timed ? instantOf({...dateParts(date), hour: wall.hour, minute: wall.minute, second: wall.second}, zone) : null;
    if (rule.until && (timed && rule.until.ms !== null ? ms > rule.until.ms : date > rule.until.date)) break;
    if ((timed ? ms : Date.parse(`${date}T00:00:00Z`)) >= before) break;
    starts.push({date, ms});
    if (rule.count && starts.length >= rule.count) break;
  }
  return starts;
}
/** One occurrence of a series as a time pair, with its instance stamp. */
function occurrence(event, {date, ms}) {
  if (event.start.kind === 'dateTime') {
    return {stamp: utcStamp(ms), start: {...event.start, ms}, end: {...event.end, ms: ms + (event.end.ms - event.start.ms)}};
  }
  return {stamp: date.replace(/-/g, ''), start: {...event.start, date}, end: {...event.end, date: addDays(date, daysBetween(event.start.date, event.end.date))}};
}

// ---- events ----------------------------------------------------------------------------------------------------------------------------
/** A start or end as sent: {kind: 'date', date} or {kind: 'dateTime', ms}, each with its timeZone when given. */
function timeOf(value, which) {
  if (value === undefined || value === null) refuse(400, 'required', `Missing ${which} time.`);
  if (!record(value)) refuse(400, 'invalid', `Invalid ${which} time.`);
  const hasDate = value.date !== undefined && value.date !== null, hasDateTime = value.dateTime !== undefined && value.dateTime !== null;
  if (hasDate === hasDateTime) refuse(400, 'invalid', `Invalid ${which} time.`);
  if (value.timeZone !== undefined && value.timeZone !== null && !validZone(value.timeZone)) refuse(400, 'invalid', `Invalid time zone definition for ${which} time.`);
  const zone = value.timeZone ?? undefined, kept = zone === undefined ? {} : {timeZone: zone};
  if (hasDate) {
    if (!dateParts(value.date)) refuse(400, 'invalid', `Invalid ${which} time.`);
    return {kind: 'date', date: value.date, ...kept};
  }
  const ms = parseDateTime(value.dateTime, zone);
  if (ms === null) refuse(400, 'invalid', typeof value.dateTime === 'string' && !/(Z|[+-]\d{2}:\d{2})$/i.test(value.dateTime) && zone === undefined ? `Missing time zone definition for ${which} time.` : `Invalid ${which} time.`);
  return {kind: 'dateTime', ms, ...kept};
}
/** The checks every version of an event passes: one form for both ends, a zone on a timed series, an end after the start. */
function checkTimes(event) {
  if (event.start.kind !== event.end.kind) refuse(400, 'invalid', 'Start and end times must either both be date or both be dateTime.');
  if (event.rule && event.start.kind === 'dateTime') {
    if (!event.start.timeZone) refuse(400, 'invalid', 'Missing time zone definition for start time.');
    if (!event.end.timeZone) refuse(400, 'invalid', 'Missing time zone definition for end time.');
  }
  if (event.start.kind === 'date' ? event.end.date <= event.start.date : event.end.ms <= event.start.ms) refuse(400, 'timeRangeEmpty', 'The specified time range is empty.');
}
const text = (value, name) => {
  if (value !== null && typeof value !== 'string') refuse(400, 'invalid', `Invalid value for: ${name}`);
  return value;
};
/** An attendee as sent: an email and the fields Google keeps per attendee. */
function attendeeOf(item) {
  if (!record(item) || typeof item.email !== 'string' || !EMAIL.test(item.email)) refuse(400, 'invalid', 'Invalid attendee email.');
  if (item.responseStatus !== undefined && !RESPONSES.has(item.responseStatus)) refuse(400, 'invalid', 'Invalid attendee response status.');
  if (item.optional !== undefined && typeof item.optional !== 'boolean') refuse(400, 'invalid', 'Invalid value for: attendees.optional');
  return {email: item.email, ...(typeof item.displayName === 'string' ? {displayName: item.displayName} : {}), ...(item.responseStatus ? {responseStatus: item.responseStatus} : {}),
    ...(item.optional !== undefined ? {optional: item.optional} : {}), ...(typeof item.comment === 'string' ? {comment: item.comment} : {})};
}
/** One attendee as it stands after a change: the given fields over the ones it had; a new attendee needs action. */
function mergeAttendee(old, given) {
  const merged = {...(old ?? {email: given.email, responseStatus: 'needsAction'}), ...given};
  merged.responseStatus = given.responseStatus ?? old?.responseStatus ?? 'needsAction';
  if (merged.optional === false) delete merged.optional;
  return merged;
}
/** The attendee list after a change: the list replaced, or with attendeesOmitted only the listed attendees changed (or added). */
function attendeesAfter(current, list, omitted) {
  if (list === null) return [];
  if (!Array.isArray(list)) refuse(400, 'invalid', 'Invalid value for: attendees');
  const given = list.map(attendeeOf);
  if (new Set(given.map(item => item.email.toLowerCase())).size !== given.length) refuse(400, 'invalid', 'Duplicate attendee.');
  const find = (items, email) => items.find(item => same(item.email, email));
  if (!omitted) return given.map(item => mergeAttendee(find(current, item.email), item));
  return [...current.map(item => find(given, item.email) ? mergeAttendee(item, find(given, item.email)) : item), ...given.filter(item => !find(current, item.email)).map(item => mergeAttendee(null, item))];
}
/** True when the calendar the event is on organizes it (the owner's own event), false for an invitation. */
const organizes = event => same(event.organizer.email, event.calendarId);
/** Sorted-key JSON, so two versions compare by value. */
const canonical = value => JSON.stringify(value, (key, item) => record(item) ? Object.fromEntries(Object.keys(item).sort().map(name => [name, item[name]])) : item);
/** A start or end as a list shows it, in a zone. */
const shownTime = (value, zone) => value.kind === 'date' ? {date: value.date, ...(value.timeZone ? {timeZone: value.timeZone} : {})} : {dateTime: formatInstant(value.ms, zone), ...(value.timeZone ? {timeZone: value.timeZone} : {})};
/** A feed's token or page token: opaque, naming its feed, its place in the log, the log's epoch and the query. */
const tokenOf = (kind, feed, at, epoch, binding) => Buffer.from(JSON.stringify({kind, feed, at, epoch, binding})).toString('base64url');
function tokenRead(text) {
  try {
    const token = JSON.parse(Buffer.from(text, 'base64url').toString('utf8'));
    return record(token) && tokenOf(token.kind, token.feed, token.at, token.epoch, token.binding) === text ? token : null;
  } catch { return null; }
}

export class CalendarSimulator {
  /**
   * clock() gives the time changes carry and quick add reads; token is the bearer token the account sends; owner is {email, zone}; scopes
   * are the token's granted scopes (by default the six of Fabric's Calendar sign-in).
   */
  constructor({clock = () => Date.parse('2026-10-23T13:00:00.000Z'), token = 'calendar-token', owner = {email: 'owner@example.com', zone: 'America/Toronto'},
    scopes: granted = scopes('calendar.events', 'calendar.calendarlist', 'calendar.calendars', 'calendar.acls', 'calendar.settings.readonly', 'calendar.freebusy')} = {}) {
    if (!record(owner) || typeof owner.email !== 'string' || !EMAIL.test(owner.email) || !validZone(owner.zone)) throw new Error('owner is {email, zone} with an IANA zone.');
    this.clock = clock;
    this.token = token;
    this.scopes = new Set(granted);
    this.calls = [];
    this.switches = new Map();
    this.holds = new Map();
    this.deleted = 200;
    this.short = null;
    this.repeats = 0;
    this.data = {owner: {email: owner.email, zone: owner.zone}, calendars: {}, events: {}, acl: {}, conferences: {}, notifications: [], feeds: {}, next: {event: 1, etag: 1, calendar: 1, seq: 1, conference: 1}};
    this.data.calendars[owner.email] = {id: owner.email, summary: owner.email, timeZone: owner.zone, accessRole: 'owner', primary: true, etag: this.#etag(this.data)};
    this.data.acl[owner.email] = {[`user:${owner.email}`]: {role: 'owner', etag: this.#etag(this.data)}};
    this.#mark(this.data, 'list', owner.email);
    this.#mark(this.data, `acl:${owner.email}`, `user:${owner.email}`);
    this.request = this.request.bind(this);
  }
  state() { return structuredClone(this.data); }
  writes() { return this.calls.filter(call => call.write); }
  reads() { return this.calls.filter(call => call.route && !call.write); }
  notifications() { return structuredClone(this.data.notifications); }
  #switch(kind, route, extra = {}, {times = 1} = {}) {
    if (!Number.isSafeInteger(times) && times !== Infinity) throw new Error('times is a whole number or Infinity.');
    this.switches.set(route, {kind, left: times, ...extra});
    return this;
  }
  fail(route, answer, options) { return this.#switch('fail', route, {answer: structuredClone(answer)}, options); }
  drop(route, options) { return this.#switch('drop', route, {}, options); }
  swallow(route, options) { return this.#switch('swallow', route, {}, options); }
  oversize(route, bytes, options) { return this.#switch('oversize', route, {bytes}, options); }
  hold(route) {
    let reach, release;
    const reached = new Promise(resolve => { reach = resolve; }), released = new Promise(resolve => { release = resolve; });
    this.holds.set(route, {reached, released, reach, release: () => { this.holds.delete(route); release(); }});
    return {reached, release: this.holds.get(route).release};
  }
  #take(route) {
    const entry = this.switches.get(route);
    if (!entry) return null;
    if (--entry.left <= 0) this.switches.delete(route);
    return entry;
  }
  /** How a deleted event reads back: 200 with status cancelled (Google's answer), or 404 or 410. */
  deletedAs(status) {
    if (![200, 404, 410].includes(status)) throw new Error('deletedAs takes 200, 404 or 410.');
    this.deleted = status;
    return this;
  }
  /** Ends the tokens of one feed, whatever their age: a calendar's events, its rules with {feed: 'acl'}, or the list with {feed: 'list'}. */
  expireToken(calendarId, {feed = 'events'} = {}) {
    const key = feed === 'list' ? 'list' : `${feed}:${this.#calendar(this.data, calendarId)?.id ?? calendarId}`;
    (this.data.feeds[key] ??= newLog()).epoch++;
    return this;
  }
  /** The next page of any feed holds n items and a next page, whatever is left: n = 0 is an empty page. */
  shortPage(n = 0) { this.short = n; return this; }
  /** The next delta of any feed also holds the last n items a read has already held. */
  redeliver(n = 1) { this.repeats = n; return this; }
  /** The next call to a route answers Google's rate limit, as a 403 or a 429 of domain usageLimits, with no Retry-After. */
  rateLimit(route, {status = 403, times} = {}) {
    return this.fail(route, googleError(status, 'rateLimitExceeded', 'Rate Limit Exceeded', {domain: 'usageLimits'}), times === undefined ? undefined : {times});
  }

  // ---- test data ---------------------------------------------------------------------------------------------------------------------
  #etag(state) { return `"${3_400_000_000_000_000 + state.next.etag++ * 1000}"`; }
  /** Someone else changes the event: its etag and updated time move, so an etag read before is stale. */
  touch(calendarId, eventId) {
    const calendar = this.#calendar(this.data, calendarId), event = calendar ? this.data.events[eventId] : null;
    if (!event || event.calendarId !== calendar.id) throw new Error(`No event ${eventId} on ${calendarId}.`);
    event.etag = this.#etag(this.data);
    event.updated = this.clock();
    this.#mark(this.data, `events:${event.calendarId}`, event.id);
    return this.#render(this.data, event);
  }
  /** One of an event's guests answers: its etag and updated move, and a delta holds it. */
  guestResponds(calendarId, eventId, email, status) {
    const calendar = this.#calendar(this.data, calendarId), event = calendar ? this.data.events[eventId] : null, guest = event?.calendarId === calendar?.id ? event?.attendees.find(item => same(item.email, email)) : null;
    if (!guest || !RESPONSES.has(status)) throw new Error('guestResponds takes a calendar, one of its events, a guest of it and an answer.');
    guest.responseStatus = status;
    this.#commit(this.data, event);
    return this.#render(this.data, event);
  }
  /** Reminders change: the etag moves, and updated does not, as Google documents it. */
  setReminders(calendarId, eventId, reminders) {
    const calendar = this.#calendar(this.data, calendarId), event = calendar ? this.data.events[eventId] : null;
    if (!event || event.calendarId !== calendar.id) throw new Error(`No event ${eventId} on ${calendarId}.`);
    event.reminders = reminders;
    event.etag = this.#etag(this.data);
    this.#mark(this.data, `events:${event.calendarId}`, event.id);
    return this.#render(this.data, event);
  }
  /** An event another account organizes, with the calendar as a guest who has not answered: on the owner's primary calendar unless `calendarId` says otherwise, and with `hidden` left off the calendar. */
  invite({calendarId = this.data.owner.email, summary = 'Invitation', description, start, end, organizer = 'organizer@other.example', attendees = [], recurrence, hidden = false} = {}) {
    const state = this.data, calendar = this.#calendar(state, calendarId);
    if (!calendar) throw new Error(`No calendar ${calendarId}.`);
    const guests = attendees.map(item => attendeeOf(typeof item === 'string' ? {email: item} : item)).map(item => mergeAttendee(null, item));
    const event = {...this.#fresh(calendar, {summary, description, start, end, recurrence}), organizer: {email: organizer}, creator: {email: organizer},
      attendees: [{email: organizer, responseStatus: 'accepted'}, ...guests, {email: calendar.id, responseStatus: 'needsAction'}], ...(hidden ? {hidden: true} : {})};
    checkTimes(event);
    this.#commit(state, event);
    return this.#render(state, event);
  }
  /** Inserts an event as the owner, unrecorded, with an event type Google sets itself (focusTime, outOfOffice, ...) and a client's own id when given. */
  seed(calendarId, resource, {eventType = 'default', id} = {}) {
    const state = this.data, calendar = this.#calendar(state, calendarId);
    if (!calendar) throw new Error(`No calendar ${calendarId}.`);
    const event = {...this.#build(state, calendar, resource, {now: this.clock(), conference: 0}).event, eventType, ...(id ? {id, seq: state.next.seq++} : {})};
    this.#commit(state, event);
    return this.#render(state, event);
  }
  /** Another account's calendar the owner sees, at an access role (freeBusyReader, reader, writer or owner). */
  addCalendar({id, summary = id, timeZone = this.data.owner.zone, accessRole = 'reader'} = {}) {
    if (typeof id !== 'string' || !id || this.data.calendars[id] || !validZone(timeZone) || !['freeBusyReader', 'reader', 'writer', 'owner'].includes(accessRole)) throw new Error('addCalendar takes a new id, a zone and an access role.');
    this.data.calendars[id] = {id, summary, timeZone, accessRole, etag: this.#etag(this.data)};
    this.data.acl[id] = {};
    this.#mark(this.data, 'list', id);
    return this.#entry(this.data.calendars[id]);
  }
  /** A change to the owner's own entry for a calendar. */
  #entryChanged(calendarId, change) {
    const calendar = this.#calendar(this.data, calendarId);
    if (!calendar) throw new Error(`No calendar ${calendarId}.`);
    Object.assign(calendar, change, {etag: this.#etag(this.data)});
    this.#mark(this.data, 'list', calendar.id);
    return this.#entry(calendar);
  }
  /** The owner hides a calendar from the list, or shows it again. */
  hideCalendar(calendarId, hidden = true) { return this.#entryChanged(calendarId, {hidden}); }
  /** A cosmetic change, which only the owner sees: the entry's etag moves. */
  recolor(calendarId, colorId) { return this.#entryChanged(calendarId, {colorId}); }
  /**
   * Someone changes the owner's access to a calendar. Google's calendarList.list page: "If only read-only fields such as calendar properties or ACLs have changed, the entry won't be returned." So the role
   * moves with no log entry, and only a full read or the entry's next change shows it.
   */
  changeRole(calendarId, accessRole) {
    const calendar = this.#calendar(this.data, calendarId);
    if (!calendar) throw new Error(`No calendar ${calendarId}.`);
    calendar.accessRole = accessRole;
    return this;
  }
  /** The owner takes a calendar off the list. */
  leaveCalendar(calendarId) {
    const calendar = this.#calendar(this.data, calendarId);
    if (!calendar) throw new Error(`No calendar ${calendarId}.`);
    this.#unlisted(this.data, calendar.id);
  }
  /** A user rule on a calendar, as someone sharing it in Google Calendar adds one. */
  share(calendarId, email, role = 'reader') {
    const calendar = this.#calendar(this.data, calendarId);
    if (!calendar || !EMAIL.test(email) || !['freeBusyReader', 'reader', 'writer', 'owner'].includes(role)) throw new Error('share takes a calendar, an email and a role.');
    this.data.acl[calendar.id][`user:${email}`] = {role, etag: this.#etag(this.data)};
    this.#mark(this.data, `acl:${calendar.id}`, `user:${email}`);
    return this.#rule(calendar.id, `user:${email}`, this.data.acl[calendar.id][`user:${email}`]);
  }
  /** A public calendar: the one rule of scope default, which holds no value. */
  sharePublic(calendarId, role = 'reader') {
    const calendar = this.#calendar(this.data, calendarId);
    if (!calendar) throw new Error(`No calendar ${calendarId}.`);
    this.data.acl[calendar.id].default = {role, etag: this.#etag(this.data)};
    this.#mark(this.data, `acl:${calendar.id}`, 'default');
    return this.#rule(calendar.id, 'default', this.data.acl[calendar.id].default);
  }
  /** Someone stops sharing a calendar with a person, or with everyone when `email` is null. */
  unshare(calendarId, email = null) {
    const calendar = this.#calendar(this.data, calendarId);
    if (!calendar) throw new Error(`No calendar ${calendarId}.`);
    this.#ruleGone(this.data, calendar.id, email === null ? 'default' : `user:${email}`);
  }

  // ---- shared pieces -----------------------------------------------------------------------------------------------------------------
  /** Writes one change to a feed's log: an item's newest place, and what stands in for it when it has left that feed. */
  #mark(state, feed, id, gone = null) {
    const log = state.feeds[feed] ??= newLog();
    log.items[id] = ++log.at;
    if (gone) log.gone[id] = gone;
    else delete log.gone[id];
  }
  /** A calendar leaves the owner's list: the entry reads deleted in a delta. */
  #unlisted(state, id) {
    this.#mark(state, 'list', id, {etag: this.#etag(state)});
    delete state.calendars[id];
  }
  /** A rule goes: it reads role none in a delta. */
  #ruleGone(state, calendarId, ruleId) {
    this.#mark(state, `acl:${calendarId}`, ruleId, {etag: this.#etag(state)});
    delete state.acl[calendarId][ruleId];
  }
  #calendar(state, id) { return typeof id === 'string' ? state.calendars[id === 'primary' ? state.owner.email : id] ?? null : null; }
  #readable(state, id) { return this.#calendar(state, id) ?? notFound(); }
  #writable(state, id) {
    const calendar = this.#readable(state, id);
    if (!WRITERS.has(calendar.accessRole)) refuse(403, 'requiredAccessLevel', 'You need to have writer access to this calendar.');
    return calendar;
  }
  /** An event of a calendar by id; `instances` also finds one occurrence of a series by its instance id. */
  #event(state, calendar, eventId, {instances = false} = {}) {
    const event = state.events[eventId];
    if (event && event.calendarId === calendar.id) return {event, instance: null};
    const match = /^(.+)_(\d{8}(?:T\d{6}Z)?)$/.exec(eventId), master = match ? state.events[match[1]] : null;
    if (master && master.calendarId === calendar.id && master.rule) {
      const found = startsOf(master).map(start => occurrence(master, start)).find(item => item.stamp === match[2]);
      if (found) return instances ? {event: master, instance: found} : {event: this.#exception(master, found), instance: null};
    }
    return notFound();
  }
  /** The item a write on one occurrence makes, with the series' fields and that occurrence's own id and times. Nothing stands until the write commits it. */
  #exception(master, {stamp, start, end}) {
    return {...structuredClone(master), id: `${master.id}_${stamp}`, start, end, originalStart: start, recurringEventId: master.id, recurrence: null, rule: null};
  }
  /** A new event's own fields, before the calendar's organizer is set. */
  #fresh(calendar, body) {
    const start = timeOf(body.start, 'start'), end = timeOf(body.end, 'end'), rule = ruleOf(body.recurrence);
    const event = {calendarId: calendar.id, status: 'confirmed', eventType: 'default', start, end, recurrence: rule ? [...body.recurrence] : null, rule, attendees: [], conference: null};
    for (const field of ['summary', 'description', 'location']) if (body[field] !== undefined && body[field] !== null) event[field] = text(body[field], field);
    if (body.transparency !== undefined) {
      if (!['opaque', 'transparent'].includes(body.transparency)) refuse(400, 'invalid', 'Invalid value for: transparency');
      event.transparency = body.transparency;
    }
    return event;
  }
  /** An inserted event, checked whole: {event, conference} where conference is {requestId, made} or null. */
  #build(state, calendar, body, {now, conference}) {
    if (!record(body)) refuse(400, 'invalid', 'Invalid JSON payload received.');
    const event = {...this.#fresh(calendar, body), organizer: calendar.primary ? {email: state.owner.email} : {email: calendar.id, displayName: calendar.summary},
      creator: {email: state.owner.email}, created: now, updated: now};
    if (body.attendees !== undefined) event.attendees = attendeesAfter([], body.attendees, false);
    checkTimes(event);
    return {event, conference: this.#conference(state, body, conference)};
  }
  /** The conference a createRequest asks for, under conferenceDataVersion=1 only: the one its requestId made before, or a new one. */
  #conference(state, body, version) {
    const request = version === 1 && record(body.conferenceData) ? body.conferenceData.createRequest : undefined;
    if (request === undefined) return null;
    if (!record(request) || typeof request.requestId !== 'string' || !request.requestId || request.requestId.length > 1024) refuse(400, 'invalid', 'Invalid conference create request.');
    if (!record(request.conferenceSolutionKey) || request.conferenceSolutionKey.type !== 'hangoutsMeet') refuse(400, 'invalid', 'Invalid conference type value.');
    return {requestId: request.requestId, made: !state.conferences[request.requestId]};
  }
  /** Stores an event: an id when it has none, a new etag, a sequence for list order, and the conference it asked for. */
  #commit(state, event, conference = null) {
    if (!event.id) {
      event.id = hex(`event:${state.next.event++}`).slice(0, 26);
      event.seq = state.next.seq++;
      event.created ??= this.clock();
    }
    event.updated = this.clock();
    event.etag = this.#etag(state);
    if (conference) {
      if (conference.made) {
        const letters = [...hex(`meet:${state.next.conference++}:${conference.requestId}`)].map(digit => String.fromCharCode(97 + parseInt(digit, 16))).join('');
        state.conferences[conference.requestId] = {conferenceId: `${letters.slice(0, 3)}-${letters.slice(3, 7)}-${letters.slice(7, 10)}`};
      }
      event.conference = conference.requestId;
    }
    state.events[event.id] = event;
    this.#mark(state, `events:${event.calendarId}`, event.id);
    return event;
  }
  /** One notification per guest Google would email, under sendUpdates; none emails nobody. */
  #notify(state, event, kind, mode, to = null) {
    if (mode === 'none') return;
    const domain = state.owner.email.split('@')[1].toLowerCase();
    let recipients = to ?? event.attendees.filter(item => !same(item.email, state.owner.email) && !same(item.email, event.organizer.email)).map(item => item.email);
    if (mode === 'externalOnly') recipients = recipients.filter(email => email.split('@')[1].toLowerCase() !== domain);
    for (const email of recipients) state.notifications.push({kind, eventId: event.id, calendarId: event.calendarId, to: email});
  }
  #render(state, event, {zone = null, maxAttendees = null, instance = null} = {}) {
    const calendar = state.calendars[event.calendarId], shown = zone ?? calendar?.timeZone ?? state.owner.zone, id = instance ? `${event.id}_${instance.stamp}` : event.id;
    const time = value => shownTime(value, shown);
    const person = (entry, self) => ({email: entry.email, ...(entry.displayName ? {displayName: entry.displayName} : {}), ...(self ? {self: true} : {})});
    const out = {kind: 'calendar#event', etag: event.etag, id, status: event.status, htmlLink: `https://www.google.com/calendar/event?eid=${Buffer.from(`${id} ${event.calendarId}`).toString('base64url')}`,
      created: iso(event.created), updated: iso(event.updated)};
    for (const field of ['summary', 'description', 'location']) if (event[field] !== undefined) out[field] = event[field];
    out.creator = person(event.creator, same(event.creator.email, state.owner.email));
    out.organizer = person(event.organizer, organizes(event));
    out.start = time(instance ? instance.start : event.start);
    out.end = time(instance ? instance.end : event.end);
    if (!instance && event.recurrence) out.recurrence = [...event.recurrence];
    if (instance) { out.recurringEventId = event.id; out.originalStartTime = time(instance.start); }
    if (event.recurringEventId) { out.recurringEventId = event.recurringEventId; out.originalStartTime = time(event.originalStart); }
    if (event.reminders) out.reminders = event.reminders;
    if (event.transparency) out.transparency = event.transparency;
    out.iCalUID = `${event.id}@google.com`;
    let attendees = event.attendees.map(item => ({...item, ...(same(item.email, event.organizer.email) ? {organizer: true} : {}), ...(same(item.email, event.calendarId) ? {self: true} : {})}));
    if (maxAttendees !== null && attendees.length > maxAttendees) { attendees = attendees.filter(item => item.self); out.attendeesOmitted = true; }
    if (attendees.length) out.attendees = attendees;
    const conference = event.conference ? state.conferences[event.conference] : null;
    if (conference) {
      out.hangoutLink = `https://meet.google.com/${conference.conferenceId}`;
      out.conferenceData = {createRequest: {requestId: event.conference, conferenceSolutionKey: {type: 'hangoutsMeet'}, status: {statusCode: 'success'}},
        entryPoints: [{entryPointType: 'video', uri: out.hangoutLink, label: `meet.google.com/${conference.conferenceId}`}],
        conferenceSolution: {key: {type: 'hangoutsMeet'}, name: 'Google Meet'}, conferenceId: conference.conferenceId};
    }
    out.eventType = event.eventType;
    return out;
  }
  /** A cancelled event as a list shows it: the organizer's copy with its details, a cancelled occurrence with the three fields Google documents, and any other copy its id alone. */
  #cancelled(state, event, options = {}) {
    if (!event.recurringEventId && organizes(event)) return this.#render(state, event, options);
    const shown = {kind: 'calendar#event', etag: event.etag, id: event.id, status: 'cancelled'}, zone = options.zone ?? state.calendars[event.calendarId]?.timeZone ?? state.owner.zone;
    return event.recurringEventId ? {...shown, recurringEventId: event.recurringEventId, originalStartTime: shownTime(event.originalStart, zone)} : shown;
  }
  #entry(calendar) {
    return {kind: 'calendar#calendarListEntry', etag: calendar.etag, id: calendar.id, summary: calendar.summary, ...(calendar.description ? {description: calendar.description} : {}),
      timeZone: calendar.timeZone, accessRole: calendar.accessRole, ...(calendar.primary ? {primary: true} : {}), ...(calendar.hidden ? {hidden: true} : {}), ...(calendar.colorId ? {colorId: calendar.colorId} : {})};
  }
  #resource(calendar) {
    return {kind: 'calendar#calendar', etag: calendar.etag, id: calendar.id, summary: calendar.summary, ...(calendar.description ? {description: calendar.description} : {}),
      timeZone: calendar.timeZone, conferenceProperties: {allowedConferenceSolutionTypes: ['hangoutsMeet']}};
  }
  #rule(calendarId, ruleId, rule) {
    const [type, ...value] = ruleId.split(':');
    return {kind: 'calendar#aclRule', etag: rule.etag, id: ruleId, scope: {type, ...(value.length ? {value: value.join(':')} : {})}, role: rule.role};
  }
  /** Where a token stands in a feed's log: it must name this feed and this query, and its epoch must still stand. */
  #place(log, feed, text, kind, binding) {
    const token = tokenRead(text), bad = kind === 'sync' ? 'Invalid sync token value.' : 'Invalid page token value.';
    if (!token || token.kind !== kind || token.feed !== feed || token.binding !== binding || !Number.isSafeInteger(token.at) || token.at < 0 || token.at > log.at) refuse(400, 'invalid', bad);
    if (token.epoch !== log.epoch) refuse(410, 'fullSyncRequired', 'Sync token is no longer valid, a full sync is required.', {domain: 'calendar', locationType: 'parameter', location: 'syncToken'});
    return token.at;
  }
  /**
   * One page of a change feed. With no token it is a full read, and with one it is what moved since, in the order each item last moved. `show(id, delta)` is what one log entry shows
   * this read. A page token holds a place in the log, so what changes during a walk comes round again, and the token on the last page leaves nothing behind. A series under singleEvents stays
   * whole on its page.
   */
  #walk(state, feed, query, {max, refused, show}) {
    const log = state.feeds[feed] ??= newLog(), binding = bindingOf(query), sync = query.get('syncToken'), pageToken = query.get('pageToken'), delta = sync !== null;
    if (delta) {
      for (const name of refused) if (query.has(name)) refuse(400, 'invalid', `${name} cannot be sent beside a sync token.`);
      for (const name of ['showDeleted', 'showHidden']) if (query.get(name) === 'false') refuse(400, 'invalid', `${name} cannot be false beside a sync token.`);
    }
    const since = delta ? this.#place(log, feed, sync, 'sync', binding) : 0, after = pageToken === null ? since : this.#place(log, feed, pageToken, 'page', binding);
    const inOrder = Object.entries(log.items).sort((a, b) => a[1] - b[1]), repeats = delta && pageToken === null ? this.repeats : 0, short = this.short;
    const entries = [...(repeats ? inOrder.filter(([, at]) => at <= since).slice(-repeats) : []), ...inOrder.filter(([, at]) => at > after)];
    if (repeats) this.repeats = 0;
    this.short = null;
    const size = short ?? max, items = [];
    let place = after, cut = short !== null;
    for (const [id, at] of entries) {
      const shown = show(id, delta);
      if (items.length + shown.length > size && (items.length || short !== null)) { cut = true; break; }
      items.push(...shown);
      place = Math.max(place, at);
    }
    return {items, ...(cut ? {nextPageToken: tokenOf('page', feed, place, log.epoch, binding)} : {nextSyncToken: tokenOf('sync', feed, log.at, log.epoch, binding)})};
  }
  /** sendUpdates as given (one of three values), or none when absent; the deprecated sendNotifications reads as all or none. */
  #sendUpdates(query) {
    const values = query.getAll('sendUpdates');
    if (values.length > 1 || (values.length === 1 && !SEND_UPDATES.has(values[0]))) refuse(400, 'invalidParameter', `Invalid value '${values.join(',')}'. Values must match the following regular expression: '(all|externalOnly|none)'`);
    if (values.length) return values[0];
    const old = query.getAll('sendNotifications');
    if (old.length > 1 || (old.length === 1 && !['true', 'false'].includes(old[0]))) refuse(400, 'invalidParameter', 'Invalid value for: sendNotifications');
    return old[0] === 'true' ? 'all' : 'none';
  }
  #conferenceVersion(query) {
    const value = query.get('conferenceDataVersion');
    if (value === null) return 0;
    if (!['0', '1'].includes(value)) refuse(400, 'invalid', 'Invalid conference data version.');
    return Number(value);
  }
  /** A page of `items` at `token`, `max` a page: {items, next}. A token is opaque and names its list. */
  #page(items, token, max, kind) {
    let start = 0;
    if (token !== null) {
      const decoded = Buffer.from(token, 'base64url').toString('utf8'), match = new RegExp(`^${kind}:([0-9]{1,6})$`).exec(decoded);
      if (!match || Buffer.from(decoded).toString('base64url') !== token) refuse(400, 'invalid', 'Invalid page token value.');
      start = Number(match[1]);
    }
    const next = start + max < items.length ? Buffer.from(`${kind}:${start + max}`).toString('base64url') : null;
    return {items: items.slice(start, start + max), next};
  }
  #count(query, name, {fallback, max}) {
    const value = query.get(name);
    if (value === null) return fallback;
    if (!/^[0-9]{1,6}$/.test(value) || Number(value) < 1 || Number(value) > max) refuse(400, 'invalid', `Invalid value for: ${name}`);
    return Number(value);
  }
  #zone(query) {
    const zone = query.get('timeZone');
    if (zone !== null && !validZone(zone)) refuse(400, 'invalid', 'Invalid time zone definition.');
    return zone;
  }
  #span(calendar, time) { return time.kind === 'dateTime' ? time.ms : instantOf(dateParts(time.date), calendar.timeZone); }
  /** The occurrences a series still holds: one written apart stands as its own item, and a cancelled one is gone. */
  #occurrences(state, event, before = Infinity) { return startsOf(event, before).map(start => occurrence(event, start)).filter(instance => !state.events[`${event.id}_${instance.stamp}`]); }
  /** The items showDeleted adds to a bounded list: a cancelled series is its occurrences under singleEvents, and never the series itself. */
  #deletedItems(state, calendar, single) {
    const span = time => this.#span(calendar, time);
    return Object.values(state.events).filter(event => event.calendarId === calendar.id && event.status === 'cancelled').sort((a, b) => a.seq - b.seq).flatMap(event => {
      if (!event.rule) return [{event, instance: null, start: span(event.start), end: span(event.end)}];
      const items = this.#occurrences(state, event).map(instance => ({event, instance, start: span(instance.start), end: span(instance.end)}));
      return single ? items : items.length ? [{event, instance: null, start: items[0].start, end: items.at(-1).end, any: items}] : [];
    });
  }
  /** A cancelled occurrence of a cancelled series, as a list under singleEvents shows it. */
  #cancelledOccurrence(state, event, instance, options) {
    return this.#cancelled(state, {...event, id: `${event.id}_${instance.stamp}`, recurringEventId: event.id, originalStart: instance.start}, options);
  }
  /** Each item of a calendar as an interval [start, end) in milliseconds, all-day ones in the calendar's zone, series expanded up to `before`. */
  #intervals(state, calendar, {expand, before = Infinity}) {
    const span = time => this.#span(calendar, time);
    const out = [];
    for (const event of Object.values(state.events).filter(item => item.calendarId === calendar.id && item.status !== 'cancelled').sort((a, b) => a.seq - b.seq)) {
      if (!event.rule) { out.push({event, instance: null, start: span(event.start), end: span(event.end)}); continue; }
      const items = this.#occurrences(state, event, before).map(instance => ({event, instance, start: span(instance.start), end: span(instance.end)}));
      if (expand) out.push(...items);
      else if (items.length) out.push({event, instance: null, start: items[0].start, end: items.at(-1).end, any: items});
    }
    return out;
  }

  // ---- the routes ----------------------------------------------------------------------------------------------------------------------
  #routes = null;
  get routes() {
    return this.#routes ??= [
      {method: 'GET', template: '/users/me/calendarList', scopes: scopes('calendar', 'calendar.calendarlist', 'calendar.calendarlist.readonly', 'calendar.readonly'), handle: ctx => this.#calendarList(ctx)},
      {method: 'GET', template: '/users/me/calendarList/{calendarId}', scopes: scopes('calendar', 'calendar.calendarlist', 'calendar.calendarlist.readonly', 'calendar.readonly'),
        handle: ({state, params}) => (calendar => ok(this.#entry(calendar), {etag: calendar.etag}))(this.#readable(state, params.calendarId))},
      {method: 'GET', template: '/users/me/settings/{setting}', scopes: scopes('calendar', 'calendar.readonly', 'calendar.settings', 'calendar.settings.readonly'), handle: ({state, params}) => {
        if (params.setting !== 'timezone') return notFound();
        const etag = `"${hex(`timezone:${state.owner.zone}`).slice(0, 16)}"`;
        return ok({kind: 'calendar#setting', etag, id: 'timezone', value: state.owner.zone}, {etag});
      }},
      {method: 'GET', template: '/calendars/{calendarId}/events', scopes: EVENTS_READ, fields: EVENT_LIST_FIELDS, handle: ctx => this.#list(ctx)},
      {method: 'POST', template: '/calendars/{calendarId}/events', write: true, scopes: EVENTS_WRITE, handle: ctx => this.#insert(ctx)},
      {method: 'POST', template: '/calendars/{calendarId}/events/quickAdd', write: true, scopes: EVENTS_WRITE, handle: ctx => this.#quickAdd(ctx)},
      {method: 'GET', template: '/calendars/{calendarId}/events/{eventId}', scopes: EVENTS_READ, handle: ctx => this.#get(ctx)},
      {method: 'PATCH', template: '/calendars/{calendarId}/events/{eventId}', write: true, scopes: EVENTS_WRITE, handle: ctx => this.#change(ctx, false)},
      {method: 'PUT', template: '/calendars/{calendarId}/events/{eventId}', write: true, scopes: EVENTS_WRITE, handle: ctx => this.#change(ctx, true)},
      {method: 'DELETE', template: '/calendars/{calendarId}/events/{eventId}', write: true, scopes: EVENTS_WRITE, handle: ctx => this.#delete(ctx)},
      {method: 'POST', template: '/calendars/{calendarId}/events/{eventId}/move', write: true, scopes: scopes('calendar', 'calendar.events'), handle: ctx => this.#move(ctx)},
      {method: 'POST', template: '/freeBusy', scopes: scopes('calendar', 'calendar.freebusy', 'calendar.readonly'), handle: ctx => this.#freeBusy(ctx)},
      {method: 'POST', template: '/calendars', write: true, scopes: scopes('calendar', 'calendar.calendars'), handle: ctx => this.#newCalendar(ctx)},
      {method: 'GET', template: '/calendars/{calendarId}', scopes: scopes('calendar', 'calendar.calendars', 'calendar.calendars.readonly', 'calendar.readonly'),
        handle: ({state, params}) => (calendar => ok(this.#resource(calendar), {etag: calendar.etag}))(this.#readable(state, params.calendarId))},
      {method: 'DELETE', template: '/calendars/{calendarId}', write: true, scopes: scopes('calendar', 'calendar.calendars'), handle: ({state, params}) => {
        const calendar = this.#readable(state, params.calendarId);
        if (calendar.primary) refuse(400, 'cannotDeletePrimaryCalendar', 'Cannot delete the primary calendar. Clear it instead.');
        if (calendar.accessRole !== 'owner') refuse(403, 'forbidden', 'Forbidden');
        for (const [id, event] of Object.entries(state.events)) if (event.calendarId === calendar.id) delete state.events[id];
        this.#unlisted(state, calendar.id);
        delete state.acl[calendar.id];
        return {status: 204, data: null};
      }},
      {method: 'GET', template: '/calendars/{calendarId}/acl', scopes: scopes('calendar', 'calendar.acls', 'calendar.acls.readonly', 'calendar.readonly'), handle: ctx => this.#aclList(ctx)},
      {method: 'GET', template: '/calendars/{calendarId}/acl/{ruleId}', scopes: scopes('calendar', 'calendar.acls', 'calendar.acls.readonly', 'calendar.readonly'), handle: ({state, params}) => {
        const calendar = this.#readable(state, params.calendarId), rule = state.acl[calendar.id]?.[params.ruleId];
        return rule ? ok(this.#rule(calendar.id, params.ruleId, rule), {etag: rule.etag}) : notFound();
      }},
      {method: 'DELETE', template: '/calendars/{calendarId}/acl/{ruleId}', write: true, scopes: scopes('calendar', 'calendar.acls'), handle: ({state, params}) => {
        const calendar = this.#readable(state, params.calendarId);
        if (calendar.accessRole !== 'owner') refuse(403, 'forbidden', 'Forbidden');
        if (!state.acl[calendar.id]?.[params.ruleId]) return notFound();
        this.#ruleGone(state, calendar.id, params.ruleId);
        return {status: 204, data: null};
      }},
    ].map(route => ({...route, key: `${route.method} ${route.template}`, parts: route.template.slice(1).split('/').map(part => /^\{\w+\}$/.test(part) ? {param: part.slice(1, -1)} : {literal: part})}));
  }

  #calendarList({state, query}) {
    const max = this.#count(query, 'maxResults', {fallback: 100, max: 250}), log = state.feeds.list, showHidden = query.get('showHidden') === 'true', showDeleted = query.get('showDeleted') === 'true';
    const page = this.#walk(state, 'list', query, {max, refused: LIST_NOT_BESIDE_TOKEN, show: (id, delta) => {
      const calendar = state.calendars[id];
      if (!calendar) return delta || showDeleted ? [{kind: 'calendar#calendarListEntry', etag: log.gone[id].etag, id, deleted: true}] : [];
      return calendar.hidden && !delta && !showHidden ? [] : [this.#entry(calendar)];
    }});
    return ok({kind: 'calendar#calendarList', etag: `"${hex(canonical(page.items.map(item => item.etag))).slice(0, 16)}"`, ...page});
  }
  #aclList({state, params, query}) {
    const calendar = this.#readable(state, params.calendarId), feed = `acl:${calendar.id}`, showDeleted = query.get('showDeleted') === 'true';
    if (!WRITERS.has(calendar.accessRole)) refuse(403, 'forbidden', 'Forbidden');
    const max = this.#count(query, 'maxResults', {fallback: 100, max: 250}), log = state.feeds[feed] ??= newLog();
    const page = this.#walk(state, feed, query, {max, refused: [], show: (id, delta) => {
      const rule = state.acl[calendar.id]?.[id];
      if (rule) return [this.#rule(calendar.id, id, rule)];
      return delta || showDeleted ? [this.#rule(calendar.id, id, {role: 'none', etag: log.gone[id].etag})] : [];
    }});
    return ok({kind: 'calendar#acl', etag: `"${hex(canonical(page.items.map(item => item.etag))).slice(0, 16)}"`, ...page});
  }
  #list({state, params, query}) {
    const calendar = this.#readable(state, params.calendarId);
    if (query.has('syncToken') || !NOT_BESIDE_TOKEN.some(name => query.has(name))) return this.#feed(state, calendar, query);
    const orderBy = query.get('orderBy'), single = query.get('singleEvents') === 'true', showHidden = query.get('showHiddenInvitations') === 'true';
    if (orderBy !== null && !['startTime', 'updated'].includes(orderBy)) refuse(400, 'invalidParameter', `Invalid value '${orderBy}' for orderBy.`);
    if (orderBy === 'startTime' && !single) refuse(400, 'badRequest', 'The requested ordering is not available for the particular query.');
    const bound = name => {
      if (query.get(name) === null) return null;
      const ms = parseDateTime(query.get(name), undefined, {needOffset: true});
      return ms === null ? refuse(400, 'badRequest', 'Bad Request') : ms;
    };
    const timeMin = bound('timeMin'), timeMax = bound('timeMax');
    if (timeMin !== null && timeMax !== null && timeMin >= timeMax) refuse(400, 'timeRangeEmpty', 'The specified time range is empty.');
    const max = this.#count(query, 'maxResults', {fallback: 250, max: 2500}), zone = this.#zone(query);
    const maxAttendees = query.get('maxAttendees') === null ? null : this.#count(query, 'maxAttendees', {fallback: null, max: 1_000_000});
    const words = (query.get('q') ?? '').toLowerCase().split(/\s+/).filter(Boolean);
    const overlaps = item => (timeMin === null || item.end > timeMin) && (timeMax === null || item.start < timeMax);
    const matches = ({event}) => words.every(word => [event.summary, event.description, event.location, ...event.attendees.map(item => item.email)].some(field => typeof field === 'string' && field.toLowerCase().includes(word)));
    const deleted = query.get('showDeleted') === 'true' ? this.#deletedItems(state, calendar, single) : [];
    let items = [...this.#intervals(state, calendar, {expand: single, before: timeMax ?? Infinity}), ...deleted].filter(item => (item.any ? item.any.some(overlaps) : overlaps(item)) && matches(item) && (showHidden || !item.event.hidden));
    if (orderBy === 'startTime') items.sort((a, b) => a.start - b.start || (a.event.seq - b.event.seq));
    if (orderBy === 'updated') items.sort((a, b) => a.event.updated - b.event.updated || (a.event.seq - b.event.seq));
    const page = this.#page(items, query.get('pageToken'), max, 'events'), options = {zone, maxAttendees};
    const shown = ({event, instance}) => event.status !== 'cancelled' ? this.#render(state, event, {...options, instance}) : instance ? this.#cancelledOccurrence(state, event, instance, options) : this.#cancelled(state, event, options);
    return ok({kind: 'calendar#events', etag: `"${hex(canonical(page.items.map(item => item.event.etag))).slice(0, 16)}"`, summary: calendar.summary, updated: iso(this.clock()),
      timeZone: calendar.timeZone, accessRole: calendar.accessRole, defaultReminders: [], ...(page.next ? {nextPageToken: page.next} : {}), items: page.items.map(shown)});
  }
  /** events.list as a change feed: a full read with no token, a delta with one, both from the calendar's log. */
  #feed(state, calendar, query) {
    const feed = `events:${calendar.id}`, single = query.get('singleEvents') === 'true', showDeleted = query.get('showDeleted') === 'true', showHidden = query.get('showHiddenInvitations') === 'true';
    const max = this.#count(query, 'maxResults', {fallback: 250, max: 2500}), zone = this.#zone(query);
    const options = {zone, maxAttendees: query.get('maxAttendees') === null ? null : this.#count(query, 'maxAttendees', {fallback: null, max: 1_000_000})}, log = state.feeds[feed] ??= newLog();
    const page = this.#walk(state, feed, query, {max, refused: NOT_BESIDE_TOKEN, show: (id, delta) => {
      const event = state.events[id];
      // The entry a move leaves on its source calendar.
      if (event?.calendarId !== calendar.id) return delta || showDeleted ? [{kind: 'calendar#event', etag: log.gone[id].etag, id, status: 'cancelled'}] : [];
      if (event.hidden && !showHidden) return [];
      if (event.status === 'cancelled') {
        if (!delta && !showDeleted) return [];
        return single && event.rule ? this.#occurrences(state, event).map(instance => this.#cancelledOccurrence(state, event, instance, options)) : [this.#cancelled(state, event, options)];
      }
      return single && event.rule ? this.#occurrences(state, event).map(instance => this.#render(state, event, {...options, instance})) : [this.#render(state, event, options)];
    }});
    return ok({kind: 'calendar#events', etag: `"${hex(canonical(page.items.map(item => item.etag))).slice(0, 16)}"`, summary: calendar.summary, updated: iso(this.clock()),
      timeZone: calendar.timeZone, accessRole: calendar.accessRole, defaultReminders: [], ...page});
  }
  #get({state, params, query}) {
    const calendar = this.#readable(state, params.calendarId), {event, instance} = this.#event(state, calendar, params.eventId, {instances: true});
    if (event.status === 'cancelled' && this.deleted !== 200) return this.deleted === 404 ? notFound() : refuse(410, 'deleted', 'Resource has been deleted');
    const maxAttendees = query.get('maxAttendees') === null ? null : this.#count(query, 'maxAttendees', {fallback: null, max: 1_000_000});
    return ok(this.#render(state, event, {zone: this.#zone(query), maxAttendees, instance}), {etag: event.etag});
  }
  #insert({state, params, query, body, now}) {
    const calendar = this.#writable(state, params.calendarId), mode = this.#sendUpdates(query), version = this.#conferenceVersion(query);
    const {event, conference} = this.#build(state, calendar, body ?? {}, {now, conference: version});
    this.#commit(state, event, conference);
    this.#notify(state, event, 'invitation', mode);
    return ok(this.#render(state, event), {etag: event.etag});
  }
  #quickAdd({state, params, query, now}) {
    const calendar = this.#writable(state, params.calendarId), mode = this.#sendUpdates(query), words = query.get('text');
    if (!words) refuse(400, 'required', 'Required parameter: text');
    const zone = calendar.timeZone, form = /^(.+?) on (\d{4}-\d{2}-\d{2}) at (\d{1,2})(?::(\d{2}))?(am|pm) to (\d{1,2})(?::(\d{2}))?(am|pm)$/i.exec(words.trim());
    const clock = (hour, minute, half) => Number(hour) >= 1 && Number(hour) <= 12 && Number(minute ?? 0) <= 59 ? {hour: Number(hour) % 12 + (half.toLowerCase() === 'pm' ? 12 : 0), minute: Number(minute ?? 0)} : null;
    const day = form ? dateParts(form[2]) : null, from = form ? clock(form[3], form[4], form[5]) : null, to = form ? clock(form[6], form[7], form[8]) : null;
    let summary = words, start, end;
    if (day && from && to && to.hour * 60 + to.minute > from.hour * 60 + from.minute) {
      summary = form[1].trim();
      [start, end] = [instantOf({...day, ...from}, zone), instantOf({...day, ...to}, zone)];
    } else {
      const wall = wallOf(now, zone);
      start = instantOf({...wall, minute: 0, second: 0}, zone) + HOUR_MS;
      end = start + HOUR_MS;
    }
    const event = {calendarId: calendar.id, status: 'confirmed', eventType: 'default', summary, start: {kind: 'dateTime', ms: start, timeZone: zone}, end: {kind: 'dateTime', ms: end, timeZone: zone},
      recurrence: null, rule: null, attendees: [], conference: null, organizer: calendar.primary ? {email: state.owner.email} : {email: calendar.id, displayName: calendar.summary},
      creator: {email: state.owner.email}, created: now};
    this.#commit(state, event);
    this.#notify(state, event, 'invitation', mode);
    return ok(this.#render(state, event), {etag: event.etag});
  }
  /** PATCH (replace = false) or PUT (replace = true) of one event, under If-Match. */
  #change({state, params, query, body, headers}, replace) {
    const calendar = this.#writable(state, params.calendarId), {event} = this.#event(state, calendar, params.eventId);
    if (event.status === 'cancelled') refuse(410, 'deleted', 'Resource has been deleted');
    const mode = this.#sendUpdates(query), version = this.#conferenceVersion(query);
    if (headers['if-match'] !== undefined && headers['if-match'] !== event.etag) refuse(412, 'conditionNotMet', 'Precondition Failed', {locationType: 'header', location: 'If-Match'});
    const given = body ?? {};
    if (!record(given)) refuse(400, 'invalid', 'Invalid JSON payload received.');
    if (given.eventType !== undefined && given.eventType !== event.eventType) refuse(400, 'invalid', 'The event type cannot be changed.');
    const next = structuredClone(event);
    if (replace) {
      Object.assign(next, this.#fresh(calendar, given), {organizer: event.organizer, creator: event.creator, eventType: event.eventType, conference: event.conference});
      for (const field of ['summary', 'description', 'location', 'transparency']) if (given[field] === undefined) delete next[field];
      next.attendees = given.attendees === undefined ? [] : attendeesAfter(event.attendees, given.attendees, false);
    } else {
      for (const field of ['summary', 'description', 'location']) if (Object.hasOwn(given, field)) { if (given[field] === null) delete next[field]; else next[field] = text(given[field], field); }
      if (Object.hasOwn(given, 'start')) next.start = timeOf(given.start, 'start');
      if (Object.hasOwn(given, 'end')) next.end = timeOf(given.end, 'end');
      if (Object.hasOwn(given, 'recurrence')) { next.rule = ruleOf(given.recurrence); next.recurrence = next.rule ? [...given.recurrence] : null; }
      if (Object.hasOwn(given, 'transparency')) {
        if (!['opaque', 'transparent'].includes(given.transparency)) refuse(400, 'invalid', 'Invalid value for: transparency');
        next.transparency = given.transparency;
      }
      if (Object.hasOwn(given, 'attendees')) next.attendees = attendeesAfter(event.attendees, given.attendees, given.attendeesOmitted === true);
    }
    const conference = this.#conference(state, given, version);
    const organizer = organizes(event);
    // A guest may change only their own answer: every shared field compares equal once the owner's own responseStatus is set aside.
    const shared = item => canonical({...item, conference: conference ? conference.requestId : item.conference, attendees: item.attendees.map(entry => same(entry.email, state.owner.email) ? {...entry, responseStatus: null} : entry)});
    if (!organizer && (shared(next) !== shared(event) || conference)) refuse(403, 'forbiddenForNonOrganizer', 'Shared properties can only be changed by the organizer of the event.', {domain: 'calendar'});
    checkTimes(next);
    this.#commit(state, next, conference);
    if (organizer) {
      this.#notify(state, next, 'update', mode);
      const removed = event.attendees.filter(item => !next.attendees.some(kept => same(kept.email, item.email))).map(item => item.email).filter(email => !same(email, state.owner.email) && !same(email, event.organizer.email));
      if (removed.length) this.#notify(state, next, 'cancellation', mode, removed);
    } else {
      const answer = item => item.attendees.find(entry => same(entry.email, state.owner.email))?.responseStatus;
      if (answer(next) !== answer(event)) this.#notify(state, next, 'response', mode, [event.organizer.email]);
    }
    return ok(this.#render(state, next), {etag: next.etag});
  }
  #delete({state, params, query}) {
    const calendar = this.#writable(state, params.calendarId), {event} = this.#event(state, calendar, params.eventId);
    if (event.status === 'cancelled') refuse(410, 'deleted', 'Resource has been deleted');
    const mode = this.#sendUpdates(query);
    event.status = 'cancelled';
    event.updated = this.clock();
    event.etag = this.#etag(state);
    state.events[event.id] = event;
    this.#mark(state, `events:${calendar.id}`, event.id);
    for (const item of event.rule ? Object.values(state.events) : []) {
      if (item.recurringEventId !== event.id || item.status === 'cancelled') continue;
      item.status = 'cancelled';
      item.updated = this.clock();
      item.etag = this.#etag(state);
      this.#mark(state, `events:${calendar.id}`, item.id);
    }
    if (organizes(event)) this.#notify(state, event, 'cancellation', mode);
    return {status: 204, data: null};
  }
  #move({state, params, query}) {
    const calendar = this.#writable(state, params.calendarId), {event} = this.#event(state, calendar, params.eventId);
    if (event.status === 'cancelled') refuse(410, 'deleted', 'Resource has been deleted');
    const mode = this.#sendUpdates(query), destinationId = query.get('destination');
    if (!destinationId) refuse(400, 'required', 'Required parameter: destination');
    const destination = this.#writable(state, destinationId);
    if (!organizes(event)) refuse(403, 'forbiddenForNonOrganizer', 'Only the organizer can move an event.', {domain: 'calendar'});
    if (event.recurringEventId) refuse(400, 'cannotChangeOrganizerOfInstance', 'Cannot change the organizer of an instance.', {domain: 'calendar'});
    if (event.eventType !== 'default') refuse(400, 'eventTypeRestriction', 'Only default events can be moved.', {domain: 'calendar'});
    const next = {...structuredClone(event), calendarId: destination.id, organizer: destination.primary ? {email: state.owner.email} : {email: destination.id, displayName: destination.summary}};
    this.#commit(state, next);
    this.#mark(state, `events:${calendar.id}`, event.id, {etag: this.#etag(state)});
    this.#notify(state, next, 'update', mode);
    const answer = this.#render(state, next);
    // Live run TOQJPGEU (C8): Google answers the move with one etag, and the moved event then reads back with a newer one.
    next.etag = this.#etag(state);
    return ok(answer, {etag: answer.etag});
  }
  #freeBusy({state, body}) {
    if (!record(body)) refuse(400, 'invalid', 'Invalid JSON payload received.');
    for (const name of ['timeMin', 'timeMax']) if (body[name] === undefined) refuse(400, 'required', `Missing ${name} parameter.`);
    const [timeMin, timeMax] = ['timeMin', 'timeMax'].map(name => parseDateTime(body[name], undefined, {needOffset: true}) ?? refuse(400, 'invalid', `Invalid value for: ${name}`));
    if (timeMin >= timeMax) refuse(400, 'timeRangeEmpty', 'The specified time range is empty.');
    if (body.timeZone !== undefined && !validZone(body.timeZone)) refuse(400, 'invalid', 'Invalid time zone definition.');
    if (!Array.isArray(body.items) || body.items.length > 50 || body.items.some(item => !record(item) || typeof item.id !== 'string' || !item.id)) refuse(400, 'invalid', 'Invalid value for: items');
    const shown = ms => formatInstant(ms, body.timeZone ?? 'UTC'), calendars = {};
    for (const {id} of body.items) {
      const calendar = this.#calendar(state, id);
      if (!calendar) { calendars[id] = {errors: [{domain: 'global', reason: 'notFound'}], busy: []}; continue; }
      const blocks = this.#intervals(state, calendar, {expand: true, before: timeMax}).filter(item => item.event.transparency !== 'transparent' && item.end > timeMin && item.start < timeMax)
        .map(item => [Math.max(item.start, timeMin), Math.min(item.end, timeMax)]).sort((a, b) => a[0] - b[0]);
      const merged = [];
      for (const block of blocks) if (merged.length && block[0] <= merged.at(-1)[1]) merged.at(-1)[1] = Math.max(merged.at(-1)[1], block[1]); else merged.push([...block]);
      calendars[id] = {busy: merged.map(([start, end]) => ({start: shown(start), end: shown(end)}))};
    }
    return ok({kind: 'calendar#freeBusy', timeMin: iso(timeMin), timeMax: iso(timeMax), calendars});
  }
  #newCalendar({state, body}) {
    if (!record(body)) refuse(400, 'invalid', 'Invalid JSON payload received.');
    if (typeof body.summary !== 'string' || !body.summary.trim()) refuse(400, 'required', 'Missing title.');
    if (body.timeZone !== undefined && !validZone(body.timeZone)) refuse(400, 'invalid', 'Invalid time zone definition.');
    if (body.description !== undefined && typeof body.description !== 'string') refuse(400, 'invalid', 'Invalid value for: description');
    const id = `c_${hex(`calendar:${state.next.calendar++}`)}@group.calendar.google.com`;
    const calendar = {id, summary: body.summary, ...(body.description ? {description: body.description} : {}), timeZone: body.timeZone ?? state.owner.zone, accessRole: 'owner', etag: this.#etag(state)};
    state.calendars[id] = calendar;
    state.acl[id] = {[`user:${state.owner.email}`]: {role: 'owner', etag: this.#etag(state)}};
    this.#mark(state, 'list', id);
    this.#mark(state, `acl:${id}`, `user:${state.owner.email}`);
    return ok(this.#resource(calendar), {etag: calendar.etag});
  }

  /** The route a method and a decoded path below the base take, with its parameters; literals win over parameters. */
  #routeOf(method, path) {
    const segments = path === '/' ? [] : path.slice(1).split('/').map(segment => { try { return decodeURIComponent(segment); } catch { return segment; } });
    let best = null;
    for (const route of this.routes) {
      if (route.method !== method || route.parts.length !== segments.length) continue;
      const params = {};
      let score = 0;
      const fits = route.parts.every((part, index) => {
        if (part.literal !== undefined) { score += 2; return part.literal === segments[index]; }
        params[part.param] = segments[index];
        score += 1;
        return segments[index] !== '';
      });
      if (fits && (!best || score > best.score)) best = {route, params, score};
    }
    return best;
  }

  async request({url, method = 'GET', headers = {}, body, allowedOrigins, maxBytes = 2 * 1024 * 1024, responseType = 'json', redirect = 'error', responseHeaders = DEFAULT_RESPONSE_HEADERS, timeoutMs = 15000}) {
    let target;
    try { target = new URL(url); } catch { throw notSent('Invalid request URL.'); }
    if (target.protocol !== 'https:' || target.username || target.password || target.hash || (target.port && target.port !== '443')) throw notSent('Only credential-free HTTPS URLs on port 443 are allowed.');
    if (!Array.isArray(allowedOrigins) || !allowedOrigins.includes(target.origin)) throw notSent('Request origin is outside the connection grant.');
    if (!['json', 'buffer'].includes(responseType) || !['error', 'report'].includes(redirect) || !Array.isArray(responseHeaders)) throw notSent('Unsupported response handling.');
    if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000 || !Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 10 * 1024 * 1024) throw notSent('Invalid request limits.');
    if (!/^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/.test(method)) throw notSent('Unsupported HTTP method.');
    const lower = {};
    for (const [name, value] of Object.entries(headers)) {
      if (UNSAFE_HEADER.test(name) || !/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(name) || typeof value !== 'string' || /[\r\n]/.test(value)) throw notSent('Unsafe request header.');
      lower[name.toLowerCase()] = value;
    }
    if (body !== undefined && !(typeof body === 'string' || Buffer.isBuffer(body))) throw notSent('Request body must be serialized.');
    if (body !== undefined && Buffer.byteLength(body) > 1024 * 1024) throw notSent('Request body is too large.');
    if (target.origin !== ORIGIN) throw notSent('Provider DNS lookup failed or timed out.');
    // Sent from here on: the call is recorded, without its Authorization header.
    const inBase = target.pathname.startsWith(`${BASE_PATH}/`), path = inBase ? target.pathname.slice(BASE_PATH.length) : target.pathname;
    const found = inBase ? this.#routeOf(method, path) : null;
    const raw = body === undefined ? undefined : Buffer.isBuffer(body) ? body.toString('utf8') : body;
    let parsed;
    if (raw !== undefined) { try { parsed = JSON.parse(raw); } catch { parsed = raw; } }
    const query = {};
    for (const [name, value] of target.searchParams) query[name] = Object.hasOwn(query, name) ? [query[name]].flat().concat(value) : value;
    const {authorization, ...kept} = lower;
    const call = {method, origin: target.origin, path, route: found?.route.key ?? null, query, headers: kept, body: parsed, write: found?.route.write === true, status: null};
    this.calls.push(call);
    const gate = found ? this.holds.get(found.route.key) : null;
    if (gate) { gate.reach(); await gate.released; }
    const chosen = found ? this.#take(found.route.key) : null;
    let answer;
    if (authorization !== `Bearer ${this.token}`) answer = googleError(401, 'authError', 'Invalid Credentials', {status: true, locationType: 'header', location: 'Authorization'});
    else if (!found) answer = googleError(404, 'notFound', 'Not Found');
    else if (!found.route.scopes.some(scope => this.scopes.has(scope))) answer = googleError(403, 'insufficientPermissions', 'Request had insufficient authentication scopes.', {status: true});
    else if (chosen?.kind === 'fail') answer = structuredClone(chosen.answer);
    else {
      const state = chosen?.kind === 'swallow' ? structuredClone(this.data) : this.data;
      try {
        if (raw !== undefined && typeof parsed === 'string') refuse(400, 'parseError', 'Parse Error');
        const fields = target.searchParams.get('fields'), mask = fields === null ? null : maskOf(fields);
        if (mask && found.route.fields) checkMask(mask, found.route.fields, fields);
        answer = found.route.handle({params: found.params, query: target.searchParams, body: parsed, headers: lower, state, now: this.clock()});
        if (mask && answer.status < 300 && answer.data) answer = {...answer, data: masked(answer.data, mask)};
      } catch (error) {
        if (!(error instanceof Refusal)) throw error;
        answer = error.answer;
      }
      if (chosen?.kind === 'drop') { call.status = answer.status; throw lost('Provider connection failed.'); }
      if (chosen?.kind === 'oversize') answer = {...answer, data: {...answer.data, padding: 'x'.repeat(Math.max(0, chosen.bytes))}};
    }
    call.status = answer.status;
    const headersOut = Object.fromEntries(Object.entries(answer.headers ?? {}).map(([name, value]) => [name.toLowerCase(), String(value)]));
    const bytes = answer.data === null || answer.data === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(answer.data), 'utf8');
    if (bytes.length > maxBytes) throw lost('Provider response exceeded the size limit.');
    if (bytes.length) headersOut['content-type'] ??= 'application/json; charset=UTF-8';
    const shown = {};
    for (const key of responseHeaders) if (headersOut[key] !== undefined) shown[key] = headersOut[key];
    // A fresh parse of the bytes, so nothing the caller holds shares memory with the simulator's state.
    return {status: answer.status, headers: shown, data: responseType === 'buffer' ? bytes : bytes.length ? JSON.parse(bytes.toString('utf8')) : null};
  }
}

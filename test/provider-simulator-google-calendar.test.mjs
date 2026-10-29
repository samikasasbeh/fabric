import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {CalendarSimulator, ORIGIN, BASE} from './fixtures/provider-simulators/google-calendar.mjs';

// F10.13 part 1 (docs/F10.13-BUILD-MAP.md part 1 and section 3): the Calendar simulator Calendar's actions run against in step 13. It must
// keep the network seam's contract (lib/network.mjs) and Google Calendar's documented behaviour, as its own header comment names it. It is
// written from that comment and from Google's Calendar v3 reference, never from Calendar's action file, rows or scope facts, so an action
// bug and a simulator bug cannot cancel out. Nothing here calls Google.
const TOKEN = 'calendar-token-5e2a', AUTH = {Authorization: `Bearer ${TOKEN}`};
const SCOPE = name => `https://www.googleapis.com/auth/${name}`;
const SIX = ['calendar.events', 'calendar.calendarlist', 'calendar.calendars', 'calendar.acls', 'calendar.settings.readonly', 'calendar.freebusy'].map(SCOPE);
const OWNER = {email: 'owner@example.com', zone: 'America/Toronto'};
const TORONTO = 'America/Toronto';
const sim = (options = {}) => new CalendarSimulator({token: TOKEN, owner: OWNER, scopes: SIX, clock: () => Date.parse('2026-10-23T13:00:00.000Z'), ...options});
/** One request through the seam below the API base, with the account's token unless `headers` says otherwise. */
const send = (simulator, method, path, {body, headers = AUTH, query, ...more} = {}) => {
  const url = new URL(`${BASE}${path}`);
  for (const [name, value] of Object.entries(query ?? {})) for (const item of [value].flat()) url.searchParams.append(name, String(item));
  return simulator.request({url: url.href, method, headers: {...headers, ...(body === undefined ? {} : {'Content-Type': 'application/json'})}, ...(body === undefined ? {} : {body: JSON.stringify(body)}),
    allowedOrigins: [ORIGIN], ...more});
};
const timed = (start, end, extra = {}) => ({summary: 'Review', start: {dateTime: start, timeZone: TORONTO}, end: {dateTime: end, timeZone: TORONTO}, ...extra});
const insert = (simulator, resource, {calendarId = 'primary', query} = {}) => send(simulator, 'POST', `/calendars/${encodeURIComponent(calendarId)}/events`, {body: resource, query});
const list = (simulator, query, calendarId = 'primary') => send(simulator, 'GET', `/calendars/${encodeURIComponent(calendarId)}/events`, {query});
const get = (simulator, eventId, {calendarId = 'primary', query} = {}) => send(simulator, 'GET', `/calendars/${encodeURIComponent(calendarId)}/events/${encodeURIComponent(eventId)}`, {query});
const patch = (simulator, eventId, body, {calendarId = 'primary', query, headers = AUTH} = {}) => send(simulator, 'PATCH', `/calendars/${encodeURIComponent(calendarId)}/events/${encodeURIComponent(eventId)}`, {body, query, headers});
const reasonOf = answer => [answer.status, answer.data?.error?.errors?.[0]?.reason];

test('the seam: only the headers asked for come back, an answer over maxBytes throws sent true, and requests refused before sending are never recorded', async () => {
  const simulator = sim();
  const made = await insert(simulator, timed('2026-10-30T10:00:00', '2026-10-30T10:30:00'));
  assert.deepEqual(Object.keys(made.headers).sort(), ['content-type', 'etag'], 'the default list: content-type, etag, retry-after, x-ratelimit-remaining');
  assert.deepEqual(Object.keys((await get(simulator, made.data.id)).headers).sort(), ['content-type', 'etag']);
  assert.deepEqual((await send(simulator, 'GET', `/calendars/primary/events/${made.data.id}`, {responseHeaders: ['etag']})).headers, {etag: made.data.etag});
  await assert.rejects(list(simulator, {}, 'primary').then(() => send(simulator, 'GET', '/calendars/primary/events', {maxBytes: 64})), error => error.sent === true && /size limit/.test(error.message));
  const before = simulator.calls.length;
  for (const [label, request] of [['an origin outside the grant', {url: `${BASE}/users/me/calendarList`, method: 'GET', headers: AUTH, allowedOrigins: ['https://gmail.googleapis.com']}],
    ['plain http', {url: 'http://www.googleapis.com/calendar/v3/users/me/calendarList', method: 'GET', headers: AUTH, allowedOrigins: [ORIGIN]}],
    ['an unsafe header', {url: `${BASE}/users/me/calendarList`, method: 'GET', headers: {...AUTH, Host: 'x'}, allowedOrigins: [ORIGIN]}],
    ['a body that is not serialized', {url: `${BASE}/calendars/primary/events`, method: 'POST', headers: AUTH, body: {summary: 'x'}, allowedOrigins: [ORIGIN]}],
    ['a body over 1 MiB', {url: `${BASE}/calendars/primary/events`, method: 'POST', headers: AUTH, body: JSON.stringify({summary: 'x'.repeat(1024 * 1024)}), allowedOrigins: [ORIGIN]}],
    ['an origin the simulator does not serve', {url: 'https://gmail.googleapis.com/gmail/v1/users/me/labels', method: 'GET', headers: AUTH, allowedOrigins: ['https://gmail.googleapis.com']}]]) {
    await assert.rejects(simulator.request(request), error => error.sent === false, label);
  }
  assert.equal(simulator.calls.length, before, 'refused before sending: never recorded');
  // A path on Google's origin outside the Calendar base is sent and answered 404, as Google answers it.
  const outside = await simulator.request({url: `${ORIGIN}/drive/v3/files`, method: 'GET', headers: AUTH, allowedOrigins: [ORIGIN]});
  assert.deepEqual([outside.status, simulator.calls.at(-1).route], [404, null]);
});

test('401 without the token and 403 for a scope the token lacks, both in Google\'s error shape, change nothing; calls are recorded without Authorization', async () => {
  const simulator = sim();
  for (const headers of [{}, {Authorization: 'Bearer wrong'}]) {
    const answer = await insert(simulator, timed('2026-10-30T10:00:00', '2026-10-30T10:30:00'), {query: {}}).then(() => send(simulator, 'POST', '/calendars/primary/events', {body: timed('2026-10-30T11:00:00', '2026-10-30T11:30:00'), headers}));
    assert.equal(answer.status, 401);
    assert.deepEqual(Object.keys(answer.data.error).sort(), ['code', 'errors', 'message', 'status']);
    assert.deepEqual([answer.data.error.code, answer.data.error.errors[0].domain, answer.data.error.errors[0].reason, answer.data.error.status], [401, 'global', 'authError', 'UNAUTHENTICATED']);
  }
  assert.equal(Object.keys(simulator.state().events).length, 2, 'only the two authorized inserts made an event');
  // The simulator's own scope table (Calendar's Discovery document): freeBusy needs calendar.freebusy (or a broader read), settings.get
  // needs calendar.settings.readonly, and the broad calendar scope reaches everything.
  const narrow = sim({scopes: [SCOPE('calendar.events'), SCOPE('calendar.calendarlist')]});
  const busy = await send(narrow, 'POST', '/freeBusy', {body: {timeMin: '2026-10-30T00:00:00Z', timeMax: '2026-10-31T00:00:00Z', items: [{id: 'primary'}]}});
  assert.deepEqual([busy.status, busy.data.error.code, busy.data.error.errors[0].domain, busy.data.error.errors[0].reason, busy.data.error.status], [403, 403, 'global', 'insufficientPermissions', 'PERMISSION_DENIED']);
  assert.deepEqual(reasonOf(await send(narrow, 'GET', '/users/me/settings/timezone')), [403, 'insufficientPermissions']);
  assert.deepEqual(reasonOf(await send(narrow, 'POST', '/calendars', {body: {summary: 'A'}})), [403, 'insufficientPermissions']);
  assert.equal(Object.keys(narrow.state().calendars).length, 1, 'a refused insert made no calendar');
  assert.deepEqual(reasonOf(await send(narrow, 'GET', '/calendars/primary/acl/user:owner@example.com')), [403, 'insufficientPermissions']);
  assert.equal((await send(narrow, 'GET', '/users/me/calendarList/primary')).status, 200);
  assert.equal((await send(narrow, 'GET', '/calendars/primary/events')).status, 200);
  // A scope whose grant depends on the object (calendar.app.created, calendar.events.owned) is not in the table: refused, never looser.
  assert.deepEqual(reasonOf(await send(sim({scopes: [SCOPE('calendar.events.owned')]}), 'GET', '/calendars/primary/events')), [403, 'insufficientPermissions']);
  const broad = sim({scopes: [SCOPE('calendar')]});
  assert.equal((await send(broad, 'GET', '/users/me/settings/timezone')).status, 200);
  assert.equal((await send(broad, 'POST', '/freeBusy', {body: {timeMin: '2026-10-30T00:00:00Z', timeMax: '2026-10-31T00:00:00Z', items: [{id: 'primary'}]}})).status, 200);
  assert.equal(JSON.stringify(simulator.calls).includes(TOKEN), false, 'the token is never recorded');
  assert.ok(simulator.calls.every(call => !Object.keys(call.headers).some(name => /authorization/i.test(name))));
  assert.deepEqual(simulator.calls.map(call => call.route), Array(4).fill('POST /calendars/{calendarId}/events'));
});

test('insert, then get: the etag field equals the ETag header, the answers are equal, and organizer, creator, eventType and the zone come from the calendar', async () => {
  const simulator = sim();
  const made = await insert(simulator, timed('2026-10-30T10:00:00', '2026-10-30T10:30:00', {description: 'Notes', location: 'Room 1'}));
  assert.equal(made.status, 200);
  assert.equal(made.data.etag, made.headers.etag);
  assert.match(made.data.id, /^[a-v0-9]{5,1024}$/, 'base32hex, as Google documents event ids');
  assert.deepEqual([made.data.kind, made.data.status, made.data.eventType, made.data.summary, made.data.description, made.data.location], ['calendar#event', 'confirmed', 'default', 'Review', 'Notes', 'Room 1']);
  assert.deepEqual([made.data.organizer, made.data.creator], [{email: OWNER.email, self: true}, {email: OWNER.email, self: true}]);
  assert.deepEqual([made.data.start, made.data.end], [{dateTime: '2026-10-30T10:00:00-04:00', timeZone: TORONTO}, {dateTime: '2026-10-30T10:30:00-04:00', timeZone: TORONTO}]);
  const read = await get(simulator, made.data.id);
  assert.deepEqual([read.status, read.data, read.headers.etag], [200, made.data, made.data.etag]);
  // An offset instant with no zone keeps the instant and is shown in the calendar's zone; timeZone on get shows another zone.
  const utc = await insert(simulator, {summary: 'UTC', start: {dateTime: '2026-10-30T18:00:00Z'}, end: {dateTime: '2026-10-30T18:30:00Z'}});
  assert.deepEqual(utc.data.start, {dateTime: '2026-10-30T14:00:00-04:00'});
  assert.deepEqual((await get(simulator, utc.data.id, {query: {timeZone: 'Europe/Paris'}})).data.start, {dateTime: '2026-10-30T19:00:00+01:00'});
  assert.deepEqual((await get(simulator, utc.data.id, {query: {timeZone: 'UTC'}})).data.start, {dateTime: '2026-10-30T18:00:00Z'});
  // A wall time with no offset and no zone is refused: Google requires one or the other.
  assert.deepEqual(reasonOf(await insert(simulator, {summary: 'x', start: {dateTime: '2026-10-30T10:00:00'}, end: {dateTime: '2026-10-30T11:00:00'}})), [400, 'invalid']);
  assert.deepEqual(reasonOf(await insert(simulator, {summary: 'x', start: {dateTime: '2026-10-30T10:00:00', timeZone: 'Mars/Base'}, end: {dateTime: '2026-10-30T11:00:00', timeZone: 'Mars/Base'}})), [400, 'invalid']);
  assert.equal((await get(simulator, 'nosuchevent00')).status, 404);
});

test('an all-day end is exclusive: an end equal to the start answers 400, as does an end before the start or a mixed form; a missing end is required', async () => {
  const simulator = sim();
  const day = await insert(simulator, {summary: 'Day', start: {date: '2026-11-02'}, end: {date: '2026-11-03'}});
  assert.deepEqual([day.status, day.data.start, day.data.end], [200, {date: '2026-11-02'}, {date: '2026-11-03'}]);
  const year = await insert(simulator, {summary: 'Eve', start: {date: '2026-12-31'}, end: {date: '2027-01-01'}});
  assert.equal(year.status, 200);
  assert.deepEqual(reasonOf(await insert(simulator, {summary: 'Same', start: {date: '2026-11-02'}, end: {date: '2026-11-02'}})), [400, 'timeRangeEmpty']);
  assert.deepEqual(reasonOf(await insert(simulator, {summary: 'Back', start: {date: '2026-11-02'}, end: {date: '2026-11-01'}})), [400, 'timeRangeEmpty']);
  assert.deepEqual(reasonOf(await insert(simulator, timed('2026-10-30T10:00:00', '2026-10-30T10:00:00'))), [400, 'timeRangeEmpty']);
  assert.deepEqual(reasonOf(await insert(simulator, {summary: 'Mixed', start: {date: '2026-11-02'}, end: {dateTime: '2026-11-02T10:00:00Z'}})), [400, 'invalid']);
  assert.deepEqual(reasonOf(await insert(simulator, {summary: 'Both', start: {date: '2026-11-02', dateTime: '2026-11-02T10:00:00Z'}, end: {date: '2026-11-03'}})), [400, 'invalid']);
  assert.deepEqual(reasonOf(await insert(simulator, {summary: 'Half', start: {date: '2026-11-02'}})), [400, 'required']);
  assert.deepEqual(reasonOf(await insert(simulator, {summary: 'Bad', start: {date: '2026-02-30'}, end: {date: '2026-03-01'}})), [400, 'invalid']);
  assert.equal(Object.keys(simulator.state().events).length, 2, 'only the two valid events were made');
});

test('a recurring timed event needs a zone on start and end; only FREQ DAILY or WEEKLY with COUNT, UNTIL, INTERVAL and BYDAY is accepted', async () => {
  const simulator = sim();
  const noZone = await insert(simulator, {summary: 'R', start: {dateTime: '2026-10-26T10:00:00-04:00'}, end: {dateTime: '2026-10-26T10:30:00-04:00'}, recurrence: ['RRULE:FREQ=WEEKLY;COUNT=3']});
  assert.deepEqual([...reasonOf(noZone), noZone.data.error.message], [400, 'invalid', 'Missing time zone definition for start time.']);
  const noEndZone = await insert(simulator, {summary: 'R', start: {dateTime: '2026-10-26T10:00:00-04:00', timeZone: TORONTO}, end: {dateTime: '2026-10-26T10:30:00-04:00'}, recurrence: ['RRULE:FREQ=WEEKLY;COUNT=3']});
  assert.equal(noEndZone.data.error.message, 'Missing time zone definition for end time.');
  for (const recurrence of [['RRULE:FREQ=MONTHLY;COUNT=3'], ['RRULE:FREQ=WEEKLY;BYMONTH=1'], ['RRULE:FREQ=WEEKLY;COUNT=3;UNTIL=20261231T000000Z'], ['RRULE:FREQ=WEEKLY;BYDAY=1MO'],
    ['RRULE:FREQ=WEEKLY;COUNT=0'], ['RRULE:FREQ=DAILY;INTERVAL=x'], ['RRULE:COUNT=3'], ['RRULE:FREQ=WEEKLY;WKST=SU;COUNT=2'], ['RRULE:FREQ=DAILY;COUNT=2', 'EXDATE:20261027T140000Z'],
    ['RRULE:FREQ=DAILY;COUNT=2', 'RRULE:FREQ=WEEKLY;COUNT=2'], 'RRULE:FREQ=DAILY;COUNT=2']) {
    assert.deepEqual(reasonOf(await insert(simulator, timed('2026-10-26T10:00:00', '2026-10-26T10:30:00', {recurrence}))), [400, 'invalid'], JSON.stringify(recurrence));
  }
  assert.equal(Object.keys(simulator.state().events).length, 0, 'nothing was made');
  // An all-day recurring event has no wall time to place, so it needs no zone.
  assert.equal((await insert(simulator, {summary: 'Days', start: {date: '2026-11-02'}, end: {date: '2026-11-03'}, recurrence: ['RRULE:FREQ=DAILY;COUNT=3']})).status, 200);
});

test('singleEvents expands a weekly event of 3 from 2026-10-26 10:00 America/Toronto in its own zone: 10:00 local each week, the last two at -05:00', async () => {
  const simulator = sim();
  const weekly = await insert(simulator, timed('2026-10-26T10:00:00', '2026-10-26T10:30:00', {summary: 'Weekly', recurrence: ['RRULE:FREQ=WEEKLY;COUNT=3']}));
  assert.equal(weekly.status, 200);
  assert.deepEqual(weekly.data.recurrence, ['RRULE:FREQ=WEEKLY;COUNT=3']);
  const window = {timeMin: '2026-10-25T00:00:00Z', timeMax: '2026-12-01T00:00:00Z'};
  const local = await list(simulator, {singleEvents: 'true', orderBy: 'startTime', timeZone: TORONTO, ...window});
  assert.deepEqual(local.data.items.map(item => item.start.dateTime), ['2026-10-26T10:00:00-04:00', '2026-11-02T10:00:00-05:00', '2026-11-09T10:00:00-05:00']);
  assert.deepEqual(local.data.items.map(item => item.end.dateTime), ['2026-10-26T10:30:00-04:00', '2026-11-02T10:30:00-05:00', '2026-11-09T10:30:00-05:00']);
  assert.deepEqual(local.data.items.map(item => item.id), ['20261026T140000Z', '20261102T150000Z', '20261109T150000Z'].map(stamp => `${weekly.data.id}_${stamp}`));
  assert.ok(local.data.items.every(item => item.recurringEventId === weekly.data.id && item.recurrence === undefined));
  assert.deepEqual(local.data.items[1].originalStartTime, {dateTime: '2026-11-02T10:00:00-05:00', timeZone: TORONTO});
  assert.deepEqual((await list(simulator, {singleEvents: 'true', orderBy: 'startTime', timeZone: 'UTC', ...window})).data.items.map(item => item.start.dateTime),
    ['2026-10-26T14:00:00Z', '2026-11-02T15:00:00Z', '2026-11-09T15:00:00Z']);
  // An instance reads back by its id; without singleEvents the series is listed once.
  const instance = await get(simulator, `${weekly.data.id}_20261102T150000Z`, {query: {timeZone: TORONTO}});
  assert.deepEqual([instance.status, instance.data.start.dateTime, instance.data.recurringEventId], [200, '2026-11-02T10:00:00-05:00', weekly.data.id]);
  assert.equal((await get(simulator, `${weekly.data.id}_20261103T150000Z`)).status, 404, 'no occurrence starts then');
  assert.deepEqual((await list(simulator, window)).data.items.map(item => item.id), [weekly.data.id]);
  // INTERVAL, BYDAY and UNTIL.
  const every = await insert(simulator, timed('2026-11-16T09:00:00', '2026-11-16T09:15:00', {summary: 'Every', recurrence: ['RRULE:FREQ=DAILY;INTERVAL=2;COUNT=3']}));
  const days = await insert(simulator, timed('2026-11-16T12:00:00', '2026-11-16T12:30:00', {summary: 'Days', recurrence: ['RRULE:FREQ=WEEKLY;BYDAY=MO,WE;COUNT=4']}));
  const until = await insert(simulator, timed('2026-11-16T15:00:00', '2026-11-16T15:30:00', {summary: 'Until', recurrence: ['RRULE:FREQ=WEEKLY;INTERVAL=2;UNTIL=20261215T000000Z']}));
  const series = async event => (await list(simulator, {singleEvents: 'true', orderBy: 'startTime', timeZone: TORONTO, q: event.data.summary, timeMin: '2026-11-01T00:00:00Z', timeMax: '2027-01-01T00:00:00Z'}))
    .data.items.map(item => item.start.dateTime.slice(0, 10));
  assert.deepEqual(await series(every), ['2026-11-16', '2026-11-18', '2026-11-20']);
  assert.deepEqual(await series(days), ['2026-11-16', '2026-11-18', '2026-11-23', '2026-11-25']);
  assert.deepEqual(await series(until), ['2026-11-16', '2026-11-30', '2026-12-14']);
  // An all-day series: dates, no offsets.
  const daily = await insert(simulator, {summary: 'Allday', start: {date: '2026-11-20'}, end: {date: '2026-11-21'}, recurrence: ['RRULE:FREQ=DAILY;COUNT=3']});
  assert.deepEqual((await list(simulator, {singleEvents: 'true', orderBy: 'startTime', q: 'Allday', timeMin: '2026-11-01T00:00:00Z', timeMax: '2027-01-01T00:00:00Z'})).data.items.map(item => [item.id, item.start, item.end]),
    [['20261120', '2026-11-20', '2026-11-21'], ['20261121', '2026-11-21', '2026-11-22'], ['20261122', '2026-11-22', '2026-11-23']].map(([stamp, start, end]) => [`${daily.data.id}_${stamp}`, {date: start}, {date: end}]));
});

test('orderBy=startTime without singleEvents answers 400; timeMin bounds the end and timeMax the start, both exclusive; cancelled events are left out', async () => {
  const simulator = sim();
  assert.deepEqual(reasonOf(await list(simulator, {orderBy: 'startTime'})), [400, 'badRequest']);
  assert.deepEqual(reasonOf(await list(simulator, {orderBy: 'startTime', singleEvents: 'false'})), [400, 'badRequest']);
  assert.deepEqual(reasonOf(await list(simulator, {orderBy: 'title', singleEvents: 'true'})), [400, 'invalidParameter']);
  assert.deepEqual(reasonOf(await list(simulator, {timeMin: '2026-10-30'})), [400, 'badRequest'], 'timeMin is an RFC 3339 instant with an offset');
  const made = await insert(simulator, timed('2026-10-30T10:00:00', '2026-10-30T10:30:00'));
  const ids = async window => (await list(simulator, {singleEvents: 'true', orderBy: 'startTime', ...window})).data.items.map(item => item.id);
  assert.deepEqual(await ids({timeMin: '2026-10-30T10:30:00-04:00'}), [], 'an event ending at timeMin is out');
  assert.deepEqual(await ids({timeMin: '2026-10-30T10:29:59-04:00'}), [made.data.id]);
  assert.deepEqual(await ids({timeMin: '2026-10-30T10:15:00-04:00'}), [made.data.id], 'timeMin after the start but before the end: in (it bounds the end)');
  assert.deepEqual(await ids({timeMax: '2026-10-30T10:00:00-04:00'}), [], 'an event starting at timeMax is out');
  assert.deepEqual(await ids({timeMax: '2026-10-30T10:00:01-04:00'}), [made.data.id]);
  assert.deepEqual(await ids({timeMax: '2026-10-30T10:15:00-04:00'}), [made.data.id], 'timeMax before the end but after the start: in (it bounds the start)');
  // An all-day event spans its days in the calendar's zone.
  const day = await insert(simulator, {summary: 'Day', start: {date: '2026-11-02'}, end: {date: '2026-11-03'}});
  assert.deepEqual(await ids({timeMin: '2026-11-03T04:59:59Z', timeMax: '2026-11-04T00:00:00Z'}), [day.data.id], 'Toronto midnight is 05:00Z in November');
  assert.deepEqual(await ids({timeMin: '2026-11-03T05:00:00Z', timeMax: '2026-11-04T00:00:00Z'}), []);
  assert.equal((await send(simulator, 'DELETE', `/calendars/primary/events/${made.data.id}`)).status, 204);
  assert.deepEqual(await ids({}), [day.data.id], 'the cancelled event is left out');
});

test('a stale If-Match answers 412 conditionNotMet and changes nothing; the current one applies and moves the etag; without If-Match the change applies', async () => {
  const simulator = sim();
  const made = await insert(simulator, timed('2026-10-30T10:00:00', '2026-10-30T10:30:00'));
  const first = made.data.etag;
  const before = simulator.state();
  const stale = await patch(simulator, made.data.id, {summary: 'Changed'}, {headers: {...AUTH, 'If-Match': '"1"'}});
  assert.deepEqual([...reasonOf(stale), stale.data.error.code], [412, 'conditionNotMet', 412]);
  assert.deepEqual(simulator.state(), before, 'nothing changed');
  const put = await send(simulator, 'PUT', `/calendars/primary/events/${made.data.id}`, {body: timed('2026-10-30T11:00:00', '2026-10-30T11:30:00'), headers: {...AUTH, 'If-Match': '"1"'}});
  assert.deepEqual(reasonOf(put), [412, 'conditionNotMet']);
  assert.deepEqual(simulator.state(), before);
  const changed = await patch(simulator, made.data.id, {summary: 'Changed'}, {headers: {...AUTH, 'If-Match': first}});
  assert.deepEqual([changed.status, changed.data.summary, changed.data.etag === changed.headers.etag, changed.data.etag !== first], [200, 'Changed', true, true]);
  assert.deepEqual([changed.data.start, changed.data.description], [made.data.start, undefined], 'patch keeps every field it does not name');
  assert.deepEqual(reasonOf(await patch(simulator, made.data.id, {summary: 'Again'}, {headers: {...AUTH, 'If-Match': first}})), [412, 'conditionNotMet'], 'the first etag is stale now');
  const free = await patch(simulator, made.data.id, {location: 'Room 2'});
  assert.deepEqual([free.status, free.data.location, free.data.summary], [200, 'Room 2', 'Changed'], 'Google does not require If-Match');
  // touch(): someone else changes the event, so the etag a caller read is stale.
  const read = await get(simulator, made.data.id);
  simulator.touch('primary', made.data.id);
  assert.deepEqual(reasonOf(await patch(simulator, made.data.id, {summary: 'Late'}, {headers: {...AUTH, 'If-Match': read.data.etag}})), [412, 'conditionNotMet']);
  assert.notEqual((await get(simulator, made.data.id)).data.etag, read.data.etag);
  // PUT replaces the whole event: a field it leaves out is cleared.
  const now = (await get(simulator, made.data.id)).data;
  const replaced = await send(simulator, 'PUT', `/calendars/primary/events/${made.data.id}`, {body: timed('2026-10-30T11:00:00', '2026-10-30T11:30:00', {summary: 'Put'}), headers: {...AUTH, 'If-Match': now.etag}});
  assert.deepEqual([replaced.status, replaced.data.summary, replaced.data.location, replaced.data.start.dateTime, replaced.data.id], [200, 'Put', undefined, '2026-10-30T11:00:00-04:00', made.data.id]);
  assert.deepEqual(reasonOf(await send(simulator, 'PUT', `/calendars/primary/events/${made.data.id}`, {body: {summary: 'No times'}})), [400, 'required']);
  // A patch that leaves the times invalid is refused whole.
  assert.deepEqual(reasonOf(await patch(simulator, made.data.id, {end: {dateTime: '2026-10-30T10:00:00', timeZone: TORONTO}})), [400, 'timeRangeEmpty']);
});

test('attendees: a patch replaces the list; an organizer\'s change and the owner\'s own entry carry self and organizer flags; a guest with attendeesOmitted changes only their own response', async () => {
  const simulator = sim();
  const made = await insert(simulator, timed('2026-10-30T10:00:00', '2026-10-30T10:30:00', {attendees: [{email: 'ada@example.org'}, {email: OWNER.email, responseStatus: 'accepted'}]}));
  assert.deepEqual(made.data.attendees, [{email: 'ada@example.org', responseStatus: 'needsAction'}, {email: OWNER.email, responseStatus: 'accepted', organizer: true, self: true}]);
  const replaced = await patch(simulator, made.data.id, {attendees: [{email: OWNER.email, responseStatus: 'accepted'}, {email: 'grace@example.org'}]});
  assert.deepEqual(replaced.data.attendees.map(item => [item.email, item.responseStatus]), [[OWNER.email, 'accepted'], ['grace@example.org', 'needsAction']], 'the list is replaced');
  const kept = await patch(simulator, made.data.id, {attendees: [{email: OWNER.email}, {email: 'grace@example.org', responseStatus: 'tentative'}, {email: 'linus@example.org'}]});
  assert.deepEqual(kept.data.attendees.map(item => [item.email, item.responseStatus]), [[OWNER.email, 'accepted'], ['grace@example.org', 'tentative'], ['linus@example.org', 'needsAction']],
    'an entry with no response keeps the one it had');
  // An invitation another account organizes: the owner is a guest.
  const invited = simulator.invite({summary: 'Their meeting', start: {dateTime: '2026-11-03T15:00:00Z'}, end: {dateTime: '2026-11-03T16:00:00Z'}, organizer: 'inviter@other.example',
    attendees: ['guest2@other.example']});
  assert.deepEqual([invited.organizer, invited.attendees.map(item => [item.email, item.responseStatus, item.organizer === true, item.self === true])],
    [{email: 'inviter@other.example'}, [['inviter@other.example', 'accepted', true, false], ['guest2@other.example', 'needsAction', false, false], [OWNER.email, 'needsAction', false, true]]]);
  const others = invited.attendees.filter(item => item.email !== OWNER.email);
  const answered = await patch(simulator, invited.id, {attendeesOmitted: true, attendees: [{email: OWNER.email, responseStatus: 'accepted'}]});
  assert.equal(answered.status, 200);
  assert.deepEqual(answered.data.attendees.find(item => item.self).responseStatus, 'accepted');
  assert.deepEqual(answered.data.attendees.filter(item => item.email !== OWNER.email), others, 'the other attendees are untouched');
  assert.notEqual(answered.data.etag, invited.etag);
  // Without attendeesOmitted the one-entry list would drop the other attendees: forbidden for a guest, and nothing changes.
  const before = simulator.state();
  for (const body of [{attendees: [{email: OWNER.email, responseStatus: 'declined'}]}, {summary: 'Mine now'},
    {attendeesOmitted: true, attendees: [{email: 'guest2@other.example', responseStatus: 'declined'}]}, {attendeesOmitted: true, attendees: [{email: 'new@other.example'}]}]) {
    assert.deepEqual(reasonOf(await patch(simulator, invited.id, body)), [403, 'forbiddenForNonOrganizer'], JSON.stringify(body));
  }
  assert.deepEqual(simulator.state(), before);
  // The organizer may use attendeesOmitted too: only the listed attendee changes.
  const own = await patch(simulator, made.data.id, {attendeesOmitted: true, attendees: [{email: 'linus@example.org', optional: true}]});
  assert.deepEqual(own.data.attendees.map(item => [item.email, item.responseStatus, item.optional === true]), [[OWNER.email, 'accepted', false], ['grace@example.org', 'tentative', false], ['linus@example.org', 'needsAction', true]]);
  // maxAttendees: more attendees than asked for leaves only the caller's own entry, with attendeesOmitted.
  const trimmed = await get(simulator, made.data.id, {query: {maxAttendees: 1}});
  assert.deepEqual([trimmed.data.attendees, trimmed.data.attendeesOmitted], [[{email: OWNER.email, responseStatus: 'accepted', organizer: true, self: true}], true]);
  assert.deepEqual([(await get(simulator, made.data.id, {query: {maxAttendees: 3}})).data.attendees.length, (await get(simulator, made.data.id, {query: {maxAttendees: 3}})).data.attendeesOmitted], [3, undefined]);
});

test('move: a default event moves, keeps its id and gets the destination as organizer; another event type answers 400 and stays; the destination must be writable', async () => {
  const simulator = sim();
  const a = await send(simulator, 'POST', '/calendars', {body: {summary: 'Calendar A'}}), b = await send(simulator, 'POST', '/calendars', {body: {summary: 'Calendar B'}});
  const made = await insert(simulator, timed('2026-10-30T10:00:00', '2026-10-30T10:30:00'), {calendarId: a.data.id});
  assert.deepEqual(made.data.organizer, {email: a.data.id, displayName: 'Calendar A', self: true});
  const moved = await send(simulator, 'POST', `/calendars/${encodeURIComponent(a.data.id)}/events/${made.data.id}/move`, {query: {destination: b.data.id, sendUpdates: 'none'}});
  assert.deepEqual([moved.status, moved.data.id, moved.data.organizer, moved.data.etag !== made.data.etag], [200, made.data.id, {email: b.data.id, displayName: 'Calendar B', self: true}, true]);
  const after = await get(simulator, made.data.id, {calendarId: b.data.id});
  assert.equal(after.status, 200);
  // Live run TOQJPGEU (C8): Google answers the move with one etag and the moved event reads back with a newer one; start and end stay.
  assert.deepEqual([after.data.etag !== moved.data.etag, after.data.start, after.data.end], [true, moved.data.start, moved.data.end]);
  assert.equal((await get(simulator, made.data.id, {calendarId: a.data.id})).status, 404, 'no longer on the source');
  // Another event type stays where it is.
  const focus = simulator.seed(a.data.id, timed('2026-10-31T10:00:00', '2026-10-31T12:00:00', {summary: 'Focus'}), {eventType: 'focusTime'});
  assert.equal(focus.eventType, 'focusTime');
  const before = simulator.state();
  assert.deepEqual(reasonOf(await send(simulator, 'POST', `/calendars/${encodeURIComponent(a.data.id)}/events/${focus.id}/move`, {query: {destination: b.data.id}})), [400, 'eventTypeRestriction']);
  assert.deepEqual(simulator.state(), before, 'it stays');
  // A destination the owner cannot write, or does not have, refuses.
  simulator.addCalendar({id: 'holidays@group.v.calendar.google.com', summary: 'Holidays', accessRole: 'reader'});
  assert.deepEqual(reasonOf(await send(simulator, 'POST', `/calendars/${encodeURIComponent(b.data.id)}/events/${made.data.id}/move`, {query: {destination: 'holidays@group.v.calendar.google.com'}})), [403, 'requiredAccessLevel']);
  assert.deepEqual(reasonOf(await send(simulator, 'POST', `/calendars/${encodeURIComponent(b.data.id)}/events/${made.data.id}/move`, {query: {destination: 'nobody@group.calendar.google.com'}})), [404, 'notFound']);
  assert.deepEqual(reasonOf(await send(simulator, 'POST', `/calendars/${encodeURIComponent(b.data.id)}/events/${made.data.id}/move`)), [400, 'required']);
  // Moving to the primary calendar: the owner is the organizer.
  const home = await send(simulator, 'POST', `/calendars/${encodeURIComponent(b.data.id)}/events/${made.data.id}/move`, {query: {destination: 'primary'}});
  assert.deepEqual([home.status, home.data.organizer], [200, {email: OWNER.email, self: true}]);
});

test('delete answers 204; a deleted event reads back cancelled, or 404 or 410 under deletedAs(); a second delete answers 410', async () => {
  for (const status of [200, 404, 410]) {
    const simulator = sim();
    if (status !== 200) simulator.deletedAs(status);
    const made = await insert(simulator, timed('2026-10-30T10:00:00', '2026-10-30T10:30:00'));
    const gone = await send(simulator, 'DELETE', `/calendars/primary/events/${made.data.id}`, {query: {sendUpdates: 'none'}});
    assert.deepEqual([gone.status, gone.data], [204, null]);
    const read = await get(simulator, made.data.id);
    if (status === 200) assert.deepEqual([read.status, read.data.status, read.data.id], [200, 'cancelled', made.data.id]);
    else assert.deepEqual(reasonOf(read), [status, status === 404 ? 'notFound' : 'deleted']);
    assert.deepEqual(reasonOf(await send(simulator, 'DELETE', `/calendars/primary/events/${made.data.id}`)), [410, 'deleted']);
    assert.deepEqual(reasonOf(await send(simulator, 'DELETE', '/calendars/primary/events/nosuchevent00')), [404, 'notFound']);
  }
});

test('Meet: conferenceData.createRequest is read only with conferenceDataVersion=1, and a requestId seen before creates no second conference', async () => {
  const simulator = sim();
  const meet = requestId => timed('2026-10-30T10:00:00', '2026-10-30T10:30:00', {conferenceData: {createRequest: {requestId, conferenceSolutionKey: {type: 'hangoutsMeet'}}}});
  const ignored = await insert(simulator, meet('job-1-meet'));
  assert.deepEqual([ignored.status, ignored.data.conferenceData, ignored.data.hangoutLink], [200, undefined, undefined], 'ignored without conferenceDataVersion=1');
  assert.equal((await insert(simulator, meet('job-1-meet'), {query: {conferenceDataVersion: 0}})).data.hangoutLink, undefined);
  const first = await insert(simulator, meet('job-1-meet'), {query: {conferenceDataVersion: 1}});
  assert.equal(first.data.conferenceData.createRequest.status.statusCode, 'success');
  assert.equal(first.data.conferenceData.createRequest.requestId, 'job-1-meet');
  assert.match(first.data.conferenceData.conferenceId, /^[a-z]{3}-[a-z]{4}-[a-z]{3}$/);
  assert.equal(first.data.hangoutLink, `https://meet.google.com/${first.data.conferenceData.conferenceId}`);
  const again = await insert(simulator, meet('job-1-meet'), {query: {conferenceDataVersion: 1}});
  assert.equal(again.data.conferenceData.conferenceId, first.data.conferenceData.conferenceId, 'the same requestId: the same conference');
  assert.equal(Object.keys(simulator.state().conferences).length, 1, 'no second conference');
  const other = await insert(simulator, meet('job-2-meet'), {query: {conferenceDataVersion: 1}});
  assert.notEqual(other.data.conferenceData.conferenceId, first.data.conferenceData.conferenceId);
  assert.equal(Object.keys(simulator.state().conferences).length, 2);
  assert.deepEqual((await get(simulator, first.data.id)).data.hangoutLink, first.data.hangoutLink);
  assert.deepEqual(reasonOf(await insert(simulator, meet('job-3-meet'), {query: {conferenceDataVersion: 2}})), [400, 'invalid']);
  assert.deepEqual(reasonOf(await insert(simulator, {...meet('job-4-meet'), conferenceData: {createRequest: {requestId: 'job-4-meet', conferenceSolutionKey: {type: 'eventNamedHangout'}}}}, {query: {conferenceDataVersion: 1}})), [400, 'invalid']);
});

test('quick add reads one documented-by-the-simulator form in the calendar\'s zone; any other text becomes a one-hour event at the next whole hour', async () => {
  const simulator = sim();
  const parsed = await send(simulator, 'POST', '/calendars/primary/events/quickAdd', {query: {text: '[SYNTHETIC] Lunch on 2026-11-03 at 3pm to 3:30pm', sendUpdates: 'none'}});
  assert.deepEqual([parsed.status, parsed.data.summary, parsed.data.start, parsed.data.end], [200, '[SYNTHETIC] Lunch', {dateTime: '2026-11-03T15:00:00-05:00', timeZone: TORONTO}, {dateTime: '2026-11-03T15:30:00-05:00', timeZone: TORONTO}]);
  assert.deepEqual((await get(simulator, parsed.data.id)).data, parsed.data);
  const noon = await send(simulator, 'POST', '/calendars/primary/events/quickAdd', {query: {text: 'Talk on 2026-11-04 at 12:15am to 1am'}});
  assert.deepEqual([noon.data.start.dateTime, noon.data.end.dateTime], ['2026-11-04T00:15:00-05:00', '2026-11-04T01:00:00-05:00']);
  const loose = await send(simulator, 'POST', '/calendars/primary/events/quickAdd', {query: {text: 'Coffee with Ada tomorrow'}});
  assert.deepEqual([loose.data.summary, loose.data.start.dateTime, loose.data.end.dateTime], ['Coffee with Ada tomorrow', '2026-10-23T10:00:00-04:00', '2026-10-23T11:00:00-04:00'], 'the clock reads 09:00 in Toronto');
  assert.deepEqual(reasonOf(await send(simulator, 'POST', '/calendars/primary/events/quickAdd')), [400, 'required']);
  assert.deepEqual(simulator.writes().map(call => call.route), Array(4).fill('POST /calendars/{calendarId}/events/quickAdd'));
});

test('freeBusy merges busy blocks of opaque, confirmed events and instances, clips them to the window, and marks an unknown calendar with errors', async () => {
  const simulator = sim();
  await insert(simulator, timed('2026-10-30T10:00:00', '2026-10-30T11:00:00'));
  await insert(simulator, timed('2026-10-30T10:30:00', '2026-10-30T11:30:00'));
  await insert(simulator, timed('2026-10-30T11:30:00', '2026-10-30T12:00:00'), {});
  await insert(simulator, timed('2026-10-30T14:00:00', '2026-10-30T15:00:00', {transparency: 'transparent'}));
  const cancelled = await insert(simulator, timed('2026-10-30T16:00:00', '2026-10-30T17:00:00'));
  await send(simulator, 'DELETE', `/calendars/primary/events/${cancelled.data.id}`);
  await insert(simulator, timed('2026-10-29T08:00:00', '2026-10-29T08:30:00', {recurrence: ['RRULE:FREQ=DAILY;COUNT=3']}));
  await insert(simulator, timed('2026-10-30T23:00:00', '2026-10-31T01:00:00'));
  const window = {timeMin: '2026-10-30T00:00:00-04:00', timeMax: '2026-10-31T00:00:00-04:00'};
  const busy = await send(simulator, 'POST', '/freeBusy', {body: {...window, items: [{id: 'primary'}, {id: 'nobody@group.calendar.google.com'}]}});
  assert.deepEqual([busy.status, busy.data.kind, busy.data.timeMin, busy.data.timeMax], [200, 'calendar#freeBusy', '2026-10-30T04:00:00.000Z', '2026-10-31T04:00:00.000Z']);
  assert.deepEqual(busy.data.calendars.primary.busy, [{start: '2026-10-30T12:00:00Z', end: '2026-10-30T12:30:00Z'}, {start: '2026-10-30T14:00:00Z', end: '2026-10-30T16:00:00Z'},
    {start: '2026-10-31T03:00:00Z', end: '2026-10-31T04:00:00Z'}], 'merged, instances expanded, clipped to the window; the transparent and cancelled ones are free');
  assert.deepEqual(busy.data.calendars['nobody@group.calendar.google.com'], {errors: [{domain: 'global', reason: 'notFound'}], busy: []});
  const local = await send(simulator, 'POST', '/freeBusy', {body: {...window, timeZone: TORONTO, items: [{id: 'primary'}]}});
  assert.deepEqual(local.data.calendars.primary.busy[0], {start: '2026-10-30T08:00:00-04:00', end: '2026-10-30T08:30:00-04:00'});
  assert.deepEqual(reasonOf(await send(simulator, 'POST', '/freeBusy', {body: {timeMin: window.timeMax, timeMax: window.timeMin, items: [{id: 'primary'}]}})), [400, 'timeRangeEmpty']);
  assert.deepEqual(reasonOf(await send(simulator, 'POST', '/freeBusy', {body: {timeMax: window.timeMax, items: [{id: 'primary'}]}})), [400, 'required']);
  assert.equal(simulator.writes().filter(call => call.path === '/freeBusy').length, 0, 'POST /freeBusy changes nothing: recorded as a read');
});

test('calendars, the calendar list and settings: insert, get and delete a calendar (not the primary), list pages, primary resolves, the time zone setting', async () => {
  const simulator = sim();
  const made = await send(simulator, 'POST', '/calendars', {body: {summary: 'Calendar A', description: 'Test', timeZone: 'Europe/Paris'}});
  assert.match(made.data.id, /^c_[0-9a-f]{64}@group\.calendar\.google\.com$/);
  assert.deepEqual([made.status, made.data.kind, made.data.summary, made.data.description, made.data.timeZone, made.data.etag === made.headers.etag], [200, 'calendar#calendar', 'Calendar A', 'Test', 'Europe/Paris', true]);
  assert.deepEqual((await send(simulator, 'GET', `/calendars/${encodeURIComponent(made.data.id)}`)).data, made.data);
  assert.equal((await send(simulator, 'POST', '/calendars', {body: {summary: 'Calendar B'}})).data.timeZone, TORONTO, 'the owner\'s zone by default');
  assert.deepEqual(reasonOf(await send(simulator, 'POST', '/calendars', {body: {description: 'no title'}})), [400, 'required']);
  assert.deepEqual(reasonOf(await send(simulator, 'POST', '/calendars', {body: {summary: 'Z', timeZone: 'Nowhere/Land'}})), [400, 'invalid']);
  const primary = await send(simulator, 'GET', '/calendars/primary');
  assert.deepEqual([primary.data.id, primary.data.timeZone], [OWNER.email, TORONTO]);
  // The calendar list pages; primary resolves to the owner's address.
  const first = await send(simulator, 'GET', '/users/me/calendarList', {query: {maxResults: 2}});
  assert.deepEqual([first.data.kind, first.data.items.length, typeof first.data.nextPageToken], ['calendar#calendarList', 2, 'string']);
  assert.deepEqual(first.data.items[0], {kind: 'calendar#calendarListEntry', etag: first.data.items[0].etag, id: OWNER.email, summary: OWNER.email, timeZone: TORONTO, accessRole: 'owner', primary: true});
  const second = await send(simulator, 'GET', '/users/me/calendarList', {query: {maxResults: 2, pageToken: first.data.nextPageToken}});
  assert.deepEqual([second.data.items.map(item => item.summary), second.data.nextPageToken], [['Calendar B'], undefined]);
  assert.deepEqual(reasonOf(await send(simulator, 'GET', '/users/me/calendarList', {query: {pageToken: 'forged'}})), [400, 'invalid']);
  assert.deepEqual(reasonOf(await send(simulator, 'GET', '/users/me/calendarList', {query: {maxResults: 251}})), [400, 'invalid']);
  const entry = await send(simulator, 'GET', '/users/me/calendarList/primary');
  assert.deepEqual([entry.data.id, entry.data.primary, entry.data.timeZone], [OWNER.email, true, TORONTO]);
  assert.equal((await send(simulator, 'GET', `/users/me/calendarList/${encodeURIComponent(made.data.id)}`)).data.accessRole, 'owner');
  assert.deepEqual(reasonOf(await send(simulator, 'GET', '/users/me/calendarList/nobody%40group.calendar.google.com')), [404, 'notFound']);
  const zone = await send(simulator, 'GET', '/users/me/settings/timezone');
  assert.deepEqual([zone.status, zone.data.kind, zone.data.id, zone.data.value], [200, 'calendar#setting', 'timezone', TORONTO]);
  assert.deepEqual(reasonOf(await send(simulator, 'GET', '/users/me/settings/nosuchsetting')), [404, 'notFound']);
  // Delete: a secondary calendar goes with its events and its list entry; the primary cannot be deleted.
  const event = await insert(simulator, timed('2026-10-30T10:00:00', '2026-10-30T10:30:00'), {calendarId: made.data.id});
  assert.equal((await send(simulator, 'DELETE', `/calendars/${encodeURIComponent(made.data.id)}`)).status, 204);
  assert.deepEqual(reasonOf(await send(simulator, 'GET', `/calendars/${encodeURIComponent(made.data.id)}`)), [404, 'notFound']);
  assert.deepEqual(reasonOf(await get(simulator, event.data.id, {calendarId: made.data.id})), [404, 'notFound']);
  assert.equal((await send(simulator, 'GET', '/users/me/calendarList')).data.items.length, 2);
  assert.deepEqual(reasonOf(await send(simulator, 'DELETE', '/calendars/primary')), [400, 'cannotDeletePrimaryCalendar']);
  simulator.addCalendar({id: 'team@group.calendar.google.com', summary: 'Team', accessRole: 'writer'});
  assert.deepEqual(reasonOf(await send(simulator, 'DELETE', '/calendars/team%40group.calendar.google.com')), [403, 'forbidden'], 'only an owner deletes a calendar');
});

test('ACL: get then delete a user rule; a deleted rule reads back 404; only the calendar\'s owner may delete', async () => {
  const simulator = sim();
  const a = await send(simulator, 'POST', '/calendars', {body: {summary: 'Calendar A'}});
  const rule = simulator.share(a.data.id, 'fabric-share@example.com', 'reader');
  assert.deepEqual([rule.id, rule.scope, rule.role], ['user:fabric-share@example.com', {type: 'user', value: 'fabric-share@example.com'}, 'reader']);
  const path = `/calendars/${encodeURIComponent(a.data.id)}/acl/${encodeURIComponent('user:fabric-share@example.com')}`;
  const read = await send(simulator, 'GET', path);
  assert.deepEqual([read.status, read.data.kind, read.data.id, read.data.role, read.data.scope], [200, 'calendar#aclRule', 'user:fabric-share@example.com', 'reader', {type: 'user', value: 'fabric-share@example.com'}]);
  assert.equal((await send(simulator, 'GET', `/calendars/${encodeURIComponent(a.data.id)}/acl/${encodeURIComponent(`user:${OWNER.email}`)}`)).data.role, 'owner', 'the owner\'s own rule');
  assert.deepEqual([(await send(simulator, 'DELETE', path)).status, reasonOf(await send(simulator, 'GET', path)), reasonOf(await send(simulator, 'DELETE', path))], [204, [404, 'notFound'], [404, 'notFound']]);
  simulator.addCalendar({id: 'team@group.calendar.google.com', summary: 'Team', accessRole: 'writer'});
  simulator.share('team@group.calendar.google.com', 'someone@example.com', 'reader');
  assert.deepEqual(reasonOf(await send(simulator, 'DELETE', '/calendars/team%40group.calendar.google.com/acl/user%3Asomeone%40example.com')), [403, 'forbidden']);
  assert.equal(simulator.writes().filter(call => call.route === 'DELETE /calendars/{calendarId}/acl/{ruleId}').length, 3);
});

test('sendUpdates: a value other than all, externalOnly or none answers 400 and changes nothing; none, or no value, records no notification; all and externalOnly record one per guest', async () => {
  const simulator = sim();
  const guests = {attendees: [{email: OWNER.email, responseStatus: 'accepted'}, {email: 'colleague@example.com'}, {email: 'outside@other.example'}]};
  const before = simulator.state();
  for (const value of ['yes', 'false', 'ALL', '']) {
    assert.deepEqual(reasonOf(await insert(simulator, timed('2026-10-30T10:00:00', '2026-10-30T10:30:00', guests), {query: {sendUpdates: value}})), [400, 'invalidParameter'], value);
  }
  assert.deepEqual(simulator.state(), before);
  const quiet = await insert(simulator, timed('2026-10-30T10:00:00', '2026-10-30T10:30:00', guests), {query: {sendUpdates: 'none'}});
  const silent = await insert(simulator, timed('2026-10-30T11:00:00', '2026-10-30T11:30:00', guests));
  assert.deepEqual(simulator.notifications(), [], 'none, and no value, email nobody');
  for (const [method, path, query] of [['PATCH', `/calendars/primary/events/${quiet.data.id}`, {sendUpdates: 'everyone'}], ['DELETE', `/calendars/primary/events/${quiet.data.id}`, {sendUpdates: 'everyone'}],
    ['POST', `/calendars/primary/events/${quiet.data.id}/move`, {destination: 'primary', sendUpdates: 'everyone'}], ['POST', '/calendars/primary/events/quickAdd', {text: 'Lunch', sendUpdates: 'everyone'}]]) {
    assert.deepEqual(reasonOf(await send(simulator, method, path, {query, ...(method === 'PATCH' ? {body: {summary: 'x'}} : {})})), [400, 'invalidParameter'], `${method} ${path}`);
  }
  assert.equal((await patch(simulator, quiet.data.id, {summary: 'Quiet'}, {query: {sendUpdates: 'none'}})).status, 200);
  assert.deepEqual(simulator.notifications(), []);
  const loud = await insert(simulator, timed('2026-10-30T12:00:00', '2026-10-30T12:30:00', guests), {query: {sendUpdates: 'all'}});
  assert.deepEqual(simulator.notifications().map(item => [item.kind, item.to, item.eventId]), [['invitation', 'colleague@example.com', loud.data.id], ['invitation', 'outside@other.example', loud.data.id]], 'every guest but the owner');
  await patch(simulator, silent.data.id, {summary: 'Outside only'}, {query: {sendUpdates: 'externalOnly'}});
  assert.deepEqual(simulator.notifications().slice(2).map(item => [item.kind, item.to]), [['update', 'outside@other.example']], 'externalOnly: guests outside the owner\'s domain');
  await send(simulator, 'DELETE', `/calendars/primary/events/${loud.data.id}`, {query: {sendUpdates: 'all'}});
  assert.deepEqual(simulator.notifications().slice(3).map(item => [item.kind, item.to]), [['cancellation', 'colleague@example.com'], ['cancellation', 'outside@other.example']]);
  // A guest's own answer, sent with all: the organizer hears of it.
  const invited = simulator.invite({summary: 'Theirs', start: {dateTime: '2026-11-03T15:00:00Z'}, end: {dateTime: '2026-11-03T16:00:00Z'}, organizer: 'inviter@other.example'});
  await patch(simulator, invited.id, {attendeesOmitted: true, attendees: [{email: OWNER.email, responseStatus: 'declined'}]}, {query: {sendUpdates: 'all'}});
  assert.deepEqual(simulator.notifications().slice(5).map(item => [item.kind, item.to]), [['response', 'inviter@other.example']]);
});

test('list: q matches summary, description, location and attendee emails in any case; maxResults and pageToken page; timeZone sets every offset', async () => {
  const simulator = sim();
  const one = await insert(simulator, timed('2026-10-30T10:00:00', '2026-10-30T10:30:00', {summary: '[SYNTHETIC] Fabric C2 r1'}));
  const two = await insert(simulator, timed('2026-10-30T09:00:00', '2026-10-30T09:30:00', {summary: 'Standup', description: 'about the synthetic run'}));
  const three = await insert(simulator, timed('2026-10-30T11:00:00', '2026-10-30T11:30:00', {summary: 'Lunch', location: 'Synthetic Cafe'}));
  const four = await insert(simulator, timed('2026-10-30T12:00:00', '2026-10-30T12:30:00', {summary: 'Call', attendees: [{email: 'SYNTHETIC-guest@example.org'}]}));
  await insert(simulator, timed('2026-10-30T13:00:00', '2026-10-30T13:30:00', {summary: 'Other'}));
  const found = await list(simulator, {q: 'synthetic', singleEvents: 'true', orderBy: 'startTime'});
  assert.deepEqual(found.data.items.map(item => item.id), [two.data.id, one.data.id, three.data.id, four.data.id]);
  assert.deepEqual((await list(simulator, {q: '[SYNTHETIC] c2'})).data.items.map(item => item.id), [one.data.id], 'every word must match');
  const ids = [], pages = [];
  let token;
  do {
    const page = await list(simulator, {singleEvents: 'true', orderBy: 'startTime', maxResults: 2, ...(token ? {pageToken: token} : {})});
    ids.push(...page.data.items.map(item => item.id));
    pages.push(page.data.items.length);
    token = page.data.nextPageToken;
  } while (token);
  assert.deepEqual([ids.length, pages], [5, [2, 2, 1]]);
  assert.deepEqual(ids.slice(0, 4), [two.data.id, one.data.id, three.data.id, four.data.id]);
  assert.deepEqual(reasonOf(await list(simulator, {maxResults: 2501})), [400, 'invalid']);
  assert.deepEqual(reasonOf(await list(simulator, {pageToken: 'not-a-token'})), [400, 'invalid']);
  const listed = await list(simulator, {timeZone: 'Asia/Kolkata', singleEvents: 'true', orderBy: 'startTime', maxResults: 1});
  assert.deepEqual([listed.data.kind, listed.data.timeZone, listed.data.items[0].start.dateTime], ['calendar#events', TORONTO, '2026-10-30T18:30:00+05:30']);
  assert.equal(simulator.writes().length, 5, 'reads record no write');
  assert.deepEqual(reasonOf(await list(simulator, {}, 'nobody@group.calendar.google.com')), [404, 'notFound']);
});

test('switches: fail, drop, swallow, oversize and hold, each for the next call to one route; reads() and writes() split the calls', async () => {
  const route = 'PATCH /calendars/{calendarId}/events/{eventId}';
  const simulator = sim(), made = await insert(simulator, timed('2026-10-30T10:00:00', '2026-10-30T10:30:00'));
  simulator.fail(route, {status: 500, data: {error: {code: 500, message: 'Backend Error', errors: [{domain: 'global', reason: 'backendError', message: 'Backend Error'}]}}});
  assert.deepEqual(reasonOf(await patch(simulator, made.data.id, {summary: 'A'})), [500, 'backendError']);
  assert.equal((await get(simulator, made.data.id)).data.summary, 'Review', 'fail changes nothing');
  simulator.drop(route);
  await assert.rejects(patch(simulator, made.data.id, {summary: 'B'}), error => error.sent === true);
  assert.equal((await get(simulator, made.data.id)).data.summary, 'B', 'drop applies the change, then loses the answer');
  simulator.swallow(route);
  const swallowed = await patch(simulator, made.data.id, {summary: 'C'});
  assert.deepEqual([swallowed.status, swallowed.data.summary, (await get(simulator, made.data.id)).data.summary], [200, 'C', 'B'], 'swallow answers as if applied');
  simulator.oversize('GET /calendars/{calendarId}/events/{eventId}', 4096);
  await assert.rejects(send(simulator, 'GET', `/calendars/primary/events/${made.data.id}`, {maxBytes: 2048}), error => error.sent === true);
  const gate = simulator.hold(route), running = patch(simulator, made.data.id, {summary: 'D'});
  await gate.reached;
  assert.equal((await get(simulator, made.data.id)).data.summary, 'B', 'held: not applied yet');
  gate.release();
  assert.equal((await running).data.summary, 'D');
  assert.deepEqual([simulator.writes().map(call => call.route), simulator.reads().every(call => !call.write)],
    [['POST /calendars/{calendarId}/events', route, route, route, route], true]);
  assert.deepEqual(simulator.writes()[1].body, {summary: 'A'});
});

test('the simulator imports only node built-ins: never lib/, catalog/, an action file or the scope facts', () => {
  const text = readFileSync(new URL('./fixtures/provider-simulators/google-calendar.mjs', import.meta.url), 'utf8');
  const specifiers = [...text.matchAll(/(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)(['"`])([^'"`]+)\1/g)].map(match => match[2]);
  assert.ok(specifiers.length > 0);
  assert.deepEqual(specifiers.filter(specifier => !specifier.startsWith('node:')), []);
});

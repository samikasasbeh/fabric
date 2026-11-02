import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadActionCatalog} from '../lib/action-catalog.mjs';
import {TRANSFORMS} from '../lib/transforms/index.mjs';
import {triggerIds} from '../lib/triggers.mjs';
import {CalendarSimulator, ORIGIN, BASE} from './fixtures/provider-simulators/google-calendar.mjs';
import {caseTests} from './fixtures/provider-simulators/cases.mjs';
import {OWNER_EMAIL, SIX as HARNESS_SIX, TOKEN as HARNESS_TOKEN, calendarDeps} from './fixtures/actions/calendar-harness.mjs';
import {shippedTriggers, triggerWorld} from './fixtures/actions/trigger-harness.mjs';

// Iteration 9 step 8 (docs/I07-BUILD-MAP.md step 8): Google Calendar's eight trigger blocks on the simulator. The first part holds the simulator to Google's sync guide, written from that
// guide and never from the trigger file, so a trigger bug and a simulator bug cannot cancel out. The rest walks each trigger through the shared harness, as an agent and an owner would.
// Nothing here listens on a port or reaches Google.
const TOKEN = 'calendar-token-5e2a', AUTH = {Authorization: `Bearer ${TOKEN}`}, SCOPE = name => `https://www.googleapis.com/auth/${name}`;
const SIX = ['calendar.events', 'calendar.calendarlist', 'calendar.calendars', 'calendar.acls', 'calendar.settings.readonly', 'calendar.freebusy'].map(SCOPE);
const OWNER = {email: 'owner@example.com', zone: 'America/Toronto'}, ZONE = OWNER.zone, EVENTS_ROUTE = 'GET /calendars/{calendarId}/events';
const CAL_A = 'run-a@group.calendar.google.com', CAL_B = 'run-b@group.calendar.google.com';

const sim = () => {
  const simulator = new CalendarSimulator({token: TOKEN, owner: OWNER, scopes: SIX, clock: () => sim.now});
  simulator.addCalendar({id: CAL_A, accessRole: 'owner'});
  simulator.addCalendar({id: CAL_B, accessRole: 'owner'});
  return simulator;
};
sim.now = Date.parse('2026-10-23T13:00:00.000Z');
const send = (simulator, method, path, {body, query} = {}) => {
  const url = new URL(`${BASE}${path}`);
  for (const [name, value] of Object.entries(query ?? {})) url.searchParams.append(name, String(value));
  return simulator.request({url: url.href, method, headers: {...AUTH, ...(body === undefined ? {} : {'Content-Type': 'application/json'})}, ...(body === undefined ? {} : {body: JSON.stringify(body)}), allowedOrigins: [ORIGIN]});
};
const list = (simulator, query, calendarId = CAL_A) => send(simulator, 'GET', `/calendars/${encodeURIComponent(calendarId)}/events`, {query});
const eventPath = (calendarId, eventId) => `/calendars/${encodeURIComponent(calendarId)}/events/${encodeURIComponent(eventId)}`;
const reasonOf = answer => [answer.status, answer.data?.error?.errors?.[0]?.reason];
const idsOf = answer => answer.data.items.map(item => item.id);
const timed = (summary, day = 28, extra = {}) => ({summary, start: {dateTime: `2026-10-${day}T10:00:00`, timeZone: ZONE}, end: {dateTime: `2026-10-${day}T10:30:00`, timeZone: ZONE}, ...extra});
const daily = (summary, count = 3) => timed(summary, 28, {recurrence: [`RRULE:FREQ=DAILY;COUNT=${count}`]});
/** The instance id of a series' occurrence on a day of the month: 10:00 in Toronto is 14:00 UTC until the clocks change. */
const occurrenceId = (id, day) => `${id}_202610${day}T140000Z`;

test('a feed: the token comes on the last page alone, a delta holds each item once as it stands now, and an empty delta still answers a token', async () => {
  const simulator = sim(), made = [1, 2, 3].map(number => simulator.seed(CAL_A, timed(`Event ${number}`)));
  const first = await list(simulator, {maxResults: 2}), last = await list(simulator, {maxResults: 2, pageToken: first.data.nextPageToken});
  assert.deepEqual([idsOf(first), first.data.nextSyncToken], [made.slice(0, 2).map(item => item.id), undefined], 'a page with more behind it has no token');
  assert.deepEqual([idsOf(last), last.data.nextPageToken], [[made[2].id], undefined]);
  assert.ok(last.data.nextSyncToken, 'the last page ends the walk');
  await send(simulator, 'PATCH', eventPath(CAL_A, made[0].id), {body: {summary: 'First change'}});
  await send(simulator, 'PATCH', eventPath(CAL_A, made[0].id), {body: {summary: 'Second change'}});
  const delta = await list(simulator, {maxResults: 2, syncToken: last.data.nextSyncToken});
  assert.deepEqual(delta.data.items.map(item => [item.id, item.summary]), [[made[0].id, 'Second change']], 'two writes on one item read once');
  const empty = await list(simulator, {maxResults: 2, syncToken: delta.data.nextSyncToken});
  assert.deepEqual([idsOf(empty), typeof empty.data.nextSyncToken], [[], 'string']);
  assert.deepEqual(idsOf(await list(simulator, {maxResults: 2, syncToken: last.data.nextSyncToken})), [made[0].id], 'an old token stays good, so a poll can replay');
});

test('a write during a walk comes round again, so the token on the last page misses nothing', async () => {
  const simulator = sim(), made = [1, 2].map(number => simulator.seed(CAL_A, timed(`Event ${number}`)));
  const first = await list(simulator, {maxResults: 1});
  await send(simulator, 'PATCH', eventPath(CAL_A, made[0].id), {body: {summary: 'Read already, and changed'}});
  const second = await list(simulator, {maxResults: 1, pageToken: first.data.nextPageToken}), third = await list(simulator, {maxResults: 1, pageToken: second.data.nextPageToken});
  assert.deepEqual(third.data.items.map(item => item.summary), ['Read already, and changed']);
  assert.deepEqual(idsOf(await list(simulator, {maxResults: 1, syncToken: third.data.nextSyncToken})), []);
});

test('a token binds its calendar and its query: another calendar, another query and a damaged token each answer 400, and an unknown calendar 404', async () => {
  const simulator = sim(), {data: {nextSyncToken: token}} = await list(simulator, {maxResults: 50});
  assert.deepEqual(reasonOf(await list(simulator, {maxResults: 50, syncToken: token}, CAL_B)), [400, 'invalid'], 'a token names one calendar');
  assert.deepEqual(reasonOf(await list(simulator, {maxResults: 40, syncToken: token})), [400, 'invalid'], 'a page size is part of the query');
  assert.deepEqual(reasonOf(await list(simulator, {maxResults: 50, syncToken: `${token}x`})), [400, 'invalid'], 'a damaged token is no 410');
  assert.equal((await list(simulator, {maxResults: 50, syncToken: token})).status, 200);
  assert.deepEqual(reasonOf(await list(simulator, {maxResults: 50, syncToken: token}, 'gone@group.calendar.google.com')), [404, 'notFound']);
});

test('each of the eight parameters Google refuses beside a token answers 400, as showDeleted=false does, and a list with one of them is no feed', async () => {
  const simulator = sim(), {data: {nextSyncToken: token}} = await list(simulator, {});
  const values = {iCalUID: 'a@google.com', orderBy: 'updated', privateExtendedProperty: 'a=b', q: 'word', sharedExtendedProperty: 'a=b', timeMin: '2026-10-01T00:00:00Z', timeMax: '2026-10-02T00:00:00Z', updatedMin: '2026-10-01T00:00:00Z'};
  assert.equal(Object.keys(values).length, 8);
  for (const [name, value] of Object.entries(values)) {
    assert.deepEqual(reasonOf(await list(simulator, {syncToken: token, [name]: value})), [400, 'invalid'], name);
    assert.equal((await list(simulator, {[name]: value})).data.nextSyncToken, undefined, `${name} with no token is a plain list`);
  }
  assert.deepEqual(reasonOf(await list(simulator, {syncToken: token, showDeleted: 'false'})), [400, 'invalid']);
});

test('expireToken() is unconnected to age: an old token reads until then, and answers Google\'s exact 410 after', async () => {
  const simulator = sim(), {data: {nextSyncToken: token}} = await list(simulator, {});
  assert.equal((await list(simulator, {syncToken: token})).status, 200);
  const {data: {nextSyncToken: other}} = await list(simulator, {}, CAL_B);
  simulator.expireToken(CAL_A);
  const answer = await list(simulator, {syncToken: token}), message = 'Sync token is no longer valid, a full sync is required.';
  assert.deepEqual([answer.status, answer.data], [410, {error: {code: 410, message, errors: [{domain: 'calendar', reason: 'fullSyncRequired', message, locationType: 'parameter', location: 'syncToken'}]}}]);
  assert.equal((await list(simulator, {syncToken: other}, CAL_B)).status, 200, 'another calendar keeps its tokens');
  assert.equal((await list(simulator, {})).status, 200, 'and a full read starts again');
});

test('a change only to a read-only field leaves the list delta, as Google\'s page says of ACLs, and the next change that returns the entry shows the new role', async () => {
  const simulator = sim(), read = async query => (await send(simulator, 'GET', '/users/me/calendarList', {query})).data, {nextSyncToken} = await read({});
  simulator.changeRole(CAL_B, 'reader');
  const delta = await read({syncToken: nextSyncToken});
  assert.deepEqual(delta.items, [], 'no entry, though the role moved');
  assert.equal((await read({})).items.find(item => item.id === CAL_B).accessRole, 'reader', 'a full read shows it');
  simulator.hideCalendar(CAL_B);
  assert.deepEqual((await read({syncToken: delta.nextSyncToken})).items.map(item => [item.id, item.accessRole, item.hidden]), [[CAL_B, 'reader', true]]);
});

test('shortPage(0) gives an empty page with a next page, shortPage(1) a short one, and redeliver(n) repeats the last n in the next delta alone', async () => {
  const simulator = sim(), made = [1, 2, 3].map(number => simulator.seed(CAL_A, timed(`Event ${number}`)));
  simulator.shortPage(0);
  const empty = await list(simulator, {});
  assert.deepEqual([idsOf(empty), Boolean(empty.data.nextPageToken), empty.data.nextSyncToken], [[], true, undefined]);
  simulator.shortPage(1);
  const short = await list(simulator, {pageToken: empty.data.nextPageToken});
  assert.deepEqual([idsOf(short), Boolean(short.data.nextPageToken)], [[made[0].id], true]);
  const rest = await list(simulator, {pageToken: short.data.nextPageToken});
  assert.deepEqual(idsOf(rest), [made[1].id, made[2].id]);
  simulator.redeliver(1);
  const again = await list(simulator, {syncToken: rest.data.nextSyncToken});
  assert.deepEqual(idsOf(again), [made[2].id], 'an item the last read held comes again');
  assert.deepEqual(idsOf(await list(simulator, {syncToken: again.data.nextSyncToken})), [], 'once');
});

test('a cancelled event stays in the log: the organizer\'s copy keeps its details, any other copy holds its id and status, and a full read leaves it out', async () => {
  const simulator = sim(), mine = simulator.seed(CAL_A, timed('Mine')), invited = simulator.invite({calendarId: CAL_A, summary: 'Theirs', start: timed('').start, end: timed('').end});
  const {data: {nextSyncToken: token}} = await list(simulator, {});
  assert.equal((await send(simulator, 'DELETE', eventPath(CAL_A, mine.id))).status, 204);
  await send(simulator, 'DELETE', eventPath(CAL_A, invited.id));
  const {data: {items}} = await list(simulator, {syncToken: token}), byId = new Map(items.map(item => [item.id, item]));
  assert.deepEqual([byId.get(mine.id).status, byId.get(mine.id).summary], ['cancelled', 'Mine']);
  assert.deepEqual(Object.keys(byId.get(invited.id)).sort(), ['etag', 'id', 'kind', 'status']);
  assert.deepEqual(idsOf(await list(simulator, {})), [], 'a full read holds what stands');
  assert.deepEqual(idsOf(await list(simulator, {showDeleted: 'true'})).sort(), [mine.id, invited.id].sort());
});

test('a write on one occurrence makes an item with its own id, a deleted one holds the three documented fields, and each takes its place in an expanded list', async () => {
  const simulator = sim(), {id} = simulator.seed(CAL_A, daily('Stand-up')), {data: {nextSyncToken: token}} = await list(simulator, {});
  const moved = occurrenceId(id, 29), dropped = occurrenceId(id, 30);
  const changed = await send(simulator, 'PATCH', eventPath(CAL_A, moved), {body: {summary: 'Stand-up, moved'}});
  assert.deepEqual([changed.status, changed.data.id, changed.data.recurringEventId, changed.data.originalStartTime.dateTime], [200, moved, id, '2026-10-29T10:00:00-04:00']);
  assert.equal((await send(simulator, 'DELETE', eventPath(CAL_A, dropped))).status, 204);
  const {data: {items}} = await list(simulator, {syncToken: token});
  assert.deepEqual(items.map(item => item.id), [moved, dropped], 'a delta holds the two occurrences, and not the series');
  assert.deepEqual(items[1], {kind: 'calendar#event', etag: items[1].etag, id: dropped, status: 'cancelled', recurringEventId: id, originalStartTime: {dateTime: '2026-10-30T10:00:00-04:00', timeZone: ZONE}});
  assert.deepEqual((await list(simulator, {singleEvents: 'true', orderBy: 'startTime'})).data.items.map(item => [item.id, item.summary]), [[occurrenceId(id, 28), 'Stand-up'], [moved, 'Stand-up, moved']], 'one in its place, and one gone');
  assert.deepEqual(reasonOf(await send(simulator, 'PATCH', eventPath(CAL_A, `${id}_20261127T150000Z`), {body: {summary: 'No such occurrence'}})), [404, 'notFound']);
  assert.deepEqual(reasonOf(await send(simulator, 'POST', `${eventPath(CAL_A, occurrenceId(id, 28))}/move`, {query: {destination: CAL_B}})), [400, 'cannotChangeOrganizerOfInstance']);
});

test('showDeleted keeps its singleEvents rule: a deleted series is one item, and with singleEvents its occurrences and never the series', async () => {
  const simulator = sim(), {id} = simulator.seed(CAL_A, daily('Stand-up'));
  await send(simulator, 'DELETE', eventPath(CAL_A, id));
  assert.deepEqual(idsOf(await list(simulator, {showDeleted: 'true'})), [id]);
  const single = await list(simulator, {showDeleted: 'true', singleEvents: 'true'});
  assert.deepEqual(idsOf(single), [28, 29, 30].map(day => occurrenceId(id, day)));
  assert.ok(single.data.items.every(item => item.status === 'cancelled' && item.recurringEventId === id));
  assert.deepEqual(idsOf(await list(simulator, {showDeleted: 'true', timeMin: '2026-10-29T00:00:00Z', timeMax: '2026-10-29T23:00:00Z', singleEvents: 'true'})), [occurrenceId(id, 29)], 'a bounded list keeps its bounds');
  assert.deepEqual(idsOf(await list(simulator, {timeMin: '2026-10-29T00:00:00Z'})), [], 'and with no showDeleted a bounded list holds none');
});

test('a deleted series cancels the occurrences written apart from it, so each reads in the delta', async () => {
  const simulator = sim(), {id} = simulator.seed(CAL_A, daily('Stand-up')), moved = occurrenceId(id, 29);
  await send(simulator, 'PATCH', eventPath(CAL_A, moved), {body: {summary: 'Moved'}});
  const {data: {nextSyncToken: token}} = await list(simulator, {});
  await send(simulator, 'DELETE', eventPath(CAL_A, id));
  assert.deepEqual((await list(simulator, {syncToken: token})).data.items.map(item => [item.id, item.status]), [[id, 'cancelled'], [moved, 'cancelled']]);
});

test('a move leaves a cancelled entry on its source with the id and status alone, and an item with the same id on its destination, and an undo reverses both', async () => {
  const simulator = sim(), {id} = simulator.seed(CAL_A, timed('Moves')), {data: {nextSyncToken: a}} = await list(simulator, {}), {data: {nextSyncToken: b}} = await list(simulator, {}, CAL_B);
  assert.equal((await send(simulator, 'POST', `${eventPath(CAL_A, id)}/move`, {query: {destination: CAL_B}})).status, 200);
  const source = await list(simulator, {syncToken: a}), destination = await list(simulator, {syncToken: b}, CAL_B);
  assert.deepEqual(source.data.items.map(item => Object.keys(item).sort()), [['etag', 'id', 'kind', 'status']]);
  assert.deepEqual(source.data.items.map(item => [item.id, item.status]), [[id, 'cancelled']]);
  assert.deepEqual(destination.data.items.map(item => [item.id, item.status, item.organizer.email]), [[id, 'confirmed', CAL_B]]);
  await send(simulator, 'POST', `${eventPath(CAL_B, id)}/move`, {query: {destination: CAL_A}});
  assert.deepEqual((await list(simulator, {syncToken: source.data.nextSyncToken})).data.items.map(item => [item.id, item.status]), [[id, 'confirmed']]);
  assert.deepEqual((await list(simulator, {syncToken: destination.data.nextSyncToken}, CAL_B)).data.items.map(item => [item.id, item.status]), [[id, 'cancelled']]);
});

test('an invitation sits on any calendar with a self entry for that calendar, a hidden one needs showHiddenInvitations, and on a secondary calendar the owner\'s address is not self', async () => {
  const simulator = sim(), {start, end} = timed(''), shown = simulator.invite({calendarId: CAL_A, summary: 'Shown', start, end, attendees: [OWNER.email]}), hidden = simulator.invite({calendarId: CAL_A, summary: 'Hidden', start, end, hidden: true});
  assert.deepEqual(shown.attendees.filter(item => item.self).map(item => [item.email, item.responseStatus]), [[CAL_A, 'needsAction']]);
  assert.equal(shown.attendees.find(item => item.email === OWNER.email).self, undefined);
  assert.deepEqual(idsOf(await list(simulator, {})), [shown.id]);
  assert.deepEqual(idsOf(await list(simulator, {showHiddenInvitations: 'true'})), [shown.id, hidden.id]);
  assert.equal(simulator.invite({start, end}).attendees.find(item => item.self).email, OWNER.email, 'the primary calendar still reads its owner');
});

test('a guest\'s answer moves the etag and updated, setReminders moves the etag and not updated, and each reads in a delta', async () => {
  const simulator = sim(), made = simulator.seed(CAL_A, timed('Review', 28, {attendees: [{email: 'guest@example.com'}]})), {data: {nextSyncToken: token}} = await list(simulator, {});
  const at = sim.now;
  sim.now += 60_000;
  const answered = simulator.guestResponds(CAL_A, made.id, 'guest@example.com', 'accepted');
  assert.deepEqual([answered.attendees[0].responseStatus, answered.etag !== made.etag, answered.updated], ['accepted', true, new Date(at + 60_000).toISOString()]);
  const delta = await list(simulator, {syncToken: token});
  assert.deepEqual(idsOf(delta), [made.id]);
  sim.now += 60_000;
  const quiet = simulator.setReminders(CAL_A, made.id, {useDefault: false, overrides: [{method: 'popup', minutes: 5}]});
  assert.deepEqual([quiet.etag !== answered.etag, quiet.updated], [true, answered.updated]);
  assert.deepEqual(idsOf(await list(simulator, {syncToken: delta.data.nextSyncToken})), [made.id]);
  assert.throws(() => simulator.guestResponds(CAL_A, made.id, 'nobody@example.com', 'accepted'));
  assert.throws(() => simulator.guestResponds(CAL_A, made.id, 'guest@example.com', 'maybe'));
});

test('the calendar list is a feed: a removed entry reads deleted, a hidden one hidden, a colour moves the etag, 100 a page by default and 250 at most, and two parameters are refused beside a token', async () => {
  const simulator = sim(), read = query => send(simulator, 'GET', '/users/me/calendarList', {query}), start = await read({});
  assert.deepEqual([start.data.items.length, start.data.nextPageToken, typeof start.data.nextSyncToken], [3, undefined, 'string']);
  for (const name of ['minAccessRole', 'showOwnOrganizationOnly']) assert.deepEqual(reasonOf(await read({syncToken: start.data.nextSyncToken, [name]: 'owner'})), [400, 'invalid'], name);
  assert.deepEqual(reasonOf(await read({maxResults: 251})), [400, 'invalid']);
  const before = start.data.items.find(item => item.id === CAL_B);
  simulator.recolor(CAL_B, '7');
  const colour = await read({syncToken: start.data.nextSyncToken});
  assert.deepEqual(colour.data.items.map(item => [item.id, item.etag === before.etag, item.colorId]), [[CAL_B, false, '7']]);
  simulator.hideCalendar(CAL_B);
  const hidden = await read({syncToken: colour.data.nextSyncToken});
  assert.deepEqual(hidden.data.items.map(item => [item.id, item.hidden]), [[CAL_B, true]]);
  assert.deepEqual((await read({})).data.items.map(item => item.id).sort(), [OWNER.email, CAL_A].sort(), 'a full read leaves a hidden entry out');
  assert.equal((await read({showHidden: 'true'})).data.items.length, 3);
  await send(simulator, 'DELETE', `/calendars/${encodeURIComponent(CAL_B)}`);
  const removed = await read({syncToken: hidden.data.nextSyncToken});
  assert.deepEqual(removed.data.items.map(item => [item.id, item.deleted]), [[CAL_B, true]]);
  assert.deepEqual(reasonOf(await list(simulator, {}, CAL_B)), [404, 'notFound']);
  simulator.expireToken(null, {feed: 'list'});
  assert.deepEqual(reasonOf(await read({syncToken: removed.data.nextSyncToken})), [410, 'fullSyncRequired']);
});

test('the calendar list reads 100 a page unless asked, and pages by the token it gave', async () => {
  const simulator = sim();
  for (let number = 0; number < 101; number++) simulator.addCalendar({id: `c${number}@group.calendar.google.com`});
  const first = await send(simulator, 'GET', '/users/me/calendarList');
  assert.deepEqual([first.data.items.length, Boolean(first.data.nextPageToken), first.data.nextSyncToken], [100, true, undefined]);
  const last = await send(simulator, 'GET', '/users/me/calendarList', {query: {pageToken: first.data.nextPageToken}});
  assert.deepEqual([last.data.items.length, typeof last.data.nextSyncToken], [4, 'string']);
});

test('sharing is a feed: a removed rule reads role none, a public calendar is a default rule with no value, and a reader of the calendar is refused', async () => {
  const simulator = sim(), read = (query, calendarId = CAL_A) => send(simulator, 'GET', `/calendars/${encodeURIComponent(calendarId)}/acl`, {query});
  const start = await read({});
  assert.deepEqual([start.status, start.data.items, typeof start.data.nextSyncToken], [200, [], 'string']);
  const rule = simulator.share(CAL_A, 'friend@example.com', 'reader');
  simulator.sharePublic(CAL_A);
  const added = await read({syncToken: start.data.nextSyncToken});
  assert.deepEqual(added.data.items.map(item => [item.id, item.role, item.scope]), [['user:friend@example.com', 'reader', {type: 'user', value: 'friend@example.com'}], ['default', 'reader', {type: 'default'}]]);
  assert.equal((await send(simulator, 'DELETE', `/calendars/${encodeURIComponent(CAL_A)}/acl/${encodeURIComponent(rule.id)}`)).status, 204);
  const removed = await read({syncToken: added.data.nextSyncToken});
  assert.deepEqual(removed.data.items.map(item => [item.id, item.role, item.scope]), [[rule.id, 'none', {type: 'user', value: 'friend@example.com'}]]);
  assert.deepEqual((await read({})).data.items.map(item => item.id), ['default'], 'a full read holds what stands');
  simulator.share(CAL_A, 'friend@example.com', 'writer');
  assert.deepEqual((await read({syncToken: removed.data.nextSyncToken})).data.items.map(item => [item.id, item.role]), [[rule.id, 'writer']]);
  simulator.unshare(CAL_A, 'friend@example.com');
  simulator.addCalendar({id: 'shared@group.calendar.google.com', accessRole: 'reader'});
  assert.deepEqual(reasonOf(await read({}, 'shared@group.calendar.google.com')), [403, 'forbidden']);
  simulator.addCalendar({id: 'writer@group.calendar.google.com', accessRole: 'writer'});
  assert.equal((await read({}, 'writer@group.calendar.google.com')).status, 200);
});

test('fields is a mask: it keeps what it names at each depth, it keeps a token only if it names one, and a bad one answers 400 and reads nothing', async () => {
  const simulator = sim(), {id} = simulator.seed(CAL_A, timed('Masked', 28, {attendees: [{email: 'guest@example.com'}], location: 'Room'}));
  const answer = await list(simulator, {fields: 'nextSyncToken,items(id,start/dateTime,attendees(email))'});
  assert.deepEqual(Object.keys(answer.data).sort(), ['items', 'nextSyncToken']);
  assert.deepEqual(answer.data.items, [{id, start: {dateTime: '2026-10-28T10:00:00-04:00'}, attendees: [{email: 'guest@example.com'}]}]);
  assert.deepEqual(Object.keys((await list(simulator, {fields: 'items(id)'})).data), ['items']);
  assert.deepEqual(Object.keys((await list(simulator, {fields: 'items/id'})).data.items[0]), ['id']);
  assert.equal((await list(simulator, {fields: 'items(*)'})).data.items[0].location, 'Room');
  const calls = simulator.calls.length;
  for (const bad of ['items(', 'items(id', 'items)', ',', 'items,', 'nope', 'items(nope)', '']) assert.deepEqual(reasonOf(await list(simulator, {fields: bad})), [400, 'invalidParameter'], JSON.stringify(bad));
  assert.equal(simulator.calls.length, calls + 8);
  const entry = await send(simulator, 'GET', '/users/me/calendarList', {query: {fields: 'items(id)'}});
  assert.deepEqual(Object.keys(entry.data.items[0]), ['id'], 'any answer takes a mask');
  assert.deepEqual(reasonOf(await send(simulator, 'POST', eventPath(CAL_A, id).replace(/\/[^/]+$/, ''), {body: timed('Refused'), query: {fields: '('}})), [400, 'invalidParameter']);
  assert.equal((await list(simulator, {})).data.items.length, 1, 'a refused mask changes nothing');
});

test('a rate limit carries domain usageLimits at 403 and at 429, with no Retry-After, and a listed time reads again after it', async () => {
  const simulator = sim();
  simulator.rateLimit(EVENTS_ROUTE);
  const refused = await list(simulator, {});
  assert.deepEqual([refused.status, refused.data.error.errors[0].domain, refused.headers['retry-after']], [403, 'usageLimits', undefined]);
  simulator.rateLimit(EVENTS_ROUTE, {status: 429});
  const again = await list(simulator, {});
  assert.deepEqual([again.status, again.data.error.errors[0].domain], [429, 'usageLimits']);
  assert.equal((await list(simulator, {})).status, 200);
});

test('every event type reads in the feed, with a client id up to 1,024 characters', async () => {
  const simulator = sim(), birthday = simulator.seed(CAL_A, timed('Birthday'), {eventType: 'birthday'}), long = 'a'.repeat(1024), own = simulator.seed(CAL_A, timed('Client id'), {id: long});
  assert.deepEqual((await list(simulator, {})).data.items.map(item => [item.id, item.eventType]), [[birthday.id, 'birthday'], [long, 'default']]);
  assert.equal(own.id, long);
});

test('the simulator imports only node built-ins, and reads no trigger file', () => {
  const text = readFileSync(new URL('./fixtures/provider-simulators/google-calendar.mjs', import.meta.url), 'utf8');
  const specifiers = [...text.matchAll(/(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)(['"`])([^'"`]+)\1/g)].map(match => match[2]);
  assert.deepEqual(specifiers.filter(specifier => !specifier.startsWith('node:')), []);
  assert.doesNotMatch(text, /catalog\/triggers|readFileSync/);
});

test('the four transforms step 8 ships are registered, each with its clock, step data and codes', () => {
  const entry = id => TRANSFORMS.get(id), facts = id => [entry(id).usesClock, Object.keys(entry(id).stepData), [...entry(id).refuses].sort()];
  assert.deepEqual(facts('collections.calendarGuests@1'), [false, ['list'], ['too_many_items']]);
  assert.deepEqual(facts('collections.calendarSelf@1'), [false, ['event'], []]);
  assert.deepEqual(facts('time.offsetFromNow@1'), [true, [], ['time_invalid']]);
  assert.deepEqual(facts('time.isAfter@1'), [true, [], ['time_invalid']]);
});

// ---- each trigger on the shared harness ---------------------------------------------------------------------------------------------------
const INTERVAL = 150_000, MINUTE = 60_000, DAY = 86_400_000, LEAD = 15, GUEST = 'guest@example.com', LIST_ROUTE = 'GET /users/me/calendarList', ACL_ROUTE = 'GET /calendars/{calendarId}/acl';
const onA = {calendarId: CAL_A}, soon = {calendarId: CAL_A, leadMinutes: LEAD}, MANIFEST = JSON.parse(readFileSync(new URL('./fixtures/provider-simulators/google-calendar.trigger-cases.json', import.meta.url), 'utf8'));
/** Lets a test say what a provider said, in Google's words. */
const refusalBody = (status, reason, message = reason) => ({status, data: {error: {code: status, message, errors: [{domain: 'global', reason, message}]}}});
const iso = ms => new Date(ms).toISOString();
const offset = (world, minutes) => iso(world.now + minutes * MINUTE);
/** A timed event around now, in minutes, as Google takes one. */
const around = (world, summary, from, to = from + 30, extra = {}) => ({summary, start: {dateTime: offset(world, from)}, end: {dateTime: offset(world, to)}, ...extra});
const calendarWorld = (t, options) => {
  const world = triggerWorld(t, 'google-calendar', options);
  for (const id of [CAL_A, CAL_B]) world.simulator.addCalendar({id, accessRole: 'owner'});
  return world;
};
/** One request to the simulator as a person's own write, with no call through Fabric. */
function api(world, method, path, {query, body} = {}) {
  const url = new URL(`${BASE}${path}`);
  for (const [name, value] of Object.entries(query ?? {})) url.searchParams.append(name, value);
  return world.simulator.request({url: url.href, method, headers: {Authorization: `Bearer ${HARNESS_TOKEN}`, ...(body === undefined ? {} : {'Content-Type': 'application/json'})}, ...(body === undefined ? {} : {body: JSON.stringify(body)}), allowedOrigins: [ORIGIN]});
}
const edit = (world, calendarId, eventId, body) => api(world, 'PATCH', eventPath(calendarId, eventId), {body});
const remove = (world, calendarId, eventId) => api(world, 'DELETE', eventPath(calendarId, eventId));
const move = (world, from, to, eventId) => api(world, 'POST', `${eventPath(from, eventId)}/move`, {query: {destination: to}});
/** A watch started and approved, with no read yet. */
async function started(world, key, args = onA) {
  const {id} = await world.subscribe(key, args);
  assert.equal(world.approve(id).status, 'starting');
  return id;
}
/** A watch that has read to the present. */
async function watching(world, key, args = onA) {
  const id = await started(world, key, args);
  assert.equal((await world.pollNow(id)).status, 'active');
  return id;
}
/** The next poll, one interval on. */
async function poll(world, id) {
  world.advance(INTERVAL);
  return world.pollNow(id);
}
const feedOf = (world, id, index = 0) => world.store.get('triggerFeeds', world.record(id).feeds[index]);
const fired = events => events.filter(event => event.type === 'trigger.event');
const gaps = events => events.filter(event => event.type === 'trigger.gap');
/** Everything a page of events holds, as [watch, trigger event id or gap reason]. */
const newEvents = async (world, id) => (await world.events()).events.filter(event => !id || event.subscriptionId === id);
const gapRows = (world, id) => world.store.db.prepare("SELECT COUNT(*) AS count FROM trigger_events WHERE subscription_id = ? AND kind = 'trigger.gap'").get(id).count;
const auditRows = world => world.store.list('activity').length;
const seenCount = world => world.store.db.prepare('SELECT COUNT(*) AS count FROM trigger_seen').get().count;
const feedReads = (world, route = EVENTS_ROUTE) => world.simulator.calls.filter(call => call.route === route);
/** Makes the next write of a feed's cursors throw, as a crash between the two stores would. */
function crashAtCursor(world) {
  const {put, appendPoll} = world.store;
  let appended = false;
  world.store.appendPoll = poll => { const answer = appendPoll.call(world.store, poll); appended = true; world.store.appendPoll = appendPoll; return answer; };
  world.store.put = (collection, document) => {
    if (appended && collection === 'triggerFeeds') { world.store.put = put; throw new Error('crashed before the cursor moved'); }
    return put.call(world.store, collection, document);
  };
}
/** Walks a feed to the end of a walk that takes more than one poll. */
async function drain(world, id, most = 40) {
  for (let polls = 0; polls < most; polls++) {
    const watch = await poll(world, id);
    if (watch.status === 'paused' || (watch.status === 'active' && !feedOf(world, id).page)) return watch;
  }
  assert.fail('the walk did not end');
}

// What each trigger needs: `args`, what stands `before` the baseline, a `write` that must give one event, what that event `says`, a route and a stand-in that fills it past its limit.
const eventWrite = key => world => edit(world, CAL_A, world.before.id, {summary: 'Changed'}).then(() => ({eventId: world.before.id, key}));
const TRIGGERS = {
  'new-event': {args: onA, before: world => world.simulator.seed(CAL_A, timed('Before')), write: async world => ({eventId: world.simulator.seed(CAL_A, timed('New')).id}), says: {status: 'confirmed', title: 'New', organizer: CAL_A},
    fill: world => { for (let number = 0; number < 5001; number++) world.simulator.seed(CAL_A, timed(`Event ${number}`)); }},
  'event-changed': {args: onA, before: world => world.simulator.seed(CAL_A, timed('Before')), write: eventWrite('event-changed'), says: {status: 'confirmed', title: 'Changed'},
    fill: world => { for (let number = 0; number < 5001; number++) world.simulator.seed(CAL_A, timed(`Event ${number}`)); }},
  'event-cancelled': {args: onA, before: world => world.simulator.seed(CAL_A, timed('Before')), write: async world => { await remove(world, CAL_A, world.before.id); return {eventId: world.before.id}; }, says: {status: 'cancelled', title: 'Before'},
    fill: world => { for (let number = 0; number < 5001; number++) world.simulator.seed(CAL_A, timed(`Event ${number}`)); }, overflow: async (world, id) => {
      for (const item of Object.values(world.simulator.state().events)) if (item.calendarId === CAL_A && item.status !== 'cancelled') await remove(world, CAL_A, item.id);
      return drain(world, id);
    }},
  'invitation-needs-response': {args: onA, before: world => world.simulator.invite({calendarId: CAL_A, ...timed('Before')}), write: async world => ({eventId: world.simulator.invite({calendarId: CAL_A, ...timed('Asked')}).id}), says: {title: 'Asked', organizer: 'organizer@other.example'},
    fill: world => { for (let number = 0; number < 5001; number++) world.simulator.invite({calendarId: CAL_A, ...timed(`Event ${number}`)}); }},
  'guest-responded': {args: onA, before: world => world.simulator.seed(CAL_A, timed('Before', 28, {attendees: [{email: GUEST}]})), write: async world => {
    world.simulator.guestResponds(CAL_A, world.before.id, GUEST, 'accepted');
    return {eventId: world.before.id, guest: GUEST};
  }, says: {response: 'accepted', title: 'Before'}, fill: world => { for (let number = 0; number < 1252; number++) world.simulator.seed(CAL_A, timed(`Event ${number}`, 28, {attendees: [0, 1, 2, 3].map(guest => ({email: `g${number}-${guest}@example.com`, responseStatus: 'accepted'}))})); }},
  'starting-soon': {args: soon, before: world => world.simulator.seed(CAL_A, around(world, 'Before', 10)), write: async world => ({eventId: world.simulator.seed(CAL_A, around(world, 'Soon', 10)).id}), says: {title: 'Soon'}},
  'calendar-list-changed': {args: {}, route: LIST_ROUTE, before: world => world.simulator.addCalendar({id: 'before@group.calendar.google.com'}), write: async world => ({calendarId: world.simulator.addCalendar({id: 'new@group.calendar.google.com'}).id}), says: {accessRole: 'reader'},
    fill: world => { for (let number = 0; number < 5001; number++) world.simulator.addCalendar({id: `c${number}@group.calendar.google.com`}); }},
  'calendar-sharing-changed': {args: onA, route: ACL_ROUTE, before: world => world.simulator.share(CAL_A, 'before@example.com'), write: async world => ({ruleId: world.simulator.share(CAL_A, 'new@example.com').id}), says: {role: 'reader', scopeType: 'user', scopeValue: 'new@example.com'},
    fill: world => { for (let number = 0; number < 5001; number++) world.simulator.share(CAL_A, `g${number}@example.com`); }},
};
/** A world past its baseline on one trigger, with what stood before it read. */
async function ready(t, key, options) {
  const world = calendarWorld(t, options), spec = TRIGGERS[key];
  world.before = spec.before(world);
  return {world, spec, id: await watching(world, key, spec.args), route: spec.route ?? EVENTS_ROUTE, row: shippedTriggers('google-calendar').triggers.find(item => item.key === key).rows[0]};
}

const implementations = Object.fromEntries(Object.keys(TRIGGERS).flatMap(key => Object.entries({
  async 'baseline-silent'(t) {
    const {world, id} = await ready(t, key);
    assert.deepEqual([(await world.events()).events, world.record(id).status], [[], 'active'], 'what stood before the watch stays unreported');
    await poll(world, id);
    assert.deepEqual((await world.events()).events, [], 'on the next read too');
  },
  async 'one-then-zero'(t) {
    const {world, spec, id, route} = await ready(t, key), made = await spec.write(world), audited = auditRows(world);
    await poll(world, id);
    const {events} = await world.events();
    assert.deepEqual(events.map(event => event.type), ['trigger.event']);
    assert.equal(world.store.db.prepare('SELECT expires_at - created_at AS kept FROM trigger_events').get().kept, (key === 'starting-soon' ? 1 : 7) * DAY, 'kept for as long as its block says');
    assert.deepEqual([audited > 0, auditRows(world)], [true, audited], 'a request and an approval each wrote a row, and a poll writes none');
    assert.equal(events[0].subscriptionId, id);
    for (const [name, value] of Object.entries({...made, ...spec.says})) if (name !== 'key') assert.equal(events[0].fields[name], value, name);
    const reads = feedReads(world, route).length;
    await poll(world, id);
    assert.deepEqual([feedReads(world, route).length, feedReads(world, route).at(-1).status], [reads + 1, 200], 'the provider answered the second read');
    assert.deepEqual((await world.events()).events, [], 'and it gave nothing');
  },
  async 'crash-before-cursor'(t) {
    const {world, spec, id} = await ready(t, key);
    await spec.write(world);
    world.advance(INTERVAL);
    crashAtCursor(world);
    await assert.rejects(world.pollNow(id), /crashed before the cursor moved/);
    assert.equal(fired((await world.events()).events).length, 1, 'the event landed before the crash');
    await poll(world, id);
    assert.deepEqual((await world.events()).events, [], 'the replay reads it again and stores nothing');
    // And with a gap on the way: it lands once, however many times its poll runs.
    if (key === 'starting-soon') world.advance((LEAD + 1) * MINUTE);
    else if (key === 'calendar-list-changed') world.simulator.expireToken(null, {feed: 'list'});
    else world.simulator.expireToken(CAL_A, key === 'calendar-sharing-changed' ? {feed: 'acl'} : {});
    world.advance(INTERVAL);
    crashAtCursor(world);
    await assert.rejects(world.pollNow(id), /crashed before the cursor moved/);
    assert.equal(gaps((await world.events()).events).length, 1);
    await poll(world, id);
    assert.deepEqual(fired((await world.events()).events), []);
    assert.equal(gapRows(world, id), 1, 'the replay ends the same gap, and stores no second one');
    await poll(world, id);
    assert.deepEqual((await world.events()).events, []);
  },
  async 'background-never'(t) {
    const {world, spec, id, route} = await ready(t, key), reads = feedReads(world, route).length;
    await spec.write(world);
    world.store.put('backgroundPolicies', {id: world.account, connectionId: world.account, mode: 'deny', updatedAt: 'x'});
    const watch = await poll(world, id);
    assert.deepEqual([watch.status, watch.reason, feedReads(world, route).length], ['paused', 'background_off', reads], 'no request goes out');
    assert.deepEqual((await world.events()).events, []);
  },
  async 'row-never-mid-poll'(t) {
    const {world, spec, id, row} = await ready(t, key), {cursors} = feedOf(world, id), {request} = world.runtime;
    await spec.write(world);
    world.runtime.request = async (...args) => { const answer = await request(...args); world.setRow(row, 'deny'); return answer; };
    const watch = await poll(world, id);
    assert.deepEqual([watch.status, watch.reason], ['paused', 'permission_changed']);
    assert.deepEqual([fired((await world.events()).events), feedOf(world, id).cursors], [[], cursors], 'what was read is dropped, and the place stays');
  },
  async 'malformed-cursor'(t) {
    const {world, id, route} = await ready(t, key), feed = feedOf(world, id), reads = feedReads(world, route).length;
    // A window holds its place in its seen rows, so the one place it can store is a page.
    world.store.put('triggerFeeds', key === 'starting-soon' ? {...feed, page: {token: 'not\nprintable', walk: 'delta'}} : {...feed, cursors: {sync: 'not\nprintable'}});
    const watch = await poll(world, id);
    assert.deepEqual([watch.status, watch.reason, feedReads(world, route).length], ['paused', 'cursor_invalid', reads], 'a bad place is never sent');
  },
  async caps(t) {
    if (key === 'starting-soon') {
      const {world, id} = await ready(t, key);
      for (let number = 0; number < 101; number++) world.simulator.seed(CAL_A, around(world, `Event ${number}`, 5 + number / 100));
      await poll(world, id);
      const {events} = await world.events();
      assert.deepEqual(events.map(event => [event.type, event.fields.reason]), [['trigger.gap', 'overflow']], 'a window with nothing known in it past its bound tells of it once, and reports none');
      await poll(world, id);
      assert.deepEqual((await world.events()).events, [], 'each of those counts as read');
      assert.equal(world.record(id).status, 'active');
      return;
    }
    const world = calendarWorld(t), spec = TRIGGERS[key];
    spec.fill(world);
    const id = await started(world, key, spec.args);
    const watch = spec.overflow ? await (async () => { await drain(world, id); return spec.overflow(world, id); })() : await drain(world, id);
    assert.deepEqual([watch.status, watch.reason, watch.detail], ['paused', 'too_many_items', 'seen_limit'], 'past 5,000 Fabric cannot tell new from old, and it never guesses');
  },
  async 'resync-gap'(t) {
    const {world, spec, id} = await ready(t, key), rows = seenCount(world);
    if (key === 'starting-soon') {
      world.advance((LEAD + 1) * MINUTE);
      await world.pollNow(id);
      assert.deepEqual((await world.events()).events.map(event => [event.type, event.fields.reason]), [['trigger.gap', 'window']]);
      return;
    }
    const lost = await spec.write(world);
    if (key === 'calendar-list-changed') world.simulator.expireToken(null, {feed: 'list'});
    else world.simulator.expireToken(CAL_A, key === 'calendar-sharing-changed' ? {feed: 'acl'} : {});
    assert.equal((await poll(world, id)).status, 'active', 'a 410 pauses nothing');
    const {events} = await world.events();
    assert.deepEqual(events.map(event => [event.type, event.fields.reason]), [['trigger.gap', 'resync']], 'what changed in the gap is not told one by one');
    assert.ok(seenCount(world) >= rows, 'every seen row stays');
    await poll(world, id);
    assert.deepEqual((await world.events()).events, [], `the read that ended the gap kept its place: ${Object.keys(lost)}`);
  },
  async 'pause-on-refusal'(t) {
    const {world, spec, id, route} = await ready(t, key), {cursors} = feedOf(world, id);
    await spec.write(world);
    world.simulator.fail(route, refusalBody(403, 'forbidden', 'Forbidden'));
    const watch = await poll(world, id);
    assert.deepEqual([watch.status, watch.reason], ['paused', 'provider_refused']);
    assert.deepEqual([(await world.events()).events, feedOf(world, id).cursors], [[], cursors]);
  },
}).map(([kind, run]) => [`${key} v1/${kind}`, run])));
caseTests(test, MANIFEST, shippedTriggers('google-calendar').triggers, implementations);

// ---- the file --------------------------------------------------------------------------------------------------------------------------------
test('the file holds eight blocks for seven sources, six on their polling fallback, and it stays a candidate until a live pass certifies it', () => {
  const file = JSON.parse(readFileSync(new URL('../catalog/triggers/google-calendar.json', import.meta.url), 'utf8'));
  assert.deepEqual([file.appId, file.reviewStatus], ['google-calendar', 'candidate']);
  assert.deepEqual(file.triggers.map(item => [item.key, item.delivery.method, item.delivery.fallback ?? null]), [['new-event', 'watch', 'polling'], ['event-changed', 'watch', 'polling'], ['event-cancelled', 'watch', 'polling'],
    ['invitation-needs-response', 'watch', 'polling'], ['guest-responded', 'watch', 'polling'], ['starting-soon', 'polling', null], ['calendar-list-changed', 'watch', 'polling'], ['calendar-sharing-changed', 'polling', null]]);
  const {triggers} = file, computed = triggerIds(file, calendarDeps());
  for (const item of triggers) {
    assert.equal(item.id, computed.get(`${item.key} v${item.version}`), `${item.key} holds its computed id`);
    assert.equal(item.certified, undefined);
  }
  assert.deepEqual(Object.keys(MANIFEST.cases).sort(), triggers.map(item => `${item.key} v${item.version}`).sort());
  const catalog = loadActionCatalog();
  assert.equal(catalog.triggersRefused.has('google-calendar'), false);
  assert.deepEqual(triggers.map(item => catalog.triggerOf(item.id).status), triggers.map(() => 'candidate'), 'nothing goes live before its live pass');
});

test('the feed reads one request\'s query on every call, baseline included, and sends no singleEvents, no showDeleted and no orderBy', async t => {
  const world = calendarWorld(t), {simulator} = world, id = await started(world, 'new-event');
  for (let number = 0; number < 251; number++) simulator.seed(CAL_A, timed(`Event ${number}`));
  await world.pollNow(id);
  simulator.seed(CAL_A, timed('New'));
  await poll(world, id);
  const reads = feedReads(world), queries = reads.map(({query: {syncToken, pageToken, ...rest}}) => JSON.stringify(rest));
  assert.equal(reads.length, 3, 'two pages of baseline and one delta');
  assert.deepEqual(new Set(queries).size, 1);
  assert.deepEqual(Object.keys(reads[0].query).sort(), ['fields', 'maxResults', 'showHiddenInvitations']);
  assert.ok(reads[2].query.syncToken, 'and the delta sends the token the last page gave');
});

test('each block reads as often as it says: two minutes on events and the clock, fifteen on the list and on sharing, with no jitter past the floor', async t => {
  const every = {'new-event': 120, 'event-changed': 120, 'event-cancelled': 120, 'invitation-needs-response': 120, 'guest-responded': 120, 'starting-soon': 120, 'calendar-list-changed': 900, 'calendar-sharing-changed': 900};
  for (const [key, seconds] of Object.entries(every)) {
    const world = calendarWorld(t), id = await watching(world, key, TRIGGERS[key].args);
    assert.equal(feedOf(world, id).nextPollAt, world.now + seconds * 1000, key);
  }
});

test('the five feed sources send one request', async t => {
  const world = calendarWorld(t), keys = ['new-event', 'event-changed', 'event-cancelled', 'invitation-needs-response', 'guest-responded'], ids = [];
  for (const key of keys) ids.push(await started(world, key));
  await world.pollNow(ids[0]);
  assert.equal(feedReads(world).length, 1, 'a baseline reads once for all of them');
  assert.deepEqual(new Set(ids.map(id => world.record(id).feeds[0])).size, 1, 'one feed');
  assert.deepEqual(ids.map(id => world.record(id).status), keys.map(() => 'active'));
  world.simulator.seed(CAL_A, timed('New'));
  await poll(world, ids[0]);
  assert.equal(feedReads(world).length, 2);
  assert.deepEqual(fired((await world.events()).events).map(event => event.subscriptionId), [ids[0]], 'and only the new-event lens fires');
});

test('a watch that joins a running feed needs no second walk: it knows what stood before it, an answer given before it joined stays quiet, and the next change fires', async t => {
  const world = calendarWorld(t), {simulator} = world, fresh = await watching(world, 'new-event'), {id: eventId} = simulator.seed(CAL_A, timed('Review', 28, {attendees: [{email: GUEST}]}));
  await poll(world, fresh);
  simulator.guestResponds(CAL_A, eventId, GUEST, 'accepted');
  await poll(world, fresh);
  await world.events();
  const reads = feedReads(world).length, changed = await started(world, 'event-changed'), answered = await started(world, 'guest-responded');
  await poll(world, fresh);
  assert.deepEqual([world.record(changed).status, world.record(answered).status, feedReads(world).length], ['active', 'active', reads + 1], 'one read of the delta, and no full read');
  assert.deepEqual((await world.events()).events, []);
  await edit(world, CAL_A, eventId, {summary: 'Review, moved'});
  simulator.guestResponds(CAL_A, eventId, GUEST, 'declined');
  await poll(world, fresh);
  assert.deepEqual(fired((await world.events()).events).map(event => event.subscriptionId).sort(), [changed, answered].sort());
});

test('a row at Never stops the watches that read it and no others, it stays paused when the row comes back, and a Resume tells of the gap once', async t => {
  const world = calendarWorld(t), id = await watching(world, 'new-event'), list = await watching(world, 'calendar-list-changed', {}), reads = feedReads(world).length;
  world.setRow('google-calendar.events.read', 'deny');
  world.simulator.seed(CAL_A, timed('Behind the row'));
  world.simulator.addCalendar({id: 'new@group.calendar.google.com'});
  const watch = await poll(world, id);
  assert.deepEqual([watch.status, watch.reason, feedReads(world).length], ['paused', 'permission_changed', reads], 'no call goes out for it');
  await poll(world, list);
  assert.deepEqual([world.record(list).status, fired((await world.events()).events).map(event => event.subscriptionId)], ['active', [list]], 'the list reads another row');
  world.setRow('google-calendar.events.read', 'allow');
  assert.equal((await poll(world, id)).status, 'paused', 'a pause never ends on its own');
  assert.equal(world.resume(id).status, 'starting');
  assert.equal((await poll(world, id)).status, 'active');
  assert.deepEqual((await world.events()).events.map(event => [event.type, event.fields.reason]), [['trigger.gap', 'resume']]);
  world.simulator.seed(CAL_A, timed('After the Resume'));
  await poll(world, id);
  assert.deepEqual(fired((await world.events()).events).map(event => event.fields.title), ['After the Resume']);
});

// ---- series, moves and returns -----------------------------------------------------------------------------------------------------------------
test('a series is one event: new, and cancelled', async t => {
  const world = calendarWorld(t), id = await watching(world, 'new-event'), cancelled = await watching(world, 'event-cancelled'), {id: series} = world.simulator.seed(CAL_A, daily('Stand-up', 3));
  await poll(world, id);
  assert.deepEqual(fired((await world.events()).events).map(event => [event.subscriptionId, event.fields.eventId]), [[id, series]]);
  await remove(world, CAL_A, series);
  await poll(world, cancelled);
  assert.deepEqual(fired((await world.events()).events).map(event => [event.subscriptionId, event.fields.eventId]), [[cancelled, series]]);
});

test('one occurrence is one event: changed names its series, it is no new event, and a cancelled one tells where it stood', async t => {
  const world = calendarWorld(t), {id: series} = world.simulator.seed(CAL_A, daily('Stand-up', 3)), fresh = await watching(world, 'new-event'), changed = await watching(world, 'event-changed'), cancelled = await watching(world, 'event-cancelled');
  await edit(world, CAL_A, occurrenceId(series, 29), {summary: 'Stand-up, moved'});
  await poll(world, fresh);
  assert.deepEqual(fired((await world.events()).events).map(event => [event.subscriptionId, event.fields.eventId, event.fields.recurringEventId]), [[changed, occurrenceId(series, 29), series]]);
  await remove(world, CAL_A, occurrenceId(series, 30));
  await poll(world, fresh);
  assert.deepEqual(fired((await world.events()).events).map(event => [event.subscriptionId, event.fields.eventId, event.fields.recurringEventId, event.fields.originalStart]),
    [[cancelled, occurrenceId(series, 30), series, '2026-10-30T10:00:00-04:00']]);
});

test('a move gives cancelled plus new: the source hears cancelled, the destination new and never changed, and the undo reverses it with no new event for a known id', async t => {
  const world = calendarWorld(t), {id: eventId} = world.simulator.seed(CAL_A, timed('Moves')), left = await watching(world, 'event-cancelled'), arrived = await watching(world, 'new-event', {calendarId: CAL_B});
  const changed = await watching(world, 'event-changed', {calendarId: CAL_B}), back = await watching(world, 'new-event'), gone = await watching(world, 'event-cancelled', {calendarId: CAL_B}), asked = [left, arrived, changed, back, gone];
  await move(world, CAL_A, CAL_B, eventId);
  for (const id of [left, arrived]) await poll(world, id);
  assert.deepEqual(fired((await world.events()).events).map(event => [event.subscriptionId, event.fields.eventId]).sort(), [[left, eventId], [arrived, eventId]].sort());
  await move(world, CAL_B, CAL_A, eventId);
  for (const id of [left, arrived]) await poll(world, id);
  assert.deepEqual(fired((await world.events()).events).map(event => event.subscriptionId), [gone], 'A already knows this id');
  assert.deepEqual(asked.map(id => world.record(id).status), asked.map(() => 'active'));
});

test('a revert gives an event: A to B to A fires twice, and a dedupe key never repeats', async t => {
  const world = calendarWorld(t), {id: eventId} = world.simulator.seed(CAL_A, timed('Before')), id = await watching(world, 'event-changed');
  for (const summary of ['After', 'Before']) {
    await edit(world, CAL_A, eventId, {summary});
    await poll(world, id);
    assert.deepEqual(fired((await world.events()).events).map(event => event.fields.title), [summary]);
  }
  const keys = world.store.db.prepare('SELECT dedupe_key FROM trigger_events').all().map(row => row.dedupe_key);
  assert.equal(new Set(keys).size, 2);
});

test('a create is no change, the next edit is, and reminders, a repeat and a redelivered item are none', async t => {
  const world = calendarWorld(t), id = await watching(world, 'event-changed'), {id: eventId} = world.simulator.seed(CAL_A, timed('Created'));
  await poll(world, id);
  assert.deepEqual((await world.events()).events, [], 'knownBy: Google gives no change kind, and a create is an id this lens never saw');
  world.simulator.setReminders(CAL_A, eventId, {useDefault: false, overrides: [{method: 'popup', minutes: 5}]});
  await poll(world, id);
  world.simulator.touch(CAL_A, eventId);
  await poll(world, id);
  world.simulator.redeliver(1);
  await poll(world, id);
  assert.deepEqual((await world.events()).events, [], 'the hash reads what a person calls a change');
  await edit(world, CAL_A, eventId, {location: 'Room'});
  await poll(world, id);
  assert.equal(fired((await world.events()).events).length, 1);
});

test('a cancelled event is no change, and a birthday is none: event-changed reads live events of the four types', async t => {
  const world = calendarWorld(t), {simulator} = world, {id: eventId} = simulator.seed(CAL_A, timed('Mine')), {id: birthday} = simulator.seed(CAL_A, timed('Birthday'), {eventType: 'birthday'}), id = await watching(world, 'event-changed');
  await edit(world, CAL_A, birthday, {summary: 'Birthday, moved'});
  await remove(world, CAL_A, eventId);
  await poll(world, id);
  assert.deepEqual((await world.events()).events, []);
});

test('an event made and deleted between two polls reads cancelled alone, and a new one on a calendar that was empty is one event', async t => {
  const world = calendarWorld(t), fresh = await watching(world, 'new-event'), cancelled = await watching(world, 'event-cancelled'), {id: eventId} = world.simulator.seed(CAL_A, timed('Short lived'));
  await remove(world, CAL_A, eventId);
  await poll(world, fresh);
  assert.deepEqual(fired((await world.events()).events).map(event => [event.subscriptionId, event.fields.title]), [[cancelled, 'Short lived']]);
});

test('an event type outside the four is no new event, and a cancelled copy of someone else\'s event tells only its id', async t => {
  const world = calendarWorld(t), {simulator} = world, fresh = await watching(world, 'new-event'), cancelled = await watching(world, 'event-cancelled');
  simulator.seed(CAL_A, timed('Birthday'), {eventType: 'birthday'});
  simulator.seed(CAL_A, timed('At home'), {eventType: 'workingLocation'});
  const focus = simulator.seed(CAL_A, timed('Heads down'), {eventType: 'focusTime'}), {id: theirs} = simulator.invite({calendarId: CAL_A, ...timed('Theirs')});
  await poll(world, fresh);
  assert.deepEqual(fired((await world.events()).events).map(event => event.fields.eventId), [focus.id, theirs]);
  await remove(world, CAL_A, theirs);
  await poll(world, fresh);
  assert.deepEqual(fired((await world.events()).events).map(event => [event.subscriptionId, Object.keys(event.fields).sort()]), [[cancelled, ['calendarId', 'eventId', 'status']]]);
});

// ---- walks, and what stops one -------------------------------------------------------------------------------------------------------------------
test('a delta past the item bound still finishes, each item once, and the token lands on its last page', async t => {
  const world = calendarWorld(t), id = await watching(world, 'new-event'), {sync} = feedOf(world, id).cursors, made = [];
  for (let number = 0; number < 600; number++) made.push(world.simulator.seed(CAL_A, timed(`Event ${number}`)).id);
  await poll(world, id);
  assert.deepEqual([feedOf(world, id).cursors.sync, feedOf(world, id).page.walk, world.record(id).status], [sync, 'delta', 'active'], 'the cut walk keeps the old token and its page');
  await drain(world, id);
  assert.notEqual(feedOf(world, id).cursors.sync, sync);
  const seen = [];
  for (let page = (await world.events({limit: 100})).events; page.length; page = (await world.events({limit: 100})).events) seen.push(...fired(page).map(event => event.fields.eventId));
  assert.deepEqual(seen, made);
  assert.equal(world.record(id).status, 'active');
});

test('a baseline past ten pages resumes over several polls, stays silent, and takes its token from its last page', async t => {
  const world = calendarWorld(t), id = await started(world, 'new-event');
  for (let number = 0; number < 2600; number++) world.simulator.seed(CAL_A, timed(`Event ${number}`));
  let polls = 1;
  assert.equal((await world.pollNow(id)).status, 'starting');
  assert.deepEqual([feedOf(world, id).page.walk, feedOf(world, id).cursors], ['baseline', {}], 'no token until the walk ends');
  while (world.record(id).status === 'starting') { await poll(world, id); polls++; }
  assert.ok(polls >= 6, `the item bound stops each poll at two pages: ${polls} polls`);
  assert.ok(feedOf(world, id).cursors.sync);
  assert.deepEqual((await world.events()).events, [], 'a baseline tells nothing, whatever its length');
  world.simulator.seed(CAL_A, timed('After the walk'));
  await poll(world, id);
  assert.deepEqual(fired((await world.events()).events).map(event => event.fields.title), ['After the walk']);
});

test('a 404 pauses with no gap: a calendar that has gone is no lost place', async t => {
  const world = calendarWorld(t), id = await watching(world, 'new-event'), other = await watching(world, 'new-event', {calendarId: CAL_B}), {cursors} = feedOf(world, id);
  assert.equal((await api(world, 'DELETE', `/calendars/${encodeURIComponent(CAL_A)}`)).status, 204);
  const watch = await poll(world, id);
  assert.deepEqual([watch.status, watch.reason, watch.detail], ['paused', 'provider_refused', 'http_404']);
  assert.deepEqual([(await world.events()).events, feedOf(world, id).cursors], [[], cursors]);
  assert.equal(world.record(other).status, 'active', 'another calendar reads on');
});

test('a 404 is read once: it is no lost place, so Fabric never reads the list again to find one', async t => {
  const world = calendarWorld(t), id = await watching(world, 'new-event'), reads = feedReads(world).length;
  world.simulator.fail(EVENTS_ROUTE, refusalBody(404, 'notFound', 'Not Found'));
  const watch = await poll(world, id);
  assert.deepEqual([watch.status, watch.reason, feedReads(world).length], ['paused', 'provider_refused', reads + 1]);
  assert.deepEqual((await world.events()).events, []);
});

test('an empty page with a next page continues, and the walk ends in one poll', async t => {
  const world = calendarWorld(t), id = await watching(world, 'new-event');
  world.simulator.seed(CAL_A, timed('After an empty page'));
  world.simulator.shortPage(0);
  assert.equal((await poll(world, id)).status, 'active');
  assert.deepEqual(fired((await world.events()).events).map(event => event.fields.title), ['After an empty page']);
  assert.deepEqual(feedOf(world, id).page, null);
});

test('a 403 of domain usageLimits and any 429 wait and pause nothing, and the read after them finds the event', async t => {
  for (const status of [403, 429]) {
    const world = calendarWorld(t), id = await watching(world, 'new-event'), {cursors} = feedOf(world, id);
    world.simulator.seed(CAL_A, timed('Waited for'));
    world.simulator.rateLimit(EVENTS_ROUTE, {status});
    assert.equal((await poll(world, id)).status, 'active');
    assert.deepEqual([feedOf(world, id).wait?.reason, feedOf(world, id).cursors, (await world.events()).events], ['limited', cursors, []]);
    await poll(world, id);
    assert.deepEqual(fired((await world.events()).events).map(event => event.fields.title), ['Waited for']);
  }
});

test('a 410 keeps every seen row: the gap is one event, and an event known before it does not repeat', async t => {
  const world = calendarWorld(t), {id: known} = world.simulator.seed(CAL_A, timed('Known')), id = await watching(world, 'new-event'), changed = await watching(world, 'event-changed'), rows = seenCount(world);
  assert.ok(rows > 0);
  world.simulator.seed(CAL_A, timed('Inside the gap'));
  world.simulator.expireToken(CAL_A);
  await poll(world, id);
  const {events} = await world.events();
  assert.deepEqual(events.map(event => [event.type, event.fields.reason, event.subscriptionId]).sort(), [id, changed].sort().map(watch => ['trigger.gap', 'resync', watch]));
  assert.ok(seenCount(world) > rows, 'the rows it held stay, and the walk adds what it read');
  await poll(world, id);
  assert.deepEqual((await world.events()).events, []);
  await edit(world, CAL_A, known, {summary: 'Known, and changed'});
  await poll(world, id);
  assert.deepEqual(fired((await world.events()).events).map(event => event.subscriptionId), [changed], 'a known item is still known');
});

test('an event no block can carry never holds the cursor: a client id of 1,024 characters gives one gap, and the next event reads', async t => {
  const world = calendarWorld(t), id = await watching(world, 'new-event'), {sync} = feedOf(world, id).cursors;
  world.simulator.seed(CAL_A, timed('Too long'), {id: 'a'.repeat(1024)});
  await poll(world, id);
  assert.deepEqual((await world.events()).events.map(event => [event.type, event.fields.reason]), [['trigger.gap', 'stall']]);
  assert.notEqual(feedOf(world, id).cursors.sync, sync);
  world.simulator.seed(CAL_A, timed('Next'));
  await poll(world, id);
  assert.deepEqual(fired((await world.events()).events).map(event => event.fields.title), ['Next']);
});

// ---- guests and invitations --------------------------------------------------------------------------------------------------------------------
test('a guest going Yes, Maybe, Yes gives three events, and a repeat gives none', async t => {
  const world = calendarWorld(t), {id: eventId} = world.simulator.seed(CAL_A, timed('Review', 28, {attendees: [{email: GUEST}]})), id = await watching(world, 'guest-responded');
  for (const answer of ['accepted', 'tentative', 'accepted']) {
    world.simulator.guestResponds(CAL_A, eventId, GUEST, answer);
    await poll(world, id);
    assert.deepEqual(fired((await world.events()).events).map(event => [event.fields.guest, event.fields.response, event.fields.eventId]), [[GUEST, answer, eventId]]);
  }
  world.simulator.guestResponds(CAL_A, eventId, GUEST, 'accepted');
  await poll(world, id);
  assert.deepEqual((await world.events()).events, [], 'the answer stands as it was');
});

test('a guest added is no change and no answer, a guest at needsAction is none, and the organizer and the calendar itself never read as guests', async t => {
  const world = calendarWorld(t), {id: eventId} = world.simulator.seed(CAL_A, timed('Review')), changed = await watching(world, 'event-changed'), answered = await watching(world, 'guest-responded');
  await edit(world, CAL_A, eventId, {attendees: [{email: GUEST}, {email: CAL_A, responseStatus: 'accepted'}]});
  await poll(world, changed);
  assert.deepEqual((await world.events()).events, []);
  world.simulator.guestResponds(CAL_A, eventId, GUEST, 'needsAction');
  world.simulator.guestResponds(CAL_A, eventId, CAL_A, 'declined');
  await poll(world, changed);
  assert.deepEqual((await world.events()).events, [], 'the calendar\'s own entry is no guest of its event');
  world.simulator.guestResponds(CAL_A, eventId, GUEST, 'declined');
  await poll(world, changed);
  assert.deepEqual(fired((await world.events()).events).map(event => [event.subscriptionId, event.fields.response]), [[answered, 'declined']]);
});

test('an event on someone else\'s calendar gives no guest answer: only the organizer\'s copy tells', async t => {
  const world = calendarWorld(t), id = await watching(world, 'guest-responded');
  const {id: eventId} = world.simulator.invite({calendarId: CAL_A, ...timed('Theirs'), attendees: [{email: GUEST, responseStatus: 'accepted'}]});
  await poll(world, id);
  world.simulator.guestResponds(CAL_A, eventId, GUEST, 'declined');
  await poll(world, id);
  assert.deepEqual((await world.events()).events, []);
});

test('an invitation fires on a secondary calendar, where self is no address of the owner\'s, and a hidden one fires too', async t => {
  const world = calendarWorld(t), id = await watching(world, 'invitation-needs-response');
  const shown = world.simulator.invite({calendarId: CAL_A, ...timed('Shown'), attendees: [{email: OWNER_EMAIL, responseStatus: 'accepted'}]}), hidden = world.simulator.invite({calendarId: CAL_A, ...timed('Hidden'), hidden: true});
  world.simulator.seed(CAL_A, timed('Mine', 28, {attendees: [{email: CAL_A}]}));
  await poll(world, id);
  assert.deepEqual(fired((await world.events()).events).map(event => event.fields.eventId), [shown.id, hidden.id], 'and the calendar\'s own event asks nothing of it, though its own entry reads needsAction');
});

test('an invitation pending at baseline stays silent, and one already answered gives none', async t => {
  const world = calendarWorld(t), pending = world.simulator.invite({calendarId: CAL_A, ...timed('Pending')}), id = await watching(world, 'invitation-needs-response');
  world.simulator.touch(CAL_A, pending.id);
  const answered = world.simulator.invite({calendarId: CAL_A, ...timed('Answered')});
  world.simulator.guestResponds(CAL_A, answered.id, CAL_A, 'accepted');
  await poll(world, id);
  assert.deepEqual((await world.events()).events, []);
});

test('calendar list: Google leaves a change of your access out of the sync feed, so a lowered role gives no event and the card does not promise one, and the role shows with the next change', async t => {
  const world = calendarWorld(t), id = await watching(world, 'calendar-list-changed', {}), {simulator} = world, {description} = shippedTriggers('google-calendar').triggers.find(item => item.key === 'calendar-list-changed');
  simulator.changeRole(CAL_B, 'reader');
  await poll(world, id);
  assert.deepEqual(fired((await world.events()).events), []);
  assert.equal(world.record(id).status, 'active');
  assert.doesNotMatch(description, /access to it changes/);
  assert.match(description, /leaves a change of your access out/);
  simulator.hideCalendar(CAL_B);
  await poll(world, id);
  assert.deepEqual(fired((await world.events()).events).map(event => [event.fields.calendarId, event.fields.accessRole, event.fields.hidden]), [[CAL_B, 'reader', true]]);
});

// ---- starting soon -----------------------------------------------------------------------------------------------------------------------------
test('starting soon tells once, with this calendar\'s own answer, and a moved start is a new alert', async t => {
  const world = calendarWorld(t), id = await watching(world, 'starting-soon', soon), {simulator} = world;
  const invited = simulator.invite({calendarId: CAL_A, ...around(world, 'Asked', 10), attendees: [{email: GUEST}]});
  await poll(world, id);
  assert.deepEqual(fired((await world.events()).events).map(event => [event.fields.eventId, event.fields.myResponse]), [[invited.id, 'needsAction']]);
  await poll(world, id);
  assert.deepEqual((await world.events()).events, []);
  await edit(world, CAL_A, simulator.seed(CAL_A, around(world, 'Mine', 240)).id, around(world, 'Mine', 12));
  await poll(world, id);
  assert.deepEqual(fired((await world.events()).events).map(event => event.fields.title), ['Mine']);
});

test('a day with more meetings than a poll reads waits its normal interval: reading the window again gets no further, and an owner with a busy calendar pays for each read', async t => {
  const world = calendarWorld(t), {simulator} = world;
  for (let index = 0; index < 120; index++) simulator.seed(CAL_A, around(world, `Busy ${index}`, 60 + index));
  const id = await watching(world, 'starting-soon', {calendarId: CAL_A, leadMinutes: 1440}), sent = simulator.reads().length;
  await world.ticking(10 * MINUTE);
  assert.equal(simulator.reads().length - sent, 10, 'five walks of two pages, one for each interval that passed');
  assert.equal(world.record(id).status, 'active');
});

test('two leads keep two windows, so one meeting alerts each watch once', async t => {
  const world = calendarWorld(t), short = await watching(world, 'starting-soon', soon), long = await watching(world, 'starting-soon', {calendarId: CAL_A, leadMinutes: 30});
  assert.notEqual(world.record(short).feeds[0], world.record(long).feeds[0]);
  world.simulator.seed(CAL_A, around(world, 'Soon', 20));
  await poll(world, short);
  await world.pollNow(long);
  assert.deepEqual(fired((await world.events()).events).map(event => event.subscriptionId), [long], 'twenty minutes out is past the shorter lead');
  world.advance(10 * MINUTE);
  await world.pollNow(short);
  await world.pollNow(long);
  assert.deepEqual(fired((await world.events()).events).map(event => event.subscriptionId), [short]);
});

test('a poll later than the lead gives one gap and no late alert', async t => {
  const world = calendarWorld(t), id = await watching(world, 'starting-soon', soon);
  world.simulator.seed(CAL_A, around(world, 'Missed', 10, 40));
  world.advance((LEAD + 5) * MINUTE);
  assert.equal((await world.pollNow(id)).status, 'active');
  assert.deepEqual((await world.events()).events.map(event => [event.type, event.fields.reason]), [['trigger.gap', 'window']]);
  await poll(world, id);
  assert.deepEqual((await world.events()).events, []);
});

test('an all-day event gives no alert', async t => {
  const world = calendarWorld(t), id = await watching(world, 'starting-soon', soon);
  world.simulator.seed(CAL_A, {summary: 'All day', start: {date: '2026-10-23'}, end: {date: '2026-10-24'}});
  assert.equal((await poll(world, id)).status, 'active', 'its filter stops at the missing time, before the clock test reads one');
  assert.deepEqual((await world.events()).events, []);
  assert.deepEqual(feedReads(world).at(-1).status, 200);
});

test('a meeting under way gives none: Google\'s timeMin bounds its end, so it is listed, and it has started', async t => {
  const world = calendarWorld(t), id = await watching(world, 'starting-soon', soon);
  const {id: eventId} = world.simulator.seed(CAL_A, around(world, 'Under way', -5, 25));
  const listed = await api(world, 'GET', `/calendars/${encodeURIComponent(CAL_A)}/events`, {query: {timeMin: offset(world, 2), singleEvents: 'true', orderBy: 'startTime'}});
  assert.deepEqual(idsOf(listed), [eventId], 'Google lists it');
  await poll(world, id);
  assert.deepEqual((await world.events()).events, []);
});

test('a meeting still ahead after the gap gives one event', async t => {
  const world = calendarWorld(t), id = await watching(world, 'starting-soon', soon);
  world.advance((LEAD + 5) * MINUTE);
  world.simulator.seed(CAL_A, around(world, 'Still ahead', 10));
  await world.pollNow(id);
  assert.deepEqual((await world.events()).events.map(event => [event.type, event.fields.reason ?? event.fields.title]), [['trigger.event', 'Still ahead'], ['trigger.gap', 'window']]);
});

// ---- the calendar list and sharing -----------------------------------------------------------------------------------------------------------------
test('the list tells of a hide and a show, of a calendar taken off it and of a change of access, and a colour tells nothing', async t => {
  const world = calendarWorld(t), id = await watching(world, 'calendar-list-changed', {}), {simulator} = world, once = async () => { await poll(world, id); return fired((await world.events()).events).map(event => event.fields); };
  simulator.recolor(CAL_B, '7');
  assert.deepEqual(await once(), []);
  simulator.hideCalendar(CAL_B);
  assert.deepEqual((await once()).map(fields => [fields.calendarId, fields.hidden]), [[CAL_B, true]]);
  simulator.hideCalendar(CAL_B, false);
  assert.deepEqual((await once()).map(fields => [fields.calendarId, fields.hidden]), [[CAL_B, undefined]]);
  simulator.leaveCalendar(CAL_B);
  assert.deepEqual((await once()).map(fields => [fields.calendarId, fields.removed]), [[CAL_B, true]]);
});

test('sharing tells of a person, of a removal as role none, of a return, and of a public calendar with no value', async t => {
  const world = calendarWorld(t), id = await watching(world, 'calendar-sharing-changed'), {simulator} = world, once = async () => { await poll(world, id); return fired((await world.events()).events).map(event => [event.fields.ruleId, event.fields.role, event.fields.scopeValue]); };
  const rule = 'user:friend@example.com';
  simulator.share(CAL_A, 'friend@example.com');
  assert.deepEqual(await once(), [[rule, 'reader', 'friend@example.com']]);
  simulator.unshare(CAL_A, 'friend@example.com');
  assert.deepEqual(await once(), [[rule, 'none', 'friend@example.com']]);
  simulator.share(CAL_A, 'friend@example.com');
  assert.deepEqual(await once(), [[rule, 'reader', 'friend@example.com']], 'latest value, never a set of values');
  simulator.sharePublic(CAL_A);
  assert.deepEqual(await once(), [['default', 'reader', undefined]]);
});

test('a reader\'s calendar pauses provider_refused on its first poll, with Fabric sending nothing at subscribe', async t => {
  const world = calendarWorld(t);
  world.simulator.addCalendar({id: 'shared@group.calendar.google.com', accessRole: 'reader'});
  const id = await started(world, 'calendar-sharing-changed', {calendarId: 'shared@group.calendar.google.com'});
  assert.equal(world.simulator.calls.length, 0);
  const watch = await world.pollNow(id);
  assert.deepEqual([watch.status, watch.reason, watch.detail], ['paused', 'provider_refused', 'http_403']);
});

// ---- subscribe refusals ---------------------------------------------------------------------------------------------------------------------------
test('primary is refused for every trigger on a calendar, since it and the owner\'s address would make two feeds, and a lead under twice the interval too', async t => {
  const world = calendarWorld(t), {triggerEntries} = world;
  for (const {key} of triggerEntries.filter(entry => entry.trigger.resource.includes('calendarId'))) {
    await assert.rejects(world.subscribe(key, {calendarId: 'primary', ...(key === 'starting-soon' ? {leadMinutes: LEAD} : {})}), error => error.code === 'invalid_request' && /not primary/.test(error.message), key);
  }
  await assert.rejects(world.subscribe('starting-soon', {calendarId: CAL_A, leadMinutes: 3}), error => error.code === 'invalid_request', 'the schema\'s floor');
  assert.equal(world.store.list('subscriptions').length, 0);
  assert.equal((await world.subscribe('starting-soon', {calendarId: CAL_A, leadMinutes: 5})).status, 'awaiting_approval');
});

test('sharing without calendar.acls is refused at subscribe and names Add access, while a watch on events stands', async t => {
  const world = calendarWorld(t, {scopes: HARNESS_SIX.filter(scope => !scope.endsWith('calendar.acls'))});
  await assert.rejects(world.subscribe('calendar-sharing-changed', onA), error => error.code === 'invalid_request' && /Add access/.test(error.message));
  assert.equal((await world.subscribe('new-event', onA)).status, 'awaiting_approval');
});

// ---- limits ------------------------------------------------------------------------------------------------------------------------------------
test('5,005 guest rows pause the guest watch alone: a new-event watch beside it reads on', async t => {
  const world = calendarWorld(t);
  TRIGGERS['guest-responded'].fill(world);
  const guests = await started(world, 'guest-responded'), fresh = await started(world, 'new-event');
  await drain(world, fresh);
  assert.deepEqual([world.record(guests).status, world.record(guests).reason, world.record(guests).detail, world.record(fresh).status], ['paused', 'too_many_items', 'seen_limit', 'active']);
  world.simulator.seed(CAL_A, timed('New'));
  await poll(world, fresh);
  assert.deepEqual(fired((await world.events()).events).map(event => [event.subscriptionId, event.fields.title]), [[fresh, 'New']]);
});

test('a page of 1,250 answers pauses guest-responded alone, and a watch on new events takes the same page', async t => {
  const world = calendarWorld(t);
  for (const number of [0, 1]) world.simulator.seed(CAL_A, timed(`Event ${number}`, 28, {attendees: Array.from({length: 625}, (_, index) => ({email: `g${number}-${index}@example.com`, responseStatus: 'accepted'}))}));
  const guests = await started(world, 'guest-responded'), fresh = await started(world, 'new-event');
  await world.pollNow(fresh);
  assert.deepEqual([world.record(guests).status, world.record(guests).reason, world.record(guests).detail, world.record(fresh).status], ['paused', 'too_many_items', 'too_many_items', 'active']);
});

test('after guest-responded and calendar-sharing-changed run, no seen row and no dedupe key holds an address', async t => {
  const world = calendarWorld(t), {simulator} = world, {id: eventId} = simulator.seed(CAL_A, timed('Review', 28, {attendees: [{email: GUEST}]}));
  const guests = await watching(world, 'guest-responded'), sharing = await watching(world, 'calendar-sharing-changed');
  simulator.guestResponds(CAL_A, eventId, GUEST, 'accepted');
  simulator.share(CAL_A, 'friend@example.com');
  await poll(world, guests);
  await poll(world, sharing);
  assert.equal(fired((await world.events()).events).length, 2, 'each has run and fired');
  const seen = world.store.db.prepare('SELECT feed_id, lens, item_key, value_hash FROM trigger_seen').all(), keys = world.store.db.prepare('SELECT dedupe_key FROM trigger_events').all();
  assert.ok(seen.length > 0 && keys.length === 2);
  assert.doesNotMatch(JSON.stringify([seen, keys]), /@/);
});

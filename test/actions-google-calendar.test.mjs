import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync, readFileSync} from 'node:fs';
import {validateActionFile} from '../lib/actions.mjs';
import {ACTION_REFUSED, PREPARED, RUN_WORDS} from '../lib/actions-runtime.mjs';
import {STATUS_WORDS} from '../lib/action-catalog.mjs';
import {FabricProtocol} from '../lib/fabric-protocol.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {RULES} from '../lib/live-guard.mjs';
import {checkPlan, fillPlaceholders} from '../lib/live-certify.mjs';
import {calendarHarness, calendarDeps, calendarFile, OWNER_EMAIL, SIX, TOKEN, ZONE} from './fixtures/actions/calendar-harness.mjs';
import {caseTests} from './fixtures/provider-simulators/cases.mjs';
import {actionSchema, withIds} from './fixtures/actions/fixture-app.mjs';

// F10.13 part 2 (docs/F10.13-BUILD-MAP.md section 3, part 2): Calendar's 13 reviewed actions (catalog/actions/google-calendar.json) on the
// Calendar simulator, through the action runtime, as an agent's call and the owner's approval run them; every case of Calendar's simulator
// case list (test/fixtures/provider-simulators/google-calendar.cases.json) through caseTests(); and the live plan C0 to C13
// (catalog/live-tests/google-calendar.json) against step 12's plan check. Nothing here reaches Google. Every test reads the file with its ids
// recomputed (withIds()), so a seeded fault inside it is caught by what the action does; test/f10-13-churn.test.mjs checks the shipped ids.

const READ = {readOnly: true, destructive: false, idempotent: true, openWorld: true}, WRITE = {readOnly: false, destructive: false, idempotent: false, openWorld: true};
const BOUND = {readOnly: false, destructive: false, idempotent: true, openWorld: true}, DELETE = {readOnly: false, destructive: true, idempotent: true, openWorld: true};
/** Section 2's table: each action's row, effect and hints. */
const TABLE = Object.freeze({
  'find-events': ['google-calendar.events.read', 'read', READ], 'get-event': ['google-calendar.events.read', 'read', READ], 'list-calendars': ['google-calendar.calendars.read', 'read', READ],
  'find-free-time': ['google-calendar.availability.read', 'read', READ], 'create-event': ['google-calendar.events.write', 'write', WRITE], 'quick-add': ['google-calendar.events.write', 'write', WRITE],
  'update-event': ['google-calendar.events.write', 'write', BOUND], 'update-guests': ['google-calendar.events.write', 'write', BOUND], 'respond-event': ['google-calendar.events.write', 'write', BOUND],
  'delete-event': ['google-calendar.events.delete', 'delete', DELETE], 'move-event': ['google-calendar.events.write', 'write', WRITE], 'create-calendar': ['google-calendar.calendars.write', 'write', WRITE],
  'stop-sharing': ['google-calendar.sharing.write', 'delete', DELETE]});
const TIMED = (start, end) => ({start: {dateTime: start, timeZone: ZONE}, end: {dateTime: end, timeZone: ZONE}});
const REVIEW = {summary: 'Review', ...TIMED('2026-11-02T10:00:00-05:00', '2026-11-02T10:30:00-05:00')};
const EVENTS = 'GET /calendars/{calendarId}/events', EVENT = 'GET /calendars/{calendarId}/events/{eventId}';

/** Asserts how a job ended, and any of its fields. */
function ended(job, status, errorCode, extra = {}) {
  assert.deepEqual([job.status, job.errorCode ?? null], [status, errorCode], `${job.error} ${JSON.stringify(job.details ?? job.reason ?? '')}`);
  for (const [key, value] of Object.entries(extra)) assert.deepEqual(job[key], value, key);
  return job;
}
/** An action refusal: failed, action_refused, its reason (and transform) in details. */
const refusedAs = (job, reason) => { ended(job, 'failed', ACTION_REFUSED); assert.equal(job.details?.reason, reason, JSON.stringify(job.details)); return job; };
const writes = h => h.simulator.writes().map(call => `${call.method} ${call.path}`);
const calls = h => h.simulator.calls.map(call => `${call.method} ${call.path}`);
/** A write job prepared to its one card: awaiting the owner, phase final, nothing written yet. */
async function prepared(h, key, input) {
  const before = h.simulator.writes().length, job = await h.run(key, input);
  assert.deepEqual([job.status, job.action?.phase, h.simulator.writes().length], ['awaiting_approval', 'final', before], `${key}: ${job.error ?? ''} ${JSON.stringify(job.details ?? '')}`);
  return job;
}
const approved = async (h, key, input) => h.approve(await prepared(h, key, input));
/** The exact body a prepared job will send, parsed. */
const bodyOf = (h, job, index = 0) => JSON.parse(h.prepared(job).content.perform[index].body);
const urlOf = (h, job, index = 0) => new URL(h.prepared(job).content.perform[index].url);
const seed = (h, resource = REVIEW, options) => h.simulator.seed('primary', structuredClone(resource), options);
const stored = (h, id) => h.simulator.state().events[id];

// ---- the file ---------------------------------------------------------------------------------------------------------------------------
/** Calendar's shipped file with each id recomputed from its content, as an author writes them. */
const currentFile = (deps = calendarDeps()) => withIds(calendarFile(), deps);

// F10.14 listed churn: step 14's live pass certified all 13, each naming the shipped evidence. That each names the hash of exactly its
// definition, with a passing record there, is test/live-evidence.test.mjs's: here it would fail on any edit of the file, and so hide
// whether this file's behaviour tests notice the edit (branch review of step 14).
test('the file: 13 actions, each placed in its row with its effect and hints (section 2); each certified by step 14\'s evidence, no superseded id', () => {
  const file = currentFile(), {actions} = validateActionFile(file, calendarDeps());
  assert.deepEqual(actions.map(entry => entry.key), Object.keys(TABLE));
  for (const entry of actions) {
    const [row, effect, hints] = TABLE[entry.key];
    assert.deepEqual([entry.version, entry.row, entry.effect, entry.action.hints, entry.unplaced, entry.sensitive], [1, row, effect, hints, false, false], entry.key);
    assert.ok(entry.placements.every(placement => !placement.unplaced && placement.groupId.startsWith('google-calendar.')), entry.key);
    assert.equal(entry.placements.filter(placement => placement.phase === 'perform').at(-1).groupId, row, `${entry.key}: the last perform step lands in its row`);
    assert.deepEqual([Object.keys(entry.action.certified), entry.action.certified.evidence], [['evidence', 'definitionHash'], 'docs/live-evidence/google-calendar/actions.json'], `${entry.key}: certified by step 14's evidence`);
  }
  assert.deepEqual([file.specVersion, file.pinnedParameters, file.superseded, ['candidate', 'reviewed'].includes(file.reviewStatus)], ['fabric/0.2', {}, undefined, true]);
  const schema = actionSchema();
  assert.ok(schema(file), JSON.stringify(schema.errors));
  // At most 5 requests per action: Update or reschedule is the largest (the event, the zone or its fallback, the PATCH and its readback).
  assert.ok(actions.every(entry => entry.placements.length <= 5), 'at most 5 steps');
  assert.deepEqual(actions.find(entry => entry.key === 'update-event').placements.map(placement => placement.stepId), ['event', 'tz', 'tzPrimary', 'patch', 'check']);
});

test('without Google\'s map the file is refused, not run: Find free time\'s reviewed-read POST counts as a write until it places (F10.10), and every other action is unplaced', () => {
  const file = currentFile(), deps = calendarDeps({map: null});
  assert.throws(() => validateActionFile(file, deps), /find-free-time v1: declares effect read, but its methods say at least write/);
  const rest = {...file, actions: file.actions.filter(action => action.key !== 'find-free-time')};
  assert.deepEqual(validateActionFile(rest, deps).actions.map(entry => entry.unplaced), Array(12).fill(true));
  // The shipped folders themselves (13 candidates with the map, Calendar refused without one) are test/actions-catalog.test.mjs's.
});

test('at start without live evidence: 13 candidates that never run and that no agent can be given', async t => {
  const h = calendarHarness(t, {evidence: false});
  assert.deepEqual([...h.catalog.entries.values()].map(item => [item.status, item.reason]), Array(13).fill(['candidate', STATUS_WORDS.evidence]));
  assert.ok(h.store.list('capabilities').filter(capability => capability.driver === 'action').every(capability => capability.status === 'candidate'));
  await assert.rejects(h.run('list-calendars v1', {}));
  const protocol = new FabricProtocol({store: h.store, runtime: h.runtime, clock: () => h.now, origin: 'http://127.0.0.1:59997'});
  assert.throws(() => protocol.createClient({name: 'Calendar agent', bindings: [{connectionId: h.account, capabilityId: h.idOf('list-calendars v1')}]}, null), {code: 'permission_denied'});
  assert.deepEqual([h.simulator.calls.length, h.store.list('clientGrants').length], [0, 0]);
});

// ---- daylight-saving changes (spec line 1065) -----------------------------------------------------------------------------------------
test('daylight-saving changes: a skipped time refuses time_nonexistent and a repeated one time_ambiguous, nothing written; each side of the change sends its own offset', async t => {
  const h = calendarHarness(t), event = {calendarId: 'primary', kind: 'timed', summary: 'Plan', notify: 'none'};
  refusedAs(await h.run('create-event v1', {...event, start: '2026-03-08T02:30:00', end: '2026-03-08T03:30:00'}), 'time_nonexistent');
  refusedAs(await h.run('create-event v1', {...event, start: '2026-11-01T01:30:00', end: '2026-11-01T03:00:00'}), 'time_ambiguous');
  assert.deepEqual(writes(h), [], 'nothing written');
  const before = await prepared(h, 'create-event v1', {...event, start: '2026-10-31T10:00:00', end: '2026-10-31T10:30:00'});
  const after = await prepared(h, 'create-event v1', {...event, start: '2026-11-01T10:00:00', end: '2026-11-01T10:30:00'});
  assert.deepEqual(bodyOf(h, before).start, {dateTime: '2026-10-31T10:00:00-04:00', timeZone: ZONE});
  assert.deepEqual(bodyOf(h, after).start, {dateTime: '2026-11-01T10:00:00-05:00', timeZone: ZONE});
  ended(await h.approve(after), 'succeeded', null);
});

test('daylight-saving changes: a weekly event of 3 across 2026-11-01 stays at 10:00; Find events across the change sends both offsets; Find free time frees the right hours', async t => {
  const h = calendarHarness(t);
  const weekly = await approved(h, 'create-event v1', {calendarId: 'primary', kind: 'timed', summary: 'Standup', start: '2026-10-25T10:00:00', end: '2026-10-25T10:15:00',
    recurrence: 'RRULE:FREQ=WEEKLY;COUNT=3', notify: 'none'});
  ended(weekly, 'succeeded', null);
  assert.deepEqual(h.simulator.writes()[0].body.recurrence, ['RRULE:FREQ=WEEKLY;COUNT=3']);
  const found = ended(await h.run('find-events v1', {calendarId: 'primary', from: '2026-10-24T00:00:00', to: '2026-11-10T00:00:00'}), 'succeeded', null);
  assert.deepEqual(found.result.data.events.map(item => item.start.dateTime), ['2026-10-25T10:00:00-04:00', '2026-11-01T10:00:00-05:00', '2026-11-08T10:00:00-05:00']);
  assert.ok(found.result.data.events.every(item => item.recurringEventId === weekly.result.data.id));
  // A window across the change: from midnight EDT to midnight EST.
  const across = ended(await h.run('find-events v1', {calendarId: 'primary', from: '2026-10-31T00:00:00', to: '2026-11-02T00:00:00'}), 'succeeded', null);
  const query = h.simulator.calls.filter(call => call.route === EVENTS).at(-1).query;
  assert.deepEqual([query.timeMin, query.timeMax, query.timeZone, across.result.data.timeZone], ['2026-10-31T00:00:00-04:00', '2026-11-02T00:00:00-05:00', ZONE, ZONE]);
  // 00:00 EDT (04:00Z) to 12:00 EST (17:00Z) on 2026-11-01 is 13 hours; the standup is busy 10:00 to 10:15 EST (15:00Z to 15:15Z).
  const free = ended(await h.run('find-free-time v1', {from: '2026-11-01T00:00:00', to: '2026-11-01T12:00:00', calendars: ['primary'], minMinutes: 30}), 'succeeded', null);
  assert.deepEqual(free.result.data.free, [{start: '2026-11-01T04:00:00Z', end: '2026-11-01T15:00:00Z'}, {start: '2026-11-01T15:15:00Z', end: '2026-11-01T17:00:00Z'}]);
});

// ---- all-day events -------------------------------------------------------------------------------------------------------------------
test('an all-day end is exclusive: one day, three days and a year end; the card shows the first day and the day count, never the end', async t => {
  const h = calendarHarness(t), allDay = (date, days) => prepared(h, 'create-event v1', {calendarId: 'primary', kind: 'all-day', summary: 'Away', date, days, notify: 'none'});
  const one = await allDay('2026-11-02', 1), three = await allDay('2026-11-02', 3), year = await allDay('2026-12-31', 1);
  assert.deepEqual([bodyOf(h, one).start, bodyOf(h, one).end], [{date: '2026-11-02'}, {date: '2026-11-03'}]);
  assert.deepEqual(bodyOf(h, three).end, {date: '2026-11-05'});
  assert.deepEqual(bodyOf(h, year).end, {date: '2027-01-01'});
  const fields = h.fields(three);
  assert.deepEqual([fields['All day from'], fields.Days], ['2026-11-02', 3]);
  assert.ok(!h.card(three).exact.blocks.find(block => block.label === 'Fields').text.includes('2026-11-05'), 'the exclusive end is never a card line');
  const done = ended(await h.approve(three), 'succeeded', null);
  assert.deepEqual([stored(h, done.result.data.id).end, done.result.data.end], [{kind: 'date', date: '2026-11-05'}, {date: '2026-11-05'}]);
});

// ---- a changed event --------------------------------------------------------------------------------------------------------------------
test('a 412 means failed, changed since it was read, and nothing changed; C6\'s race: the first of two jobs on one version lands, the second fails the same way', async t => {
  const h = calendarHarness(t), event = seed(h);
  const job = await prepared(h, 'update-event v1', {calendarId: 'primary', eventId: event.id, newTime: {start: '2026-11-02T11:00:00', end: '2026-11-02T11:30:00'}, notify: 'none'});
  assert.equal(h.prepared(job).content.perform[0].headers['If-Match'], event.etag, 'If-Match is the etag read first');
  const touched = h.simulator.touch('primary', event.id);
  ended(await h.approve(job), 'failed', 'provider_failed', {providerStatus: 412, reason: 'content_changed', error: RUN_WORDS.content_changed});
  assert.deepEqual([writes(h), stored(h, event.id).etag, stored(h, event.id).start.ms], [[`PATCH /calendars/primary/events/${event.id}`], touched.etag, Date.parse('2026-11-02T15:00:00Z')]);
  // The race: both prepared before either card is approved, so both bind the same etag.
  const input = {calendarId: 'primary', eventId: event.id, notify: 'none'};
  const first = await prepared(h, 'update-event v1', {...input, newTime: {start: '2026-11-02T10:30:00', end: '2026-11-02T11:00:00'}});
  const second = await prepared(h, 'update-event v1', {...input, newTime: {start: '2026-11-02T12:00:00', end: '2026-11-02T12:30:00'}});
  const landed = ended(await h.approve(first), 'succeeded', null);
  ended(await h.approve(second), 'failed', 'provider_failed', {providerStatus: 412, reason: 'content_changed'});
  assert.deepEqual([stored(h, event.id).etag, stored(h, event.id).start.ms], [landed.result.data.etag, Date.parse('2026-11-02T15:30:00Z')], 'the event is the first job\'s result');
});

// ---- guests -----------------------------------------------------------------------------------------------------------------------------
test('merging guests keeps each attendee whole and in place; removing the organizer or you refuses before any write; a present guest added or an absent one removed changes nothing', async t => {
  const h = calendarHarness(t);
  const event = seed(h, {...REVIEW, attendees: [{email: 'ann@example.com', responseStatus: 'accepted', comment: 'Yes'}, {email: 'bob@example.com', responseStatus: 'tentative', optional: true}]});
  const input = {calendarId: 'primary', eventId: event.id, notify: 'none'};
  const job = await prepared(h, 'update-guests v1', {...input, add: ['cy@example.com', 'ANN@example.com'], remove: ['bob@example.com']});
  assert.deepEqual(bodyOf(h, job), {attendees: [{email: 'ann@example.com', responseStatus: 'accepted', comment: 'Yes'}, {email: 'cy@example.com'}]});
  const fields = h.fields(job);
  assert.deepEqual([fields['Guests now'], fields['Guests added'], fields['Guests removed'], fields.Event, fields['Starts now']],
    ['ann@example.com\nbob@example.com', 'cy@example.com', 'bob@example.com', 'Review', '2026-11-02T10:00:00-05:00']);
  assert.match(h.card(job).exact.blocks.find(block => block.label === 'Fields').text, /^Guests now: ann@example\.com\nbob@example\.com$/m);
  const done = ended(await h.approve(job), 'succeeded', null);
  assert.deepEqual([done.result.data.added, done.result.data.removed], [['cy@example.com'], ['bob@example.com']]);
  assert.deepEqual(stored(h, event.id).attendees.map(item => [item.email, item.responseStatus]), [['ann@example.com', 'accepted'], ['cy@example.com', 'needsAction']]);
  // You, and an invitation's organizer, are never removed: refused before any write.
  refusedAs(await h.run('update-guests v1', {...input, add: [], remove: [OWNER_EMAIL]}), 'attendee_protected');
  const invitation = h.simulator.invite({...REVIEW, organizer: 'org@other.example', attendees: ['dan@example.com']});
  refusedAs(await h.run('update-guests v1', {calendarId: 'primary', eventId: invitation.id, add: [], remove: ['org@other.example'], notify: 'none'}), 'attendee_protected');
  // On a shared calendar's event you neither organize nor attend, only your own address protects you: still refused.
  const team = h.simulator.addCalendar({id: 'team@group.calendar.google.com', accessRole: 'writer'}), shared = h.simulator.seed(team.id, structuredClone(REVIEW));
  refusedAs(await h.run('update-guests v1', {calendarId: team.id, eventId: shared.id, add: [], remove: [OWNER_EMAIL], notify: 'none'}), 'attendee_protected');
  assert.equal(h.simulator.writes().length, 1);
  // Adding a guest who is there and removing one who is not: the list as it was, and nothing added or removed on the card.
  const same = await prepared(h, 'update-guests v1', {...input, add: ['ann@example.com'], remove: ['zed@example.com']});
  assert.deepEqual(bodyOf(h, same).attendees.map(item => item.email), ['ann@example.com', 'cy@example.com']);
  assert.deepEqual([h.fields(same)['Guests added'], h.fields(same)['Guests removed']], ['', '']);
  // An event with no guests shows an empty Guests now line, never a refusal.
  const alone = seed(h);
  assert.equal(h.fields(await prepared(h, 'update-event v1', {calendarId: 'primary', eventId: alone.id, summary: 'Solo', notify: 'none'}))['Guests now'], '');
});

test('Respond refuses match_none when you are not a guest, with nothing sent; on an invitation it sends attendeesOmitted and only your entry, and the other attendees stay', async t => {
  const h = calendarHarness(t), own = seed(h);
  refusedAs(await h.run('respond-event v1', {calendarId: 'primary', eventId: own.id, response: 'accepted', notify: 'none'}), 'match_none');
  assert.deepEqual(writes(h), []);
  const invitation = h.simulator.invite({...REVIEW, organizer: 'org@other.example', attendees: [{email: 'dan@example.com', responseStatus: 'declined'}]});
  const job = await prepared(h, 'respond-event v1', {calendarId: 'primary', eventId: invitation.id, response: 'accepted', notify: 'none'});
  assert.deepEqual(bodyOf(h, job), {attendeesOmitted: true, attendees: [{email: OWNER_EMAIL, responseStatus: 'accepted'}]});
  assert.deepEqual([h.fields(job).Organizer, h.fields(job)['Your answer']], ['org@other.example', 'accepted']);
  ended(await h.approve(job), 'succeeded', null);
  const answered = h.simulator.state().events[invitation.id];
  assert.deepEqual(answered.attendees.map(item => [item.email, item.responseStatus]), [['org@other.example', 'accepted'], ['dan@example.com', 'declined'], [OWNER_EMAIL, 'accepted']]);
});

// ---- who Google emails -------------------------------------------------------------------------------------------------------------------
test('a notify choice other than none is on the card and in the exact request, and Google emails the guests; none emails nobody; notify is never left to a default', async t => {
  const h = calendarHarness(t), base = {calendarId: 'primary', kind: 'timed', summary: 'Plan', start: '2026-11-02T10:00:00', end: '2026-11-02T10:30:00', guests: ['ann@example.com']};
  const all = await prepared(h, 'create-event v1', {...base, notify: 'all'});
  assert.equal(h.fields(all)['Emails Google sends'], 'all');
  assert.equal(urlOf(h, all).searchParams.get('sendUpdates'), 'all');
  assert.match(h.card(all).exact.blocks.find(block => block.label === 'create: Request').text, /sendUpdates=all/);
  ended(await h.approve(all), 'succeeded', null);
  assert.deepEqual(h.simulator.notifications().map(item => [item.kind, item.to]), [['invitation', 'ann@example.com']]);
  const none = await prepared(h, 'create-event v1', {...base, notify: 'none'});
  assert.deepEqual([h.fields(none)['Emails Google sends'], urlOf(h, none).searchParams.getAll('sendUpdates'), urlOf(h, none).searchParams.has('sendNotifications')], ['none', ['none'], false]);
  ended(await h.approve(none), 'succeeded', null);
  assert.equal(h.simulator.notifications().length, 1, 'none emails nobody');
  const sent = h.simulator.calls.length;
  await assert.rejects(h.run('create-event v1', base), 'notify is required');
  assert.equal(h.simulator.calls.length, sent, 'refused before any call');
});

// ---- moving -------------------------------------------------------------------------------------------------------------------------------
test('Move refuses an event type other than default (wrong_kind), with nothing sent and nothing moved; a default event moves and is read on its destination', async t => {
  const h = calendarHarness(t), other = h.simulator.addCalendar({id: 'team@group.calendar.google.com', accessRole: 'owner'});
  const focus = seed(h, REVIEW, {eventType: 'focusTime'});
  const refused = refusedAs(await h.run('move-event v1', {calendarId: 'primary', eventId: focus.id, destination: other.id, notify: 'none'}), 'wrong_kind');
  assert.deepEqual([refused.details.transform, refused.details.transformReason, writes(h), stored(h, focus.id).calendarId], ['collections.oneOf@1', 'not_one_of', [], OWNER_EMAIL]);
  const plain = seed(h);
  const moved = ended(await approved(h, 'move-event v1', {calendarId: 'primary', eventId: plain.id, destination: other.id, notify: 'none'}), 'succeeded', null);
  assert.deepEqual([stored(h, plain.id).calendarId, moved.result.data.calendarId, moved.result.verification.status], [other.id, other.id, 'verified']);
  assert.equal(h.simulator.calls.at(-1).path, `/calendars/${other.id}/events/${plain.id}`, 'read back on the destination');
  assert.notEqual(stored(h, plain.id).etag, moved.result.data.etag, 'verified although the event reads back with a newer etag than the move answered (live run TOQJPGEU, C8)');
  // The readback checks the same id with the same start and end: one the event no longer has reads back unverified.
  const second = seed(h), job = await prepared(h, 'move-event v1', {calendarId: 'primary', eventId: second.id, destination: other.id, notify: 'none'});
  const hold = h.simulator.hold('GET /calendars/{calendarId}/events/{eventId}'), running = h.approve(job);
  await hold.reached;
  const held = h.simulator.data.events[second.id];
  held.start = {...held.start, ms: held.start.ms + 3_600_000};
  hold.release();
  const changed = ended(await running, 'uncertain', 'outcome_uncertain');
  assert.equal(changed.result.verification.status, 'unverified');
});

// ---- Meet (critique test 16) ------------------------------------------------------------------------------------------------------------
test('critique test 16: one job\'s Meet requestId is the same in the card, the digest\'s job keys and the dispatched body, and a restart never sends it again; two jobs get two ids', async t => {
  const h = calendarHarness(t), input = {calendarId: 'primary', kind: 'timed', summary: 'Call', start: '2026-11-02T10:00:00', end: '2026-11-02T10:30:00', meet: true, notify: 'none'};
  const job = await prepared(h, 'create-event v1', input), key = job.action.jobKeys.meet;
  assert.match(key, /^[0-9a-f]{32}$/);
  const shown = JSON.parse(h.card(job).exact.blocks.find(block => block.label === 'create: Body').text);
  assert.deepEqual([shown.conferenceData.createRequest, urlOf(h, job).searchParams.get('conferenceDataVersion')], [{requestId: key, conferenceSolutionKey: {type: 'hangoutsMeet'}}, '1']);
  const done = ended(await h.approve(job), 'succeeded', null);
  assert.equal(h.simulator.writes()[0].body.conferenceData.createRequest.requestId, key);
  assert.deepEqual([done.result.data.conferenceStatus, /^https:\/\/meet\.google\.com\//.test(done.result.data.hangoutLink)], ['success', true]);
  // A restart: the job is finished, so recovering sends nothing again.
  const restarted = new Runtime({store: h.store, permissions: h.permissions, proxyPolicy: h.proxyPolicy, connections: h.connections, request: h.simulator.request, clock: () => h.now, actions: h.catalog});
  restarted.recover();
  assert.equal(h.simulator.writes().length, 1);
  const again = await prepared(h, 'create-event v1', input);
  assert.notEqual(again.action.jobKeys.meet, key, 'a new job, a new requestId');
  ended(await h.approve(again), 'succeeded', null);
  assert.equal(Object.keys(h.simulator.state().conferences).length, 2);
});

// ---- the owner's zone -------------------------------------------------------------------------------------------------------------------
test('the time zone: the settings read with its scope, else the primary calendar\'s entry (access stays granted); "Access settings and calendar sharing" at Never refuses every action that reads the zone', async t => {
  let h = calendarHarness(t, {zone: 'Europe/Paris'});
  const found = ended(await h.run('find-events v1', {calendarId: 'primary', from: '2026-11-02T00:00:00', to: '2026-11-03T00:00:00'}), 'succeeded', null);
  assert.deepEqual([calls(h)[0], found.action.plan.skipped, found.result.data.timeZone], ['GET /users/me/settings/timezone', ['tzPrimary'], 'Europe/Paris']);
  h = calendarHarness(t, {zone: 'Europe/Paris', scopes: SIX.filter(scope => !scope.endsWith('settings.readonly'))});
  const fallback = ended(await h.run('find-events v1', {calendarId: 'primary', from: '2026-11-02T00:00:00', to: '2026-11-03T00:00:00'}), 'succeeded', null);
  assert.deepEqual([calls(h)[0], fallback.action.plan.skipped, h.simulator.calls[1].query.timeMin], ['GET /users/me/calendarList/primary', ['tz'], '2026-11-02T00:00:00+01:00']);
  h = calendarHarness(t);
  h.setRow('google-calendar.settings.read', 'deny');
  for (const [key, input] of [['find-events v1', {calendarId: 'primary', from: '2026-11-02T00:00:00', to: '2026-11-03T00:00:00'}],
    ['find-free-time v1', {from: '2026-11-02T00:00:00', to: '2026-11-03T00:00:00', calendars: ['primary'], minMinutes: 30}],
    ['create-event v1', {calendarId: 'primary', kind: 'timed', summary: 'Plan', start: '2026-11-02T10:00:00', end: '2026-11-02T10:30:00', notify: 'none'}],
    ['update-event v1', {calendarId: 'primary', eventId: 'any', summary: 'Plan', notify: 'none'}]]) {
    await assert.rejects(h.run(key, input), error => error.code === 'permission_denied' || /Never/.test(error.message), key);
  }
  assert.equal(h.simulator.calls.length, 0, 'refused before any call (T8)');
  ended(await h.run('list-calendars v1', {}), 'succeeded', null);
});

// ---- free time ----------------------------------------------------------------------------------------------------------------------------
test('Find free time runs at Allow with no card and no write lock, merges busy blocks across calendars, and refuses busy_unknown for a calendar Google could not read', async t => {
  const h = calendarHarness(t), team = h.simulator.addCalendar({id: 'team@group.calendar.google.com', accessRole: 'reader'});
  seed(h, {summary: 'A', ...TIMED('2026-11-02T09:00:00-05:00', '2026-11-02T10:00:00-05:00')});
  h.simulator.seed(team.id, {summary: 'B', ...TIMED('2026-11-02T09:30:00-05:00', '2026-11-02T11:00:00-05:00')});
  const job = await h.run('find-free-time v1', {from: '2026-11-02T08:00:00', to: '2026-11-02T12:00:00', calendars: ['primary', team.id], minMinutes: 30});
  ended(job, 'succeeded', null, {effect: 'read'});
  assert.deepEqual([job.action.modes, job.action.approvals, [...h.runtime.writeLocks]], [{prepare: 'allow', resolve: null, perform: 'allow'}, [], []], 'no card, no lock');
  assert.deepEqual(job.result.data.free, [{start: '2026-11-02T13:00:00Z', end: '2026-11-02T14:00:00Z'}, {start: '2026-11-02T16:00:00Z', end: '2026-11-02T17:00:00Z'}]);
  assert.deepEqual(h.simulator.calls.at(-1).body, {timeMin: '2026-11-02T08:00:00-05:00', timeMax: '2026-11-02T12:00:00-05:00', timeZone: ZONE, items: [{id: 'primary'}, {id: team.id}]});
  refusedAs(await h.run('find-free-time v1', {from: '2026-11-02T08:00:00', to: '2026-11-02T12:00:00', calendars: ['primary', 'gone@group.calendar.google.com'], minMinutes: 30}), 'busy_unknown');
});

// ---- cancelling ----------------------------------------------------------------------------------------------------------------------------
// Google's get "always returns" a deleted event, with status cancelled: that verifies. The runtime's address identity holds only on 404 or 410
// (test/actions-runtime.test.mjs, F10.11), so no one identity accepts all three answers: a 404 or 410 readback ends uncertain, never failed
// and never retried (docs/F10.13-BUILD-MAP.md section 10).
test('Cancel verifies Google\'s cancelled answer, and a 404 or 410 readback ends unverified, never failed; on an invitation the card names the organizer and how to tell them', async t => {
  for (const [status, outcome, verification] of [[200, 'succeeded', 'verified'], [404, 'uncertain', 'unverified'], [410, 'uncertain', 'unverified']]) {
    const h = calendarHarness(t), event = seed(h);
    h.simulator.deletedAs(status);
    const done = ended(await approved(h, 'delete-event v1', {calendarId: 'primary', eventId: event.id, notify: 'none'}), outcome, outcome === 'succeeded' ? null : 'outcome_uncertain');
    assert.deepEqual([done.result.verification.status, done.result.data, stored(h, event.id).status, writes(h).length], [verification, {id: event.id}, 'cancelled', 1], String(status));
  }
  const h = calendarHarness(t), invitation = h.simulator.invite({...REVIEW, organizer: 'org@other.example'});
  const fields = h.fields(await prepared(h, 'delete-event v1', {calendarId: 'primary', eventId: invitation.id, notify: 'none'}));
  assert.equal(fields.Organizer, 'org@other.example');
  assert.match(fields['If you are a guest'], /removes it from your calendar only\. To tell the organizer, use Respond to an invitation with declined\./);
});

// ---- sharing ------------------------------------------------------------------------------------------------------------------------------
test('Stop sharing reads back 404, and refuses an owner\'s rule (wrong_kind) with nothing sent', async t => {
  const h = calendarHarness(t);
  h.simulator.share('primary', 'fabric-share@example.com', 'reader');
  const job = await prepared(h, 'stop-sharing v1', {calendarId: 'primary', ruleId: 'user:fabric-share@example.com'});
  assert.deepEqual([h.fields(job)['Shared with'], h.fields(job)['Address or domain'], h.fields(job)['Access it gives']], ['user', 'fabric-share@example.com', 'reader']);
  const done = ended(await h.approve(job), 'succeeded', null);
  assert.deepEqual([done.result.verification.status, h.simulator.calls.at(-1).status], ['verified', 404]);
  refusedAs(await h.run('stop-sharing v1', {calendarId: 'primary', ruleId: `user:${OWNER_EMAIL}`}), 'wrong_kind');
  assert.deepEqual(writes(h), ['DELETE /calendars/primary/acl/user:fabric-share@example.com']);
});

// ---- calendars and quick add -------------------------------------------------------------------------------------------------------------
test('Create a calendar refuses zone_invalid with nothing sent and makes one in a zone it names; Quick add returns the times Google read', async t => {
  const h = calendarHarness(t);
  refusedAs(await h.run('create-calendar v1', {summary: 'Team', timeZone: 'Mars/Olympus'}), 'zone_invalid');
  refusedAs(await h.run('create-calendar v1', {summary: 'Team', timeZone: 'america/toronto'}), 'zone_invalid');
  assert.deepEqual(writes(h), []);
  const made = ended(await approved(h, 'create-calendar v1', {summary: 'Team', timeZone: 'Europe/Paris'}), 'succeeded', null);
  assert.deepEqual([made.result.data.summary, made.result.data.timeZone, made.result.verification.status], ['Team', 'Europe/Paris', 'verified']);
  const quick = await prepared(h, 'quick-add v1', {calendarId: 'primary', text: 'Lunch on 2026-11-02 at 12pm to 1pm', notify: 'none'});
  assert.deepEqual([urlOf(h, quick).searchParams.get('text'), h.prepared(quick).content.perform[0].body], ['Lunch on 2026-11-02 at 12pm to 1pm', null], 'the text in the query, and no body');
  const done = ended(await h.approve(quick), 'succeeded', null);
  assert.deepEqual([done.result.data.summary, done.result.data.start.dateTime, done.result.data.end.dateTime], ['Lunch', '2026-11-02T12:00:00-05:00', '2026-11-02T13:00:00-05:00']);
});

// ---- updating ----------------------------------------------------------------------------------------------------------------------------
test('Update sends only the fields given, shows the event as it is beside the change, and a swallowed PATCH ends unverified', async t => {
  const h = calendarHarness(t), event = seed(h, {...REVIEW, location: 'Room 1'});
  const title = await prepared(h, 'update-event v1', {calendarId: 'primary', eventId: event.id, summary: 'Review 2', notify: 'none'});
  assert.deepEqual(bodyOf(h, title), {summary: 'Review 2'});
  const time = await prepared(h, 'update-event v1', {calendarId: 'primary', eventId: event.id, newTime: {start: '2026-11-03T09:00:00', end: '2026-11-03T09:30:00'}, notify: 'none'});
  assert.deepEqual(bodyOf(h, time), {start: {dateTime: '2026-11-03T09:00:00-05:00', timeZone: ZONE}, end: {dateTime: '2026-11-03T09:30:00-05:00', timeZone: ZONE}});
  const fields = h.fields(time);
  assert.deepEqual([fields['Starts now'], fields['New start (local time)'], fields['New end (local time)'], fields['Time zone'], fields['New title']],
    ['2026-11-02T10:00:00-05:00', '2026-11-03T09:00:00', '2026-11-03T09:30:00', ZONE, undefined]);
  ended(await h.approve(title), 'succeeded', null);
  assert.deepEqual([stored(h, event.id).summary, stored(h, event.id).location], ['Review 2', 'Room 1'], 'only the title changed');
  h.simulator.swallow('PATCH /calendars/{calendarId}/events/{eventId}');
  const swallowed = await approved(h, 'update-event v1', {calendarId: 'primary', eventId: event.id, location: 'Room 2', notify: 'none'});
  ended(swallowed, 'uncertain', 'outcome_uncertain');
  assert.equal(swallowed.result.verification.status, 'unverified');
});

// ---- pages -----------------------------------------------------------------------------------------------------------------------------------
test('pages: Find events (25 a page) and List my calendars (50 a page) return nextPageToken and take it back; a page size is not an input', async t => {
  const h = calendarHarness(t);
  for (let index = 0; index < 30; index++) seed(h, {summary: `Slot ${index}`, ...TIMED(`2026-11-02T${String(8 + Math.floor(index / 4)).padStart(2, '0')}:${String((index % 4) * 15).padStart(2, '0')}:00-05:00`,
    `2026-11-02T${String(8 + Math.floor(index / 4)).padStart(2, '0')}:${String((index % 4) * 15 + 10).padStart(2, '0')}:00-05:00`)});
  const window = {calendarId: 'primary', from: '2026-11-02T00:00:00', to: '2026-11-03T00:00:00'};
  const first = ended(await h.run('find-events v1', window), 'succeeded', null);
  assert.deepEqual([first.result.data.events.length, typeof first.result.data.nextPageToken, h.simulator.calls.at(-1).query.maxResults], [25, 'string', '25']);
  const second = ended(await h.run('find-events v1', {...window, pageToken: first.result.data.nextPageToken}), 'succeeded', null);
  assert.deepEqual([second.result.data.events.length, second.result.data.nextPageToken], [5, undefined]);
  for (let index = 0; index < 55; index++) h.simulator.addCalendar({id: `c${index}@group.calendar.google.com`});
  const page = ended(await h.run('list-calendars v1', {}), 'succeeded', null);
  assert.deepEqual([page.result.data.calendars.length, h.simulator.calls.at(-1).query.maxResults, page.result.data.calendars[0]], [50, '50',
    {id: OWNER_EMAIL, summary: OWNER_EMAIL, primary: true, accessRole: 'owner', timeZone: ZONE}]);
  const rest = ended(await h.run('list-calendars v1', {pageToken: page.result.data.nextPageToken}), 'succeeded', null);
  assert.deepEqual([rest.result.data.calendars.length, rest.result.data.nextPageToken], [6, undefined]);
  const sent = h.simulator.calls.length;
  await assert.rejects(h.run('find-events v1', {...window, maxResults: 100}));
  await assert.rejects(h.run('list-calendars v1', {maxResults: 100}));
  assert.equal(h.simulator.calls.length, sent);
});

// ---- modes -----------------------------------------------------------------------------------------------------------------------------------
test('modes: reads run at Allow with no card; a write asks once under the defaults; with "Access events" at Ask it stops twice, reads then the final request', async t => {
  const h = calendarHarness(t), event = seed(h);
  ended(await h.run('get-event v1', {calendarId: 'primary', eventId: event.id}), 'succeeded', null);
  const once = await prepared(h, 'update-event v1', {calendarId: 'primary', eventId: event.id, summary: 'One stop', notify: 'none'});
  assert.deepEqual(once.action.modes, {prepare: 'allow', resolve: null, perform: 'ask'});
  h.setRow('google-calendar.events.read', 'ask');
  const reads = await h.run('update-event v1', {calendarId: 'primary', eventId: event.id, summary: 'Two stops', notify: 'none'});
  assert.deepEqual([reads.status, reads.action.phase], ['awaiting_approval', 'reads']);
  const final = await h.approve(reads);
  assert.deepEqual([final.status, final.action.phase, h.simulator.writes().length], ['awaiting_approval', 'final', 0]);
  ended(await h.approve(final), 'succeeded', null);
  assert.equal(stored(h, event.id).summary, 'Two stops');
});

// ---- secrets and evidence ----------------------------------------------------------------------------------------------------------------------
test('credentials never reach a job, a prepared request, a card, an audit row or an output; evidence and stores stay under the temp root', async t => {
  const shipped = new URL('../docs/live-evidence/google-calendar/actions.json', import.meta.url), before = readFileSync(shipped, 'utf8');
  const h = calendarHarness(t), event = seed(h, {...REVIEW, description: `Notes ${TOKEN} end`});
  const read = ended(await h.run('get-event v1', {calendarId: 'primary', eventId: event.id}), 'succeeded', null);
  const job = await prepared(h, 'update-event v1', {calendarId: 'primary', eventId: event.id, summary: 'Checked', notify: 'none'});
  const card = h.card(job), done = ended(await h.approve(job), 'succeeded', null);
  for (const [name, value] of [['jobs', h.store.list('jobs')], ['prepared', h.store.list(PREPARED)], ['card', card], ['audit', h.store.list('activity')], ['outputs', [read.result, done.result]]]) {
    assert.ok(!JSON.stringify(value).includes(TOKEN), name);
  }
  assert.equal(read.result.data.description, 'Notes [redacted] end', 'the token an answer echoes is scrubbed before anything reads it');
  assert.ok(existsSync(`${h.root}/docs/live-evidence/google-calendar/actions.json`));
  assert.equal(readFileSync(shipped, 'utf8'), before, 'the shipped evidence is never written by a test');
});

// ---- the F10.13 check: the card shows what is sent (docs/F10.13-BUILD-MAP.md section 12) -------------------------------------------------------
test('F10.13 check: Create event refuses an event given the other kind\'s times or missing its own (wrong_kind) before any request, so its card never shows a time it does not send', async t => {
  const h = calendarHarness(t), base = {calendarId: 'primary', summary: 'Plan', notify: 'none'};
  const timed = {...base, kind: 'timed', start: '2026-11-02T10:00:00', end: '2026-11-02T10:30:00'}, allDay = {...base, kind: 'all-day', date: '2026-12-25', days: 3};
  for (const input of [{...timed, date: allDay.date}, {...timed, days: 3}, {...timed, date: allDay.date, days: 3}, {...allDay, start: timed.start}, {...allDay, end: timed.end},
    {...allDay, start: timed.start, end: timed.end}, {...base, kind: 'timed', start: timed.start}, {...base, kind: 'all-day', date: allDay.date}]) {
    const job = refusedAs(await h.run('create-event v1', input), 'wrong_kind');
    assert.deepEqual([job.details.transform, job.details.transformReason], ['collections.oneOf@1', 'not_one_of'], JSON.stringify(input));
  }
  assert.deepEqual(h.simulator.calls, [], 'refused before any request, the zone read included');
  // Each kind alone builds its card: a timed event's lines or an all-day event's, never both.
  const one = h.fields(await prepared(h, 'create-event v1', timed)), two = h.fields(await prepared(h, 'create-event v1', allDay));
  assert.deepEqual([Object.keys(one).filter(label => ['All day from', 'Days'].includes(label)), Object.keys(two).filter(label => label.startsWith('Starts') || label.startsWith('Ends'))], [[], []]);
});

test('F10.13 check: every card shows what its request sends and the event as it is now: times with the zone, the guests, who Google emails', async t => {
  const h = calendarHarness(t), team = h.simulator.addCalendar({id: 'team@group.calendar.google.com', accessRole: 'owner'});
  const card = async (key, input) => h.fields(await prepared(h, key, input));
  // Create event: a timed event's lines, the exact instants in the card's body block; an all-day event's first day and day count.
  const timed = await prepared(h, 'create-event v1', {calendarId: 'primary', kind: 'timed', summary: 'Plan', start: '2026-11-02T10:00:00', end: '2026-11-02T10:30:00',
    recurrence: 'RRULE:FREQ=WEEKLY;COUNT=3', guests: ['ann@example.com', 'bob@example.com'], meet: true, notify: 'externalOnly'});
  assert.deepEqual(h.fields(timed), {Calendar: 'primary', Event: 'Plan', 'Starts (local time)': '2026-11-02T10:00:00', 'Ends (local time)': '2026-11-02T10:30:00', 'Time zone': ZONE,
    Repeats: 'RRULE:FREQ=WEEKLY;COUNT=3', Guests: 'ann@example.com\nbob@example.com', 'Emails Google sends': 'externalOnly'});
  const shown = JSON.parse(h.card(timed).exact.blocks.find(block => block.label === 'create: Body').text);
  assert.deepEqual([shown.start, shown.end, shown.attendees], [{dateTime: '2026-11-02T10:00:00-05:00', timeZone: ZONE}, {dateTime: '2026-11-02T10:30:00-05:00', timeZone: ZONE},
    [{email: 'ann@example.com'}, {email: 'bob@example.com'}]]);
  assert.deepEqual(await card('create-event v1', {calendarId: team.id, kind: 'all-day', summary: 'Away', date: '2026-11-02', days: 2, notify: 'none'}),
    {Calendar: team.id, Event: 'Away', 'Time zone': ZONE, 'All day from': '2026-11-02', Days: 2, Guests: '', 'Emails Google sends': 'none'});
  assert.deepEqual(await card('quick-add v1', {calendarId: 'primary', text: 'Lunch on 2026-11-02 at 12pm to 1pm', notify: 'all'}),
    {Calendar: 'primary', Text: 'Lunch on 2026-11-02 at 12pm to 1pm', Times: 'Google reads the date and time from the text, in your calendar\'s time zone.', 'Emails Google sends': 'all'});
  // A write on an event shows it as read: its title, its start (an all-day event's day) and its guests.
  const away = h.simulator.seed('primary', {summary: 'Away', start: {date: '2026-11-02'}, end: {date: '2026-11-03'}});
  assert.deepEqual(await card('update-event v1', {calendarId: 'primary', eventId: away.id, summary: 'Away 2', notify: 'none'}),
    {Calendar: 'primary', Event: 'Away', 'Event id': away.id, 'Starts now (all day)': '2026-11-02', 'Guests now': '', 'New title': 'Away 2', 'Time zone': ZONE, 'Emails Google sends': 'none'});
  const invitation = h.simulator.invite({...REVIEW, organizer: 'org@other.example', attendees: [{email: 'dan@example.com', responseStatus: 'declined'}]});
  assert.deepEqual(await card('respond-event v1', {calendarId: 'primary', eventId: invitation.id, response: 'declined', notify: 'none'}),
    {Calendar: 'primary', Event: 'Review', 'Event id': invitation.id, 'Starts now': '2026-11-02T10:00:00-05:00', 'Guests now': `org@other.example\ndan@example.com\n${OWNER_EMAIL}`,
      Organizer: 'org@other.example', 'Your answer': 'declined', 'Emails Google sends': 'none'});
  const event = seed(h, {...REVIEW, attendees: [{email: 'ann@example.com', responseStatus: 'accepted'}, {email: 'bob@example.com'}]});
  assert.deepEqual(await card('delete-event v1', {calendarId: 'primary', eventId: event.id, notify: 'all'}),
    {Calendar: 'primary', Event: 'Review', 'Event id': event.id, 'Starts now': '2026-11-02T10:00:00-05:00', 'Guests now': 'ann@example.com\nbob@example.com', Organizer: OWNER_EMAIL,
      'If you are a guest': 'Deleting an invitation removes it from your calendar only. To tell the organizer, use Respond to an invitation with declined.', 'Emails Google sends': 'all'});
  assert.deepEqual(await card('move-event v1', {calendarId: 'primary', eventId: event.id, destination: team.id, notify: 'none'}),
    {Calendar: 'primary', Event: 'Review', 'Event id': event.id, 'Starts now': '2026-11-02T10:00:00-05:00', 'Guests now': 'ann@example.com\nbob@example.com', 'Move to': team.id,
      'Emails Google sends': 'none'});
  assert.deepEqual(await card('create-calendar v1', {summary: 'Team', description: 'Plans', timeZone: 'Europe/Paris'}), {Name: 'Team', Description: 'Plans', 'Time zone': 'Europe/Paris'});
  // A read that asks shows its window as exact instants with the zone.
  h.setRow('google-calendar.events.read', 'ask');
  h.setRow('google-calendar.availability.read', 'ask');
  const find = await h.run('find-events v1', {calendarId: 'primary', from: '2026-10-31T00:00:00', to: '2026-11-02T00:00:00', q: 'Review'});
  assert.deepEqual([find.status, h.fields(find)], ['awaiting_approval', {Calendar: 'primary', From: '2026-10-31T00:00:00-04:00 (America/Toronto)', To: '2026-11-02T00:00:00-05:00 (America/Toronto)', Search: 'Review'}]);
  const free = await h.run('find-free-time v1', {from: '2026-11-01T00:00:00', to: '2026-11-01T12:00:00', calendars: ['primary', team.id], minMinutes: 30});
  assert.deepEqual([free.status, h.fields(free)], ['awaiting_approval', {From: '2026-11-01T00:00:00-04:00 (America/Toronto)', To: '2026-11-01T12:00:00-05:00 (America/Toronto)',
    Calendars: `primary\n${team.id}`, 'Shortest block (minutes)': 30}]);
  assert.deepEqual(writes(h), [], 'nothing sent before an approval');
});

test('F10.13 check: without the settings scope every write reads the zone from the primary calendar\'s entry, on its card and in its body', async t => {
  const h = calendarHarness(t, {zone: 'Europe/Paris', scopes: SIX.filter(scope => !scope.endsWith('settings.readonly'))});
  const create = await prepared(h, 'create-event v1', {calendarId: 'primary', kind: 'timed', summary: 'Plan', start: '2026-11-02T10:00:00', end: '2026-11-02T10:30:00', notify: 'none'});
  assert.deepEqual([bodyOf(h, create).start, bodyOf(h, create).end, h.fields(create)['Time zone']],
    [{dateTime: '2026-11-02T10:00:00+01:00', timeZone: 'Europe/Paris'}, {dateTime: '2026-11-02T10:30:00+01:00', timeZone: 'Europe/Paris'}, 'Europe/Paris']);
  const event = seed(h);
  const update = await prepared(h, 'update-event v1', {calendarId: 'primary', eventId: event.id, newTime: {start: '2026-11-03T09:00:00', end: '2026-11-03T09:30:00'}, notify: 'none'});
  assert.deepEqual([bodyOf(h, update).start, bodyOf(h, update).end, h.fields(update)['Time zone']],
    [{dateTime: '2026-11-03T09:00:00+01:00', timeZone: 'Europe/Paris'}, {dateTime: '2026-11-03T09:30:00+01:00', timeZone: 'Europe/Paris'}, 'Europe/Paris']);
  assert.ok(!calls(h).includes('GET /users/me/settings/timezone'), 'the settings step never runs without its scope');
  ended(await h.approve(create), 'succeeded', null);
  ended(await h.approve(update), 'succeeded', null);
});

// ---- the simulator case list (check 5)---------------------------------------------------------------------------------------------------------
const MANIFEST = JSON.parse(readFileSync(new URL('./fixtures/provider-simulators/google-calendar.cases.json', import.meta.url), 'utf8'));
const ENTRIES = validateActionFile(currentFile(), calendarDeps()).actions;
const GOOGLE_ERROR = (code, reason) => ({status: code, data: {error: {code, message: reason, errors: [{domain: 'global', reason, message: reason}]}}});
const CREATE = {calendarId: 'primary', kind: 'timed', summary: 'Plan', start: '2026-11-02T10:00:00', end: '2026-11-02T10:30:00', notify: 'none'};
const WINDOW = {calendarId: 'primary', from: '2026-11-02T00:00:00', to: '2026-11-03T00:00:00'};
const FREE = {from: '2026-11-02T08:00:00', to: '2026-11-02T12:00:00', calendars: ['primary'], minMinutes: 30};
/** A write's case: run it to its card and approve it, or expect a refusal before any write. */
const lost = async (h, route, key, input) => { h.simulator.drop(route); const job = ended(await approved(h, key, input), 'uncertain', 'outcome_uncertain'); return job; };
const swallowed = async (h, route, key, input) => { h.simulator.swallow(route); const job = ended(await approved(h, key, input), 'uncertain', 'outcome_uncertain'); assert.equal(job.result.verification.status, 'unverified'); return job; };
const refusedNever = async (h, row, key, input) => {
  h.setRow(row, 'deny');
  await assert.rejects(h.run(key, input), error => error.code === 'permission_denied' || /Never/.test(error.message));
  assert.equal(h.simulator.calls.length, 0);
};
const invitation = h => h.simulator.invite({...REVIEW, organizer: 'org@other.example', attendees: ['dan@example.com']});
const ROUTES = {insert: 'POST /calendars/{calendarId}/events', quickAdd: 'POST /calendars/{calendarId}/events/quickAdd', patch: 'PATCH /calendars/{calendarId}/events/{eventId}',
  delete: 'DELETE /calendars/{calendarId}/events/{eventId}', move: 'POST /calendars/{calendarId}/events/{eventId}/move', calendars: 'POST /calendars', unshare: 'DELETE /calendars/{calendarId}/acl/{ruleId}'};
const team = h => h.simulator.addCalendar({id: 'team@group.calendar.google.com', accessRole: 'owner'});
const IMPLEMENTATIONS = {
  'find-events v1/succeeds': async t => { const h = calendarHarness(t); seed(h); assert.equal(ended(await h.run('find-events v1', WINDOW), 'succeeded', null).result.data.events[0].summary, 'Review'); },
  'find-events v1/refused': async t => {
    const h = calendarHarness(t);
    refusedAs(await h.run('find-events v1', {...WINDOW, from: '2026-03-08T02:30:00'}), 'time_nonexistent');
    assert.ok(!calls(h).some(route => route.startsWith('GET /calendars/')));
  },
  'find-events v1/provider-refusal': async t => { const h = calendarHarness(t); h.simulator.fail(EVENTS, GOOGLE_ERROR(404, 'notFound')); ended(await h.run('find-events v1', WINDOW), 'failed', 'provider_failed', {providerStatus: 404}); },
  'get-event v1/succeeds': async t => { const h = calendarHarness(t), event = seed(h); assert.equal(ended(await h.run('get-event v1', {calendarId: 'primary', eventId: event.id}), 'succeeded', null).result.data.etag, event.etag); },
  'get-event v1/refused': async t => refusedNever(calendarHarness(t), 'google-calendar.events.read', 'get-event v1', {calendarId: 'primary', eventId: 'any'}),
  'get-event v1/provider-refusal': async t => { const h = calendarHarness(t); ended(await h.run('get-event v1', {calendarId: 'primary', eventId: 'missing'}), 'failed', 'provider_failed', {providerStatus: 404}); },
  'list-calendars v1/succeeds': async t => { const h = calendarHarness(t); assert.equal(ended(await h.run('list-calendars v1', {}), 'succeeded', null).result.data.calendars[0].id, OWNER_EMAIL); },
  'list-calendars v1/refused': async t => refusedNever(calendarHarness(t), 'google-calendar.calendars.read', 'list-calendars v1', {}),
  'list-calendars v1/provider-refusal': async t => { const h = calendarHarness(t); h.simulator.fail('GET /users/me/calendarList', GOOGLE_ERROR(403, 'forbidden')); ended(await h.run('list-calendars v1', {}), 'failed', 'provider_failed', {providerStatus: 403}); },
  'find-free-time v1/succeeds': async t => { const h = calendarHarness(t); seed(h); assert.equal(ended(await h.run('find-free-time v1', FREE), 'succeeded', null).result.data.free.length, 2); },
  'find-free-time v1/refused': async t => refusedAs(await calendarHarness(t).run('find-free-time v1', {...FREE, calendars: ['gone@group.calendar.google.com']}), 'busy_unknown'),
  'find-free-time v1/provider-refusal': async t => { const h = calendarHarness(t); h.simulator.fail('POST /freeBusy', GOOGLE_ERROR(400, 'badRequest')); ended(await h.run('find-free-time v1', FREE), 'failed', 'provider_failed', {providerStatus: 400}); },
  'create-event v1/succeeds': async t => { const h = calendarHarness(t); const job = ended(await approved(h, 'create-event v1', CREATE), 'succeeded', null); assert.equal(job.result.verification.status, 'verified'); },
  'create-event v1/refused': async t => { const h = calendarHarness(t); refusedAs(await h.run('create-event v1', {...CREATE, recurrence: 'RRULE:FREQ=FORTNIGHTLY'}), 'time_invalid'); assert.deepEqual(writes(h), []); },
  'create-event v1/provider-refusal': async t => {
    const h = calendarHarness(t);
    h.simulator.fail(ROUTES.insert, GOOGLE_ERROR(403, 'requiredAccessLevel'));
    ended(await approved(h, 'create-event v1', CREATE), 'failed', 'provider_failed', {providerStatus: 403});
    assert.deepEqual(h.simulator.state().events, {});
  },
  'create-event v1/unverified': async t => swallowed(calendarHarness(t), ROUTES.insert, 'create-event v1', CREATE),
  'create-event v1/lost-answer': async t => { const h = calendarHarness(t); await lost(h, ROUTES.insert, 'create-event v1', CREATE); assert.equal(Object.keys(h.simulator.state().events).length, 1, 'applied'); },
  'quick-add v1/succeeds': async t => { const h = calendarHarness(t); ended(await approved(h, 'quick-add v1', {calendarId: 'primary', text: 'Plan on 2026-11-02 at 9am to 10am', notify: 'none'}), 'succeeded', null); },
  'quick-add v1/refused': async t => refusedNever(calendarHarness(t), 'google-calendar.events.write', 'quick-add v1', {calendarId: 'primary', text: 'Plan', notify: 'none'}),
  'quick-add v1/provider-refusal': async t => { const h = calendarHarness(t); h.simulator.fail(ROUTES.quickAdd, GOOGLE_ERROR(400, 'invalid')); ended(await approved(h, 'quick-add v1', {calendarId: 'primary', text: 'Plan', notify: 'none'}), 'failed', 'provider_failed', {providerStatus: 400}); },
  'quick-add v1/unverified': async t => swallowed(calendarHarness(t), ROUTES.quickAdd, 'quick-add v1', {calendarId: 'primary', text: 'Plan', notify: 'none'}),
  'quick-add v1/lost-answer': async t => lost(calendarHarness(t), ROUTES.quickAdd, 'quick-add v1', {calendarId: 'primary', text: 'Plan', notify: 'none'}),
  'update-event v1/succeeds': async t => { const h = calendarHarness(t), event = seed(h); const job = ended(await approved(h, 'update-event v1', {calendarId: 'primary', eventId: event.id, summary: 'New', notify: 'none'}), 'succeeded', null); assert.equal(job.result.data.etag, stored(h, event.id).etag); },
  'update-event v1/refused': async t => {
    const h = calendarHarness(t), event = seed(h);
    refusedAs(await h.run('update-event v1', {calendarId: 'primary', eventId: event.id, newTime: {start: '2026-03-08T02:00:00', end: '2026-03-08T04:00:00'}, notify: 'none'}), 'time_nonexistent');
    assert.deepEqual(writes(h), []);
  },
  'update-event v1/provider-refusal': async t => {
    const h = calendarHarness(t), event = seed(h), job = await prepared(h, 'update-event v1', {calendarId: 'primary', eventId: event.id, summary: 'New', notify: 'none'});
    h.simulator.touch('primary', event.id);
    ended(await h.approve(job), 'failed', 'provider_failed', {providerStatus: 412, reason: 'content_changed'});
  },
  'update-event v1/unverified': async t => { const h = calendarHarness(t), event = seed(h); await swallowed(h, ROUTES.patch, 'update-event v1', {calendarId: 'primary', eventId: event.id, summary: 'New', notify: 'none'}); },
  'update-event v1/lost-answer': async t => { const h = calendarHarness(t), event = seed(h); await lost(h, ROUTES.patch, 'update-event v1', {calendarId: 'primary', eventId: event.id, summary: 'New', notify: 'none'}); assert.equal(stored(h, event.id).summary, 'New'); },
  'update-guests v1/succeeds': async t => { const h = calendarHarness(t), event = seed(h); ended(await approved(h, 'update-guests v1', {calendarId: 'primary', eventId: event.id, add: ['ann@example.com'], remove: [], notify: 'none'}), 'succeeded', null); },
  'update-guests v1/refused': async t => { const h = calendarHarness(t), event = seed(h); refusedAs(await h.run('update-guests v1', {calendarId: 'primary', eventId: event.id, add: [], remove: [OWNER_EMAIL], notify: 'none'}), 'attendee_protected'); assert.deepEqual(writes(h), []); },
  'update-guests v1/provider-refusal': async t => {
    const h = calendarHarness(t), event = seed(h), job = await prepared(h, 'update-guests v1', {calendarId: 'primary', eventId: event.id, add: ['ann@example.com'], remove: [], notify: 'none'});
    h.simulator.touch('primary', event.id);
    ended(await h.approve(job), 'failed', 'provider_failed', {providerStatus: 412, reason: 'content_changed'});
  },
  'update-guests v1/unverified': async t => { const h = calendarHarness(t), event = seed(h); await swallowed(h, ROUTES.patch, 'update-guests v1', {calendarId: 'primary', eventId: event.id, add: ['ann@example.com'], remove: [], notify: 'none'}); },
  'update-guests v1/lost-answer': async t => { const h = calendarHarness(t), event = seed(h); await lost(h, ROUTES.patch, 'update-guests v1', {calendarId: 'primary', eventId: event.id, add: ['ann@example.com'], remove: [], notify: 'none'}); },
  'respond-event v1/succeeds': async t => {
    const h = calendarHarness(t), event = invitation(h);
    const job = ended(await approved(h, 'respond-event v1', {calendarId: 'primary', eventId: event.id, response: 'tentative', notify: 'none'}), 'succeeded', null);
    assert.deepEqual([job.result.data.response, job.result.verification.status], ['tentative', 'verified']);
  },
  'respond-event v1/refused': async t => { const h = calendarHarness(t), event = seed(h); refusedAs(await h.run('respond-event v1', {calendarId: 'primary', eventId: event.id, response: 'accepted', notify: 'none'}), 'match_none'); },
  'respond-event v1/provider-refusal': async t => {
    const h = calendarHarness(t), event = invitation(h), job = await prepared(h, 'respond-event v1', {calendarId: 'primary', eventId: event.id, response: 'accepted', notify: 'none'});
    h.simulator.touch('primary', event.id);
    ended(await h.approve(job), 'failed', 'provider_failed', {providerStatus: 412, reason: 'content_changed'});
  },
  'respond-event v1/unverified': async t => { const h = calendarHarness(t), event = invitation(h); await swallowed(h, ROUTES.patch, 'respond-event v1', {calendarId: 'primary', eventId: event.id, response: 'accepted', notify: 'none'}); },
  'respond-event v1/lost-answer': async t => { const h = calendarHarness(t), event = invitation(h); await lost(h, ROUTES.patch, 'respond-event v1', {calendarId: 'primary', eventId: event.id, response: 'accepted', notify: 'none'}); },
  'delete-event v1/succeeds': async t => { const h = calendarHarness(t), event = seed(h); ended(await approved(h, 'delete-event v1', {calendarId: 'primary', eventId: event.id, notify: 'none'}), 'succeeded', null); },
  'delete-event v1/refused': async t => refusedNever(calendarHarness(t), 'google-calendar.events.delete', 'delete-event v1', {calendarId: 'primary', eventId: 'any', notify: 'none'}),
  'delete-event v1/provider-refusal': async t => {
    const h = calendarHarness(t), event = seed(h);
    h.simulator.fail(ROUTES.delete, GOOGLE_ERROR(403, 'forbidden'));
    ended(await approved(h, 'delete-event v1', {calendarId: 'primary', eventId: event.id, notify: 'none'}), 'failed', 'provider_failed', {providerStatus: 403});
    assert.equal(stored(h, event.id).status, 'confirmed');
  },
  'delete-event v1/unverified': async t => { const h = calendarHarness(t), event = seed(h); await swallowed(h, ROUTES.delete, 'delete-event v1', {calendarId: 'primary', eventId: event.id, notify: 'none'}); },
  'delete-event v1/lost-answer': async t => { const h = calendarHarness(t), event = seed(h); await lost(h, ROUTES.delete, 'delete-event v1', {calendarId: 'primary', eventId: event.id, notify: 'none'}); assert.equal(stored(h, event.id).status, 'cancelled'); },
  'move-event v1/succeeds': async t => { const h = calendarHarness(t), event = seed(h), other = team(h); ended(await approved(h, 'move-event v1', {calendarId: 'primary', eventId: event.id, destination: other.id, notify: 'none'}), 'succeeded', null); },
  'move-event v1/refused': async t => {
    const h = calendarHarness(t), event = seed(h, REVIEW, {eventType: 'outOfOffice'}), other = team(h);
    refusedAs(await h.run('move-event v1', {calendarId: 'primary', eventId: event.id, destination: other.id, notify: 'none'}), 'wrong_kind');
  },
  'move-event v1/provider-refusal': async t => {
    const h = calendarHarness(t), event = seed(h), other = h.simulator.addCalendar({id: 'read-only@group.calendar.google.com', accessRole: 'reader'});
    ended(await approved(h, 'move-event v1', {calendarId: 'primary', eventId: event.id, destination: other.id, notify: 'none'}), 'failed', 'provider_failed', {providerStatus: 403});
    assert.equal(stored(h, event.id).calendarId, OWNER_EMAIL);
  },
  'move-event v1/unverified': async t => { const h = calendarHarness(t), event = seed(h), other = team(h); await swallowed(h, ROUTES.move, 'move-event v1', {calendarId: 'primary', eventId: event.id, destination: other.id, notify: 'none'}); },
  'move-event v1/lost-answer': async t => { const h = calendarHarness(t), event = seed(h), other = team(h); await lost(h, ROUTES.move, 'move-event v1', {calendarId: 'primary', eventId: event.id, destination: other.id, notify: 'none'}); },
  'create-calendar v1/succeeds': async t => { const h = calendarHarness(t); assert.equal(ended(await approved(h, 'create-calendar v1', {summary: 'Team'}), 'succeeded', null).result.data.timeZone, ZONE); },
  'create-calendar v1/refused': async t => { const h = calendarHarness(t); refusedAs(await h.run('create-calendar v1', {summary: 'Team', timeZone: '+05:30'}), 'zone_invalid'); assert.equal(h.simulator.calls.length, 0); },
  'create-calendar v1/provider-refusal': async t => { const h = calendarHarness(t); h.simulator.fail(ROUTES.calendars, GOOGLE_ERROR(403, 'quotaExceeded')); ended(await approved(h, 'create-calendar v1', {summary: 'Team'}), 'failed', 'provider_failed', {providerStatus: 403}); },
  'create-calendar v1/unverified': async t => swallowed(calendarHarness(t), ROUTES.calendars, 'create-calendar v1', {summary: 'Team'}),
  'create-calendar v1/lost-answer': async t => lost(calendarHarness(t), ROUTES.calendars, 'create-calendar v1', {summary: 'Team'}),
  'stop-sharing v1/succeeds': async t => { const h = calendarHarness(t); h.simulator.share('primary', 'fabric-share@example.com'); ended(await approved(h, 'stop-sharing v1', {calendarId: 'primary', ruleId: 'user:fabric-share@example.com'}), 'succeeded', null); },
  'stop-sharing v1/refused': async t => { const h = calendarHarness(t); refusedAs(await h.run('stop-sharing v1', {calendarId: 'primary', ruleId: `user:${OWNER_EMAIL}`}), 'wrong_kind'); assert.deepEqual(writes(h), []); },
  'stop-sharing v1/provider-refusal': async t => {
    const h = calendarHarness(t);
    h.simulator.share('primary', 'fabric-share@example.com');
    h.simulator.fail(ROUTES.unshare, GOOGLE_ERROR(403, 'forbidden'));
    ended(await approved(h, 'stop-sharing v1', {calendarId: 'primary', ruleId: 'user:fabric-share@example.com'}), 'failed', 'provider_failed', {providerStatus: 403});
  },
  'stop-sharing v1/unverified': async t => { const h = calendarHarness(t); h.simulator.share('primary', 'fabric-share@example.com'); await swallowed(h, ROUTES.unshare, 'stop-sharing v1', {calendarId: 'primary', ruleId: 'user:fabric-share@example.com'}); },
  'stop-sharing v1/lost-answer': async t => { const h = calendarHarness(t); h.simulator.share('primary', 'fabric-share@example.com'); await lost(h, ROUTES.unshare, 'stop-sharing v1', {calendarId: 'primary', ruleId: 'user:fabric-share@example.com'}); },
};
caseTests(test, MANIFEST, ENTRIES, IMPLEMENTATIONS);

// ---- the live plan (step 14's C0 to C13) ---------------------------------------------------------------------------------------------------------
const PLAN = () => JSON.parse(readFileSync(new URL('../catalog/live-tests/google-calendar.json', import.meta.url), 'utf8'));
const planDeps = () => ({entries: ENTRIES, superseded: [], groups: PERMISSION_GROUPS.get('google-calendar'), config: PROXY_CONFIGS.get('google-calendar'), rules: RULES});

test('the live plan C0 to C13 passes step 12\'s plan check against the shipped file, calls all 13 actions, and keeps C4, C6, C10 and C13 as planned', () => {
  const checked = checkPlan(PLAN(), planDeps());
  assert.deepEqual(checked.plan.tests.map(item => item.id), ['C0', 'C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7', 'C8', 'C9', 'C10', 'C11', 'C12', 'C13']);
  assert.deepEqual([...checked.actions.keys()].sort(), ENTRIES.map(entry => `${entry.key}@${entry.version}`).sort());
  const steps = id => checked.plan.tests.find(item => item.id === id).steps;
  assert.deepEqual(Object.keys(steps('C6')[0]), ['race']);
  assert.equal(steps('C6')[0].race.status, 412);
  assert.equal(steps('C4')[1].call.args.recurrence, 'RRULE:FREQ=DAILY;COUNT=3');
  assert.deepEqual(steps('C13')[0].oneTimeAsk.row, 'google-calendar.permanent.delete');
  assert.ok(steps('C10').some(step => step.call?.action === 'stop-sharing@1'));
  assert.deepEqual([checked.plan.timeZone, checked.plan.gone, checked.plan.readRows], [{path: '/users/me/settings/timezone', pointer: '/value'}, {pointer: '/status', equals: 'cancelled'},
    ['google-calendar.events.read', 'google-calendar.calendars.read', 'google-calendar.settings.read']]);
  // Each write test has its undo; every notify the plan gives is none.
  const calls = checked.plan.tests.flatMap(item => [...item.steps, ...(item.undo?.steps ?? [])]).map(step => step.call ?? step.race).filter(Boolean);
  assert.ok(calls.filter(call => Object.hasOwn(call.args ?? {}, 'notify')).every(call => call.args.notify === 'none'));
});

test('every create-event and update-event call of the plan, its placeholders filled for a run, builds a body the simulator accepts', async t => {
  const h = calendarHarness(t), a = h.simulator.addCalendar({id: 'run-a@group.calendar.google.com', accessRole: 'owner'}), b = h.simulator.addCalendar({id: 'run-b@group.calendar.google.com', accessRole: 'owner'});
  const run = {runId: 'ABCDEFGH', runDate: '2026-10-23', timeZone: ZONE, recorded: {c9Event: 'c9'}, saved: {calendarA: a.id, calendarB: b.id}};
  const event = h.simulator.seed(a.id, {summary: '[SYNTHETIC] Fabric C2 ABCDEFGH event', ...TIMED('2026-11-01T10:00:00-05:00', '2026-11-01T10:30:00-05:00')});
  run.saved.event = event.id;
  let count = 0;
  for (const item of PLAN().tests) {
    for (const step of [...item.steps, ...(item.undo?.steps ?? [])]) {
      const call = step.call ?? step.race;
      if (!call || !['create-event@1', 'update-event@1'].includes(call.action)) continue;
      const args = fillPlaceholders(call.args, {run, account: {email: OWNER_EMAIL}}, item);
      const done = await approved(h, `${call.action.replace('@', ' v')}`, args);
      ended(done, 'succeeded', null);
      count++;
    }
  }
  assert.equal(count, 6, 'C2, C3, C4 twice, C6 and its undo');
});

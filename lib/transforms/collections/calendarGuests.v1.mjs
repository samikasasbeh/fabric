// Iteration 9 step 8 (docs/I07-BUILD-MAP.md section 2.7): collections.calendarGuests@1, the items of "A guest answered your invitation". The feed gives one item per event, with its
// guests inside it, and a trigger reads one item per guest, so this turns one page into rows. A generic flatten cannot exist: a transform must declare a closed output.
// Step data: `list`, one page of events.list, the page's items. Out: {responses}, at most 1,000, each {eventId, email, responseStatus, etag, summary?, updated?, start?}.
// - Only the organizer's copy counts, the one with organizer.self: a guest may not see the others, and past 200 guests answers do not reach them. A cancelled event gives none.
// - The calendar's own entry, marked self, the organizer, marked organizer, and a guest at needsAction give none: a guest added has not answered.
// - An entry it cannot name is skipped, since one odd item must not hold a feed. An optional field that does not fit is left out, and a long title is cut, so a row stays bounded.
// - Past 1,000 rows it refuses with too_many_items, and never cuts a page in silence. That refusal belongs to this lens: only a watch on guests pauses.
import {TransformError} from '../_shared/error.v1.mjs';

const MAX_ROWS = 1000, MAX_ID = 1024, MAX_EMAIL = 320, MAX_STATUS = 16, MAX_ETAG = 256, MAX_TITLE = 1000, MAX_TIME = 40;
const SIZES = {eventId: MAX_ID, email: MAX_EMAIL, responseStatus: MAX_STATUS, etag: MAX_ETAG, summary: MAX_TITLE, updated: MAX_TIME, start: MAX_TIME};
const text = most => ({type: 'string', minLength: 1, maxLength: most});
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const fits = (value, most) => typeof value === 'string' && value.length > 0 && value.length <= most;
const refuse = code => { throw new TransformError(code); };
/** The fields a row takes from its event, leaving out any that do not fit. */
function eventFields(event) {
  const fields = {etag: event.etag}, start = record(event.start) ? event.start.dateTime ?? event.start.date : undefined;
  if (typeof event.summary === 'string' && event.summary) fields.summary = [...event.summary].slice(0, MAX_TITLE).join('');
  if (fits(event.updated, MAX_TIME)) fields.updated = event.updated;
  if (fits(start, MAX_TIME)) fields.start = start;
  return fields;
}

export const ENTRY = {name: 'collections.calendarGuests', version: 1, kind: 'map',
  input: {type: 'object', properties: {}, additionalProperties: false},
  pointerArgs: [], stepData: {list: {maxBytes: 2_097_152}}, resolvedValues: {},
  output: {type: 'object', properties: {responses: {type: 'array', maxItems: MAX_ROWS, items: {type: 'object', properties: Object.fromEntries(Object.entries(SIZES).map(([name, most]) => [name, text(most)])),
    required: ['eventId', 'email', 'responseStatus', 'etag'], additionalProperties: false}}}, required: ['responses'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 2_097_152, usesClock: false, runtimeFacts: [], refuses: ['too_many_items'], excludes: [],
  example: {input: {list: [{id: 'e1', etag: '"1"', organizer: {self: true}, attendees: [{email: 'a@example.com', responseStatus: 'accepted'}, {email: 'b@example.com', responseStatus: 'needsAction'}]}]},
    output: {responses: [{eventId: 'e1', email: 'a@example.com', responseStatus: 'accepted', etag: '"1"'}]}},
  run(input) {
    if (!Array.isArray(input.list)) refuse('input_invalid');
    const responses = [];
    for (const event of input.list) {
      if (!record(event) || event.status === 'cancelled' || !record(event.organizer) || event.organizer.self !== true) continue;
      if (!fits(event.id, MAX_ID) || !fits(event.etag, MAX_ETAG) || !Array.isArray(event.attendees)) continue;
      const fields = eventFields(event);
      for (const guest of event.attendees) {
        if (!record(guest) || guest.self === true || guest.organizer === true || guest.responseStatus === 'needsAction') continue;
        if (!fits(guest.email, MAX_EMAIL) || !fits(guest.responseStatus, MAX_STATUS)) continue;
        if (responses.length === MAX_ROWS) refuse('too_many_items');
        responses.push({eventId: event.id, email: guest.email, responseStatus: guest.responseStatus, ...fields});
      }
    }
    return {responses};
  }};

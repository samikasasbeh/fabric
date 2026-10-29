// F10.8 part j (docs/F10.8-BUILD-MAP.md): collections.mergeEmails@1, the guest list Invite or remove guests sends whole (spec lines 996,
// 1276). Step data: `event`, the event the prepare read returned, at most 2 MiB; its `attendees` (absent when there are none) and its
// `organizer`. Taking the whole event, never a list an action builds, means each kept attendee is the one Calendar returned (open point
// Minor 14). Closed: `add` and `remove` (at most 100 addresses each) and `owner`, the account's address. Out: {attendees, added, removed}.
// - Addresses compare with ASCII case folding. A guest already there is not added again; a guest who is not there is not removed. One
//   address in both lists, or one that is not a plain ASCII address, refuses with input_invalid.
// - Each kept attendee is kept whole and in place: responseStatus, organizer, self, optional, comment and the rest. New guests follow, as
//   {email}, in the order given.
// - Removing the organizer (an attendee marked organizer, or the event's /organizer/email) or the owner (an attendee marked self, or the
//   owner's address) refuses with attendee_protected, whether or not they are listed.
// - The output schema lists every attendee field of Calendar's Discovery document. A field Google adds later refuses with output_invalid,
//   never dropped in silence.
// - added and removed are for the card; they reach a preview through text.joinList@1 (open point Important 4).
// - More than 1,000 attendees, before or after the merge, refuse with too_many_items.
import {TransformError} from '../_shared/error.v1.mjs';
import {foldAscii} from '../_shared/ascii.v1.mjs';

const MAX_ATTENDEES = 1000;
const ADDRESS = {type: 'string', minLength: 3, maxLength: 254};
const TEXT = {type: 'string', maxLength: 10_000};
// Calendar's Discovery document, the EventAttendee schema.
const ATTENDEE = {type: 'object', properties: {additionalGuests: {type: 'integer', minimum: 0, maximum: 1_000_000}, comment: TEXT, displayName: TEXT,
  email: {type: 'string', maxLength: 1000}, id: {type: 'string', maxLength: 1000}, optional: {type: 'boolean'}, organizer: {type: 'boolean'}, resource: {type: 'boolean'},
  responseStatus: {type: 'string', maxLength: 64}, self: {type: 'boolean'}}, additionalProperties: false};
const PLAIN = /^[\x21-\x7e]+$/;
const SPECIAL = /["(),:;<>[\\\]]/;
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const refuse = code => { throw new TransformError(code); };

/** True for a plain ASCII address: printable, no space, no specials, one @ with text on each side. */
function plainAddress(text) {
  const at = text.indexOf('@');
  return PLAIN.test(text) && !SPECIAL.test(text) && at > 0 && at === text.lastIndexOf('@') && at < text.length - 1;
}
/** The folded addresses of a list, each once; it refuses one that is no plain address. */
function folded(list) {
  if (!list.every(plainAddress)) refuse('input_invalid');
  return new Set(list.map(foldAscii));
}

export const ENTRY = {name: 'collections.mergeEmails', version: 1, kind: 'map',
  input: {type: 'object', properties: {add: {type: 'array', maxItems: 100, items: ADDRESS}, remove: {type: 'array', maxItems: 100, items: ADDRESS}, owner: ADDRESS},
    required: ['add', 'remove', 'owner'], additionalProperties: false},
  pointerArgs: [], stepData: {event: {maxBytes: 2_097_152}}, resolvedValues: {},
  output: {type: 'object', properties: {attendees: {type: 'array', maxItems: MAX_ATTENDEES, items: ATTENDEE}, added: {type: 'array', maxItems: 100, items: ADDRESS},
    removed: {type: 'array', maxItems: 100, items: ADDRESS}}, required: ['attendees', 'added', 'removed'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 2_097_152, usesClock: false, runtimeFacts: [], refuses: ['attendee_protected', 'too_many_items'], excludes: [],
  example: {input: {event: {organizer: {email: 'org@example.com'}, attendees: [{email: 'org@example.com', organizer: true, responseStatus: 'accepted'},
    {email: 'Ann@Example.com', responseStatus: 'tentative'}]}, add: ['ann@example.com', 'bob@example.com'], remove: [], owner: 'org@example.com'},
  output: {attendees: [{email: 'org@example.com', organizer: true, responseStatus: 'accepted'}, {email: 'Ann@Example.com', responseStatus: 'tentative'}, {email: 'bob@example.com'}],
    added: ['bob@example.com'], removed: []}},
  run(input) {
    const event = input.event;
    if (!record(event)) refuse('input_invalid');
    const current = event.attendees === undefined ? [] : event.attendees;
    if (!Array.isArray(current) || !current.every(record)) refuse('input_invalid');
    if (current.length > MAX_ATTENDEES) refuse('too_many_items');
    const adding = folded(input.add), removing = folded(input.remove);
    if ([...adding].some(address => removing.has(address))) refuse('input_invalid');
    if (!plainAddress(input.owner)) refuse('input_invalid');
    const organizer = record(event.organizer) && typeof event.organizer.email === 'string' ? foldAscii(event.organizer.email) : null;
    if (removing.has(foldAscii(input.owner)) || (organizer !== null && removing.has(organizer))) refuse('attendee_protected');
    const attendees = [], removed = [], gone = new Set(), present = new Set();
    for (const attendee of current) {
      const key = typeof attendee.email === 'string' ? foldAscii(attendee.email) : null;
      if (key !== null && removing.has(key)) {
        if (attendee.organizer === true || attendee.self === true) refuse('attendee_protected');
        if (!gone.has(key)) removed.push(attendee.email);
        gone.add(key);
        continue;
      }
      if (key !== null) present.add(key);
      attendees.push(attendee);
    }
    const added = [];
    for (const address of input.add) {
      const key = foldAscii(address);
      if (present.has(key)) continue;
      present.add(key);
      attendees.push({email: address});
      added.push(address);
    }
    if (attendees.length > MAX_ATTENDEES) refuse('too_many_items');
    return {attendees, added, removed};
  }};

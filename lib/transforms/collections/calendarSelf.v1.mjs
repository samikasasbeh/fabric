// Iteration 9 step 8 (docs/I07-BUILD-MAP.md section 2.7): collections.calendarSelf@1, how this calendar answered an event. Step data: `event`, one item of a list. Out: {response?}, the
// responseStatus of the attendee marked self: true. Google sets that mark on the entry for the calendar this copy sits on, so it holds on a secondary calendar and through an alias, where
// an address would not. collections.findBy@1 matches strings, and self is a boolean. An event with no such entry, or an answer that is not short text, gives {}: nothing here refuses, or one
// odd item would stop a whole lens. It takes the first entry so marked.
const MAX_RESPONSE = 16;
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);

export const ENTRY = {name: 'collections.calendarSelf', version: 1, kind: 'map',
  input: {type: 'object', properties: {}, additionalProperties: false},
  pointerArgs: [], stepData: {event: {maxBytes: 2_097_152}}, resolvedValues: {},
  output: {type: 'object', properties: {response: {type: 'string', minLength: 1, maxLength: MAX_RESPONSE}}, additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 256, usesClock: false, runtimeFacts: [], refuses: [], excludes: [],
  example: {input: {event: {attendees: [{email: 'owner@example.com', self: true, responseStatus: 'needsAction'}]}}, output: {response: 'needsAction'}},
  run(input) {
    const attendees = record(input.event) && Array.isArray(input.event.attendees) ? input.event.attendees : [];
    const response = attendees.find(item => record(item) && item.self === true)?.responseStatus;
    return typeof response === 'string' && response.length > 0 && response.length <= MAX_RESPONSE ? {response} : {};
  }};

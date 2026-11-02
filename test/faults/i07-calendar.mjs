// Iteration 9 step 8 (docs/I07-BUILD-MAP.md step 8): Google Calendar's seeded faults, in the format of test/faults/registry.mjs. `from` is copied exactly from the current file and occurs there
// once; `to` is the faulty replacement the named tests must catch. Data only: nothing here reads or changes a file.
const STEP = 'I07';
const TESTS = ['test/triggers-calendar.test.mjs'], SIM = 'test/fixtures/provider-simulators/google-calendar.mjs', FILE = 'catalog/triggers/google-calendar.json';
const GUESTS = 'lib/transforms/collections/calendarGuests.v1.mjs', SELF = 'lib/transforms/collections/calendarSelf.v1.mjs', IS_AFTER = 'lib/transforms/time/isAfter.v1.mjs';

export const FAULTS = Object.freeze([
  {id: 'i07-cal-guests-self', step: STEP, name: '`collections.calendarGuests@1` keeps the calendar\'s own entry.',
    file: GUESTS, from: "if (!record(guest) || guest.self === true || guest.organizer === true || guest.responseStatus === 'needsAction') continue;",
    to: "if (!record(guest) || guest.organizer === true || guest.responseStatus === 'needsAction') continue;", tests: ['test/transforms-collections.test.mjs']},
  {id: 'i07-cal-self-email', step: STEP, name: '`collections.calendarSelf@1` matches by address, not `self`.',
    file: SELF, from: 'attendees.find(item => record(item) && item.self === true)', to: "attendees.find(item => record(item) && item.email === 'owner@example.com')", tests: TESTS},
  {id: 'i07-cal-known', step: STEP, name: 'No `knownBy`, so a create fires changed.',
    file: FILE, from: ',\n    "knownBy": [\n     {\n      "item": "/recurringEventId"\n     },\n     {\n      "item": "/id"\n     }\n    ]', to: '', tests: TESTS},
  {id: 'i07-cal-404-resync', step: STEP, name: 'A 404 on the feed resyncs, so a calendar that has gone reads as a lost place.',
    file: 'lib/trigger-runtime.mjs', from: 'return state.poll.resync.statusIn.includes(answer.status) || (token !== null', to: "return [...state.poll.resync.statusIn, ...(state.appId === 'google-calendar' ? [404] : [])].includes(answer.status) || (token !== null", tests: TESTS},
  {id: 'i07-cal-403', step: STEP, name: 'Any 403 waits, so a reader\'s calendar never pauses.',
    file: 'lib/trigger-rules.mjs', from: 'return listed.some(item => rule.reasons?.includes(item?.reason) || rule.domains?.includes(item?.domain))', to: "return appId === 'google-calendar' || listed.some(item => rule.reasons?.includes(item?.reason) || rule.domains?.includes(item?.domain))", tests: TESTS},
  {id: 'i07-cal-window', step: STEP, name: '`timeMin` is read as a start, so a meeting under way is reported as starting soon.',
    file: IS_AFTER, from: 'return {after: instant.millis > input.now || (instant.millis === input.now && instant.sub)};', to: 'return {after: true};', tests: TESTS},
  {id: 'i07-sim-cal-token-ignored', step: STEP, name: 'The simulator ignores a sync token, so every poll is a full list and a dedupe bug looks like success.',
    file: SIM, from: "const since = delta ? this.#place(log, feed, sync, 'sync', binding) : 0, after =", to: 'const since = 0, after =', tests: TESTS},
  {id: 'i07-sim-cal-series', step: STEP, name: 'The simulator\'s feed expands a series into its occurrences.',
    file: SIM, from: "const feed = `events:${calendar.id}`, single = query.get('singleEvents') === 'true', showDeleted", to: 'const feed = `events:${calendar.id}`, single = true, showDeleted', tests: TESTS},
  {id: 'i07-sim-cal-imports', step: STEP, name: 'The simulator imports from lib/, so a trigger bug and a simulator bug can cancel out.',
    file: SIM, from: "export const ORIGIN = 'https://www.googleapis.com';", to: "import '../../../lib/triggers.mjs';\nexport const ORIGIN = 'https://www.googleapis.com';", tests: TESTS},
  {id: 'i07-sim-cal-role', step: STEP, name: 'The simulator lists a role change in the sync feed, which Google leaves out, so a card\'s promise of it would read as proven.',
    file: SIM, from: '    calendar.accessRole = accessRole;\n', to: "    calendar.accessRole = accessRole;\n    this.#mark(this.data, 'list', calendar.id);\n", tests: TESTS},
]);

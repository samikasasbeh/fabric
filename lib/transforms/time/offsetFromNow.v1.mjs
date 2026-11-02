// Iteration 9 step 8 (docs/I07-BUILD-MAP.md section 2.7): time.offsetFromNow@1, a time a trigger reads from the clock, since {now} is only an argument of a clock transform. In: `now`, the
// poll's clock in UTC epoch milliseconds, `minutes`, 0 to 1,440, and an optional `prefer`, an RFC 3339 instant. Out: {time}: `prefer` as it stands when given, else now plus the minutes, in UTC.
// - "Starting soon" reads its window this way: timeMin at 0 minutes, and timeMax at the lead.
// - An event's time prefers Google's `updated`, which a cancelled event need not hold, and then reads the moment Fabric saw it.
// - A `prefer` that is no instant refuses with time_invalid, as a time past year 9999 does. The clock is never read here.
import {TransformError} from '../_shared/error.v1.mjs';
import {formatInstant, parseInstant} from './_format.v1.mjs';

const MINUTE = 60_000;
const refuse = code => { throw new TransformError(code); };

export const ENTRY = {name: 'time.offsetFromNow', version: 1, kind: 'map',
  input: {type: 'object', properties: {now: {type: 'integer', minimum: 0, maximum: 8_640_000_000_000_000}, minutes: {type: 'integer', minimum: 0, maximum: 1440}, prefer: {type: 'string', maxLength: 64}},
    required: ['now', 'minutes'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {time: {type: 'string', minLength: 1, maxLength: 64}}, required: ['time'], additionalProperties: false},
  maxInputBytes: 1024, maxOutputBytes: 256, usesClock: true, runtimeFacts: [], refuses: ['time_invalid'], excludes: [],
  example: {input: {now: 1_792_504_800_000, minutes: 15}, output: {time: '2026-10-20T14:15:00Z'}},
  run(input) {
    if (input.prefer !== undefined) return parseInstant(input.prefer) === null ? refuse('time_invalid') : {time: input.prefer};
    return {time: formatInstant(input.now + input.minutes * MINUTE) ?? refuse('time_invalid')};
  }};

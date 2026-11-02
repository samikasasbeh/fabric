// Iteration 9 step 8 (docs/I07-BUILD-MAP.md section 2.7): time.isAfter@1, a test a trigger's filter can read, since time.window@1 refuses and cannot be one. In: `instant`, an RFC 3339
// instant, and `now`, the poll's clock in UTC epoch milliseconds. Out: {after}: true when the instant is strictly later than now, a fraction below the millisecond counted. "Starting soon"
// needs it because Google's timeMin bounds an event's end, so a meeting under way is listed. An instant that is none refuses with time_invalid. The clock is never read here.
import {TransformError} from '../_shared/error.v1.mjs';
import {parseInstant} from './_format.v1.mjs';

export const ENTRY = {name: 'time.isAfter', version: 1, kind: 'map',
  input: {type: 'object', properties: {instant: {type: 'string', maxLength: 64}, now: {type: 'integer', minimum: 0, maximum: 8_640_000_000_000_000}}, required: ['instant', 'now'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {after: {type: 'boolean'}}, required: ['after'], additionalProperties: false},
  maxInputBytes: 1024, maxOutputBytes: 256, usesClock: true, runtimeFacts: [], refuses: ['time_invalid'], excludes: [],
  example: {input: {instant: '2026-10-20T14:00:01Z', now: 1_792_504_800_000}, output: {after: true}},
  run(input) {
    const instant = parseInstant(input.instant);
    if (instant === null) throw new TransformError('time_invalid');
    return {after: instant.millis > input.now || (instant.millis === input.now && instant.sub)};
  }};

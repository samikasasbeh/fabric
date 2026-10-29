// F10.8 part g (docs/F10.8-BUILD-MAP.md, open point Minor 4): time.window@1, a guard that uses the clock. In: start?, end?, instant? and
// maxDays? (RFC 3339 instants and a day count of 1 to 3,660), and `now`, the job's clock in UTC epoch milliseconds, read once when the
// perform bytes are built (part m). Out: {}. Each check applies only to the fields given, so one action can carry exclusive paths:
// - start and end: start strictly before end, to the millisecond, or window_order (Gmail's vacation, spec line 1027);
// - instant: not before now, or window_past; with maxDays, not after now plus maxDays days, a fraction below the millisecond counted, or
//   window_too_far (Slack scheduling uses 120 days, spec line 1140);
// - a field given alone is still read: one that is no RFC 3339 instant refuses with time_invalid.
// The cancel path of Schedule or cancel gives no instant, so nothing is checked and it passes. The clock is never read here.
import {TransformError} from '../_shared/error.v1.mjs';
import {DAY, parseInstant} from './_format.v1.mjs';

const TIME = {type: 'string', maxLength: 64};
const refuse = code => { throw new TransformError(code); };
/** An RFC 3339 instant as {millis, sub}, or a refusal. */
const instantOf = text => parseInstant(text) ?? refuse('time_invalid');

export const ENTRY = {name: 'time.window', version: 1, kind: 'guard',
  input: {type: 'object', properties: {start: TIME, end: TIME, instant: TIME, maxDays: {type: 'integer', minimum: 1, maximum: 3660},
    now: {type: 'integer', minimum: 0, maximum: 8_640_000_000_000_000}}, required: ['now'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {}, additionalProperties: false},
  maxInputBytes: 4096, maxOutputBytes: 64, usesClock: true, runtimeFacts: [], refuses: ['time_invalid', 'window_order', 'window_past', 'window_too_far'], excludes: [],
  example: {input: {instant: '2026-10-21T14:00:00Z', maxDays: 120, now: 1_792_504_800_000}, output: {}},
  run(input) {
    const start = input.start === undefined ? null : instantOf(input.start), end = input.end === undefined ? null : instantOf(input.end);
    if (start !== null && end !== null && !(start.millis < end.millis)) refuse('window_order');
    if (input.instant !== undefined) {
      const instant = instantOf(input.instant);
      if (instant.millis < input.now) refuse('window_past');
      if (input.maxDays !== undefined) {
        const limit = input.now + input.maxDays * DAY;
        if (instant.millis > limit || (instant.millis === limit && instant.sub)) refuse('window_too_far');
      }
    }
    return {};
  }};

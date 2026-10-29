// F10.8 part g (docs/F10.8-BUILD-MAP.md): time.slackTs@1. Step data: `ts`, a Slack message timestamp as Slack writes it: a string of 1 to
// 10 digits, a dot and exactly 6 digits. Closed: `than`, another ts to compare it with. Out: {ts, next, time, order?}: the ts as given; the
// ts one microsecond later, for an exclusive cursor (oldest); the instant in RFC 3339 with its microseconds; and, with `than`, -1, 0 or 1.
// Each ts becomes BigInt microseconds, never a float, and compares as a number, never as a string: '999999999.999999' is before
// '1000000000.000000', though a string comparison says otherwise (spec lines 668, 1126, 1138; measured). A JSON number, 1.5, a seventh
// fraction digit, or a ts whose next would need an eleventh digit refuses with ts_invalid.
import {TransformError} from '../_shared/error.v1.mjs';
import {utcParts} from '../_shared/utc.v1.mjs';

const TS = /^(\d{1,10})\.(\d{6})$/;
const MILLION = 1_000_000n, LIMIT = 10_000_000_000n * MILLION;
const pad = (value, width) => String(value).padStart(width, '0');

/** A ts as BigInt microseconds; it refuses anything else. */
function micros(ts) {
  const match = typeof ts === 'string' ? TS.exec(ts) : null;
  if (!match) throw new TransformError('ts_invalid');
  return BigInt(match[1]) * MILLION + BigInt(match[2]);
}

export const ENTRY = {name: 'time.slackTs', version: 1, kind: 'map',
  input: {type: 'object', properties: {than: {type: 'string', maxLength: 64}}, additionalProperties: false},
  pointerArgs: [], stepData: {ts: {maxBytes: 256}}, resolvedValues: {},
  output: {type: 'object', properties: {ts: {type: 'string', minLength: 8, maxLength: 17}, next: {type: 'string', minLength: 8, maxLength: 17},
    time: {type: 'string', format: 'date-time', maxLength: 27}, order: {type: 'integer', enum: [-1, 0, 1]}}, required: ['ts', 'next', 'time'], additionalProperties: false},
  maxInputBytes: 1024, maxOutputBytes: 512, usesClock: false, runtimeFacts: [], refuses: ['ts_invalid'], excludes: [],
  example: {input: {ts: '1355517523.000005', than: '1355517523.000004'}, output: {ts: '1355517523.000005', next: '1355517523.000006', time: '2012-12-14T20:38:43.000005Z', order: 1}},
  run(input) {
    const value = micros(input.ts), next = value + 1n;
    if (next >= LIMIT) throw new TransformError('ts_invalid');
    const seconds = value / MILLION, parts = utcParts(Number(seconds) * 1000);
    const time = `${pad(parts.year, 4)}-${pad(parts.month, 2)}-${pad(parts.day, 2)}T${pad(parts.hour, 2)}:${pad(parts.minute, 2)}:${pad(parts.second, 2)}.${pad(value % MILLION, 6)}Z`;
    const result = {ts: input.ts, next: `${next / MILLION}.${pad(next % MILLION, 6)}`, time};
    if (input.than === undefined) return result;
    const other = micros(input.than);
    return {...result, order: value < other ? -1 : value > other ? 1 : 0};
  }};

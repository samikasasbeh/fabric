// F10.8 part g (docs/F10.8-BUILD-MAP.md): time.freeSlots@1. Step data: `freeBusy`, Calendar's freeBusy.query answer, at most 1 MiB. Its
// `calendars` object is keyed by calendar id, which a closed schema cannot list (lib/compiler.mjs:130), so this parses it. Closed: `start`
// and `end` (RFC 3339 instants) and `minMinutes` (1 to 1,440). Out: {free: [{start, end}]}: the busy blocks of every calendar merged and
// taken from the window, as blocks of at least minMinutes, in UTC, sorted.
// A calendar Fabric could not read never shows as free: busy_unknown when a calendar or a group answers with `errors` (an empty list
// included), a calendar has no busy list, a busy block does not read, the answer names no calendar, or its timeMin and timeMax do not
// cover the window. Below the millisecond, busy blocks grow outward and the window shrinks inward. More than 2,000 busy blocks across
// every calendar refuse with input_too_large; a window whose start is not before its end with window_order.
import {TransformError} from '../_shared/error.v1.mjs';
import {formatInstant, parseInstant} from './_format.v1.mjs';

const MAX_BUSY = 2000;
const TIME = {type: 'string', maxLength: 64};
const refuse = code => { throw new TransformError(code); };
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
/** A provider instant as {millis, sub}; one that does not read leaves the busy time unknown. */
const readInstant = text => parseInstant(text) ?? refuse('busy_unknown');
/** Every busy block of the answer, each as [start, end] epoch milliseconds rounded outward. */
function busyBlocks(answer) {
  if (!record(answer) || !record(answer.calendars)) refuse('busy_unknown');
  if (answer.groups !== undefined && (!record(answer.groups) || Object.entries(answer.groups).some(([, group]) => !record(group) || Object.hasOwn(group, 'errors')))) {
    refuse('busy_unknown');
  }
  const calendars = Object.entries(answer.calendars), blocks = [];
  if (!calendars.length) refuse('busy_unknown');
  for (const [, calendar] of calendars) {
    if (!record(calendar) || Object.hasOwn(calendar, 'errors') || !Array.isArray(calendar.busy)) refuse('busy_unknown');
    for (const block of calendar.busy) {
      if (blocks.length === MAX_BUSY) refuse('input_too_large');
      if (!record(block)) refuse('busy_unknown');
      const start = readInstant(block.start), end = readInstant(block.end), from = start.millis, to = end.millis + (end.sub ? 1 : 0);
      if (to < from) refuse('busy_unknown');
      blocks.push([from, to]);
    }
  }
  return blocks;
}

export const ENTRY = {name: 'time.freeSlots', version: 1, kind: 'map',
  input: {type: 'object', properties: {start: TIME, end: TIME, minMinutes: {type: 'integer', minimum: 1, maximum: 1440}}, required: ['start', 'end', 'minMinutes'],
    additionalProperties: false},
  pointerArgs: [], stepData: {freeBusy: {maxBytes: 1_048_576}}, resolvedValues: {},
  output: {type: 'object', properties: {free: {type: 'array', maxItems: MAX_BUSY + 1, items: {type: 'object', properties: {start: {type: 'string', format: 'date-time', maxLength: 24},
    end: {type: 'string', format: 'date-time', maxLength: 24}}, required: ['start', 'end'], additionalProperties: false}}}, required: ['free'], additionalProperties: false},
  maxInputBytes: 1_049_600, maxOutputBytes: 262_144, usesClock: false, runtimeFacts: [], refuses: ['time_invalid', 'window_order', 'busy_unknown'], excludes: [],
  example: {input: {freeBusy: {kind: 'calendar#freeBusy', timeMin: '2026-10-20T13:00:00Z', timeMax: '2026-10-20T17:00:00Z',
    calendars: {primary: {busy: [{start: '2026-10-20T14:00:00Z', end: '2026-10-20T15:00:00Z'}]}}}, start: '2026-10-20T13:00:00Z', end: '2026-10-20T17:00:00Z', minMinutes: 30},
  output: {free: [{start: '2026-10-20T13:00:00Z', end: '2026-10-20T14:00:00Z'}, {start: '2026-10-20T15:00:00Z', end: '2026-10-20T17:00:00Z'}]}},
  run(input) {
    const start = parseInstant(input.start), end = parseInstant(input.end);
    if (start === null || end === null) refuse('time_invalid');
    const from = start.millis + (start.sub ? 1 : 0), to = end.millis, least = input.minMinutes * 60_000;
    if (!(from < to)) refuse('window_order');
    const answer = input.freeBusy;
    if (!record(answer)) refuse('busy_unknown');
    const covered = readInstant(answer.timeMin), until = readInstant(answer.timeMax);
    if (covered.millis + (covered.sub ? 1 : 0) > from || until.millis < to) refuse('busy_unknown');
    const blocks = busyBlocks(answer).filter(([low, high]) => high > from && low < to).sort(([a], [b]) => a - b);
    const free = [];
    let cursor = from;
    for (const [low, high] of blocks) {
      if (low - cursor >= least) free.push({start: formatInstant(cursor), end: formatInstant(low)});
      if (high > cursor) cursor = high;
    }
    if (to - cursor >= least) free.push({start: formatInstant(cursor), end: formatInstant(to)});
    return {free};
  }};

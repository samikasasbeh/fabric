// F10.8 part g (docs/F10.8-BUILD-MAP.md): time.rrule@1, a guard. In: {recurrence}, Calendar's list of recurrence lines. Out: the same
// list, when every line is one Calendar takes and each recur value follows RFC 5545 section 3.3.10. Otherwise time_invalid:
// - at most 10 lines, each printable ASCII in upper case, as Calendar writes them; a line is RRULE, EXRULE, RDATE or EXDATE, so DTSTART
//   and DTEND lines refuse (Calendar takes the start and end from the event), and so does a second RRULE;
// - a recur value: FREQ once and first-class, each rule part at most once, COUNT and UNTIL never together, BYDAY with a number only when
//   FREQ is MONTHLY or YEARLY (and not beside BYWEEKNO), BYMONTHDAY never WEEKLY, BYYEARDAY never DAILY, WEEKLY or MONTHLY, BYWEEKNO only
//   YEARLY, BYSETPOS only beside another BY part; every number within its range: an hour 00 to 23, a minute and a second 00 to 59 (no
//   leap second, as everywhere in this family), a day, week, month or position its grammar allows;
// - RDATE and EXDATE: VALUE=DATE or DATE-TIME (never PERIOD) and TZID at most once each, no TZID with dates, and no UTC time under a TZID.
//   A TZID is checked for its form only, so this reads no zone data.
// Every date and time is checked by calendar: UNTIL=20261020T240000Z and 20260230 refuse.
import {TransformError} from '../_shared/error.v1.mjs';
import {wallMillis, zoneForm} from './_format.v1.mjs';

const LINE = /^[\x20-\x7e]{1,1000}$/;
const DATE = /^(\d{4})(\d{2})(\d{2})$/;
const DATE_TIME = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(Z?)$/;
const NUMBER = /^([+-]?)(\d{1,3})$/;
const BY_DAY = /^(?:([+-]?)(\d{1,2}))?(SU|MO|TU|WE|TH|FR|SA)$/;
const FREQS = new Set(['SECONDLY', 'MINUTELY', 'HOURLY', 'DAILY', 'WEEKLY', 'MONTHLY', 'YEARLY']);
const WEEKDAYS = new Set(['SU', 'MO', 'TU', 'WE', 'TH', 'FR', 'SA']);
// Each numeric BY part: its lowest and highest value, and whether it may be signed (and so never zero).
const RANGES = new Map([['BYSECOND', [0, 59, false]], ['BYMINUTE', [0, 59, false]], ['BYHOUR', [0, 23, false]], ['BYMONTHDAY', [1, 31, true]], ['BYYEARDAY', [1, 366, true]],
  ['BYWEEKNO', [1, 53, true]], ['BYMONTH', [1, 12, false]], ['BYSETPOS', [1, 366, true]]]);
const PARTS = new Set(['FREQ', 'UNTIL', 'COUNT', 'INTERVAL', 'BYDAY', 'WKST', ...RANGES.keys()]);
const COUNT = /^[1-9][0-9]{0,5}$/;

const invalid = () => { throw new TransformError('time_invalid'); };
/** A date or a date-time as RFC 5545 writes them (YYYYMMDD, YYYYMMDDTHHMMSS, with Z for UTC), checked by calendar: {utc, date}, or null. */
function dateValue(text) {
  const date = DATE.exec(text);
  if (date) return wallMillis(Number(date[1]), Number(date[2]), Number(date[3]), 0, 0, 0) === null ? null : {date: true, utc: false};
  const time = DATE_TIME.exec(text);
  if (!time || wallMillis(Number(time[1]), Number(time[2]), Number(time[3]), Number(time[4]), Number(time[5]), Number(time[6])) === null) return null;
  return {date: false, utc: time[7] === 'Z'};
}
/** True when every item of a comma list passes `check`. */
const listOf = (text, check) => text.split(',').every(item => check(item));
/** True for a number of a numeric BY part within its range. */
function inRange(item, [low, high, signed]) {
  const match = NUMBER.exec(item);
  if (!match || (match[1] && !signed)) return false;
  const value = Number(match[2]);
  return value >= low && value <= high;
}
/** Checks one recur value (RFC 5545 section 3.3.10); it refuses anything else. */
function checkRecur(value) {
  const parts = new Map();
  for (const part of value.split(';')) {
    const at = part.indexOf('='), name = part.slice(0, at), text = part.slice(at + 1);
    if (at < 1 || !text || !PARTS.has(name) || parts.has(name)) invalid();
    parts.set(name, text);
  }
  const freq = parts.get('FREQ'), byDay = parts.get('BYDAY');
  if (!FREQS.has(freq)) invalid();
  if (parts.has('COUNT') && parts.has('UNTIL')) invalid();
  if (parts.has('COUNT') && !COUNT.test(parts.get('COUNT'))) invalid();
  if (parts.has('INTERVAL') && !COUNT.test(parts.get('INTERVAL'))) invalid();
  if (parts.has('UNTIL') && dateValue(parts.get('UNTIL')) === null) invalid();
  if (parts.has('WKST') && !WEEKDAYS.has(parts.get('WKST'))) invalid();
  for (const [name, range] of RANGES) if (parts.has(name) && !listOf(parts.get(name), item => inRange(item, range))) invalid();
  if (byDay !== undefined) {
    const numbered = freq === 'MONTHLY' || (freq === 'YEARLY' && !parts.has('BYWEEKNO'));
    const day = item => {
      const match = BY_DAY.exec(item);
      if (!match) return false;
      if (match[2] === undefined) return true;
      return numbered && Number(match[2]) >= 1 && Number(match[2]) <= 53;
    };
    if (!listOf(byDay, day)) invalid();
  }
  if (parts.has('BYMONTHDAY') && freq === 'WEEKLY') invalid();
  if (parts.has('BYYEARDAY') && ['DAILY', 'WEEKLY', 'MONTHLY'].includes(freq)) invalid();
  if (parts.has('BYWEEKNO') && freq !== 'YEARLY') invalid();
  if (parts.has('BYSETPOS') && ![...parts.keys()].some(name => name !== 'BYSETPOS' && name.startsWith('BY'))) invalid();
}
/** Checks the parameters and values of an RDATE or EXDATE line; it refuses anything else. */
function checkDates(params, value) {
  const seen = new Map();
  for (const param of params) {
    const at = param.indexOf('='), name = param.slice(0, at), text = param.slice(at + 1);
    if (at < 1 || (name !== 'VALUE' && name !== 'TZID') || seen.has(name)) invalid();
    seen.set(name, text);
  }
  const kind = seen.get('VALUE') ?? 'DATE-TIME', zone = seen.get('TZID');
  if (kind !== 'DATE' && kind !== 'DATE-TIME') invalid();
  if (zone !== undefined && (kind === 'DATE' || !zoneForm(zone))) invalid();
  const fits = item => {
    const found = dateValue(item);
    return found !== null && found.date === (kind === 'DATE') && !(found.utc && zone !== undefined);
  };
  if (!listOf(value, fits)) invalid();
}

export const ENTRY = {name: 'time.rrule', version: 1, kind: 'guard',
  input: {type: 'object', properties: {recurrence: {type: 'array', maxItems: 50, items: {type: 'string', maxLength: 1000}}}, required: ['recurrence'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {recurrence: {type: 'array', maxItems: 10, items: {type: 'string', maxLength: 1000}}}, required: ['recurrence'], additionalProperties: false},
  maxInputBytes: 524_288, maxOutputBytes: 16_384, usesClock: false, runtimeFacts: [], refuses: ['time_invalid'], excludes: [],
  example: {input: {recurrence: ['RRULE:FREQ=WEEKLY;COUNT=3']}, output: {recurrence: ['RRULE:FREQ=WEEKLY;COUNT=3']}},
  run(input) {
    const lines = input.recurrence;
    if (lines.length > 10) invalid();
    let rules = 0;
    for (const line of lines) {
      const colon = line.indexOf(':');
      if (!LINE.test(line) || colon < 1) invalid();
      const [name, ...params] = line.slice(0, colon).split(';'), value = line.slice(colon + 1);
      if (name === 'RRULE' || name === 'EXRULE') {
        if (params.length) invalid();
        if (name === 'RRULE' && ++rules > 1) invalid();
        checkRecur(value);
      } else if (name === 'RDATE' || name === 'EXDATE') checkDates(params, value);
      else invalid();
    }
    return {recurrence: lines};
  }};

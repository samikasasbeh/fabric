// F10.8 part g (docs/F10.8-BUILD-MAP.md): the written forms of the time family, read and written without Date (only through
// _shared/utc.v1.mjs) and without Intl, so it reads no runtime fact: RFC 3339 instants, dates, local date-times, offsets and the form of a
// zone name. Every reader checks its own ranges, never Date.parse, which reads T24:00:00Z as the next midnight (measured): the month, the
// day by calendar, the hour 00 to 23, the minute 00 to 59 and the second 00 to 59 (no leap second), and an offset within ±23:59. Each
// returns null for a bad value and leaves the code to its caller.
import {utcMillis, utcParts} from '../_shared/utc.v1.mjs';

// lib/compiler.mjs's date-time pattern (line 180), with the fields captured: upper-case T and Z, any number of fraction digits.
const INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
const LOCAL = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})$/;
const OFFSET = /^([+-])(\d{2}):(\d{2})$/;
const ZONE_PART = /^[A-Z][A-Za-z0-9_+-]{0,31}$/;
const MINUTE = 60_000;
export const DAY = 86_400_000;

/** The earliest and latest epoch seconds an RFC 3339 instant can name: years 0000 to 9999, at any offset within ±23:59. */
export const SECONDS_MIN = -62_167_305_540;
export const SECONDS_MAX = 253_402_387_139;

const pad = (value, width) => String(value).padStart(width, '0');
/** a divided by b, rounded down, for integers: exact where a / b in floating point is not. */
export const floorDiv = (a, b) => (a - (((a % b) + b) % b)) / b;

/** True for an hour 00 to 23, a minute 00 to 59 and a second 00 to 59: no hour 24 and no leap second. */
const inDay = (hour, minute, second) => hour <= 23 && minute <= 59 && second <= 59;
/** Epoch milliseconds of a UTC date (calendar-checked by utcMillis) and wall-clock time, or null when either does not exist. */
export function wallMillis(year, month, day, hour, minute, second, millisecond = 0) {
  const date = utcMillis({year, month, day});
  return date === null || !inDay(hour, minute, second) ? null : date + ((hour * 60 + minute) * 60 + second) * 1000 + millisecond;
}

/** An offset within ±23:59 in milliseconds, from its sign and its two-digit hours and minutes, or null. */
function offsetMillis(sign, hours, minutes) {
  const h = Number(hours), m = Number(minutes);
  if (h > 23 || m > 59) return null;
  return (sign === '-' ? -1 : 1) * (h * 60 + m) * MINUTE;
}

/**
 * An RFC 3339 instant as {millis, sub}: its epoch milliseconds, the fraction cut to the millisecond (so rounded down), and whether any
 * digit below the millisecond is not zero. Null when it is not one, or names a time that does not exist.
 */
export function parseInstant(text) {
  const match = typeof text === 'string' ? INSTANT.exec(text) : null;
  if (!match) return null;
  const [, year, month, day, hour, minute, second, fraction = '', sign, offsetHours, offsetMinutes] = match;
  const local = wallMillis(Number(year), Number(month), Number(day), Number(hour), Number(minute), Number(second), Number(fraction.slice(0, 3).padEnd(3, '0')));
  const offset = sign === undefined ? 0 : offsetMillis(sign, offsetHours, offsetMinutes);
  if (local === null || offset === null) return null;
  return {millis: local - offset, sub: /[1-9]/.test(fraction.slice(3))};
}

/** Epoch milliseconds as RFC 3339 in UTC: YYYY-MM-DDTHH:MM:SS, then .sss when `millis` is set or the milliseconds are not zero, then Z.
 * Null outside years 0000 to 9999. */
export function formatInstant(ms, millis = false) {
  const parts = utcParts(ms);
  if (parts === null || parts.year > 9999 || parts.year < 0) return null;
  const fraction = millis || parts.millisecond !== 0 ? `.${pad(parts.millisecond, 3)}` : '';
  return `${pad(parts.year, 4)}-${pad(parts.month, 2)}-${pad(parts.day, 2)}T${pad(parts.hour, 2)}:${pad(parts.minute, 2)}:${pad(parts.second, 2)}${fraction}Z`;
}

/** A date YYYY-MM-DD as the epoch milliseconds of its UTC midnight, or null. */
export function parseDate(text) {
  const match = typeof text === 'string' ? DATE.exec(text) : null;
  return match ? utcMillis({year: Number(match[1]), month: Number(match[2]), day: Number(match[3])}) : null;
}
/** The UTC date YYYY-MM-DD of epoch milliseconds, or null outside years 0000 to 9999. */
export function formatDate(ms) {
  const parts = utcParts(ms);
  return parts === null || parts.year > 9999 || parts.year < 0 ? null : `${pad(parts.year, 4)}-${pad(parts.month, 2)}-${pad(parts.day, 2)}`;
}

/** A local date-time YYYY-MM-DDTHH:MM:SS in years 0001 to 9999, read as if it were UTC: the milliseconds a zone's offset is then taken
 * from. Null when it is not one, or names a day, hour, minute or second that does not exist. */
export function parseLocal(text) {
  const match = typeof text === 'string' ? LOCAL.exec(text) : null;
  if (!match || Number(match[1]) < 1) return null;
  return wallMillis(Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6]));
}

/** An offset ±HH:MM within ±23:59, in milliseconds, or null. -00:00 reads as UTC. */
export function parseOffset(text) {
  const match = typeof text === 'string' ? OFFSET.exec(text) : null;
  return match ? offsetMillis(match[1], match[2], match[3]) : null;
}
/** An offset of whole minutes as ±HH:MM (UTC is +00:00), or null when it holds seconds, as local mean time does, or passes ±23:59. */
export function formatOffset(ms) {
  if (!Number.isSafeInteger(ms) || ms % MINUTE !== 0 || Math.abs(ms) > (23 * 60 + 59) * MINUTE) return null;
  const minutes = Math.abs(ms) / MINUTE;
  return `${ms < 0 ? '-' : '+'}${pad(Math.floor(minutes / 60), 2)}:${pad(minutes % 60, 2)}`;
}

/** True for a zone name in IANA form: one to three parts separated by /, each an upper-case letter, then letters, digits, _, + or -. */
export function zoneForm(text) {
  if (typeof text !== 'string') return false;
  const parts = text.split('/');
  return parts.length <= 3 && parts.every(part => ZONE_PART.test(part));
}

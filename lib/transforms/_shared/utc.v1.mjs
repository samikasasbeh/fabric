// F10.8 part b (docs/F10.8-BUILD-MAP.md, R18): the only file of the transform library that names Date. It calls new Date(ms) only
// after Number.isSafeInteger(ms), and reads only Date.UTC and the getUTC* methods, so nothing here parses a string, reads the machine
// clock or reads local time. The source scan (scripts/transform-scan.mjs) holds every other file to that.

const MAX_MILLIS = 8_640_000_000_000_000;
// 400 Gregorian years are exactly 146,097 days, so a year moved by 400 keeps its calendar. Date.UTC reads years 0 to 99 as 1900 plus
// the year; building every date 400 years later and moving back gives the year asked for.
const CYCLE_MILLIS = 146_097 * 86_400_000;
const inRange = (value, low, high) => Number.isSafeInteger(value) && value >= low && value <= high;

/** The UTC calendar fields of epoch milliseconds, or null unless they are a safe integer within Date's range. */
export function utcParts(ms) {
  if (!Number.isSafeInteger(ms) || ms < -MAX_MILLIS || ms > MAX_MILLIS) return null;
  const date = new Date(ms);
  return {year: date.getUTCFullYear(), month: date.getUTCMonth() + 1, day: date.getUTCDate(), hour: date.getUTCHours(), minute: date.getUTCMinutes(),
    second: date.getUTCSeconds(), millisecond: date.getUTCMilliseconds(), weekday: date.getUTCDay()};
}

/** Epoch milliseconds of a UTC date and time in years 0 to 9999, or null when any field is out of range or the day does not exist. */
export function utcMillis({year, month, day, hour = 0, minute = 0, second = 0, millisecond = 0}) {
  if (!inRange(year, 0, 9999) || !inRange(month, 1, 12) || !inRange(day, 1, 31) || !inRange(hour, 0, 23) || !inRange(minute, 0, 59) || !inRange(second, 0, 59)
    || !inRange(millisecond, 0, 999)) return null;
  const ms = Date.UTC(year + 400, month - 1, day, hour, minute, second, millisecond) - CYCLE_MILLIS;
  const parts = utcParts(ms);
  return parts && parts.year === year && parts.month === month && parts.day === day ? ms : null;
}

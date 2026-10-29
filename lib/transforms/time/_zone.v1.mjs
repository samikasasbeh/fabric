// F10.8 part g (docs/F10.8-BUILD-MAP.md, open question 12): zones through Intl.DateTimeFormat, the only place the time family reads zone
// data, so every module that imports this declares the tz fact. Temporal is undefined (measured), so offsets come from formatToParts.
// Every formatter names its locale, calendar, numbering system and hour cycle, so neither the process's TZ nor its locale (LC_ALL) can
// change a result.
import {sameAscii} from '../_shared/ascii.v1.mjs';
import {utcMillis} from '../_shared/utc.v1.mjs';
import {zoneForm} from './_format.v1.mjs';

/**
 * The zone name exactly as given, or null. It must be in IANA form with each part starting in upper case (so no offset zone such as
 * +05:30, which Intl accepts), Intl must know it, and it must not be a case variant of the name Intl reads it as (America/TORONTO).
 * ICU's canonical name is never returned: it drifts between versions (Europe/Kyiv reads as Europe/Kiev today, measured). Intl resolves a
 * link and its case variants alike (US/EASTERN and US/Eastern both read as America/New_York), so a case variant of a link passes.
 */
export function zoneName(text) {
  if (!zoneForm(text)) return null;
  let resolved;
  try { resolved = new Intl.DateTimeFormat('en-US', {timeZone: text}).resolvedOptions().timeZone; } catch { return null; }
  return resolved !== text && sameAscii(resolved, text) ? null : text;
}

/** A formatter that reads the wall-clock fields of an instant in `zone`, which zoneName() has accepted. */
export function zoneFormatter(zone) {
  return new Intl.DateTimeFormat('en-US', {timeZone: zone, calendar: 'gregory', numberingSystem: 'latn', hourCycle: 'h23', era: 'short', year: 'numeric', month: 'numeric',
    day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric'});
}

/** The zone's offset at epoch milliseconds `ms` (a whole second), in milliseconds: its wall clock read as UTC, less `ms`. Null when the
 * wall clock is not in years 0001 to 9999 of the common era. */
export function offsetAt(formatter, ms) {
  const fields = {};
  let era = '';
  for (const part of formatter.formatToParts(ms)) {
    if (part.type === 'era') era = part.value;
    else if (part.type === 'year') fields.year = Number(part.value);
    else if (part.type === 'month') fields.month = Number(part.value);
    else if (part.type === 'day') fields.day = Number(part.value);
    else if (part.type === 'hour') fields.hour = Number(part.value);
    else if (part.type === 'minute') fields.minute = Number(part.value);
    else if (part.type === 'second') fields.second = Number(part.value);
  }
  const local = era === 'AD' ? utcMillis(fields) : null;
  return local === null ? null : local - ms;
}

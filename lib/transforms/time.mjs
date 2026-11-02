// F10.8 parts b and g (docs/F10.8-BUILD-MAP.md): the time family list. It imports the ENTRY of each version module under time/ and lists it
// with its file, and nothing else. lib/transforms/index.mjs checks every entry at import, and the source scan holds a list to its own
// folder's modules.
import {ENTRY as allDayEnd1} from './time/allDayEnd.v1.mjs';
import {ENTRY as decimalCompare1} from './time/decimalCompare.v1.mjs';
import {ENTRY as epochMillisStringToRfc33391} from './time/epochMillisStringToRfc3339.v1.mjs';
import {ENTRY as freeSlots1} from './time/freeSlots.v1.mjs';
import {ENTRY as isAfter1} from './time/isAfter.v1.mjs';
import {ENTRY as offsetFromNow1} from './time/offsetFromNow.v1.mjs';
import {ENTRY as rfc3339ToEpochMillisString1} from './time/rfc3339ToEpochMillisString.v1.mjs';
import {ENTRY as rfc3339ToEpochSeconds1} from './time/rfc3339ToEpochSeconds.v1.mjs';
import {ENTRY as rrule1} from './time/rrule.v1.mjs';
import {ENTRY as slackTs1} from './time/slackTs.v1.mjs';
import {ENTRY as window1} from './time/window.v1.mjs';
import {ENTRY as zone1} from './time/zone.v1.mjs';
import {ENTRY as zonedToRfc33391} from './time/zonedToRfc3339.v1.mjs';

export const ENTRIES = Object.freeze([
  {file: 'time/allDayEnd.v1.mjs', entry: allDayEnd1},
  {file: 'time/decimalCompare.v1.mjs', entry: decimalCompare1},
  {file: 'time/epochMillisStringToRfc3339.v1.mjs', entry: epochMillisStringToRfc33391},
  {file: 'time/freeSlots.v1.mjs', entry: freeSlots1},
  {file: 'time/isAfter.v1.mjs', entry: isAfter1},
  {file: 'time/offsetFromNow.v1.mjs', entry: offsetFromNow1},
  {file: 'time/rfc3339ToEpochMillisString.v1.mjs', entry: rfc3339ToEpochMillisString1},
  {file: 'time/rfc3339ToEpochSeconds.v1.mjs', entry: rfc3339ToEpochSeconds1},
  {file: 'time/rrule.v1.mjs', entry: rrule1},
  {file: 'time/slackTs.v1.mjs', entry: slackTs1},
  {file: 'time/window.v1.mjs', entry: window1},
  {file: 'time/zone.v1.mjs', entry: zone1},
  {file: 'time/zonedToRfc3339.v1.mjs', entry: zonedToRfc33391},
]);

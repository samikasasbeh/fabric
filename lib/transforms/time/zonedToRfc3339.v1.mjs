// F10.8 part g (docs/F10.8-BUILD-MAP.md, open question 11): time.zonedToRfc3339@1. In: {local, zone, offset?}: a wall-clock
// YYYY-MM-DDTHH:MM:SS, a zone time.zone@1 accepts, and optionally the offset ±HH:MM the owner meant. Out: {time}, the local time with its
// offset in RFC 3339, so the owner approves the exact instant.
// The offsets the zone uses within 36 hours either side are read through Intl (no zone offset is wider than that), and each one that
// the zone really uses at the instant it gives is a reading of the local time. None: the time falls in a gap and refuses with
// time_nonexistent, even with an offset. Two: it falls in a fold and refuses with time_ambiguous, unless the given offset is one of them.
// A given offset that is no reading there refuses with time_invalid, and so does an offset of seconds (local mean time) that RFC 3339
// cannot write. Nothing is ever shifted to a nearby time.
import {TransformError} from '../_shared/error.v1.mjs';
import {formatOffset, parseLocal, parseOffset} from './_format.v1.mjs';
import {offsetAt, zoneFormatter, zoneName} from './_zone.v1.mjs';

const SIX_HOURS = 21_600_000;

export const ENTRY = {name: 'time.zonedToRfc3339', version: 1, kind: 'map',
  input: {type: 'object', properties: {local: {type: 'string', maxLength: 64}, zone: {type: 'string', maxLength: 64}, offset: {type: 'string', maxLength: 16}},
    required: ['local', 'zone'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {time: {type: 'string', format: 'date-time', maxLength: 25}}, required: ['time'], additionalProperties: false},
  maxInputBytes: 1024, maxOutputBytes: 256, usesClock: false, runtimeFacts: ['tz'], refuses: ['time_invalid', 'zone_invalid', 'time_nonexistent', 'time_ambiguous'], excludes: [],
  example: {input: {local: '2026-03-08T01:59:00', zone: 'America/Toronto'}, output: {time: '2026-03-08T01:59:00-05:00'}},
  run(input) {
    const local = parseLocal(input.local);
    if (local === null) throw new TransformError('time_invalid');
    const zone = zoneName(input.zone);
    if (zone === null) throw new TransformError('zone_invalid');
    const wanted = input.offset === undefined ? null : parseOffset(input.offset);
    if (input.offset !== undefined && wanted === null) throw new TransformError('time_invalid');
    const formatter = zoneFormatter(zone), offsets = new Set();
    for (let step = -6; step <= 6; step++) {
      const offset = offsetAt(formatter, local + step * SIX_HOURS);
      if (offset !== null) offsets.add(offset);
    }
    // A reading is an offset the zone really has at the instant it gives.
    const readings = [...offsets].filter(offset => offsetAt(formatter, local - offset) === offset);
    if (!readings.length) throw new TransformError('time_nonexistent');
    let offset;
    if (wanted !== null) {
      if (!readings.includes(wanted)) throw new TransformError('time_invalid');
      offset = wanted;
    } else if (readings.length > 1) throw new TransformError('time_ambiguous');
    else offset = readings[0];
    const written = formatOffset(offset);
    if (written === null) throw new TransformError('time_invalid');
    return {time: `${input.local}${written}`};
  }};

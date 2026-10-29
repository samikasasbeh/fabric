// F10.8 part g (docs/F10.8-BUILD-MAP.md): time.allDayEnd@1. In: {date, days}: the first day YYYY-MM-DD of an all-day event and how many
// days it lasts, 1 to 3,660. Out: {end}, the exclusive end date Calendar takes (spec lines 666, 994): the day after the last one, by UTC
// date arithmetic, so no zone and no daylight-saving change can move it. A date that does not exist, or an end past 9999-12-31, refuses
// with time_invalid.
import {TransformError} from '../_shared/error.v1.mjs';
import {DAY, formatDate, parseDate} from './_format.v1.mjs';

export const ENTRY = {name: 'time.allDayEnd', version: 1, kind: 'map',
  input: {type: 'object', properties: {date: {type: 'string', maxLength: 64}, days: {type: 'integer', minimum: 1, maximum: 3660}}, required: ['date', 'days'],
    additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {end: {type: 'string', format: 'date', maxLength: 10}}, required: ['end'], additionalProperties: false},
  maxInputBytes: 1024, maxOutputBytes: 256, usesClock: false, runtimeFacts: [], refuses: ['time_invalid'], excludes: [],
  example: {input: {date: '2026-10-01', days: 3}, output: {end: '2026-10-04'}},
  run(input) {
    const start = parseDate(input.date), end = start === null ? null : formatDate(start + input.days * DAY);
    if (end === null) throw new TransformError('time_invalid');
    return {end};
  }};

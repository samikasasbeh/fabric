// F10.8 part g (docs/F10.8-BUILD-MAP.md): time.rfc3339ToEpochSeconds@1. In: {time}, an RFC 3339 instant with its offset. Out: {seconds},
// its epoch seconds, a fraction rounded down. The compiler's pattern (lib/compiler.mjs:180) plus the ranges _format.v1.mjs checks: a
// missing offset, an offset past ±23:59, hour 24, minute 60, second 60 and a day the calendar lacks refuse with time_invalid. Gmail
// search's after and before take /seconds (part h), and so do Slack's post_at and Notion's edit-time cursor (part m).
import {TransformError} from '../_shared/error.v1.mjs';
import {SECONDS_MAX, SECONDS_MIN, floorDiv, parseInstant} from './_format.v1.mjs';

export const ENTRY = {name: 'time.rfc3339ToEpochSeconds', version: 1, kind: 'map',
  input: {type: 'object', properties: {time: {type: 'string', maxLength: 64}}, required: ['time'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {seconds: {type: 'integer', minimum: SECONDS_MIN, maximum: SECONDS_MAX}}, required: ['seconds'], additionalProperties: false},
  maxInputBytes: 1024, maxOutputBytes: 256, usesClock: false, runtimeFacts: [], refuses: ['time_invalid'], excludes: [],
  example: {input: {time: '2026-10-20T10:00:00-04:00'}, output: {seconds: 1_792_504_800}},
  run(input) {
    const instant = parseInstant(input.time);
    if (instant === null) throw new TransformError('time_invalid');
    return {seconds: floorDiv(instant.millis, 1000)};
  }};

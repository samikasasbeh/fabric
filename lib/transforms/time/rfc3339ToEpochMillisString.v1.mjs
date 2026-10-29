// F10.8 part g (docs/F10.8-BUILD-MAP.md): time.rfc3339ToEpochMillisString@1. In: {time}, an RFC 3339 instant with its offset. Out:
// {millis}, its epoch milliseconds as a decimal string, a fraction rounded down to the millisecond, as Gmail's vacation startTime and
// endTime take them (spec line 1027). Years 0000 to 9999 keep it within safe integers, as contracts/repository.mts:10 does. The same
// ranges as rfc3339ToEpochSeconds@1 refuse with time_invalid.
import {TransformError} from '../_shared/error.v1.mjs';
import {parseInstant} from './_format.v1.mjs';

export const ENTRY = {name: 'time.rfc3339ToEpochMillisString', version: 1, kind: 'map',
  input: {type: 'object', properties: {time: {type: 'string', maxLength: 64}}, required: ['time'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {millis: {type: 'string', minLength: 1, maxLength: 16}}, required: ['millis'], additionalProperties: false},
  maxInputBytes: 1024, maxOutputBytes: 256, usesClock: false, runtimeFacts: [], refuses: ['time_invalid'], excludes: [],
  example: {input: {time: '2026-10-20T10:00:00.123-04:00'}, output: {millis: '1792504800123'}},
  run(input) {
    const instant = parseInstant(input.time);
    if (instant === null) throw new TransformError('time_invalid');
    return {millis: String(instant.millis)};
  }};

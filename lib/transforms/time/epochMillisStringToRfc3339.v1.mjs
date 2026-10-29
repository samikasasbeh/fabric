// F10.8 part g (docs/F10.8-BUILD-MAP.md): time.epochMillisStringToRfc3339@1. In: {millis}, epoch milliseconds as a decimal string: an
// optional minus, then digits with no leading zero, within safe integers. Out: {time}, RFC 3339 in UTC with milliseconds
// (YYYY-MM-DDTHH:MM:SS.sssZ), so Gmail's vacation times read back exactly. Anything else, or a time outside years 0000 to 9999, refuses
// with time_invalid.
import {TransformError} from '../_shared/error.v1.mjs';
import {formatInstant} from './_format.v1.mjs';

const DECIMAL = /^-?(?:0|[1-9][0-9]{0,15})$/;

export const ENTRY = {name: 'time.epochMillisStringToRfc3339', version: 1, kind: 'map',
  input: {type: 'object', properties: {millis: {type: 'string', maxLength: 64}}, required: ['millis'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {time: {type: 'string', format: 'date-time', maxLength: 24}}, required: ['time'], additionalProperties: false},
  maxInputBytes: 1024, maxOutputBytes: 256, usesClock: false, runtimeFacts: [], refuses: ['time_invalid'], excludes: [],
  example: {input: {millis: '1792504800123'}, output: {time: '2026-10-20T14:00:00.123Z'}},
  run(input) {
    const ms = DECIMAL.test(input.millis) && input.millis !== '-0' ? Number(input.millis) : NaN;
    const time = Number.isSafeInteger(ms) ? formatInstant(ms, true) : null;
    if (time === null) throw new TransformError('time_invalid');
    return {time};
  }};

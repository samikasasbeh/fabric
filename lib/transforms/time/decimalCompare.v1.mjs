// F10.8 part g (docs/F10.8-BUILD-MAP.md): time.decimalCompare@1. In: {a, b}, two unsigned decimal strings of 1 to 20 digits, such as
// Gmail's historyId and internalDate (unsigned 64-bit values written as strings) and other high-water marks. Out: {order}: -1, 0 or 1 as
// a is below, equal to or above b, compared as BigInt, so '9' is below '10' and values past 2^53 stay exact. Anything else refuses with
// time_invalid.
import {TransformError} from '../_shared/error.v1.mjs';

const DECIMAL = /^[0-9]{1,20}$/;
/** A decimal string as BigInt; it refuses anything else. */
function decimal(text) {
  if (!DECIMAL.test(text)) throw new TransformError('time_invalid');
  return BigInt(text);
}

export const ENTRY = {name: 'time.decimalCompare', version: 1, kind: 'map',
  input: {type: 'object', properties: {a: {type: 'string', maxLength: 64}, b: {type: 'string', maxLength: 64}}, required: ['a', 'b'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {order: {type: 'integer', enum: [-1, 0, 1]}}, required: ['order'], additionalProperties: false},
  maxInputBytes: 1024, maxOutputBytes: 256, usesClock: false, runtimeFacts: [], refuses: ['time_invalid'], excludes: [],
  example: {input: {a: '9', b: '10'}, output: {order: -1}},
  run(input) {
    const a = decimal(input.a), b = decimal(input.b);
    return {order: a < b ? -1 : a > b ? 1 : 0};
  }};

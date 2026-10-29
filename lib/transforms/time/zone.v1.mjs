// F10.8 part g (docs/F10.8-BUILD-MAP.md, open question 12): time.zone@1. In: {zone}. Out: {zone}, exactly as given, when it is a name
// Intl knows, in IANA form with each part starting in upper case (UTC included), and not a case variant of the name Intl reads it as.
// Offset zones such as +05:30, which Intl accepts, and case variants such as america/toronto refuse with zone_invalid. ICU's canonical
// name is never returned, since it drifts between versions (Europe/Kyiv reads as Europe/Kiev today, measured).
import {TransformError} from '../_shared/error.v1.mjs';
import {zoneName} from './_zone.v1.mjs';

export const ENTRY = {name: 'time.zone', version: 1, kind: 'map',
  input: {type: 'object', properties: {zone: {type: 'string', maxLength: 64}}, required: ['zone'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {zone: {type: 'string', minLength: 1, maxLength: 64}}, required: ['zone'], additionalProperties: false},
  maxInputBytes: 1024, maxOutputBytes: 256, usesClock: false, runtimeFacts: ['tz'], refuses: ['zone_invalid'], excludes: [],
  example: {input: {zone: 'America/Toronto'}, output: {zone: 'America/Toronto'}},
  run(input) {
    const zone = zoneName(input.zone);
    if (zone === null) throw new TransformError('zone_invalid');
    return {zone};
  }};

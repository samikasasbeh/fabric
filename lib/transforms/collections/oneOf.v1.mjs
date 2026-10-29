// F10.8 part j (docs/F10.8-BUILD-MAP.md, R20): collections.oneOf@1, a guard. Closed: `value`, `set` (1 to 50 strings) and `fold` ('none'
// or 'ascii', A to Z only). Out: {value} when the value, folded as asked, equals one of the set's; else it refuses with not_one_of.
// - Move event: the prepared event's /eventType against ['default'] (spec lines 999, 1279).
// - Move page: the prepared page's /parent/type against the regular page parents (spec line 1404).
// Each guard runs after the prepare step it reads, so the action refuses before any write.
import {TransformError} from '../_shared/error.v1.mjs';
import {foldAscii} from '../_shared/ascii.v1.mjs';

const TEXT = {type: 'string', maxLength: 1000};

export const ENTRY = {name: 'collections.oneOf', version: 1, kind: 'guard',
  input: {type: 'object', properties: {value: TEXT, set: {type: 'array', minItems: 1, maxItems: 50, items: TEXT}, fold: {type: 'string', enum: ['none', 'ascii']}},
    required: ['value', 'set', 'fold'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {value: TEXT}, required: ['value'], additionalProperties: false},
  maxInputBytes: 65_536, maxOutputBytes: 4096, usesClock: false, runtimeFacts: [], refuses: ['not_one_of'], excludes: [],
  example: {input: {value: 'default', set: ['default'], fold: 'none'}, output: {value: 'default'}},
  run(input) {
    const fold = input.fold === 'ascii' ? foldAscii : text => text, members = new Set(input.set.map(fold));
    if (!members.has(fold(input.value))) throw new TransformError('not_one_of');
    return {value: input.value};
  }};

// F10.8 part h (docs/F10.8-BUILD-MAP.md): text.chunk@1. In: {text}. Out: {chunks}, the text in order, each chunk at most 2,000 UTF-16
// code units, which satisfies both of the spec's readings of Notion's limit (2,000 code points at spec line 670, 2,000 characters at
// line 1100). A surrogate pair at a boundary moves whole to the next chunk, so no chunk holds half a character. More than 100 chunks, the
// most rich text objects Notion takes in one array, refuses with too_many_chunks: the text is never truncated (spec lines 694, 1100). A
// lone surrogate has no form Notion can store, so it refuses with input_invalid. Empty text is no chunk. A page title is built from these
// chunks through {each} (open point Important 3), as page and block text is.
import {TransformError} from '../_shared/error.v1.mjs';

const UNITS = 2000;
const MAX_CHUNKS = 100;
const high = code => code >= 0xd800 && code <= 0xdbff;

export const ENTRY = {name: 'text.chunk', version: 1, kind: 'map',
  input: {type: 'object', properties: {text: {type: 'string', maxLength: 1_000_000}}, required: ['text'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {chunks: {type: 'array', maxItems: MAX_CHUNKS, items: {type: 'string', minLength: 1, maxLength: UNITS}}}, required: ['chunks'],
    additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 2_097_152, usesClock: false, runtimeFacts: [], refuses: ['too_many_chunks'], excludes: [],
  example: {input: {text: 'Meeting notes'}, output: {chunks: ['Meeting notes']}},
  run(input) {
    const text = input.text;
    if (!text.isWellFormed()) throw new TransformError('input_invalid');
    const chunks = [];
    for (let start = 0; start < text.length;) {
      let end = Math.min(start + UNITS, text.length);
      if (end < text.length && high(text.charCodeAt(end - 1))) end--;
      if (chunks.length === MAX_CHUNKS) throw new TransformError('too_many_chunks');
      chunks.push(text.slice(start, end));
      start = end;
    }
    return {chunks};
  }};

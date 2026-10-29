// F10.8 part h (docs/F10.8-BUILD-MAP.md): text.truncate@1. In: {text, max}, max a count of code points from 100 to 1,000,000. Out:
// {text, truncated?}. Text of at most max code points comes back whole. Longer text is cut at a code-point boundary and ends with the
// fixed marker "\n[truncated]", the whole at exactly max code points, with truncated: true (Read a canvas, spec line 1475). This is a
// read: nothing cut here is ever sent.
const MARKER = '\n[truncated]';

/** The first `count` code points of `text`, or null when it has no more than `max`. One pass. */
function cut(text, count, max) {
  let points = 0, end = -1;
  for (let index = 0; index < text.length; index++) {
    if (points === count) end = index;
    if (points === max) return text.slice(0, end);
    const code = text.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff && index + 1 < text.length) {
      const low = text.charCodeAt(index + 1);
      if (low >= 0xdc00 && low <= 0xdfff) index++;
    }
    points++;
  }
  return null;
}

export const ENTRY = {name: 'text.truncate', version: 1, kind: 'map',
  input: {type: 'object', properties: {text: {type: 'string', maxLength: 1_000_000}, max: {type: 'integer', minimum: 100, maximum: 1_000_000}}, required: ['text', 'max'],
    additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {text: {type: 'string', maxLength: 1_000_000}, truncated: {type: 'boolean', enum: [true]}}, required: ['text'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 2_097_152, usesClock: false, runtimeFacts: [], refuses: [], excludes: [],
  example: {input: {text: 'A short canvas', max: 100}, output: {text: 'A short canvas'}},
  run(input) {
    const short = cut(input.text, input.max - MARKER.length, input.max);
    return short === null ? {text: input.text} : {text: short + MARKER, truncated: true};
  }};

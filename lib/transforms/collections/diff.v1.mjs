// F10.8 part j (docs/F10.8-BUILD-MAP.md): collections.diff@1. In: {before, after}, two lists of at most 1,000 strings (the schema bound).
// Out: {add, remove}: the values of after that before lacks, in after's order, and the values of before that after lacks, in before's
// order, each value once and compared exactly. Its first user is the snapshot cursor of section 8, which compares id sets (part m). It
// declares no exclusion, so step 9 never lets its output reach a routed body pointer.
const LIST = {type: 'array', maxItems: 1000, items: {type: 'string', maxLength: 1000}};

/** The values of `list` that `other` lacks, in order, each once. */
function lacking(list, other) {
  const skip = new Set(other), out = [];
  for (const value of list) {
    if (skip.has(value)) continue;
    skip.add(value);
    out.push(value);
  }
  return out;
}

export const ENTRY = {name: 'collections.diff', version: 1, kind: 'map',
  input: {type: 'object', properties: {before: LIST, after: LIST}, required: ['before', 'after'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {add: LIST, remove: LIST}, required: ['add', 'remove'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 2_097_152, usesClock: false, runtimeFacts: [], refuses: [], excludes: [],
  example: {input: {before: ['a', 'b', 'c'], after: ['b', 'c', 'd']}, output: {add: ['d'], remove: ['a']}},
  run(input) {
    return {add: lacking(input.after, input.before), remove: lacking(input.before, input.after)};
  }};

// F10.8 part i (docs/F10.8-BUILD-MAP.md): ids.gitRefName@1. In: {name}, a branch name of 1 to 255 code points. Out: {name}, unchanged
// when it passes. The rules are git check-ref-format's ten, applied to the name under refs/heads/, so a one-level name such as main
// passes and fabric/test-<runId> passes with its slash (H7, spec line 1368):
//   1. no component starts with a dot or ends with .lock;      2. a slash somewhere (refs/heads/ gives one);
//   3. no two dots in a row;                                   4. no control, space, ~, ^ or :;
//   5. no ?, * or [;                                           6. no slash at either end and no two in a row;
//   7. no dot at the end;                                      8. no @{;
//   9. not @ alone;                                           10. no backslash.
// Two Fabric rules add to them: git's branch rule refuses a leading hyphen, and only printable ASCII passes, so no hidden or direction
// character can make a branch name read differently from what it is. Anything else refuses with ref_invalid (spec line 1063).
import {TransformError} from '../_shared/error.v1.mjs';

// Printable ASCII with no space (rule 4 and the ASCII rule), and none of ~, ^, :, ?, *, [ and backslash (rules 4, 5 and 10).
const PRINTABLE = /^[\x21-\x7e]+$/;
const FORBIDDEN = /[~^:?*[\\]/;

/** True when a branch name passes every rule above. */
function validRef(name) {
  if (!PRINTABLE.test(name) || FORBIDDEN.test(name) || name === '@' || name.startsWith('-')) return false;
  if (name.includes('..') || name.includes('@{') || name.includes('//')) return false;
  if (name.startsWith('/') || name.endsWith('/') || name.endsWith('.')) return false;
  return name.split('/').every(part => !part.startsWith('.') && !part.endsWith('.lock'));
}

export const ENTRY = {name: 'ids.gitRefName', version: 1, kind: 'map',
  input: {type: 'object', properties: {name: {type: 'string', minLength: 1, maxLength: 255}}, required: ['name'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {name: {type: 'string', minLength: 1, maxLength: 255}}, required: ['name'], additionalProperties: false},
  maxInputBytes: 2048, maxOutputBytes: 2048, usesClock: false, runtimeFacts: [], refuses: ['ref_invalid'], excludes: [],
  example: {input: {name: 'fabric/test-run1'}, output: {name: 'fabric/test-run1'}},
  run(input) {
    if (!validRef(input.name)) throw new TransformError('ref_invalid');
    return {name: input.name};
  }};

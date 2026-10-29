// F10.17 part 1 (docs/F10.17-BUILD-MAP.md part 1, F10.8 map part k): ids.repoPath@1 (unicode). In: {path}, the path of a file in a GitHub
// repository, 1 to 1,000 code points. Out: {path, workflow}, the path unchanged when it passes, and whether GitHub Actions runs it. It
// refuses path_invalid for (spec lines 1149, 1440):
//   - a slash at either end or an empty segment;            - a . or .. segment;
//   - a backslash;                                           - any percent sign, so %2e, %2F and every other encoded form;
//   - a control, hidden or direction character, or a lone surrogate, so no path reads differently from what it is;
//   - a segment over 255 code points.
// `workflow` is true when the path starts with .github/workflows/, compared with ASCII case folding, so an oddly cased path is flagged
// too: more asking, never less (open question 6). Create or update a file reads it for its card and its workflow scope.
import {TransformError} from '../_shared/error.v2.mjs';
import {foldAscii} from '../_shared/ascii.v1.mjs';
import {hasHidden} from '../_shared/hidden.v1.mjs';

const WORKFLOWS = '.github/workflows/';
const CONTROL = /[\u0000-\u001f\u007f]/;
const MAX_SEGMENT = 255;
const refuse = () => { throw new TransformError('path_invalid'); };

export const ENTRY = {name: 'ids.repoPath', version: 1, kind: 'map',
  input: {type: 'object', properties: {path: {type: 'string', minLength: 1, maxLength: 1000}}, required: ['path'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {path: {type: 'string', minLength: 1, maxLength: 1000}, workflow: {type: 'boolean'}}, required: ['path', 'workflow'], additionalProperties: false},
  maxInputBytes: 8192, maxOutputBytes: 8192, usesClock: false, runtimeFacts: ['unicode'], refuses: ['path_invalid'], excludes: [],
  example: {input: {path: 'docs/read me.md'}, output: {path: 'docs/read me.md', workflow: false}},
  run(input) {
    const path = input.path, segments = path.split('/');
    if (!path.isWellFormed() || CONTROL.test(path) || hasHidden(path)) refuse();
    if (path.includes('\\')) refuse();
    if (path.includes('%')) refuse();
    if (segments.some(segment => segment === '')) refuse();
    if (segments.some(segment => segment === '.' || segment === '..')) refuse();
    if (segments.some(segment => [...segment].length > MAX_SEGMENT)) refuse();
    return {path, workflow: foldAscii(path).startsWith(WORKFLOWS)};
  }};

// F10.17 part 1 (docs/F10.17-BUILD-MAP.md part 1, F10.8 map parts b and k): collections.stringValues@1. In: {values}, 0 to 100 {name,
// value} with string values of at most 65,535 characters. Out: an outputMap, one object of strings keyed by the names in the order given,
// placed whole at a workflow dispatch's /inputs (spec line 1442). Key rule identifier (F10.8 part b): a letter or _ first, then letters,
// digits, _ or -, at most 100, as GitHub names a workflow's inputs. It refuses name_invalid for any other name, and for a name the
// compiler refuses as an object key (lib/compiler.mjs UNSAFE_KEYS), so such a name never reaches the harness's output check; and
// name_repeated for a name given twice, compared with ASCII folding. No values give {}.
import {TransformError} from '../_shared/error.v2.mjs';
import {foldAscii} from '../_shared/ascii.v1.mjs';

const NAME = /^[A-Za-z_][A-Za-z0-9_-]*$/;
const UNSAFE_NAME = /^(?:__proto__|constructor|prototype)$/;
const VALUE = {type: 'string', maxLength: 65_535};

export const ENTRY = {name: 'collections.stringValues', version: 1, kind: 'map',
  input: {type: 'object', properties: {values: {type: 'array', maxItems: 100, items: {type: 'object', properties: {name: {type: 'string', minLength: 1, maxLength: 100}, value: VALUE},
    required: ['name', 'value'], additionalProperties: false}}}, required: ['values'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  outputMap: {key: 'identifier', maxKeys: 100, maxKeyLength: 100, value: VALUE},
  maxInputBytes: 2_097_152, maxOutputBytes: 2_097_152, usesClock: false, runtimeFacts: [], refuses: ['name_invalid', 'name_repeated'], excludes: [],
  example: {input: {values: [{name: 'env', value: 'prod'}, {name: 'dry_run', value: 'true'}]}, output: {env: 'prod', dry_run: 'true'}},
  run(input) {
    const out = new Map(), seen = new Set();
    for (const {name, value} of input.values) {
      if (!NAME.test(name) || UNSAFE_NAME.test(name)) throw new TransformError('name_invalid');
      if (seen.has(foldAscii(name))) throw new TransformError('name_repeated');
      seen.add(foldAscii(name));
      out.set(name, value);
    }
    return Object.fromEntries(out);
  }};

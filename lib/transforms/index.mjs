// F10.8 part b (docs/F10.8-BUILD-MAP.md, R16 and R17): the transform registry. It imports the harness, every error file and every family
// list, checks each listed entry with checkEntry() at import, and exports TRANSFORMS (id to frozen entry), FILES (id to its module),
// CODES (each family's codes over every error file) and runTransform(). An invalid entry stops the process at start, as reviewed data
// does in lib/option-sources.mjs. No pin is checked here (open question 16): lib/transform-pins.mjs computes and compares them.
//
// The start checks never change an output, so this file is in no hash. It may import credentialName() and secretKey(); run.mjs may not.
import {canonicalHash, checkSchema, credentialName, validateInput} from '../compiler.mjs';
import {secretKey} from '../redaction.mjs';
import {KEY_RULES, TYPE_NAME, deepFreeze, runEntry, runIn} from './run.mjs';
import {FAMILY_CODES as ERRORS_V1, TransformError} from './_shared/error.v1.mjs';
import {FAMILY_CODES as ERRORS_V2} from './_shared/error.v2.mjs';
import {FAMILY_CODES as ERRORS_V3} from './_shared/error.v3.mjs';
import {FAMILY_CODES as ERRORS_V4} from './_shared/error.v4.mjs';
import {FAMILY_CODES as ERRORS_V5} from './_shared/error.v5.mjs';
import {wellFormedPointer} from './_shared/pointer.v1.mjs';
import {ENTRIES as COLLECTIONS} from './collections.mjs';
import {ENTRIES as ENCODING} from './encoding.mjs';
import {ENTRIES as HTML_TEXT} from './html-text.mjs';
import {ENTRIES as IDS} from './ids.mjs';
import {ENTRIES as NOTION} from './notion.mjs';
import {ENTRIES as RFC5322} from './rfc5322.mjs';
import {ENTRIES as TEXT} from './text.mjs';
import {ENTRIES as TIME} from './time.mjs';

// Every error file and every family list. A later step adds its error file (_shared/error.v2.mjs and on) here, and a new family's list.
// F10.17 adds error.v2.mjs, F10.19 error.v3.mjs and the notion family, F10.21 error.v4.mjs, and Iteration 9 error.v5.mjs.
const ERROR_FILES = [ERRORS_V1, ERRORS_V2, ERRORS_V3, ERRORS_V4, ERRORS_V5];
const FAMILY_LISTS = [ENCODING, RFC5322, HTML_TEXT, TIME, TEXT, IDS, COLLECTIONS, NOTION];

const NAME = /^[a-z][a-z0-9]*\.[a-z][A-Za-z0-9]*$/;
const ARGUMENT = /^[a-z][A-Za-z0-9]{0,63}$/;
const KINDS = Object.freeze(['map', 'guard', 'schema']);
const FACTS = Object.freeze(['tz', 'charset', 'unicode']);
const FOLDS = Object.freeze(['none', 'ascii']);
const MAX_BYTES = 2_097_152;
const MAX_NOW = 8_640_000_000_000_000;
const ENTRY_KEYS = new Set(['name', 'version', 'kind', 'input', 'pointerArgs', 'stepData', 'resolvedValues', 'output', 'outputFrom', 'outputMap', 'maxInputBytes',
  'maxOutputBytes', 'usesClock', 'runtimeFacts', 'refuses', 'excludes', 'example', 'run']);
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const passes = check => { try { check(); return true; } catch { return false; } };
const exactly = (value, names) => record(value) && Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
const byteCap = value => Number.isSafeInteger(value) && value >= 1 && value <= MAX_BYTES;
const uniqueStrings = list => Array.isArray(list) && list.every(item => typeof item === 'string' && item.length > 0) && new Set(list).size === list.length;
/** A schema that is plain JSON and that checkSchema() accepts, an object at the top when `object` is set. */
const closedSchema = (schema, object = false) => record(schema) && (!object || schema.type === 'object') && passes(() => canonicalHash(schema)) && passes(() => checkSchema(schema));
/** Every property name of a schema, at any depth. */
function propertyNames(schema) {
  if (!record(schema)) return [];
  const own = record(schema.properties) ? Object.entries(schema.properties).flatMap(([name, sub]) => [name, ...propertyNames(sub)]) : [];
  return [...own, ...propertyNames(schema.items)];
}
const tokensOf = pointer => pointer === '' ? [] : pointer.slice(1).split('/').map(token => token.replace(/~1/g, '/').replace(/~0/g, '~'));

/** Each family's codes: the union of its lists over every error file. */
export const CODES = (() => {
  const union = new Map();
  for (const file of ERROR_FILES) for (const [family, codes] of Object.entries(file)) union.set(family, [...new Set([...(union.get(family) ?? []), ...codes])]);
  return new Map([...union].map(([family, codes]) => [family, Object.freeze(codes)]));
})();

/**
 * The start checks of one entry from its module `file` (relative to lib/transforms). Throws a plain Error naming the file and the
 * reason; returns nothing. Structure first, then the example, which runs through runEntry() so every harness check applies to it.
 */
export function checkEntry(entry, file) {
  const fail = reason => { throw new Error(`lib/transforms/${file}: ${reason}`); };
  if (!record(entry)) fail('an entry is an object.');
  for (const key of Object.keys(entry)) if (!ENTRY_KEYS.has(key)) fail(`unknown field ${key}.`);
  if (typeof entry.name !== 'string' || !NAME.test(entry.name)) fail('the name is family.name, as in time.allDayEnd.');
  if (!Number.isSafeInteger(entry.version) || entry.version < 1) fail('the version is a positive integer.');
  const [family, short] = entry.name.split('.'), id = `${entry.name}@${entry.version}`;
  if (file !== `${family}/${short}.v${entry.version}.mjs`) fail(`the file of ${id} is ${family}/${short}.v${entry.version}.mjs.`);
  if (typeof entry.run !== 'function') fail('run is a function.');
  if (!KINDS.includes(entry.kind)) fail('kind is map, guard or schema.');

  // The closed input, step data, resolved values and pointer arguments.
  if (!closedSchema(entry.input, true)) fail('input is a closed object schema that checkSchema() accepts.');
  const inputs = new Map(Object.entries(entry.input.properties));
  if (!record(entry.stepData)) fail('stepData maps argument names to {maxBytes}.');
  const stepData = new Map(Object.entries(entry.stepData));
  for (const [name, rule] of stepData) {
    if (!ARGUMENT.test(name) || inputs.has(name) || !exactly(rule, ['maxBytes']) || !byteCap(rule.maxBytes)) fail(`stepData ${name} is a new argument name with {maxBytes} of 1 to ${MAX_BYTES}.`);
  }
  if (!record(entry.resolvedValues)) fail('resolvedValues maps argument names to {schemaFrom, maxBytes}.');
  const resolved = new Map(Object.entries(entry.resolvedValues));
  for (const [name, rule] of resolved) {
    if (!ARGUMENT.test(name) || inputs.has(name) || stepData.has(name) || !exactly(rule, ['schemaFrom', 'maxBytes']) || !stepData.has(rule.schemaFrom) || !byteCap(rule.maxBytes)) {
      fail(`resolvedValues ${name} is a new argument name with {schemaFrom, maxBytes}, its schemaFrom a stepData argument.`);
    }
  }
  if (!uniqueStrings(entry.pointerArgs)) fail('pointerArgs lists argument names, each once.');
  for (const name of entry.pointerArgs) {
    const schema = inputs.get(name);
    if (!record(schema) || schema.type !== 'string' || !Number.isSafeInteger(schema.maxLength) || schema.maxLength > 512) fail(`pointerArgs ${name} is a string property of input with a maxLength of at most 512.`);
  }
  for (const name of [...inputs.keys(), ...propertyNames(entry.input), ...stepData.keys(), ...resolved.keys()]) if (credentialName(name)) fail(`the argument ${name} is credential-shaped.`);

  // Sizes, the clock, runtime facts and codes.
  if (!byteCap(entry.maxInputBytes)) fail(`maxInputBytes is an integer from 1 to ${MAX_BYTES}.`);
  if (!byteCap(entry.maxOutputBytes)) fail(`maxOutputBytes is an integer from 1 to ${MAX_BYTES}.`);
  if (typeof entry.usesClock !== 'boolean') fail('usesClock is true or false.');
  const now = inputs.get('now');
  if (entry.usesClock && !(record(now) && now.type === 'integer' && now.minimum >= 0 && now.maximum <= MAX_NOW && (entry.input.required ?? []).includes('now'))) {
    fail(`an entry that uses the clock declares a required integer input now with a minimum of at least 0 and a maximum of at most ${MAX_NOW}.`);
  }
  if (!entry.usesClock && (inputs.has('now') || stepData.has('now') || resolved.has('now'))) fail('an entry that does not use the clock takes no now.');
  if (!uniqueStrings(entry.runtimeFacts) || !entry.runtimeFacts.every(fact => FACTS.includes(fact))) fail('runtimeFacts lists tz, charset and unicode, each at most once.');
  if (!uniqueStrings(entry.refuses)) fail('refuses lists codes, each once.');
  // A family no error file names yet refuses with harness codes only, so F10.9's stubs of later families (notion) load.
  for (const code of entry.refuses) if (!(CODES.get(family) ?? []).includes(code)) fail(`refuses holds ${code}, which no error file lists for the ${family} family.`);

  // The output form.
  const forms = ['output', 'outputFrom', 'outputMap'].filter(key => Object.hasOwn(entry, key));
  if (entry.kind === 'map' && forms.length !== 1) fail('a map entry has exactly one of output, outputFrom and outputMap.');
  if (entry.kind === 'guard' && forms.join() !== 'output') fail('a guard entry has output only.');
  if (entry.kind === 'schema' && forms.length) fail('a schema entry has no output, outputFrom or outputMap: its result is checked as a schema and bindings.');
  if (Object.hasOwn(entry, 'output') && !closedSchema(entry.output, true)) fail('output is a closed object schema that checkSchema() accepts.');
  if (Object.hasOwn(entry, 'outputFrom')) {
    const rule = entry.outputFrom, pairs = [...resolved.values()].map(item => item.schemaFrom);
    if (!exactly(rule, ['argument', 'values']) || !pairs.includes(rule.argument)) fail('outputFrom.argument is the schemaFrom of one of the entry\'s resolvedValues.');
    const values = record(rule.values) ? Object.entries(rule.values) : [];
    if (!values.length || values.length > 64 || !values.every(([type, schema]) => TYPE_NAME.test(type) && closedSchema(schema))) fail('outputFrom.values maps 1 to 64 type names to closed schemas.');
  }
  if (Object.hasOwn(entry, 'outputMap')) {
    const rule = entry.outputMap, small = value => Number.isSafeInteger(value) && value >= 1 && value <= 100;
    if (!exactly(rule, ['key', 'maxKeys', 'maxKeyLength', 'value']) || !KEY_RULES.includes(rule.key) || !small(rule.maxKeys) || !small(rule.maxKeyLength) || !closedSchema(rule.value)) {
      fail(`outputMap is {key, maxKeys, maxKeyLength, value}: a key rule of ${KEY_RULES.join(', ')}, two integers from 1 to 100 and a closed schema.`);
    }
  }
  const outputs = [entry.output, ...(record(entry.outputFrom?.values) ? Object.entries(entry.outputFrom.values).map(([, schema]) => schema) : []), entry.outputMap?.value].filter(record);
  for (const name of outputs.flatMap(propertyNames)) if (secretKey(name)) fail(`the output property ${name} names a secret (R11).`);

  // Exclusions: only on a closed output, each naming a string field or a list of strings of it.
  if (!Array.isArray(entry.excludes)) fail('excludes is a list.');
  if (entry.excludes.length && !Object.hasOwn(entry, 'output')) fail('excludes are declared only on a closed output.');
  for (const rule of entry.excludes) {
    const keys = Object.hasOwn(rule ?? {}, 'items') ? ['pointer', 'items', 'values', 'fold'] : ['pointer', 'values', 'fold'];
    if (!exactly(rule, keys) || (Object.hasOwn(rule, 'items') && rule.items !== true) || !FOLDS.includes(rule.fold) || !uniqueStrings(rule.values) || rule.values.length > 50) {
      fail('excludes are {pointer, items?, values, fold}: items true or absent, 1 to 50 values, fold none or ascii.');
    }
    let schema = entry.output;
    for (const token of wellFormedPointer(rule.pointer) && rule.pointer ? tokensOf(rule.pointer) : [null]) schema = record(schema?.properties) ? new Map(Object.entries(schema.properties)).get(token) : undefined;
    const fits = rule.items ? schema?.type === 'array' && schema.items?.type === 'string' : schema?.type === 'string';
    if (!fits) fail(`excludes ${rule.pointer} names no ${rule.items ? 'list of strings' : 'string'} field of the output.`);
  }

  // The example: its closed part, its pointers, then a run through the harness.
  if (!exactly(entry.example, ['input', 'output']) || !record(entry.example.input)) fail('example is {input, output}.');
  const closed = Object.fromEntries(Object.entries(entry.example.input).filter(([name]) => !stepData.has(name) && !resolved.has(name)));
  if (!passes(() => validateInput(entry.input, closed))) fail('the example input fails the input schema.');
  for (const [name, pointer] of Object.entries(closed)) {
    if (entry.pointerArgs.includes(name) && (!wellFormedPointer(pointer) || tokensOf(pointer).some(token => secretKey(token)))) fail(`pointerArgs: the example's ${name} is not a well-formed pointer free of secret-shaped tokens (R11).`);
  }
  let result;
  try { result = runEntry(entry, entry.example.input); }
  catch (error) { if (error instanceof TransformError) fail(`the example refuses with ${error.code}.`); throw error; }
  if (!passes(() => canonicalHash(entry.example.output)) || canonicalHash(result) !== canonicalHash(entry.example.output)) fail('the example gives another output than the one written.');
}

function load() {
  const transforms = new Map(), files = new Map();
  for (const list of FAMILY_LISTS) {
    for (const item of list) {
      if (!exactly(item, ['file', 'entry']) || typeof item.file !== 'string') throw new Error('lib/transforms: a family list holds {file, entry} items.');
      checkEntry(item.entry, item.file);
      const id = `${item.entry.name}@${item.entry.version}`;
      if (transforms.has(id)) throw new Error(`lib/transforms/${item.file}: ${id} is listed twice.`);
      transforms.set(id, deepFreeze(item.entry));
      files.set(id, item.file);
    }
  }
  return {transforms, files};
}
const LOADED = load();
/** Every registered transform, by name@version. */
export const TRANSFORMS = LOADED.transforms;
/** Each registered transform's module, relative to lib/transforms. */
export const FILES = LOADED.files;
/** Runs a registered transform; an unknown id refuses with transform_unknown. */
export const runTransform = (id, args) => runIn(TRANSFORMS, id, args);

// F10.8 part b (docs/F10.8-BUILD-MAP.md, R14 and R17): the transform harness. runEntry() runs one entry's run() between fixed checks,
// so every transform refuses the same way and nothing unchecked goes in or comes out:
//   1. the whole of the arguments, step data and resolved values included, is plain JSON within the compiler's caps, then within the
//      entry's maxInputBytes;
//   2. the closed arguments pass the entry's input schema, and each pointer argument is a well-formed JSON pointer;
//   3. each step-data argument is present and within its maxBytes; the transform's own bounded parser checks its shape;
//   4. each resolved-values argument is within its maxBytes, its paired schema argument is a closed schema with matching bindings, and
//      the values pass that schema;
//   5. run() gets a frozen copy; a TransformError keeps its code only when the entry declares it or it is a harness code, and anything
//      else becomes transform_failed, with no message, input or stack;
//   6. the output is plain JSON within the compiler's caps, then within maxOutputBytes;
//   7. the output passes the check of its form (output, outputFrom, outputMap or a schema entry's result) and the entry's exclusions,
//      and is frozen deeply.
// It imports three compiler checks and three helpers and nothing else (scripts/transform-scan.mjs). The harness hash
// (lib/transform-pins.mjs) covers this file, those helpers, lib/compiler.mjs and the file lib/compiler.mjs imports.
import {canonicalHash, checkSchema, validateInput} from '../compiler.mjs';
import {foldAscii} from './_shared/ascii.v1.mjs';
import {HARNESS_CODES, TransformError} from './_shared/error.v1.mjs';
import {wellFormedPointer} from './_shared/pointer.v1.mjs';

const refuse = code => { throw new TransformError(code); };
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const jsonBytes = value => Buffer.byteLength(JSON.stringify(value));
/** True when `check` runs without throwing. */
const passes = check => { try { check(); return true; } catch { return false; } };
const exactly = (value, names) => record(value) && Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));

/** The key rules an outputMap may name. `identifier`: 1 to maxKeyLength ASCII characters, a letter or _ first, then letters, digits, _ or -. */
export const KEY_RULES = Object.freeze(['identifier']);
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_-]*$/;
/** A provider type name, as bindings and outputFrom value schemas name them. */
export const TYPE_NAME = /^[a-z][a-z0-9_]{0,63}$/;
/** The fixed closed schema of bindings: at most 100 {name, id, type}, one per property of the schema they bind. */
export const BINDINGS_SCHEMA = deepFreeze({type: 'array', maxItems: 100, items: {type: 'object', properties: {name: {type: 'string', minLength: 1, maxLength: 1000},
  id: {type: 'string', minLength: 1, maxLength: 256}, type: {type: 'string', minLength: 1, maxLength: 64}}, required: ['name', 'id', 'type'], additionalProperties: false}});

/** The value, frozen at every depth. */
export function deepFreeze(value) {
  if (value !== null && typeof value === 'object') {
    Object.freeze(value);
    for (const [, item] of Object.entries(value)) deepFreeze(item);
  }
  return value;
}
/** A copy of a JSON value, built with Object.fromEntries so no key can reach a prototype. */
function copy(value) {
  if (Array.isArray(value)) return value.map(item => copy(item));
  if (record(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, copy(item)]));
  return value;
}

/** True for bindings that name each property of a closed object schema once, with unique ids that are safe object keys. */
export function bindingsFit(schema, bindings) {
  if (!passes(() => validateInput(BINDINGS_SCHEMA, bindings))) return false;
  const properties = new Set(Object.keys(schema.properties)), names = new Set(), ids = new Set();
  for (const binding of bindings) {
    if (!TYPE_NAME.test(binding.type) || !properties.has(binding.name) || names.has(binding.name) || ids.has(binding.id)) return false;
    names.add(binding.name);
    ids.add(binding.id);
  }
  return names.size === properties.size && passes(() => canonicalHash(Object.fromEntries(bindings.map(binding => [binding.id, true]))));
}
/** True for {schema, bindings}: a closed object schema that checkSchema() accepts, and bindings that fit it. */
function resolvedPair(value) {
  return exactly(value, ['schema', 'bindings']) && record(value.schema) && value.schema.type === 'object' && passes(() => checkSchema(value.schema))
    && bindingsFit(value.schema, value.bindings);
}

/** The value at a pointer through objects only (an exclusion names an output field), or undefined. */
function field(value, pointer) {
  let current = value;
  for (const token of pointer.slice(1).split('/').map(part => part.replace(/~1/g, '/').replace(/~0/g, '~'))) current = record(current) ? new Map(Object.entries(current)).get(token) : undefined;
  return current;
}
/** True when an exclusion holds for the output: no value at its field, folded as declared, equals one of its values. */
function excluded(rule, output) {
  const fold = text => rule.fold === 'ascii' ? foldAscii(text) : text, values = new Set(rule.values.map(fold));
  const value = field(output, rule.pointer);
  const items = rule.items === true ? (Array.isArray(value) ? value : []) : [value];
  return items.every(item => typeof item !== 'string' || !values.has(fold(item)));
}

/** The derived closed schema of an outputFrom result: one optional property per binding whose type has a reviewed value schema. */
function outputFromSchema(rule, bindings) {
  const values = new Map(Object.entries(rule.values));
  return {type: 'object', properties: Object.fromEntries(bindings.filter(binding => values.has(binding.type)).map(binding => [binding.id, values.get(binding.type)])), additionalProperties: false};
}
function keyPasses(rule, key) {
  return rule.key === 'identifier' && key.length >= 1 && key.length <= rule.maxKeyLength && IDENTIFIER.test(key);
}

/** Runs one entry on its arguments between the harness checks. Returns the frozen output, or throws a TransformError with a fixed code. */
export function runEntry(entry, args) {
  // 1. Plain JSON, step data included: the compiler's private assertJson(), through canonicalHash(), as bounded() does.
  if (!record(args) || !passes(() => canonicalHash(args))) refuse('input_invalid');
  if (jsonBytes(args) > entry.maxInputBytes) refuse('input_too_large');
  // 2. The closed part.
  const values = new Map(Object.entries(args)), stepData = new Map(Object.entries(entry.stepData)), resolved = new Map(Object.entries(entry.resolvedValues));
  const closed = Object.fromEntries(Object.entries(args).filter(([name]) => !stepData.has(name) && !resolved.has(name)));
  if (!passes(() => validateInput(entry.input, closed))) refuse('input_invalid');
  const pointerNames = new Set(entry.pointerArgs);
  for (const [name, value] of Object.entries(closed)) if (pointerNames.has(name) && !wellFormedPointer(value)) refuse('input_invalid');
  // 3. Step data: present and within its cap.
  for (const [name, rule] of stepData) {
    if (!values.has(name)) refuse('input_invalid');
    if (jsonBytes(values.get(name)) > rule.maxBytes) refuse('input_too_large');
  }
  // 4. Resolved values: typed by their paired schema.
  for (const [name, rule] of resolved) {
    if (!values.has(name)) refuse('input_invalid');
    if (jsonBytes(values.get(name)) > rule.maxBytes) refuse('input_too_large');
    const pair = values.get(rule.schemaFrom);
    if (!resolvedPair(pair)) refuse('input_invalid');
    if (!passes(() => validateInput(pair.schema, values.get(name)))) refuse('input_invalid');
  }
  // 5. The transform itself.
  let output;
  try { output = entry.run(deepFreeze(copy(args))); }
  catch (error) {
    if (error instanceof TransformError && (entry.refuses.includes(error.code) || HARNESS_CODES.includes(error.code))) refuse(error.code);
    refuse('transform_failed');
  }
  // 6. Plain JSON within its caps.
  if (!passes(() => canonicalHash(output))) refuse('output_invalid');
  if (jsonBytes(output) > entry.maxOutputBytes) refuse('output_too_large');
  // 7. The check of the entry's output form, then its exclusions.
  if (entry.kind === 'schema') {
    if (!resolvedPair(output)) refuse('output_invalid');
  } else if (Object.hasOwn(entry, 'outputFrom')) {
    const pair = values.get(entry.outputFrom.argument);
    if (!record(output) || !resolvedPair(pair)) refuse('output_invalid');
    const schema = outputFromSchema(entry.outputFrom, pair.bindings);
    if (!passes(() => { checkSchema(schema); validateInput(schema, output); })) refuse('output_invalid');
  } else if (Object.hasOwn(entry, 'outputMap')) {
    const rule = entry.outputMap;
    if (!record(output)) refuse('output_invalid');
    const entries = Object.entries(output);
    if (entries.length > rule.maxKeys) refuse('output_invalid');
    for (const [key, value] of entries) {
      if (!keyPasses(rule, key)) refuse('output_invalid');
      if (!passes(() => validateInput(rule.value, value))) refuse('output_invalid');
    }
  } else if (!passes(() => validateInput(entry.output, output))) refuse('output_invalid');
  for (const rule of entry.excludes) if (!excluded(rule, output)) refuse('output_invalid');
  return deepFreeze(output);
}

/** Runs the entry a registry holds for `id`; an id it does not hold refuses with transform_unknown. */
export function runIn(registry, id, args) {
  const entry = registry.get(id);
  if (!entry) refuse('transform_unknown');
  return runEntry(entry, args);
}

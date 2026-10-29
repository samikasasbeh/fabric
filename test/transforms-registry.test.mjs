import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {inspect} from 'node:util';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {canonicalHash, checkSchema} from '../lib/compiler.mjs';
import {CODES, FILES, TRANSFORMS, checkEntry, runTransform} from '../lib/transforms/index.mjs';
import {runEntry} from '../lib/transforms/run.mjs';
import {FAMILY_CODES, HARNESS_CODES, TransformError} from '../lib/transforms/_shared/error.v1.mjs';
import {FAMILY_CODES as LATER_V4} from '../lib/transforms/_shared/error.v4.mjs';
import {FAMILY_CODES as FAMILY_CODES_V2, TransformError as TransformErrorV2} from '../lib/transforms/_shared/error.v2.mjs';
import {pointerReader, wellFormedPointer} from '../lib/transforms/_shared/pointer.v1.mjs';
import {hasHidden} from '../lib/transforms/_shared/hidden.v1.mjs';
import {foldAscii, isAsciiSpace, sameAscii, trimAscii} from '../lib/transforms/_shared/ascii.v1.mjs';
import {hasHidden as hostedHidden} from '../public/hosted-text.js';
import {scanTransforms} from '../scripts/transform-scan.mjs';
import {allCases, canonicalOutcome, outcome, registered} from './fixtures/transform-vectors.mjs';

// F10.8 parts a and b (docs/F10.8-BUILD-MAP.md, R14 and R16 to R18): the harness, the registry, the shared helpers and the source scan.
// Fake and spy entries run through runEntry() and checkEntry() (R17), so every branch of the harness is shown before any shipped
// transform uses it. Nothing here compares pins with the code: test/transforms-pins.test.mjs is the only test that does. (The scan reads
// imports with importsOf() from lib/transform-pins.mjs, which shape-checks pins.json when it loads and compares nothing.)
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const MIB2 = 2_097_152;
const STRING = {type: 'string', maxLength: 100};
const OBJECT = (properties, required = Object.keys(properties)) => ({type: 'object', properties, required, additionalProperties: false});
const NOW = {type: 'integer', minimum: 0, maximum: 8_640_000_000_000_000};
const FILE = 'collections/fake.v1.mjs';
/** A valid map entry of the collections family; each test changes what it needs. */
function fake(overrides = {}) {
  const entry = {name: 'collections.fake', version: 1, kind: 'map', input: OBJECT({value: STRING}), pointerArgs: [], stepData: {}, resolvedValues: {},
    output: OBJECT({value: STRING}), maxInputBytes: 4096, maxOutputBytes: 4096, usesClock: false, runtimeFacts: [], refuses: [], excludes: [],
    example: {input: {value: 'a'}, output: {value: 'a'}}, run: input => ({value: input.value}), ...overrides};
  for (const [key, value] of Object.entries(overrides)) if (value === undefined) delete entry[key];
  return entry;
}
/** A schema entry whose run() gives `result`. */
const schemaFake = (result, overrides = {}) => fake({kind: 'schema', output: undefined, run: () => result, example: {input: {value: 'a'}, output: result}, ...overrides});
const refused = code => error => {
  assert.ok(error instanceof TransformError, `expected a TransformError, got ${inspect(error)}`);
  assert.equal(error.code, code);
  assert.equal(error.message, code);
  return true;
};
const rejects = (entry, pattern, file = FILE) => assert.throws(() => checkEntry(entry, file), pattern);
/** A resolved schema argument ({resolved} of a resource-dependent input) with two writable properties. */
const PAIR = {schema: OBJECT({Status: {type: 'string', enum: ['Open', 'Done']}, Cost: {type: 'number'}}, []),
  bindings: [{name: 'Status', id: 'a%3Bb', type: 'select'}, {name: 'Cost', id: 'c1', type: 'number'}]};
const typedArgs = {stepData: {schema: {maxBytes: 65_536}}, resolvedValues: {values: {schemaFrom: 'schema', maxBytes: 4096}}, maxInputBytes: 131_072};

test('an unknown name@version refuses with transform_unknown', () => {
  for (const id of ['time.nothing@1', 'constructor', '__proto__', 'toString', '', 7]) assert.throws(() => runTransform(id, {}), refused('transform_unknown'));
});

test('every shipped entry passes checkEntry() with its file, frozen, once per id', () => {
  assert.ok(TRANSFORMS instanceof Map);
  for (const [id, entry] of TRANSFORMS) {
    assert.equal(id, `${entry.name}@${entry.version}`);
    assert.equal(FILES.get(id), `${entry.name.split('.')[0]}/${entry.name.split('.')[1]}.v${entry.version}.mjs`);
    assert.ok(Object.isFrozen(entry) && Object.isFrozen(entry.input) && Object.isFrozen(entry.example), `${id} is frozen deeply`);
    checkEntry(entry, FILES.get(id));
  }
  assert.deepEqual([...FILES.keys()].sort(), [...TRANSFORMS.keys()].sort());
  checkEntry(fake(), FILE);
});

test('checkEntry() refuses entries that break a start check', () => {
  rejects(fake({example: {input: {value: 'a'}, output: {value: 'b'}}}), /example gives another output/);
  rejects(fake({input: OBJECT({value: STRING, options: OBJECT({apiKey: STRING}, [])}, ['value'])}), /apiKey is credential-shaped/);
  rejects(fake({output: OBJECT({value: STRING, temp_clone_token: STRING}, ['value'])}), /temp_clone_token names a secret/);
  rejects(fake({input: OBJECT({value: STRING, now: NOW}, ['value'])}), /takes no now/);
  rejects(fake({usesClock: true}), /declares a required integer input now/);
  rejects(fake({refuses: ['time_invalid']}), /refuses holds time_invalid, which no error file lists for the collections family/);
  rejects(fake({refuses: ['match_none', 'match_none']}), /refuses lists codes, each once/);
  rejects(fake(), /the file of collections\.fake@1 is collections\/fake\.v1\.mjs/, 'collections/other.v1.mjs');
  rejects(fake(), /the file of/, 'time/fake.v1.mjs');
  rejects(fake(), /the file of/, 'collections/fake.v2.mjs');
  rejects(fake({excludes: [{pointer: '/ids', items: true, values: ['TRASH'], fold: 'ascii'}]}), /excludes \/ids names no list of strings/);
  rejects(fake({excludes: [{pointer: '/value', items: true, values: ['TRASH'], fold: 'ascii'}]}), /excludes \/value names no list of strings/);
  rejects(fake({excludes: [{pointer: '/value', values: ['TRASH'], fold: 'unicode'}]}), /excludes are \{pointer/);
  rejects(fake({outputMap: {key: 'identifier', maxKeys: 3, maxKeyLength: 10, value: STRING}}), /exactly one of output, outputFrom and outputMap/);
  rejects(fake({kind: 'guard', output: undefined, outputMap: {key: 'identifier', maxKeys: 3, maxKeyLength: 10, value: STRING}}), /guard entry has output only/);
  rejects(schemaFake(PAIR, {output: OBJECT({value: STRING})}), /schema entry has no output/);
  rejects(fake({...typedArgs, output: undefined, outputFrom: {argument: 'values', values: {number: OBJECT({number: {type: 'number'}})}}}), /outputFrom\.argument is the schemaFrom/);
  rejects(fake({...typedArgs, output: undefined, outputFrom: {argument: 'schema', values: {Number: OBJECT({number: {type: 'number'}})}}}), /outputFrom\.values maps/);
  rejects(fake({output: undefined, outputMap: {key: 'email', maxKeys: 3, maxKeyLength: 10, value: STRING}}), /outputMap is \{key/);
  rejects(fake({output: undefined, outputMap: {key: 'identifier', maxKeys: 101, maxKeyLength: 10, value: STRING}}), /outputMap is \{key/);
  rejects(fake({extra: true}), /unknown field extra/);
  rejects(fake({name: 'Collections.fake'}), /the name is family\.name/);
  rejects(fake({version: 0}), /version is a positive integer/);
  rejects(fake({name: 'nofamily.thing', refuses: ['match_none']}), /refuses holds match_none, which no error file lists for the nofamily family/, 'nofamily/thing.v1.mjs');
  checkEntry(fake({name: 'notion.stub'}), 'notion/stub.v1.mjs');
  rejects(fake({runtimeFacts: ['locale']}), /runtimeFacts lists/);
  rejects(fake({maxInputBytes: MIB2 + 1}), /maxInputBytes is an integer/);
  rejects(fake({maxOutputBytes: 0}), /maxOutputBytes is an integer/);
  rejects(fake({kind: 'reduce'}), /kind is map, guard or schema/);
  rejects(fake({input: OBJECT({value: {type: 'string', pattern: 'a'}})}), /input is a closed object schema/);
  rejects(fake({stepData: {value: {maxBytes: 100}}}), /stepData value is a new argument/);
  rejects(fake({stepData: {list: {maxBytes: MIB2 + 1}}}), /stepData list is a new argument/);
  rejects(fake({resolvedValues: {values: {schemaFrom: 'nothing', maxBytes: 100}}}), /resolvedValues values is a new argument/);
  rejects(fake({run: 'not a function'}), /run is a function/);
});

test('checkEntry() checks only the closed part of an example, so entries with step data load (open point Minor 2)', () => {
  const entry = fake({stepData: {list: {maxBytes: 65_536}}, maxInputBytes: 131_072, run: input => ({value: String(input.list.length)}),
    example: {input: {value: 'a', list: [1, 2]}, output: {value: '2'}}});
  checkEntry(entry, FILE);
  rejects({...entry, example: {input: {value: 'a', list: [1, 2], extra: 1}, output: {value: '2'}}}, /example input fails the input schema/);
});

test('every version module file is listed in its family list, and every listed entry has its file', () => {
  const dir = path.join(ROOT, 'lib/transforms'), onDisk = [];
  for (const folder of readdirSync(dir, {withFileTypes: true})) {
    if (!folder.isDirectory() || folder.name.startsWith('_')) continue;
    for (const name of readdirSync(path.join(dir, folder.name))) if (!name.startsWith('_') && name.endsWith('.mjs')) onDisk.push(`${folder.name}/${name}`);
  }
  assert.deepEqual([...FILES.values()].sort(), onDisk.sort());
});

test('an input one byte over maxInputBytes refuses with input_too_large before run() is called', () => {
  let calls = 0;
  const spy = fake({maxInputBytes: Buffer.byteLength(JSON.stringify({value: 'abc'})), run: input => { calls++; return {value: input.value}; }});
  assert.deepEqual(runEntry(spy, {value: 'abc'}), {value: 'abc'});
  assert.throws(() => runEntry(spy, {value: 'abcd'}), refused('input_too_large'));
  assert.equal(calls, 1);
});

test('raw step data is checked as JSON before any transform parses it', () => {
  let calls = 0;
  const run = () => { calls++; return {value: 'x'}; };
  const raw = fake({stepData: {list: {maxBytes: MIB2}}, maxInputBytes: MIB2, run});
  assert.deepEqual(runEntry(raw, {value: 'a', list: new Array(49_000).fill(0)}), {value: 'x'});
  calls = 0;
  assert.throws(() => runEntry(raw, {value: 'a', list: JSON.parse('{"__proto__": 1}')}), refused('input_invalid'), 'an own __proto__ key');
  assert.throws(() => runEntry(raw, {value: 'a', list: new Array(50_000).fill(0)}), refused('input_invalid'), '50,001 nodes within the byte caps');
  assert.throws(() => runEntry(raw, {value: 'a', list: {deep: JSON.parse(`${'['.repeat(41)}${']'.repeat(41)}`)}}), refused('input_invalid'), 'deeper than 40');
  assert.throws(() => runEntry(raw, {value: 'a'}), refused('input_invalid'), 'a step-data argument is required');
  assert.throws(() => runEntry(raw, {value: 'a', list: {text: 'x'.repeat(MIB2)}}), error => error.code === 'input_invalid' || error.code === 'input_too_large');
  const typed = fake({...typedArgs, run});
  assert.throws(() => runEntry(typed, {value: 'a', schema: PAIR, values: JSON.parse('{"constructor": "x"}')}), refused('input_invalid'), 'an own constructor key in resolved values');
  assert.throws(() => runEntry(fake(), null), refused('input_invalid'));
  assert.throws(() => runEntry(fake(), [{value: 'a'}]), refused('input_invalid'));
  assert.equal(calls, 0);
  const proto = schemaFake({schema: {type: 'object', properties: JSON.parse('{"__proto__": {"type": "string"}}'), additionalProperties: false}, bindings: [{name: '__proto__', id: 'p', type: 'rich_text'}]});
  assert.throws(() => runEntry(proto, {value: 'a'}), refused('output_invalid'), 'an own __proto__ property in a schema output');
});

test('outputs are checked for size, fields and types, and a failure carries its code and nothing else', () => {
  assert.throws(() => runEntry(fake({maxOutputBytes: 10, run: () => ({value: 'a'.repeat(20)})}), {value: 'a'}), refused('output_too_large'));
  assert.throws(() => runEntry(fake({run: () => ({value: 'a', extra: 1})}), {value: 'a'}), refused('output_invalid'));
  assert.throws(() => runEntry(fake({run: () => ({value: 1})}), {value: 'a'}), refused('output_invalid'));
  assert.throws(() => runEntry(fake({run: () => undefined}), {value: 'a'}), refused('output_invalid'));
  assert.throws(() => runEntry(fake({run: () => ({value: NaN})}), {value: 'a'}), refused('output_invalid'));
  let failure;
  try { runEntry(fake({run: input => { throw new Error(`secret text ${input.value}`); }}), {value: 'sk-live-123'}); } catch (error) { failure = error; }
  assert.ok(refused('transform_failed')(failure));
  assert.deepEqual(Object.keys(failure).sort(), ['code', 'name']);
  assert.equal(failure.cause, undefined);
  assert.ok(!inspect(failure).includes('secret text') && !inspect(failure).includes('sk-live-123'), 'no message text, input or inner stack goes with the refusal');
  assert.throws(() => runEntry(fake({refuses: ['match_none'], run: () => { throw new TransformError('match_none'); }}), {value: 'a'}), refused('match_none'));
  assert.throws(() => runEntry(fake({refuses: ['match_none'], run: () => { throw new TransformError('input_invalid'); }}), {value: 'a'}), refused('input_invalid'), 'a harness code passes');
  // Open point Minor 7: a code the entry does not declare, or one built from input text, becomes transform_failed.
  assert.throws(() => runEntry(fake({refuses: ['match_none'], run: () => { throw new TransformError('match_many'); }}), {value: 'a'}), refused('transform_failed'));
  assert.throws(() => runEntry(fake({run: input => { throw new TransformError(input.value); }}), {value: 'evil_code'}), refused('transform_failed'));
  assert.throws(() => runEntry(fake({run: input => { input.value = 'changed'; return {value: 'x'}; }}), {value: 'a'}), refused('transform_failed'), 'the input a transform sees is frozen');
  const args = {value: 'a'};
  runEntry(fake(), args);
  assert.ok(!Object.isFrozen(args), 'the caller\'s arguments are copied, never frozen in place');
  const nested = runEntry(fake({output: OBJECT({list: {type: 'array', maxItems: 2, items: OBJECT({v: STRING})}}), run: () => ({list: [{v: 'a'}]})}), {value: 'a'});
  assert.ok(Object.isFrozen(nested) && Object.isFrozen(nested.list) && Object.isFrozen(nested.list[0]), 'an output is frozen at every depth');
});

test('a schema entry\'s output is a closed schema and its bindings, checked with checkSchema() and never against an output schema (R14)', () => {
  const good = {schema: OBJECT({Name: STRING, Cost: {type: 'number'}}, []), bindings: [{name: 'Name', id: 'title', type: 'title'}, {name: 'Cost', id: 'c%3B1', type: 'number'}]};
  let touched = false;
  const spy = schemaFake(good);
  Object.defineProperty(spy, 'output', {enumerable: true, get() { touched = true; return {type: 'null'}; }});
  assert.deepEqual(runEntry(spy, {value: 'a'}), good);
  assert.equal(touched, false, 'the output schema is never read for a schema entry');
  checkEntry(schemaFake(good), FILE);
  const bad = {
    'additionalProperties true': {...good, schema: {...good.schema, additionalProperties: true}},
    'an unknown keyword': {...good, schema: OBJECT({Name: {type: 'string', pattern: 'a'}, Cost: {type: 'number'}}, [])},
    'a string at the top': {schema: STRING, bindings: []},
    'a missing binding': {...good, bindings: good.bindings.slice(0, 1)},
    'a binding of no property': {...good, bindings: [...good.bindings.slice(0, 1), {name: 'Other', id: 'o', type: 'number'}]},
    'a repeated binding id': {...good, bindings: good.bindings.map(binding => ({...binding, id: 'same'}))},
    'a repeated binding name': {...good, bindings: [good.bindings[0], {...good.bindings[0], id: 'other'}]},
    'a binding id __proto__': {...good, bindings: [good.bindings[0], {...good.bindings[1], id: '__proto__'}]},
    'a binding id constructor': {...good, bindings: [good.bindings[0], {...good.bindings[1], id: 'constructor'}]},
    'a binding type outside the type rule': {...good, bindings: [good.bindings[0], {...good.bindings[1], type: 'Number'}]},
    'a binding with an extra field': {...good, bindings: [good.bindings[0], {...good.bindings[1], hidden: true}]},
    'an extra field beside schema and bindings': {...good, extra: 1},
  };
  for (const [what, result] of Object.entries(bad)) assert.throws(() => runEntry(schemaFake(result), {value: 'a'}), refused('output_invalid'), what);
});

test('resolvedValues are typed at run time by their paired resolved schema (R14)', () => {
  const typed = fake({...typedArgs, run: input => ({value: Object.keys(input.values).sort().join()})});
  assert.deepEqual(runEntry(typed, {value: 'x', schema: PAIR, values: {Status: 'Open', Cost: 3}}), {value: 'Cost,Status'});
  const cases = {
    'an unknown property': {schema: PAIR, values: {Owner: 'x'}},
    'a wrong type': {schema: PAIR, values: {Cost: 'three'}},
    'a value outside an enum': {schema: PAIR, values: {Status: 'Maybe'}},
    'a schema that fails checkSchema()': {schema: {...PAIR, schema: OBJECT({Status: {type: 'string', pattern: 'x'}}, [])}, values: {}},
    'a schema that is not an object at the top': {schema: {schema: STRING, bindings: []}, values: {}},
    'bindings that miss a property': {schema: {...PAIR, bindings: PAIR.bindings.slice(0, 1)}, values: {}},
    'bindings with a repeated id': {schema: {...PAIR, bindings: PAIR.bindings.map(binding => ({...binding, id: 'same'}))}, values: {}},
    'a binding id __proto__': {schema: {...PAIR, bindings: [PAIR.bindings[0], {...PAIR.bindings[1], id: '__proto__'}]}, values: {}},
    'a schema argument with an extra field': {schema: {...PAIR, extra: 1}, values: {}},
    'a missing values argument': {schema: PAIR},
  };
  for (const [what, args] of Object.entries(cases)) assert.throws(() => runEntry(typed, {value: 'x', ...args}), refused('input_invalid'), what);
  assert.throws(() => runEntry(typed, {value: 'x', schema: PAIR, values: {Status: 'Open', Cost: 3}, extra: 1}), refused('input_invalid'), 'an undeclared closed argument');
  const small = fake({...typedArgs, resolvedValues: {values: {schemaFrom: 'schema', maxBytes: 10}}, run: () => ({value: 'x'})});
  assert.throws(() => runEntry(small, {value: 'x', schema: PAIR, values: {Status: 'Open', Cost: 3}}), refused('input_too_large'));
});

test('an outputFrom result is keyed by the ids its paired schema binds, each value of its type\'s reviewed shape', () => {
  const VALUES = {select: OBJECT({select: OBJECT({name: STRING})}), number: OBJECT({number: {type: 'number'}})};
  let result;
  const entry = fake({...typedArgs, output: undefined, outputFrom: {argument: 'schema', values: VALUES}, run: () => result,
    example: {input: {value: 'x', schema: PAIR, values: {Cost: 3}}, output: {c1: {number: 3}}}});
  result = {c1: {number: 3}};
  checkEntry(entry, FILE);
  const args = {value: 'x', schema: PAIR, values: {Status: 'Open', Cost: 3}};
  result = {'a%3Bb': {select: {name: 'Open'}}, c1: {number: 3}};
  assert.deepEqual(runEntry(entry, args), result);
  for (const [what, bad] of Object.entries({'a name where an id belongs': {Status: {select: {name: 'Open'}}}, 'a key no binding names': {zz: {number: 1}},
    'a select value where a number belongs': {c1: {select: {name: 'Open'}}}, 'a list': [], 'a string': 'c1'})) {
    result = bad;
    assert.throws(() => runEntry(entry, args), refused('output_invalid'), what);
  }
  // Open point Minor 12: a binding whose type has no reviewed value schema refuses only the key bound to it.
  const withFormula = {schema: OBJECT({...PAIR.schema.properties, Total: {type: 'number'}}, []), bindings: [...PAIR.bindings, {name: 'Total', id: 'f1', type: 'formula'}]};
  result = {f1: {number: 1}};
  assert.throws(() => runEntry(entry, {...args, schema: withFormula}), refused('output_invalid'), 'a key bound to a type with no value schema');
  result = {c1: {number: 3}};
  assert.deepEqual(runEntry(entry, {...args, schema: withFormula}), result);
});

test('an outputMap result passes its key rule, its key count and its value schema', () => {
  let result;
  const entry = fake({output: undefined, outputMap: {key: 'identifier', maxKeys: 3, maxKeyLength: 10, value: STRING}, run: () => result, example: {input: {value: 'a'}, output: {env: 'prod'}}});
  result = {env: 'prod'};
  checkEntry(entry, FILE);
  result = {env: 'prod', _x: '1', 'a-b': ''};
  assert.deepEqual(runEntry(entry, {value: 'a'}), result);
  const bad = {'1a': {'1a': 'x'}, 'a b': {'a b': 'x'}, 'é': {'é': 'x'}, 'an empty key': {'': 'x'}, 'an 11-character key': {abcdefghijk: 'x'}, '4 keys': {a: '1', b: '2', c: '3', d: '4'},
    'a number value': {a: 1}, 'constructor': {constructor: 'x'}, '__proto__': JSON.parse('{"__proto__": "x"}'), 'a list': ['x']};
  for (const [what, value] of Object.entries(bad)) {
    result = value;
    assert.throws(() => runEntry(entry, {value: 'a'}), refused('output_invalid'), what);
  }
});

test('declared exclusions are checked against the output at run time, folded as declared (open point Minor 6)', () => {
  let result = {ids: ['INBOX']};
  const entry = fake({output: OBJECT({ids: {type: 'array', maxItems: 10, items: STRING}, note: STRING}, ['ids']), run: () => result,
    excludes: [{pointer: '/ids', items: true, values: ['TRASH', 'SPAM'], fold: 'ascii'}, {pointer: '/note', values: ['secret'], fold: 'none'}],
    example: {input: {value: 'a'}, output: {ids: ['INBOX']}}});
  checkEntry(entry, FILE);
  assert.deepEqual(runEntry(entry, {value: 'a'}), result);
  for (const bad of [{ids: ['INBOX', 'trash']}, {ids: ['Spam']}, {ids: [], note: 'secret'}]) {
    result = bad;
    assert.throws(() => runEntry(entry, {value: 'a'}), refused('output_invalid'), JSON.stringify(bad));
  }
  result = {ids: ['TRASHED'], note: 'Secret'};
  assert.deepEqual(runEntry(entry, {value: 'a'}), result, 'fold none keeps case, and only whole values match');
});

test('pointer arguments are declared, well formed and read only through pointerReader()', () => {
  const reader = (declared, input = OBJECT({value: STRING, field: {type: 'string', maxLength: 512}})) => {
    const entry = fake({input, pointerArgs: declared, stepData: {list: {maxBytes: 65_536}}, maxInputBytes: 131_072,
      example: {input: {value: 'a', field: '/name', list: {name: 'Ann'}}, output: {value: 'Ann'}}});
    entry.run = args => ({value: String(pointerReader(entry, args)(args.list, 'field'))});
    return entry;
  };
  checkEntry(reader(['field']), FILE);
  rejects(reader([]), /example refuses with transform_failed/);
  rejects(reader(['field', 'field']), /pointerArgs lists argument names, each once/);
  rejects(reader(['field', 'value2']), /pointerArgs value2 is a string property/);
  rejects(reader(['field', 'list']), /pointerArgs list is a string property/);
  rejects(reader(['field'], OBJECT({value: STRING, field: {type: 'string', maxLength: 600}})), /pointerArgs field is a string property/);
  rejects(reader(['field'], OBJECT({value: STRING, field: {type: 'string'}})), /pointerArgs field is a string property/);
  rejects(reader(['field'], OBJECT({value: STRING, field: {type: 'integer'}})), /pointerArgs field is a string property/);
  rejects({...reader(['field']), example: {input: {value: 'a', field: '/a/temp_clone_token', list: {}}, output: {value: 'undefined'}}}, /pointerArgs: the example's field/);
  const entry = reader(['field']);
  assert.deepEqual(runEntry(entry, {value: 'a', field: '/name', list: {name: 'Bo'}}), {value: 'Bo'});
  for (const field of ['a/b', '/a~2', '/a~']) assert.throws(() => runEntry(entry, {value: 'a', field, list: {}}), refused('input_invalid'), field);
  const sneaky = reader(['field']);
  sneaky.run = args => ({value: String(pointerReader(sneaky, args)(args.list, 'value'))});
  assert.throws(() => runEntry(sneaky, {value: '/name', field: '/name', list: {name: 'Bo'}}), refused('transform_failed'), 'an undeclared name is refused at run time');
});

/** A temporary root holding a copy of lib/transforms and the lib files it imports. */
function copyRoot(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-transforms-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  cpSync(path.join(ROOT, 'lib/transforms'), path.join(root, 'lib/transforms'), {recursive: true});
  for (const file of ['compiler.mjs', 'openapi-security.mjs', 'redaction.mjs']) cpSync(path.join(ROOT, 'lib', file), path.join(root, 'lib', file));
  return root;
}
const put = (root, file, text) => { mkdirSync(path.dirname(path.join(root, file)), {recursive: true}); writeFileSync(path.join(root, file), text); };
const edit = (root, file, from, to) => {
  const text = readFileSync(path.join(root, file), 'utf8');
  assert.equal(text.split(from).length, 2, `${file} holds ${from} once`);
  writeFileSync(path.join(root, file), text.replace(from, to));
};
/** Adds the next error file after the ones the registry lists (F10.17 shipped error.v2.mjs, so a copy adds v3 or later), a fake family that
 *  refuses with its code, and both to the registry. */
function laterErrorFile(root, codes) {
  const line = /^const ERROR_FILES = \[([^\]]*)\];$/m.exec(readFileSync(path.join(root, 'lib/transforms/index.mjs'), 'utf8'));
  assert.ok(line, 'lib/transforms/index.mjs lists its error files on one line');
  const file = `error.v${line[1].split(',').length + 1}.mjs`;
  put(root, `lib/transforms/_shared/${file}`, `export {TransformError} from './error.v1.mjs';\nexport const FAMILY_CODES = Object.freeze({fake: Object.freeze(${JSON.stringify(codes)})});\n`);
  put(root, 'lib/transforms/fake/thing.v1.mjs', [
    `import {TransformError} from '../_shared/${file}';`,
    `const OBJECT = {type: 'object', properties: {refuse: {type: 'boolean'}}, required: ['refuse'], additionalProperties: false};`,
    `export const ENTRY = {name: 'fake.thing', version: 1, kind: 'map', input: OBJECT, pointerArgs: [], stepData: {}, resolvedValues: {},`,
    `  output: {type: 'object', properties: {ok: {type: 'boolean'}}, required: ['ok'], additionalProperties: false}, maxInputBytes: 100, maxOutputBytes: 100,`,
    `  usesClock: false, runtimeFacts: [], refuses: ['fake_refused'], excludes: [], example: {input: {refuse: false}, output: {ok: true}},`,
    `  run(input) { if (input.refuse) throw new TransformError('fake_refused'); return {ok: true}; }};`, ''].join('\n'));
  put(root, 'lib/transforms/fake.mjs', `import {ENTRY as thing1} from './fake/thing.v1.mjs';\n\nexport const ENTRIES = Object.freeze([{file: 'fake/thing.v1.mjs', entry: thing1}]);\n`);
  edit(root, 'lib/transforms/index.mjs', line[0], `import {FAMILY_CODES as ERRORS_NEXT} from './_shared/${file}';\nimport {ENTRIES as FAKE} from './fake.mjs';\nconst ERROR_FILES = [${line[1]}, ERRORS_NEXT];`);
  edit(root, 'lib/transforms/index.mjs', 'const FAMILY_LISTS = [', 'const FAMILY_LISTS = [FAKE, ');
}

test('a later error file adds a family and its codes without touching error.v1.mjs or the error files before it', async t => {
  const root = copyRoot(t);
  laterErrorFile(root, ['fake_refused']);
  assert.deepEqual(scanTransforms(root), [], 'the source scan accepts the later error file, the module and its list');
  const index = await import(pathToFileURL(path.join(root, 'lib/transforms/index.mjs')).href);
  assert.ok(index.TRANSFORMS.has('fake.thing@1'));
  assert.deepEqual(index.runTransform('fake.thing@1', {refuse: false}), {ok: true});
  assert.throws(() => index.runTransform('fake.thing@1', {refuse: true}), error => error.code === 'fake_refused');
  assert.deepEqual(index.CODES.get('fake'), ['fake_refused']);
  const other = copyRoot(t);
  laterErrorFile(other, ['another_code']);
  await assert.rejects(import(pathToFileURL(path.join(other, 'lib/transforms/index.mjs')).href), /fake\/thing\.v1\.mjs.*refuses/s, 'a code in no list stops the import');
});

/** True when every value `out` allows, `into` allows too. */
function fits(out, into) {
  if (!out || !into || out.type !== into.type) return false;
  if (into.enum && !(out.enum ?? [])?.length) return false;
  if (into.enum && !out.enum.every(value => into.enum.some(other => canonicalHash([value]) === canonicalHash([other])))) return false;
  if (out.type === 'string') return (out.maxLength ?? 1e6) <= (into.maxLength ?? 1e6) && (out.minLength ?? 0) >= (into.minLength ?? 0) && (!into.format || into.format === out.format);
  if (out.type === 'integer' || out.type === 'number') return (into.minimum === undefined || (out.minimum ?? -Infinity) >= into.minimum) && (into.maximum === undefined || (out.maximum ?? Infinity) <= into.maximum);
  if (out.type === 'array') return (out.maxItems ?? 10_000) <= (into.maxItems ?? 10_000) && (out.minItems ?? 0) >= (into.minItems ?? 0) && fits(out.items, into.items);
  if (out.type === 'object') return Object.entries(out.properties).every(([key, schema]) => Object.hasOwn(into.properties, key) && fits(schema, into.properties[key])) && (into.required ?? []).every(key => (out.required ?? []).includes(key));
  return true;
}
const WIRED = ['rfc5322.replyHeaders@1', 'rfc5322.build@1', 'rfc5322.decodeGmailPayload@1', 'html.toText@1', 'time.rfc3339ToEpochSeconds@1', 'text.gmailQuery@1', 'collections.labelIds@1', 'collections.findBy@1', 'collections.missing@1'];
const missingFrom = ids => ids.filter(id => !registered(id));
test('wiring (R1): each output a section 5 action picks has the shape of the argument it feeds', {todo: missingFrom(WIRED).length ? `waits for ${missingFrom(WIRED).join(', ')}` : false}, () => {
  if (missingFrom(WIRED).length) return;
  const entry = id => TRANSFORMS.get(id);
  const reply = entry('rfc5322.replyHeaders@1'), build = entry('rfc5322.build@1');
  for (const field of ['to', 'cc', 'subject', 'inReplyTo', 'references']) assert.equal(canonicalHash(reply.output.properties[field]), canonicalHash(build.input.properties[field]), `replyHeaders /${field} is exactly build's ${field}`);
  assert.ok(fits(entry('rfc5322.decodeGmailPayload@1').output.properties.html, entry('html.toText@1').input.properties.html));
  for (const field of ['after', 'before']) assert.ok(fits(entry('time.rfc3339ToEpochSeconds@1').output.properties.seconds, entry('text.gmailQuery@1').input.properties[field]), field);
  const labels = entry('collections.labelIds@1');
  assert.deepEqual(labels.output.properties.ids.items.type, 'string');
  assert.deepEqual(labels.excludes, [{pointer: '/ids', items: true, values: ['SENT', 'DRAFT', 'TRASH', 'SPAM'], fold: 'ascii'}]);
  for (const [id, field] of [['collections.findBy@1', 'matches'], ['collections.missing@1', 'missing']]) {
    const schema = entry(id).output.properties[field];
    assert.equal(schema.type, 'array');
    assert.ok(schema.maxItems <= 100, `${id} /${field} is a bounded list`);
  }
  assert.deepEqual([...entry('collections.findBy@1').pointerArgs].sort(), ['field', 'id', 'items', 'label']);
  assert.deepEqual([...entry('collections.missing@1').pointerArgs].sort(), ['field', 'items']);
});

test('every vector of every fixture file gives byte-identical canonical JSON twice, and outputs are frozen', () => {
  const cases = allCases().filter(({item}) => registered(item.transform));
  for (const {list, item} of cases) {
    assert.equal(canonicalOutcome(item), canonicalOutcome(item), `${list}: ${item.name}`);
    const result = outcome(item);
    if (result.output) {
      const frozen = value => value === null || typeof value !== 'object' || (Object.isFrozen(value) && Object.values(value).every(frozen));
      assert.ok(frozen(result.output), `${list}: ${item.name} is frozen deeply`);
    }
  }
});

test('a child process in another zone and locale gives byte-identical outputs for every vector', () => {
  const helper = pathToFileURL(fileURLToPath(new URL('./fixtures/transform-vectors.mjs', import.meta.url))).href;
  const script = `import {allCases, canonicalOutcome, registered} from ${JSON.stringify(helper)};
    const lines = allCases().filter(({item}) => registered(item.transform)).map(({list, item}) => list + ' ' + item.name + ' ' + canonicalOutcome(item));
    process.stdout.write(JSON.stringify({offset: new Date(0).getTimezoneOffset(), lines}));`;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script], {cwd: ROOT, encoding: 'utf8', env: {PATH: process.env.PATH, TZ: 'Pacific/Chatham', LC_ALL: 'tr_TR.UTF-8', LANG: 'tr_TR.UTF-8'}});
  assert.equal(child.status, 0, child.stderr);
  const {offset, lines} = JSON.parse(child.stdout);
  assert.ok(offset === -765 || offset === -825, 'the child runs in Pacific/Chatham');
  const here = allCases().filter(({item}) => registered(item.transform)).map(({list, item}) => `${list} ${item.name} ${canonicalOutcome(item)}`);
  assert.deepEqual(lines, here);
});

// The output fields a clock transform's `now` may change; every shipped entry with usesClock is listed here.
const CLOCK_FIELDS = Object.freeze({'rfc5322.build@1': ['raw', 'bytes'], 'time.window@1': []});
test('the clock is an input: only entries with usesClock take now, and now changes only their documented fields', () => {
  const clock = fake({usesClock: true, input: OBJECT({value: STRING, now: NOW}), output: OBJECT({value: STRING, at: {type: 'integer'}}),
    example: {input: {value: 'a', now: 5}, output: {value: 'a', at: 5}}, run: input => ({value: input.value, at: input.now})});
  checkEntry(clock, FILE);
  assert.deepEqual(runEntry(clock, {value: 'a', now: 7}), runEntry(clock, {value: 'a', now: 7}));
  assert.deepEqual(runEntry(clock, {value: 'a', now: 8}), {value: 'a', at: 8});
  rejects(fake({usesClock: true, input: OBJECT({value: STRING, now: {type: 'integer'}})}), /declares a required integer input now/);
  rejects(fake({usesClock: true, input: OBJECT({value: STRING, now: NOW}, ['value'])}), /declares a required integer input now/);
  assert.throws(() => runEntry(fake(), {value: 'a', now: 1}), refused('input_invalid'));
  for (const [id, entry] of TRANSFORMS) {
    if (!entry.usesClock) { assert.throws(() => runEntry(entry, {...entry.example.input, now: 1_792_504_800_000}), refused('input_invalid'), id); continue; }
    assert.ok(Object.hasOwn(CLOCK_FIELDS, id), `${id} uses the clock: list the fields now may change`);
    const later = runEntry(entry, {...entry.example.input, now: entry.example.input.now + 1000}), first = runEntry(entry, entry.example.input);
    const changed = Object.keys({...first, ...later}).filter(key => canonicalHash([first[key] ?? null]) !== canonicalHash([later[key] ?? null]));
    assert.ok(changed.every(key => CLOCK_FIELDS[id].includes(key)), `${id}: ${changed.join(', ')}`);
  }
});

test('the source scan finds nothing in the shipped tree', () => {
  assert.deepEqual(scanTransforms(ROOT), []);
});

/** A scan of one file in an otherwise empty root. */
function scanOne(t, file, text, extra = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-scan-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  put(root, `lib/transforms/${file}`, text);
  for (const [name, body] of Object.entries(extra)) put(root, `lib/transforms/${name}`, body);
  return scanTransforms(root);
}
const moduleWith = (body, facts = []) => `export const ENTRY = {runtimeFacts: ${JSON.stringify(facts)}, run(input) {\n  ${body}\n}};\n`;
const VERSION = 'collections/probe.v1.mjs';
const REFUSED = [
  ['performance.now()', 'return performance.now();', 'global'],
  ['console.log(x)', 'console.log(input); return {};', 'global'],
  ['navigator.language', 'return {value: navigator.language};', 'global'],
  ['new WebSocket(u)', 'return new WebSocket(input.u);', 'global'],
  ['globalThis[\'Da\' + \'te\']', 'return globalThis[\'Da\' + \'te\'];', 'global'],
  ['Math[name]()', 'return Math[input.name]();', 'computed'],
  ['x.constructor', 'return input.constructor;', 'name'],
  ['new Date(s) outside _shared/utc.v1.mjs', 'return {at: new Date(input.s)};', 'date'],
  ['Date.parse(s)', 'return {at: Date.parse(input.s)};', 'date'],
  ['Date.UTC outside _shared/utc.v1.mjs', 'return {at: Date.UTC(2026, 0, 1)};', 'date'],
  ['a local-time Date method', 'return {at: input.d.getHours()};', 'date'],
  ['s.toLowerCase() without unicode', 'return {value: input.s.toLowerCase()};', 'fact'],
  ['/a/i without unicode', 'return {value: /a/i.test(input.s)};', 'fact'],
  ['/\\s/ without unicode', 'return {value: /\\s/.test(input.s)};', 'fact'],
  ['s.trim() without unicode', 'return {value: input.s.trim()};', 'fact'],
  ['/\\p{L}/u without unicode', 'return {value: /\\p{L}/u.test(input.s)};', 'fact'],
  ['a.localeCompare(b)', 'return {value: input.a.localeCompare(input.b)};', 'member'],
  ['toLocaleString', 'return {value: input.n.toLocaleString()};', 'member'],
  ['a TextDecoder label other than utf-8 without charset', 'return {value: new TextDecoder(\'latin1\').decode(input.b)};', 'fact'],
  ['Intl.DateTimeFormat without tz', 'return {value: new Intl.DateTimeFormat(\'en-US\').format(0)};', 'fact'],
  ['Intl.Collator', 'return {value: new Intl.Collator(\'en\').compare(input.a, input.b)};', 'member'],
  ['/(a+)+/', 'return {value: /(a+)+$/.test(input.s)};', 'regex'],
  ['/(\\d*)*/', 'return {value: /(\\d*)*$/.test(input.s)};', 'regex'],
  ['/(?:a|b?)+/', 'return {value: /(?:a|b?)+$/.test(input.s)};', 'regex'],
  ['new RegExp(s)', 'return {value: new RegExp(input.s).test(\'a\')};', 'global'],
  ['import(s)', 'return import(input.s);', 'import'],
  ['import.meta', 'return {url: import.meta.url};', 'meta'],
  // Open point Important 6: writes to globals and prototypes, prototype names, built keys and aliases.
  ['Number.isSafeInteger = ...', 'Number.isSafeInteger = () => true; return {};', 'write'],
  ['Math.floor = ...', 'Math.floor = Math.ceil; return {};', 'write'],
  ['Math.floor += ...', 'Math.floor += 1; return {};', 'write'],
  ['delete Math.max', 'delete Math.max; return {};', 'write'],
  ['undefined = 1', 'undefined = 1; return {};', 'write'],
  ['[].__proto__.includes = ...', '[].__proto__.includes = () => true; return {};', 'name'],
  ['x.prototype', 'return {value: input.prototype};', 'name'],
  ['x[\'__proto__\']', 'return {value: input[\'__proto__\']};', 'name'],
  ['a constructor property name', 'return {constructor: 1};', 'name'],
  ['f[\'constr\' + \'uctor\']', 'const f = () => 1; return {value: f[\'constr\' + \'uctor\']};', 'computed'],
  ['a computed key from an argument', 'const key = input.k; return {value: input.list[key]};', 'computed'],
  ['a destructured computed key', 'const {[input.k]: value} = input.list; return {value};', 'computed'],
  ['Object.defineProperty', 'Object.defineProperty(input, \'x\', {value: 1}); return {};', 'member'],
  ['Object.assign', 'return Object.assign({}, input);', 'member'],
  ['JSON.parse', 'return JSON.parse(input.s);', 'member'],
  ['Buffer.alloc', 'return {value: Buffer.alloc(4).length};', 'member'],
  ['a global as a value', 'const M = Math; return {value: M.max(1, 2)};', 'alias'],
  ['a global as an argument', 'return {value: [1, 2].map(Number)};', 'alias'],
  ['a global called that is only constructed', 'return {value: Map()};', 'alias'],
  ['shadowing a global', 'const Date = 1; return {value: Date};', 'shadow'],
  ['shadowing a global with a parameter', 'const f = Math => Math; return {value: f(1)};', 'shadow'],
  ['sort without a comparator', 'return {value: input.list.sort()};', 'sort'],
  ['eval', 'return eval(input.s);', 'global'],
  ['require', 'return require(input.s);', 'global'],
  ['process.env', 'return {value: process.env.HOME};', 'global'],
  // A key is a number by construction only when every way it gets a value gives a number: ||=, ??= and += keep a string, and a
  // for-of or for-in target takes each item or key. Each of these reaches f.constructor, and so Function, when input.s is 'constructor'.
  ['a key kept by ||=', 'let k = input.s; const f = () => 1; return {value: f[k ||= 1]};', 'computed'],
  ['a key kept by ??=', 'let k = input.s; const f = () => 1; return {value: f[k ??= 1]};', 'computed'],
  ['a key built by +=', 'let k = input.s; const f = () => 1; return {value: f[k += 1]};', 'computed'],
  ['a destructured key kept by ||=', 'let k = input.s; const f = () => 1; const {[k ||= 1]: v} = f; return {value: v};', 'computed'],
  ['a for-of target used as a key', 'let k = 0; const f = () => 1; for (k of input.list) return {value: f[k]}; return {};', 'computed'],
  ['a for-in target used as a key', 'let k = 0; const f = () => 1; for (k in input.obj) return {value: f[k]}; return {};', 'computed'],
  ['a for-of pattern target used as a key', 'let k = 0; const f = () => 1; for ([k] of input.list) return {value: f[k]}; return {};', 'computed'],
  // The legacy accessors reach prototypes by a name built at run time: ({}).__lookupGetter__('__pro' + 'to__').call([]) is Array.prototype.
  ['__lookupGetter__', 'const proto = ({}).__lookupGetter__(\'__pro\' + \'to__\').call([]); proto.includes = () => true; return {};', 'name'],
  ['__lookupSetter__', 'return {value: typeof input.__lookupSetter__};', 'name'],
  ['__defineGetter__', 'input.list.__defineGetter__(\'x\', () => 1); return {};', 'name'],
  ['__defineSetter__', 'return {value: input[\'__defineSetter__\']};', 'name'],
];
test('the source scan refuses each break of the determinism rules (R18, open point Important 6)', t => {
  for (const [what, body, rule] of REFUSED) {
    const findings = scanOne(t, VERSION, moduleWith(body));
    assert.ok(findings.some(finding => finding.rule === rule && finding.file === `lib/transforms/${VERSION}`), `${what}: wanted a ${rule} finding, got ${inspect(findings)}`);
  }
});

const CLEAN = [
  'let total = 0; for (let i = 0; i < input.s.length; i++) total += input.s.charCodeAt(i); return {value: total};',
  'const bytes = new Uint8Array(4); for (let i = 0; i < 4; i++) bytes[i] = i * 2; return {value: bytes[bytes.length - 1] + bytes[0]};',
  'const list = [3, 1, 2]; return {value: list.sort((a, b) => a - b)[1 + 1]};',
  'const seen = new Map([[input.k, 1]]); return {value: seen.get(input.k) ?? 0};',
  'if (!Number.isSafeInteger(input.n) || !Array.isArray(input.list)) return {}; return {value: Object.keys(input).length};',
  'return Object.freeze({value: String.fromCharCode(65) + JSON.stringify(input.list) + Math.max(1, 2)});',
  'return {value: /^[A-Z][a-z0-9_-]*$/g.test(input.s) && /^(?:\\.([0-9]+))?$/.test(input.t) && /([a-z]{2})+/.test(input.u)};',
  'return {value: new TextDecoder(\'utf-8\', {fatal: true}).decode(new TextEncoder().encode(input.s))};',
  'return {value: input.b instanceof Uint8Array && typeof BigInt === \'function\' && BigInt(input.n) > 0n};',
  'class Refusal extends Error {} return {value: new Refusal(\'x\') instanceof Error ? undefined : NaN};',
  'return {value: input[\'name\'] ?? input.list[0] ?? input.list[-1 + 1]};',
  'let n = 0; n += 2; n -= 1; n ||= 1; n ??= 0; const list = [5, 6, 7]; for (const item of list) n = Math.max(n, item - 5); return {value: list[n] + list[n -= 1]};',
];
test('the source scan accepts the forms transforms are written in', t => {
  for (const body of CLEAN) assert.deepEqual(scanOne(t, VERSION, moduleWith(body)), [], body);
  assert.deepEqual(scanOne(t, VERSION, moduleWith('return {value: input.s.toLowerCase().trim() + new Intl.DateTimeFormat(\'en-US\').format(0) + new TextDecoder(\'latin1\').decode(input.b)};', ['charset', 'tz', 'unicode'])), []);
});

test('the source scan reads imports, exports and file names by the import rule (R18)', t => {
  const one = (file, text, extra) => scanOne(t, file, text, extra).map(finding => finding.rule);
  assert.ok(one(VERSION, `import {readFileSync} from 'node:fs';\n${moduleWith('return {};')}`).includes('import'), 'a node: import');
  assert.ok(one(VERSION, `import {canonicalHash} from '../../compiler.mjs';\n${moduleWith('return {};')}`).includes('import'), 'a version module importing the compiler');
  assert.ok(one(VERSION, `import {ENTRY as other} from './other.v1.mjs';\n${moduleWith('return {};')}`, {'collections/other.v1.mjs': moduleWith('return {};')}).includes('import'), 'a version module importing another');
  assert.ok(one(VERSION, `import {x} from '../time/_zones.v1.mjs';\n${moduleWith('return {};')}`).includes('import'), 'another family\'s helper');
  assert.ok(one(VERSION, `import * as ascii from '../_shared/ascii.v1.mjs';\n${moduleWith('return {};')}`).includes('import'), 'a namespace import');
  assert.ok(one(VERSION, `import '../_shared/ascii.v1.mjs';\n${moduleWith('return {};')}`).includes('import'), 'a side-effect import');
  assert.deepEqual(one(VERSION, `import {foldAscii} from '../_shared/ascii.v1.mjs';\nimport {TransformError} from '../_shared/error.v1.mjs';\n${moduleWith('return {value: foldAscii(input.s), e: TransformError};')}`), []);
  assert.ok(one('run.mjs', `import {credentialName} from '../compiler.mjs';\nexport const x = credentialName;\n`).includes('import-name'), 'run.mjs importing a name outside its three');
  assert.deepEqual(one('run.mjs', `import {canonicalHash, checkSchema, validateInput} from '../compiler.mjs';\nexport const x = [canonicalHash, checkSchema, validateInput];\n`), []);
  assert.ok(one('run.mjs', `import {pointerReader} from './_shared/pointer.v1.mjs';\nexport const x = pointerReader;\n`).includes('import-name'), 'run.mjs reading pointers');
  assert.ok(one('index.mjs', `import {secretKey, scrubValue} from '../redaction.mjs';\nexport const x = [secretKey, scrubValue];\n`).includes('import-name'), 'index.mjs importing a redaction name outside secretKey');
  assert.ok(one('_shared/error.v2.mjs', `import {foldAscii} from './ascii.v1.mjs';\nexport const FAMILY_CODES = {x: [foldAscii('A')]};\n`).includes('import'), 'error v2 importing anything but v1');
  assert.deepEqual(one('_shared/error.v2.mjs', `export {TransformError} from './error.v1.mjs';\nexport const FAMILY_CODES = Object.freeze({});\n`), []);
  assert.ok(one('_shared/error.v1.mjs', `import {foldAscii} from './ascii.v1.mjs';\nexport const X = foldAscii;\n`).includes('import'), 'error v1 imports nothing');
  assert.ok(one('collections.mjs', `import {run} from './collections/probe.v1.mjs';\nexport const ENTRIES = [run];\n`).includes('import-name'), 'a family list imports ENTRY only');
  assert.ok(one('collections.mjs', `import {ENTRY as other} from './time/zone.v1.mjs';\nexport const ENTRIES = [other];\n`).includes('import'), 'a family list imports its own folder only');
  assert.ok(one(VERSION, `${moduleWith('return {};')}export const OTHER = 1;\n`).includes('export'), 'a version module exports ENTRY only');
  assert.ok(one('_shared/pointer.v1.mjs', 'export function wellFormedPointer() {}\nexport function pointerReader() {}\nexport function readAnywhere() {}\n').includes('export'), 'the pointer helper exports two functions');
  assert.ok(one('notes.txt', 'hello').includes('file'), 'an unexpected file');
  assert.deepEqual(one(VERSION, moduleWith('return {};'), {'.DS_Store': 'x', '_shared/.DS_Store': 'x'}), [], 'dot files are skipped, as scripts/check.mjs skips them');
  assert.ok(one(VERSION, `import {x} from './.hidden.mjs';\n${moduleWith('return {value: x};')}`, {'collections/.hidden.mjs': 'export const x = 1;\n'}).includes('import'), 'no import may name a dot file');
  assert.ok(one('collections/deeper/x.v1.mjs', moduleWith('return {};')).includes('file'), 'a nested folder');
  assert.ok(one(VERSION, 'export const ENTRY = {run() { return {}; }};\n').includes('fact'), 'runtimeFacts must be a literal list');
  assert.ok(one(VERSION, 'export const ENTRY = {runtimeFacts: [], run() { with (Math) { return {}; } }};\n').includes('syntax'), 'with');
  assert.ok(one(VERSION, `import {} from '../_shared/ascii.v1.mjs';\n${moduleWith('return {};')}`).includes('import'), 'an empty named import is a side-effect import');
});

test('the source scan reads each import exactly as lib/transform-pins.mjs reads it, so a pin covers every helper a module reaches', t => {
  // sourcesOf() follows import lines with its own fixed reader (open point Minor 13). An import that the parser sees and the reader
  // misses would leave a helper out of the pin, so a later edit to that helper would move no pin (decision 4).
  const user = head => `${head}${moduleWith('return {value: hasHidden(input.s)};', ['unicode'])}`;
  const MISREAD = {
    'from on the next line': 'import {hasHidden} from\n  \'../_shared/hidden.v1.mjs\';\n',
    'import on its own line': 'import\n{hasHidden} from \'../_shared/hidden.v1.mjs\';\n',
    'two imports on one line': 'import {TransformError} from \'../_shared/error.v1.mjs\'; import {hasHidden} from \'../_shared/hidden.v1.mjs\';\nconst unused = TransformError;\n',
    'a comment before the import': '/* the rule */ import {hasHidden} from \'../_shared/hidden.v1.mjs\';\n',
    'an import line inside a comment': 'import {hasHidden} from \'../_shared/hidden.v1.mjs\';\n/*\nimport {foldAscii} from \'../_shared/ascii.v1.mjs\';\n*/\n',
  };
  for (const [what, head] of Object.entries(MISREAD)) {
    const findings = scanOne(t, VERSION, user(head));
    assert.ok(findings.some(finding => finding.rule === 'import-form' && finding.file === `lib/transforms/${VERSION}`), `${what}: ${inspect(findings)}`);
  }
  assert.deepEqual(scanOne(t, VERSION, user('import {hasHidden} from \'../_shared/hidden.v1.mjs\';\nimport {\n  foldAscii,\n  trimAscii,\n} from "../_shared/ascii.v1.mjs";\nconst both = [foldAscii, trimAscii];\n')), [],
    'one import per line, braces over several lines, either quote');
  assert.deepEqual(scanOne(t, '_shared/error.v2.mjs', 'export {TransformError} from \'./error.v1.mjs\';\nexport const FAMILY_CODES = Object.freeze({});\n'), [], 'a named re-export');
});

test('a regex with the g or y flag is written inside the function that uses it, so no call starts from another call\'s lastIndex', t => {
  for (const flags of ['g', 'y', 'gi']) {
    const findings = scanOne(t, VERSION, `const RE = /a/${flags};\n${moduleWith('return {value: RE.test(input.s)};', ['unicode'])}`);
    assert.ok(findings.some(finding => finding.rule === 'regex' && finding.line === 1), `/a/${flags} at the top level: ${inspect(findings)}`);
  }
  assert.deepEqual(scanOne(t, VERSION, `const RE = /^a$/;\n${moduleWith('const all = /a/g; return {value: RE.test(input.s) && input.s.replace(all, \'b\') && /a/y.exec(input.s)};')}`), []);
  assert.ok(scanOne(t, '_shared/probe.v1.mjs', 'const QUOTE = /"/g;\nexport const unquote = text => text.replace(QUOTE, \'\');\n').some(finding => finding.rule === 'regex'), 'a helper too');
});

test('the scan reads runtimeFacts where the entry keeps it: once, with no spread or computed key after it', t => {
  const lower = 'run(input) { return {value: input.s.toLowerCase()}; }';
  for (const [what, text] of [['a second runtimeFacts', `export const ENTRY = {runtimeFacts: ['unicode'], runtimeFacts: [], ${lower}};\n`],
    ['a spread after it', `const BASE = {runtimeFacts: []};\nexport const ENTRY = {runtimeFacts: ['unicode'], ...BASE, ${lower}};\n`],
    ['a computed key after it', `const KEY = 'runtime' + 'Facts';\nexport const ENTRY = {runtimeFacts: ['unicode'], [KEY]: [], ${lower}};\n`]]) {
    assert.ok(scanOne(t, VERSION, text).some(finding => finding.rule === 'fact'), what);
  }
  assert.deepEqual(scanOne(t, VERSION, `const BASE = {kind: 'map'};\nexport const ENTRY = {...BASE, runtimeFacts: ['unicode'], ${lower}};\n`), [], 'a spread before it is overridden by it');
});

test('the source scan requires each entry to declare the runtime facts its helpers use (open point Minor 3)', t => {
  const helper = {'_shared/probe.v1.mjs': 'export const letter = text => /\\p{L}/u.test(text);\n'};
  const user = facts => `import {letter} from '../_shared/probe.v1.mjs';\n${moduleWith('return {value: letter(input.s)};', facts)}`;
  assert.ok(scanOne(t, VERSION, user([]), helper).some(finding => finding.rule === 'fact' && finding.file === `lib/transforms/${VERSION}`));
  assert.deepEqual(scanOne(t, VERSION, user(['unicode']), helper), []);
  const nested = {'_shared/probe.v1.mjs': 'import {zoned} from \'./zones.v1.mjs\';\nexport const letter = zoned;\n', '_shared/zones.v1.mjs': 'export const zoned = () => new Intl.DateTimeFormat(\'en-US\', {timeZone: \'UTC\'}).format(0);\n'};
  assert.ok(scanOne(t, VERSION, user(['unicode']), nested).some(finding => finding.rule === 'fact' && finding.message.includes('tz')));
  assert.ok(scanOne(t, 'run.mjs', 'export const lower = text => text.toLowerCase();\n').some(finding => finding.rule === 'fact'), 'the harness reads no runtime fact');
  assert.ok(scanOne(t, 'run.mjs', 'import {foldAscii} from \'./_shared/ascii.v1.mjs\';\nexport const lower = foldAscii;\n', {'_shared/ascii.v1.mjs': 'export const foldAscii = text => text.toLowerCase();\n'}).some(finding => finding.rule === 'fact'), 'nor does a helper the harness imports');
  // The hidden-character rule is a regex literal with \p{...} and the u flag, so a module that uses it declares unicode.
  assert.match(readFileSync(path.join(ROOT, 'lib/transforms/_shared/hidden.v1.mjs'), 'utf8'), /\/\(\?!\[\\t\\n\\r\]\)\[\\p\{Cc\}/);
});

test('Date appears only in _shared/utc.v1.mjs, as Date.UTC or new Date(ms) after a safe-integer check', t => {
  const utc = '_shared/utc.v1.mjs';
  assert.deepEqual(scanOne(t, utc, 'export function at(ms) {\n  if (!Number.isSafeInteger(ms)) return null;\n  const date = new Date(ms);\n  return date.getUTCFullYear() + Date.UTC(2026, 0, 1);\n}\n'), []);
  for (const body of ['export const at = ms => new Date(ms).getUTCDate();\n', 'export const at = text => new Date(text, 1).getUTCDate();\n', 'export const at = () => Date.now();\n',
    'export const at = text => Date.parse(text);\n', 'export const at = () => new Date().getUTCDate();\n', 'export const D = Date;\n',
    'export function at(ms) { const date = new Date(ms); if (!Number.isSafeInteger(ms)) return null; return date; }\n']) {
    assert.ok(scanOne(t, utc, body).some(finding => finding.rule === 'date'), body);
  }
});

const ADVERSARIAL = [
  ['html.toText@1', '100,000 < with no >', () => ({html: '<'.repeat(100_000)})],
  ['html.toText@1', '10,000 nested unclosed tags', () => ({html: '<div>'.repeat(10_000)})],
  ['rfc5322.decodeRaw@1', 'a MIME tree 8 deep with 100 parts', () => ({raw: Buffer.from(nestedMime(8, 100)).toString('base64url')})],
  ['text.gmailQuery@1', 'a 1,000,000-character query value', () => ({words: 'a'.repeat(1_000_000)})],
  ['rfc5322.parseAddresses@1', '100,000 nested comments in an address', () => ({value: `${'('.repeat(100_000)}a@example.com`})],
  ['rfc5322.decodeHeader@1', '10,000 encoded-words in one header', () => ({value: new Array(10_000).fill('=?UTF-8?Q?a?=').join(' ')})],
  ['collections.findBy@1', 'findBy at its 1,000-item cap', () => ({list: {items: Array.from({length: 1000}, (_, i) => ({id: `U${i}`, email: `u${i}@example.com`}))}, items: '/items', field: '/email', id: '/id', value: 'u999@example.com', fold: 'ascii', require: 'any'})],
  ['collections.mergeEmails@1', 'mergeEmails at its caps', () => ({event: {attendees: Array.from({length: 1000}, (_, i) => ({email: `g${i}@example.com`, responseStatus: 'accepted'}))}, add: Array.from({length: 100}, (_, i) => `n${i}@example.com`), remove: [], owner: 'owner@example.com'})],
  ['collections.labelIds@1', 'labelIds at its caps', () => ({list: {labels: Array.from({length: 1000}, (_, i) => ({id: `Label_${i}`, name: `Name ${i}`}))}, names: Array.from({length: 100}, (_, i) => `name ${i}`)})],
  ['collections.diff@1', 'diff at its caps', () => ({before: Array.from({length: 1000}, (_, i) => `a${i}`), after: Array.from({length: 1000}, (_, i) => `b${i}`)})],
];
/** A raw message whose multipart parts nest `depth` levels, with `parts` parts in all. */
function nestedMime(depth, parts) {
  const lines = ['From: a@example.com', 'Subject: deep', 'MIME-Version: 1.0'];
  const open = level => lines.push(`Content-Type: multipart/mixed; boundary="b${level}"`, '', `--b${level}`);
  for (let level = 1; level < depth; level++) open(level);
  for (let index = 0; index < parts - (depth - 1); index++) lines.push('Content-Type: text/plain; charset=UTF-8', '', `part ${index}`, index === parts - depth ? `--b${depth - 1}--` : `--b${depth - 1}`);
  for (let level = depth - 2; level >= 1; level--) lines.push(`--b${level}--`);
  return lines.join('\r\n');
}
for (const [id, what, args] of ADVERSARIAL) {
  test(`adversarial input finishes within the time budget: ${id}, ${what}`, {todo: registered(id) ? false : `${id} is not built yet`}, () => {
    const started = performance.now();
    try { runTransform(id, args()); } catch (error) { if (!(error instanceof TransformError)) throw error; }
    assert.ok(performance.now() - started < 2000, `${id} took ${Math.round(performance.now() - started)} ms`);
  });
}

test('the shared helpers copy their sources exactly: the hidden rule, the ASCII fold and the pointer reader', () => {
  for (let code = 0; code <= 0x10ffff; code++) {
    const char = String.fromCodePoint(code);
    if (hasHidden(char) !== hostedHidden(char)) assert.fail(`U+${code.toString(16)}: the copied hidden rule differs from public/hosted-text.js`);
  }
  assert.equal(foldAscii('ABC xyz ÀÉ İ K'), 'abc xyz ÀÉ İ K', 'A to Z only; the Kelvin sign stays');
  assert.ok(sameAscii('TRASH', 'trash') && !sameAscii('É', 'é'));
  assert.equal(trimAscii('\t a b \n\r\f'), 'a b');
  assert.equal(trimAscii(' a '), ' a ', 'no-break and em spaces are not ASCII space');
  assert.deepEqual([9, 10, 12, 13, 32, 11, 160].map(isAsciiSpace), [true, true, true, true, true, false, false]);
  for (const [text, ok] of [['', true], ['/a', true], ['/a~0b~1c', true], ['/', true], [`/${'a/'.repeat(31)}a`, true], [`/${'a/'.repeat(32)}a`, false], ['a', false], ['/a~2', false], ['/a~', false], [7, false], [null, false]]) {
    assert.equal(wellFormedPointer(text), ok, String(text));
  }
  const entry = {pointerArgs: ['p']}, read = pointer => pointerReader(entry, {p: pointer});
  const data = {list: ['x', 'y'], 'a/b': 1, 'c~d': 2, nested: {deep: [{v: 3}]}};
  assert.equal(read('/list/1')(data, 'p'), 'y');
  assert.equal(read('/a~1b')(data, 'p'), 1);
  assert.equal(read('/c~0d')(data, 'p'), 2);
  assert.equal(read('/nested/deep/0/v')(data, 'p'), 3);
  assert.equal(read('')(data, 'p'), data);
  for (const pointer of ['/list/01', '/list/-', '/list/length', '/toString', '/nested/hasOwnProperty', '/missing/x', '/list/2']) assert.equal(read(pointer)(data, 'p'), undefined, pointer);
  assert.throws(() => read('/list')(data, 'q'), error => error instanceof Error && !(error instanceof TransformError), 'an undeclared name is a plain Error');
});

test('error.v1.mjs holds the harness codes and exactly the Codes line of each step 8 family (R16)', () => {
  assert.deepEqual(HARNESS_CODES, ['transform_unknown', 'input_invalid', 'input_too_large', 'output_invalid', 'output_too_large', 'transform_failed']);
  assert.deepEqual(FAMILY_CODES, {
    encoding: ['encoding_invalid', 'utf8_invalid', 'output_too_large'],
    rfc5322: ['header_injection', 'address_invalid', 'too_many_recipients', 'message_too_large', 'message_id_invalid', 'mime_too_deep', 'mime_too_many_parts', 'mime_invalid'],
    html: [],
    time: ['time_invalid', 'time_nonexistent', 'time_ambiguous', 'zone_invalid', 'ts_invalid', 'window_order', 'window_past', 'window_too_far', 'busy_unknown'],
    text: ['too_many_chunks', 'text_too_long', 'query_value_invalid', 'query_scope_missing', 'query_too_long', 'too_many_operators', 'repo_invalid'],
    ids: ['notion_id_invalid', 'slack_link_invalid', 'repo_invalid', 'ref_invalid'],
    collections: ['match_none', 'match_many', 'attendee_protected', 'label_unknown', 'label_system', 'not_one_of', 'too_many_items'],
  });
  assert.ok(Object.isFrozen(FAMILY_CODES) && Object.values(FAMILY_CODES).every(Object.isFrozen) && Object.isFrozen(HARNESS_CODES));
  // F10.19: error.v3.mjs adds the notion family only (test/transforms-notion.test.mjs). F10.17's error.v2.mjs adds path_invalid to ids and
  // name_invalid and name_repeated to collections (its test below), and F10.21's error.v4.mjs emoji_invalid to ids, lists only. Every other
  // step 8 family is v1's alone.
  const {notion, ...stepEight} = Object.fromEntries(CODES);
  assert.deepEqual(stepEight, {...FAMILY_CODES, ids: [...FAMILY_CODES.ids, ...FAMILY_CODES_V2.ids, ...LATER_V4.ids], collections: [...FAMILY_CODES.collections, ...FAMILY_CODES_V2.collections]}, 'the registry\'s union of the step 8 families is v1 and the later error files');
  assert.ok(Array.isArray(notion));
});

// F10.17 part 1 (docs/F10.17-BUILD-MAP.md part 1, F10.8 map part b and k): step 17's codes come in the next error file, so error.v1.mjs and
// every step 8 pin stay as they were. It re-exports TransformError and lists codes only.
test('error.v2.mjs (step 17) adds path_invalid to ids and name_invalid and name_repeated to collections; the registry holds the union of both files', () => {
  assert.equal(TransformErrorV2, TransformError, 'the one error type');
  assert.deepEqual(FAMILY_CODES_V2, {ids: ['path_invalid'], collections: ['name_invalid', 'name_repeated']});
  assert.ok(Object.isFrozen(FAMILY_CODES_V2) && Object.values(FAMILY_CODES_V2).every(Object.isFrozen));
  // F10.19's notion family and F10.21's emoji_invalid (error.v3.mjs and error.v4.mjs) sit beside it in the merged registry.
  const {notion, ...steps} = Object.fromEntries(CODES);
  assert.deepEqual(steps, {...FAMILY_CODES, ids: [...FAMILY_CODES.ids, 'path_invalid', ...LATER_V4.ids], collections: [...FAMILY_CODES.collections, 'name_invalid', 'name_repeated']});
  assert.ok(Array.isArray(notion));
  const text = readFileSync(path.join(ROOT, 'lib/transforms/_shared/error.v2.mjs'), 'utf8');
  assert.deepEqual([...text.matchAll(/^import|^export \{TransformError\} from '(.+)'/gm)].map(match => match[0]), ["export {TransformError} from './error.v1.mjs'"]);
  for (const id of ['ids.repoPath@1', 'text.mentions@1', 'collections.stringValues@1']) assert.ok(TRANSFORMS.has(id), id);
});

test('lib/compiler.mjs exports checkSchema() with its behaviour unchanged (R14)', () => {
  checkSchema(OBJECT({value: STRING}));
  for (const schema of [{type: 'string', pattern: 'a'}, {type: 'object', properties: {}}, {oneOf: []}, {type: ['string', 'null']}]) assert.throws(() => checkSchema(schema), /schema|required|properties/i);
});

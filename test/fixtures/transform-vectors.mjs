// F10.8 part a (docs/F10.8-BUILD-MAP.md): the transform vectors of test/fixtures/transforms/<list>.json, read, checked and run the same way
// by every transforms test. A file is {source, cases}. A case is {name, source?, transform, input, and exactly one of output, expect or
// refuses}: `output` is the whole result, `expect` maps JSON pointers into the result to values ({} only says it does not refuse), and
// `refuses` is the fixed code. A case names its own source when it differs from the file's: an RFC section, a provider documentation page
// (written from the documented format, never copied), or "Fabric adversarial".
//
// A vector runs through runTransform() once its transform is registered; until then it is listed as a todo and not run, so a family's
// part sees its vectors fail or pass the moment it adds the module. Values may use these directives, expanded before a case runs:
//   {"$lines": [text, ...]}      the lines joined with CRLF
//   {"$concat": [text, ...]}     the texts joined, lists among them flattened first
//   {"$repeat": [text, n]}       the text n times
//   {"$list": [n, template]}     n copies of the template, with every "{n}" in its strings replaced by the copy's index (from 0)
//   {"$base64url": text}         the unpadded base64url of the text's UTF-8 bytes; {"$base64": text} is padded base64
//   {"$hex": "c328"}             raw bytes, only inside $base64url or $base64
//   {"$absent": true}            only as an `expect` value: nothing is at that pointer
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {canonicalHash} from '../../lib/compiler.mjs';
import {CODES, TRANSFORMS, runTransform} from '../../lib/transforms/index.mjs';
import {HARNESS_CODES, TransformError} from '../../lib/transforms/_shared/error.v1.mjs';

/** Each vector file under test/fixtures/transforms/, by its list name, with the family its transforms belong to. */
// F10.19 adds the notion family's list (test/transforms-notion.test.mjs).
export const LISTS = Object.freeze({encoding: 'encoding', rfc5322: 'rfc5322', 'html-text': 'html', time: 'time', text: 'text', ids: 'ids', collections: 'collections', notion: 'notion'});
const CASE_KEYS = new Set(['name', 'source', 'transform', 'input', 'output', 'expect', 'refuses']);
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);

export function readVectors(list) {
  return JSON.parse(readFileSync(new URL(`./transforms/${list}.json`, import.meta.url), 'utf8'));
}

/** What is wrong with one vector file's shape, as sentences; empty when nothing is. */
export function vectorProblems(list, vectors) {
  const family = LISTS[list], problems = [], names = new Set();
  if (!record(vectors) || Object.keys(vectors).sort().join() !== 'cases,source') return [`${list}.json must be exactly {source, cases}.`];
  if (typeof vectors.source !== 'string' || !vectors.source.trim()) problems.push(`${list}.json needs a source.`);
  if (!Array.isArray(vectors.cases)) return [...problems, `${list}.json: cases must be a list.`];
  const codes = new Set([...HARNESS_CODES, ...(CODES.get(family) ?? [])]);
  for (const [index, item] of vectors.cases.entries()) {
    const where = `${list}.json case ${index}${typeof item?.name === 'string' ? ` (${item.name})` : ''}`;
    if (!record(item)) { problems.push(`${where} is not an object.`); continue; }
    for (const key of Object.keys(item)) if (!CASE_KEYS.has(key)) problems.push(`${where} has an unknown field ${key}.`);
    if (typeof item.name !== 'string' || !item.name.trim() || names.has(item.name)) problems.push(`${where} needs a name used once in the file.`);
    names.add(item.name);
    if (Object.hasOwn(item, 'source') && (typeof item.source !== 'string' || !item.source.trim())) problems.push(`${where} has an empty source.`);
    if (typeof item.transform !== 'string' || !new RegExp(`^${family}\\.[a-z][A-Za-z0-9]*@[1-9][0-9]*$`).test(item.transform)) problems.push(`${where} must name a ${family} transform as name@version.`);
    if (!record(item.input)) problems.push(`${where} needs an input object.`);
    const kinds = ['output', 'expect', 'refuses'].filter(key => Object.hasOwn(item, key));
    if (kinds.length !== 1) problems.push(`${where} needs exactly one of output, expect and refuses.`);
    if (Object.hasOwn(item, 'output') && !record(item.output)) problems.push(`${where}: output must be an object.`);
    if (Object.hasOwn(item, 'expect') && (!record(item.expect) || Object.keys(item.expect).some(pointer => !/^(?:\/[^/]*)+$/.test(pointer)))) problems.push(`${where}: expect maps JSON pointers to values.`);
    if (Object.hasOwn(item, 'refuses') && !codes.has(item.refuses)) problems.push(`${where} refuses with ${item.refuses}, which is neither a harness code nor a ${family} code.`);
  }
  return problems;
}

const bytesOf = value => record(value) && Object.keys(value).join() === '$hex' ? Buffer.from(value.$hex, 'hex') : Buffer.from(expand(value), 'utf8');
/** A fixture value with every directive expanded. */
export function expand(value) {
  if (Array.isArray(value)) return value.map(expand);
  if (!record(value)) return value;
  const [key, ...more] = Object.keys(value);
  if (key?.startsWith('$') && !more.length) {
    const argument = value[key];
    if (key === '$lines') return expand(argument).join('\r\n');
    if (key === '$concat') return expand(argument).flat(Infinity).join('');
    if (key === '$repeat') return expand(argument[0]).repeat(argument[1]);
    if (key === '$list') return Array.from({length: argument[0]}, (_, index) => expand(fill(argument[1], String(index))));
    if (key === '$base64url') return bytesOf(argument).toString('base64url');
    if (key === '$base64') return bytesOf(argument).toString('base64');
    if (key === '$absent') return value;
    throw new Error(`Unknown fixture directive ${key}.`);
  }
  return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, expand(item)]));
}
const fill = (value, index) => typeof value === 'string' ? value.replaceAll('{n}', index) : Array.isArray(value) ? value.map(item => fill(item, index))
  : record(value) ? Object.fromEntries(Object.entries(value).map(([name, item]) => [name, fill(item, index)])) : value;

/** The value at a JSON pointer, own properties and canonical indexes only; undefined when there is none. */
export function at(value, pointer) {
  let current = value;
  for (const token of pointer.slice(1).split('/').map(part => part.replaceAll('~1', '/').replaceAll('~0', '~'))) {
    if (current === null || typeof current !== 'object' || (Array.isArray(current) && !/^(?:0|[1-9][0-9]*)$/.test(token)) || !Object.hasOwn(current, token)) return undefined;
    current = current[token];
  }
  return current;
}

export const registered = id => TRANSFORMS.has(id);
/** Every case of every vector file, with its list. */
export function allCases() {
  return Object.keys(LISTS).flatMap(list => readVectors(list).cases.map(item => ({list, item})));
}
/** What one case gives: {output} or {code}. Anything but a TransformError is a test failure, never a vector result. */
export function outcome(item, run = runTransform) {
  try { return {output: run(item.transform, expand(item.input))}; }
  catch (error) { if (error instanceof TransformError) return {code: error.code}; throw error; }
}
/** The canonical JSON a case gives, for byte comparisons across runs and processes. */
export function canonicalOutcome(item) {
  const result = outcome(item);
  return result.code ? `code:${result.code}` : `output:${canonicalHash(result.output)}`;
}
/** Asserts one case. */
export function checkCase(item) {
  const result = outcome(item);
  if (Object.hasOwn(item, 'refuses')) { assert.deepEqual(result, {code: item.refuses}); return; }
  assert.equal(result.code, undefined, `${item.name} refused with ${result.code}`);
  if (Object.hasOwn(item, 'output')) { assert.deepEqual(result.output, expand(item.output)); return; }
  for (const [pointer, wanted] of Object.entries(item.expect)) {
    const value = at(result.output, pointer);
    if (record(wanted) && wanted.$absent === true) assert.equal(value, undefined, `${item.name}: ${pointer} should be absent`);
    else assert.deepEqual(value, expand(wanted), `${item.name}: ${pointer}`);
  }
}

/** Registers a test that a vector file is well formed, and one test per case: a todo until its transform is registered. */
export function vectorTests(list) {
  const vectors = readVectors(list);
  test(`${list} vectors: the file is well formed`, () => assert.deepEqual(vectorProblems(list, vectors), []));
  for (const item of Array.isArray(vectors.cases) ? vectors.cases : []) {
    // A pending vector is listed as a todo and not run, so the output names what each part still owes without a wall of failures.
    const pending = !registered(item.transform);
    test(`${list} vector: ${item.name}`, {todo: pending ? `${item.transform} is not built yet` : false}, () => { if (!pending) checkCase(item); });
  }
}

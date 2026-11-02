import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {CODES, FILES, TRANSFORMS, checkEntry, runTransform} from '../lib/transforms/index.mjs';
import {FAMILY_CODES as V1, TransformError} from '../lib/transforms/_shared/error.v1.mjs';
import {FAMILY_CODES as V3, TransformError as V3Error} from '../lib/transforms/_shared/error.v3.mjs';
import {FAMILY_CODES as LATER_V2} from '../lib/transforms/_shared/error.v2.mjs';
import {FAMILY_CODES as LATER_V4} from '../lib/transforms/_shared/error.v4.mjs';
import {FAMILY_CODES as LATER_V5} from '../lib/transforms/_shared/error.v5.mjs';
import {WRITABLE, READ_ONLY, kindOf, chunks} from '../lib/transforms/notion/_types.v1.mjs';
import {ROOT, readPins} from '../lib/transform-pins.mjs';
import {vectorTests} from './fixtures/transform-vectors.mjs';

// F10.19 part 1 (docs/F10.19-BUILD-MAP.md part 1 item 3; docs/F10.8-BUILD-MAP.md part k): the notion family. Six of them read one type
// table (notion/_types.v1.mjs), so what describe calls writable is exactly what schema binds, propertyValues writes and filter filters on:
// notion.title@1, notion.plainValues@1, notion.describe@1, notion.schema@1 (kind schema), notion.propertyValues@1 (outputFrom) and
// notion.filter@1. Text is cut by text.chunk@1's rule (2,000 UTF-16 units a piece, at most 100 pieces), copied into the table. Their codes
// are a new error file, _shared/error.v3.mjs (step 17 owns v2). Spec lines 1187-1190. The seventh, notion.markdownShows@1, came with step 20's
// live run: its vectors are in the fixture file.
const TITLE = 'notion.title@1', PLAIN = 'notion.plainValues@1', DESCRIBE = 'notion.describe@1', SCHEMA = 'notion.schema@1', VALUES = 'notion.propertyValues@1', FILTER = 'notion.filter@1', SHOWS = 'notion.markdownShows@1';
const IDS = [TITLE, PLAIN, DESCRIBE, SCHEMA, VALUES, FILTER, SHOWS];
const NOTION_CODES = ['property_read_only', 'property_unknown', 'property_ambiguous', 'option_unknown', 'too_many_properties', 'too_many_options', 'too_many_conditions', 'too_many_chunks'];
const refused = code => error => {
  assert.ok(error instanceof TransformError, `expected a TransformError, got ${error}`);
  assert.equal(error.code, code);
  return true;
};
const run = (id, args) => runTransform(id, args);
/** One transform's own run(), past the harness: the transform checks again what the harness checks, so it refuses on its own. */
const own = (id, args) => TRANSFORMS.get(id).run(args);
const sorted = list => [...list].sort();
const rt = (...texts) => texts.map(text => ({type: 'text', text: {content: text}, plain_text: text}));
const U1 = 'a1b2c3d4-0000-4000-8000-000000000001', U2 = 'a1b2c3d4-0000-4000-8000-000000000002';
const TEXT = {type: 'string', maxLength: 200_000};

/** A data source holding one property of every type the table names, and two it does not know, as Notion's reference shows them. */
function everyType() {
  const options = names => ({options: names.map((name, index) => ({id: `o${index}`, name, color: 'default'}))});
  const properties = {
    Name: {type: 'title', title: {}}, Notes: {type: 'rich_text', rich_text: {}}, Cost: {type: 'number', number: {format: 'number'}}, Done: {type: 'checkbox', checkbox: {}},
    Stage: {type: 'select', select: options(['Open', 'Closed'])}, State: {type: 'status', status: {...options(['Not started', 'Done']), groups: []}},
    Tags: {type: 'multi_select', multi_select: options(['red', 'blue'])}, Due: {type: 'date', date: {}}, Site: {type: 'url', url: {}}, Mail: {type: 'email', email: {}},
    Phone: {type: 'phone_number', phone_number: {}}, Owner: {type: 'people', people: {}}, Link: {type: 'relation', relation: {data_source_id: U2, type: 'single_property', single_property: {}}},
    Total: {type: 'formula', formula: {expression: '1'}}, Sum: {type: 'rollup', rollup: {function: 'sum'}}, Created: {type: 'created_time', created_time: {}},
    Author: {type: 'created_by', created_by: {}}, Edited: {type: 'last_edited_time', last_edited_time: {}}, Editor: {type: 'last_edited_by', last_edited_by: {}},
    Ticket: {type: 'unique_id', unique_id: {prefix: 'T'}}, Go: {type: 'button', button: {}}, Checked: {type: 'verification', verification: {}},
    Files: {type: 'files', files: {}}, Where: {type: 'place', place: {}}};
  return {object: 'data_source', id: U2, title: rt('Every type'), properties: Object.fromEntries(Object.entries(properties).map(([name, property], index) => [name, {id: `p${index}`, name, ...property}]))};
}

vectorTests('notion');

test('error.v3.mjs re-exports TransformError and adds the notion family; the registry\'s codes are v1\'s plus notion\'s', () => {
  assert.equal(V3Error, TransformError);
  assert.deepEqual(V3, {notion: NOTION_CODES});
  assert.ok(Object.isFrozen(V3) && Object.isFrozen(V3.notion));
  // F10.17's error.v2.mjs adds path_invalid to ids and name_invalid and name_repeated to collections, F10.21's error.v4.mjs emoji_invalid to ids,
  // and Iteration 9's error.v5.mjs link_invalid to ids, lists only.
  assert.deepEqual(Object.fromEntries(CODES), {...V1, ids: [...V1.ids, ...LATER_V2.ids, ...LATER_V4.ids, ...LATER_V5.ids], collections: [...V1.collections, ...LATER_V2.collections], notion: NOTION_CODES});
});

test('seven transforms are registered in the notion family, each passing checkEntry(), with the shapes the actions read', () => {
  for (const id of IDS) {
    assert.ok(TRANSFORMS.has(id), id);
    assert.doesNotThrow(() => checkEntry(TRANSFORMS.get(id), FILES.get(id)), id);
  }
  const entry = id => TRANSFORMS.get(id);
  assert.deepEqual(IDS.map(id => entry(id).kind), ['map', 'map', 'map', 'schema', 'map', 'map', 'map']);
  assert.deepEqual(IDS.map(id => Object.keys(entry(id).stepData)), [['object'], ['page'], ['dataSource'], ['dataSource'], ['schema'], ['schema'], ['before', 'after']]);
  assert.deepEqual(entry(VALUES).resolvedValues, {values: {schemaFrom: 'schema', maxBytes: 1_048_576}}, 'the stub\'s argument names (test/fixtures/actions/registry.mjs)');
  assert.deepEqual(Object.keys(entry(FILTER).resolvedValues), ['where']);
  assert.equal(entry(VALUES).outputFrom.argument, 'schema');
  assert.deepEqual(sorted(Object.keys(entry(VALUES).outputFrom.values)), sorted(WRITABLE), 'one reviewed value schema per writable type');
  const refuses = {[TITLE]: [], [PLAIN]: ['too_many_properties'], [DESCRIBE]: ['too_many_options', 'too_many_properties'], [SCHEMA]: ['too_many_options', 'too_many_properties'],
    [VALUES]: ['option_unknown', 'property_ambiguous', 'property_read_only', 'property_unknown', 'too_many_chunks'], [FILTER]: ['property_read_only', 'property_unknown', 'too_many_conditions'], [SHOWS]: []};
  for (const id of IDS) {
    assert.deepEqual(sorted(entry(id).refuses), refuses[id], id);
    assert.deepEqual([entry(id).usesClock, entry(id).runtimeFacts, entry(id).pointerArgs], [false, id === SHOWS ? ['unicode'] : [], []], id);
  }
});

test('notion.markdownShows@1 stays linear on a page built to make a pattern backtrack', () => {
  const started = performance.now();
  for (const page of ['<table'.repeat(100_000), `${' '.repeat(500_000)}x`, '\n'.repeat(500_000), '`'.repeat(500_000)]) own(SHOWS, {before: 'x', after: page, text: 'y'});
  assert.ok(performance.now() - started < 5000, 'a read-back runs on what a page holds, so its cost never grows with the square of it');
});

test('the type table: 13 writable types, 9 read only, and everything else unsupported', () => {
  assert.deepEqual(WRITABLE, ['title', 'rich_text', 'number', 'checkbox', 'select', 'status', 'multi_select', 'date', 'url', 'email', 'phone_number', 'people', 'relation']);
  assert.deepEqual(READ_ONLY, ['formula', 'rollup', 'created_time', 'created_by', 'last_edited_time', 'last_edited_by', 'unique_id', 'button', 'verification']);
  for (const type of READ_ONLY) assert.deepEqual(kindOf({type, property: {type}}), {writable: false, reason: 'read_only'}, type);
  for (const type of ['files', 'place', 'something_new']) assert.deepEqual(kindOf({type, property: {type}}), {writable: false, reason: 'unsupported_type'}, type);
  assert.deepEqual(kindOf({type: 'number', property: {type: 'number', number: {}}}), {writable: true});
  assert.deepEqual(kindOf({type: 'select', property: {type: 'select', select: {options: []}}}), {writable: false, reason: 'no_options'});
});

test('a property named __proto__, prototype or constructor never binds: the harness refuses the whole step data before the table reads it', () => {
  for (const name of ['__proto__', 'prototype', 'constructor']) {
    const dataSource = JSON.parse(`{"object": "data_source", "properties": {"Name": {"id": "title", "type": "title", "title": {}}, ${JSON.stringify(name)}: {"id": "x", "type": "rich_text", "rich_text": {}}}}`);
    for (const id of [SCHEMA, DESCRIBE]) assert.throws(() => run(id, {dataSource}), refused('input_invalid'), `${id} ${name}`);
    assert.throws(() => run(PLAIN, {page: dataSource}), refused('input_invalid'), name);
    const pair = run(SCHEMA, {dataSource: {object: 'data_source', properties: {Name: {id: 'title', type: 'title', title: {}}}}});
    assert.throws(() => run(VALUES, {schema: pair, values: JSON.parse(`{${JSON.stringify(name)}: "x"}`)}), refused('input_invalid'), name);
  }
});

test('chunking (spec line 1187): 2,000 UTF-16 units a piece and 100 pieces at most, a surrogate pair kept whole, the same rule as text.chunk@1', () => {
  const lengths = text => chunks(text).map(piece => piece.length);
  assert.deepEqual(chunks(''), []);
  assert.deepEqual(lengths('a'.repeat(2000)), [2000]);
  assert.deepEqual(lengths('a'.repeat(2001)), [2000, 1]);
  assert.deepEqual(lengths('a'.repeat(200_000)), Array(100).fill(2000), '100 full pieces is the most');
  assert.throws(() => chunks('a'.repeat(200_001)), refused('too_many_chunks'), 'a 101st piece refuses, never truncates');
  const pair = `${'a'.repeat(1999)}😀b`;
  assert.deepEqual(chunks(pair), ['a'.repeat(1999), '😀b'], 'the pair moves whole to the next piece');
  assert.throws(() => chunks('a\ud800'), refused('input_invalid'));
  for (const text of ['', 'Meeting notes', 'a'.repeat(4500), pair, `${'é'.repeat(3000)}${'😀'.repeat(1500)}`, '😀'.repeat(1001), 'a'.repeat(200_000)]) {
    assert.deepEqual(chunks(text), run('text.chunk@1', {text}).chunks, `the shared rule equals text.chunk@1 (${text.length} units)`);
  }
});

test('notion.title@1 joins every piece of the title, from a page\'s title property or an object\'s own title', () => {
  const page = {object: 'page', properties: {Name: {id: 'title', type: 'title', title: rt('Plan ', 'for ', 'Q4')}, Notes: {id: 'n', type: 'rich_text', rich_text: rt('not this')}}};
  assert.deepEqual(run(TITLE, {object: page}), {title: 'Plan for Q4'});
  assert.deepEqual(run(TITLE, {object: everyType()}), {title: 'Every type'});
  assert.deepEqual(run(TITLE, {object: {object: 'database', title: rt('Data', 'base')}}), {title: 'Database'});
  assert.deepEqual(run(TITLE, {object: {object: 'page', properties: {}}}), {title: ''});
});

test('notion.plainValues@1: each type\'s plain text, file names never their URLs, one line of at most 200 code points, sorted by name, at most 100', () => {
  const page = {object: 'page', id: U1, properties: {
    Name: {id: 'a', type: 'title', title: rt('Taxi ', 'home')}, Notes: {id: 'b', type: 'rich_text', rich_text: rt('one\r\ntwo\nthree\rfour\u2028five')},
    Cost: {id: 'c', type: 'number', number: 12.5}, Zero: {id: 'z', type: 'number', number: null}, Done: {id: 'd', type: 'checkbox', checkbox: false},
    Stage: {id: 'e', type: 'select', select: {name: 'Open'}}, Empty: {id: 'f', type: 'select', select: null}, State: {id: 'g', type: 'status', status: {name: 'Done'}},
    Tags: {id: 'h', type: 'multi_select', multi_select: [{name: 'red'}, {name: 'blue'}]}, Due: {id: 'i', type: 'date', date: {start: '2026-11-02T10:00:00.000-05:00', end: null}},
    Site: {id: 'j', type: 'url', url: 'https://example.com/a'}, Mail: {id: 'k', type: 'email', email: null}, Phone: {id: 'l', type: 'phone_number', phone_number: '+1 555 0100'},
    Owner: {id: 'm', type: 'people', people: [{object: 'user', id: U1}, {object: 'user', id: U2}]}, Link: {id: 'n', type: 'relation', relation: [{id: U2}], has_more: false},
    Total: {id: 'o', type: 'formula', formula: {type: 'number', number: 25}}, Flag: {id: 'p', type: 'formula', formula: {type: 'boolean', boolean: true}},
    Sum: {id: 'q', type: 'rollup', rollup: {type: 'array', array: [{type: 'title', title: rt('A')}, {type: 'number', number: 2}], function: 'show_original'}},
    Created: {id: 'r', type: 'created_time', created_time: '2026-10-01T09:00:00.000Z'}, Author: {id: 's', type: 'created_by', created_by: {object: 'user', id: U1}},
    Ticket: {id: 't', type: 'unique_id', unique_id: {prefix: 'T', number: 42}}, Go: {id: 'u', type: 'button', button: {}},
    Checked: {id: 'v', type: 'verification', verification: {state: 'verified'}},
    Files: {id: 'w', type: 'files', files: [{name: 'receipt.pdf', type: 'file', file: {url: 'https://prod-files.example/receipt.pdf?X-Amz-Signature=abc', expiry_time: '2026-10-26T13:00:00.000Z'}},
      {name: 'Site plan', type: 'external', external: {url: 'https://example.com/plan.png'}}]},
    Long: {id: 'x', type: 'rich_text', rich_text: rt('😀'.repeat(150), 'b'.repeat(100))}}};
  const out = run(PLAIN, {page}).properties, text = Object.fromEntries(out.map(item => [item.name, item.text]));
  assert.deepEqual(out.map(item => item.name), Object.keys(page.properties).sort((a, b) => a < b ? -1 : a > b ? 1 : 0), 'sorted by name');
  assert.deepEqual(text, {Author: U1, Checked: 'verified', Cost: '12.5', Created: '2026-10-01T09:00:00.000Z', Done: 'false', Due: '2026-11-02T10:00:00.000-05:00', Empty: '', Files: 'receipt.pdf, Site plan',
    Flag: 'true', Go: '', Link: U2, Long: `${'😀'.repeat(150)}${'b'.repeat(100)}`, Mail: '', Name: 'Taxi home', Notes: 'one\r\ntwo\nthree\rfour\u2028five', Owner: `${U1}, ${U2}`, Phone: '+1 555 0100',
    Site: 'https://example.com/a', Stage: 'Open', State: 'Done', Sum: 'A, 2', Tags: 'red, blue', Ticket: 'T-42', Total: '25', Zero: ''});
  const serialized = JSON.stringify(out);
  for (const url of ['prod-files.example', 'X-Amz-Signature', 'example.com/plan.png']) assert.equal(serialized.includes(url), false, `no file URL: ${url}`);
  for (const item of out) {
    assert.equal(/[\r\n\u2028\u2029\u0085\u000b\u000c]/.test(item.line), false, `${item.name}: one line`);
    assert.ok([...item.line].length <= 200, item.name);
    assert.deepEqual(Object.keys(item), ['name', 'id', 'type', 'text', 'line']);
  }
  assert.equal(out.find(item => item.name === 'Notes').line, 'one two three four five');
  assert.equal(out.find(item => item.name === 'Long').line, `${'😀'.repeat(150)}${'b'.repeat(50)}`, 'cut at 200 code points, a pair never split');
  // F10.19 part 2: lines, Update database row's "Values now" card line: "Name: line" for each property, in name order, one a line.
  const lines = run(PLAIN, {page}).lines;
  assert.deepEqual(lines.split('\n'), out.map(item => `${item.name}: ${item.line}`));
  assert.equal(lines.split('\n').find(line => line.startsWith('Notes: ')), 'Notes: one two three four five');
  const named = {object: 'page', properties: {'Two\nlines\u2028here': {id: 'a', type: 'number', number: 1}, [`${'n'.repeat(300)}`]: {id: 'b', type: 'checkbox', checkbox: true}}};
  assert.deepEqual(run(PLAIN, {page: named}).lines.split('\n'), ['Two lines here: 1', `${'n'.repeat(200)}: true`], 'a name is one line of at most 200 code points too');
  assert.equal(run(PLAIN, {page: {object: 'page', properties: {}}}).lines, '');
  const many = {object: 'page', properties: Object.fromEntries(Array.from({length: 101}, (_, index) => [`P${index}`, {id: `p${index}`, type: 'number', number: index}]))};
  assert.throws(() => run(PLAIN, {page: many}), refused('too_many_properties'));
  delete many.properties.P100;
  assert.equal(run(PLAIN, {page: many}).properties.length, 100);
});

test('notion.describe@1 and notion.schema@1 agree on what is writable: every writable type binds, read-only and unsupported types never do', () => {
  const source = everyType(), described = run(DESCRIBE, {dataSource: source}).properties, pair = run(SCHEMA, {dataSource: source});
  assert.deepEqual(described.filter(item => item.writable).map(item => item.name), pair.bindings.map(item => item.name), 'the same writable properties, in the same order');
  assert.deepEqual(sorted(pair.bindings.map(item => item.type)), sorted(WRITABLE));
  for (const item of described) {
    const type = item.type;
    assert.deepEqual([item.writable, item.reason], WRITABLE.includes(type) ? [true, undefined] : READ_ONLY.includes(type) ? [false, 'read_only'] : [false, 'unsupported_type'], type);
    assert.equal(Object.hasOwn(item, 'options'), ['select', 'status', 'multi_select'].includes(type), type);
    assert.equal(Object.hasOwn(pair.schema.properties, item.name), item.writable, `${type} binds exactly when writable`);
  }
  assert.deepEqual(pair.schema.properties, {
    Cost: {type: 'number'}, Done: {type: 'boolean'}, Due: {type: 'object', properties: {start: {type: 'string', minLength: 10, maxLength: 40}, end: {type: 'string', minLength: 10, maxLength: 40}}, required: ['start'], additionalProperties: false},
    Link: {type: 'array', maxItems: 100, items: {type: 'string', format: 'uuid'}}, Mail: {type: 'string', minLength: 3, maxLength: 254}, Name: TEXT, Notes: TEXT,
    Owner: {type: 'array', maxItems: 100, items: {type: 'string', format: 'uuid'}}, Phone: {type: 'string', minLength: 1, maxLength: 100}, Site: {type: 'string', minLength: 1, maxLength: 2000},
    Stage: {type: 'string', enum: ['Open', 'Closed']}, State: {type: 'string', enum: ['Not started', 'Done']}, Tags: {type: 'array', maxItems: 100, items: {type: 'string', enum: ['red', 'blue']}}});
  assert.deepEqual([pair.schema.required, pair.schema.additionalProperties], [[], false], 'every property optional, nothing else');
  assert.ok(pair.bindings.every(binding => binding.id === source.properties[binding.name].id), 'bindings carry each property\'s id');
  // Bounds: 100 properties, 256 options.
  const wide = count => ({object: 'data_source', properties: Object.fromEntries(Array.from({length: count}, (_, index) => [`P${index}`, {id: `p${index}`, type: 'number', number: {}}]))});
  for (const id of [DESCRIBE, SCHEMA]) {
    assert.throws(() => run(id, {dataSource: wide(101)}), refused('too_many_properties'), id);
    const options = count => ({object: 'data_source', properties: {Pick: {id: 'k', type: 'select', select: {options: Array.from({length: count}, (_, index) => ({id: `o${index}`, name: `Option ${index}`}))}}}});
    assert.throws(() => run(id, {dataSource: options(257)}), refused('too_many_options'), id);
    assert.doesNotThrow(() => run(id, {dataSource: options(256)}), id);
  }
  assert.equal(run(SCHEMA, {dataSource: wide(100)}).bindings.length, 100);
});

test('notion.schema@1 on a page binds only its title property, whatever else the page holds', () => {
  const row = {object: 'page', id: U1, parent: {type: 'data_source_id', data_source_id: U2}, properties: {Name: {id: 'title', type: 'title', title: rt('Row')}, Cost: {id: 'c1', type: 'number', number: 3},
    Stage: {id: 's1', type: 'select', select: {name: 'Open'}}}};
  assert.deepEqual(run(SCHEMA, {dataSource: row}), {schema: {type: 'object', properties: {Name: TEXT}, required: [], additionalProperties: false}, bindings: [{name: 'Name', id: 'title', type: 'title'}]});
});

test('notion.propertyValues@1 (spec line 1188): each writable type reaches the body typed and keyed by its property id; arrays are sent whole', () => {
  const pair = run(SCHEMA, {dataSource: everyType()}), id = name => pair.bindings.find(binding => binding.name === name).id;
  const values = {Name: 'Taxi', Notes: 'Paid in cash', Cost: 12.5, Done: true, Stage: 'Open', State: 'Done', Tags: ['blue', 'red'], Due: {start: '2026-11-02', end: '2026-11-04'},
    Site: 'https://example.com', Mail: 'ada@example.com', Phone: '+1 555 0100', Owner: [U1], Link: [U2, U1]};
  assert.deepEqual(run(VALUES, {schema: pair, values}), {
    [id('Name')]: {title: [{text: {content: 'Taxi'}}]}, [id('Notes')]: {rich_text: [{text: {content: 'Paid in cash'}}]}, [id('Cost')]: {number: 12.5}, [id('Done')]: {checkbox: true},
    [id('Stage')]: {select: {name: 'Open'}}, [id('State')]: {status: {name: 'Done'}}, [id('Tags')]: {multi_select: [{name: 'blue'}, {name: 'red'}]},
    [id('Due')]: {date: {start: '2026-11-02', end: '2026-11-04'}}, [id('Site')]: {url: 'https://example.com'}, [id('Mail')]: {email: 'ada@example.com'}, [id('Phone')]: {phone_number: '+1 555 0100'},
    [id('Owner')]: {people: [{object: 'user', id: U1}]}, [id('Link')]: {relation: [{id: U2}, {id: U1}]}});
  assert.deepEqual(run(VALUES, {schema: pair, values: {Due: {start: '2026-11-02T10:00:00-05:00'}, Tags: []}}), {[id('Due')]: {date: {start: '2026-11-02T10:00:00-05:00'}}, [id('Tags')]: {multi_select: []}},
    'a date without an end; an empty list clears every option');
  const long = run(VALUES, {schema: pair, values: {Notes: 'x'.repeat(4500)}})[id('Notes')].rich_text.map(piece => piece.text.content.length);
  assert.deepEqual(long, [2000, 2000, 500]);
  assert.throws(() => run(VALUES, {schema: pair, values: {Notes: '😀'.repeat(100_001)}}), refused('too_many_chunks'), 'more than 100 pieces refuses, never truncated');
});

test('notion.propertyValues@1 (spec lines 1189-1190): a read-only property, an unknown name or an unknown option is refused by the harness, and by the transform itself', () => {
  const pair = run(SCHEMA, {dataSource: everyType()});
  for (const values of [{Total: 3}, {Created: '2026-10-01'}, {Nope: 'x'}, {Stage: 'Maybe'}, {State: 'Paused'}, {Tags: ['green']}]) {
    assert.throws(() => run(VALUES, {schema: pair, values}), refused('input_invalid'), JSON.stringify(values));
  }
  // The transform's own checks, past the harness: a binding of a read-only or unsupported type, a name with no binding, an option the property
  // does not list (a schema with no enum), two names that fold the same.
  const forged = (name, type, schema = {type: 'string'}) => ({schema: {type: 'object', properties: {[name]: schema}, required: [], additionalProperties: false}, bindings: [{name, id: 'x1', type}]});
  for (const type of [...READ_ONLY, 'files']) assert.throws(() => own(VALUES, {schema: forged('P', type), values: {P: 'x'}}), refused('property_read_only'), type);
  assert.throws(() => own(VALUES, {schema: forged('P', 'number', {type: 'number'}), values: {Q: 1}}), refused('property_unknown'));
  assert.throws(() => own(VALUES, {schema: forged('P', 'select'), values: {P: 'Maybe'}}), refused('option_unknown'));
  assert.throws(() => own(VALUES, {schema: forged('P', 'multi_select', {type: 'array', items: {type: 'string'}}), values: {P: ['red']}}), refused('option_unknown'));
  assert.throws(() => own(VALUES, {schema: forged('P', 'status'), values: {P: 'Done'}}), refused('option_unknown'));
  const twins = {schema: {type: 'object', properties: {Status: TEXT, status: TEXT}, required: [], additionalProperties: false}, bindings: [{name: 'Status', id: 'a', type: 'rich_text'}, {name: 'status', id: 'b', type: 'rich_text'}]};
  assert.throws(() => run(VALUES, {schema: twins, values: {status: 'x'}}), refused('property_ambiguous'), 'two names that fold the same in ASCII');
  assert.deepEqual(run(VALUES, {schema: twins, values: {}}), {});
});

test('notion.filter@1: one condition per given property, naming its id, contains for text and list items, equals for the rest; 21 conditions refuse', () => {
  const pair = run(SCHEMA, {dataSource: everyType()}), id = name => pair.bindings.find(binding => binding.name === name).id;
  const where = {Name: 'Taxi', Notes: 'cash', Cost: 12.5, Done: false, Stage: 'Open', State: 'Done', Tags: ['red'], Due: {start: '2026-11-02'}, Site: 'example', Mail: '@example.com', Phone: '555',
    Owner: [U1], Link: [U2]};
  const and = run(FILTER, {schema: pair, where}).filter.and;
  assert.deepEqual(and, [
    {property: id('Cost'), number: {equals: 12.5}}, {property: id('Done'), checkbox: {equals: false}}, {property: id('Due'), date: {equals: '2026-11-02'}}, {property: id('Link'), relation: {contains: U2}},
    {property: id('Mail'), email: {contains: '@example.com'}}, {property: id('Name'), title: {contains: 'Taxi'}}, {property: id('Notes'), rich_text: {contains: 'cash'}}, {property: id('Owner'), people: {contains: U1}},
    {property: id('Phone'), phone_number: {contains: '555'}}, {property: id('Site'), url: {contains: 'example'}}, {property: id('Stage'), select: {equals: 'Open'}}, {property: id('State'), status: {equals: 'Done'}},
    {property: id('Tags'), multi_select: {contains: 'red'}}]);
  assert.ok(and.every(condition => pair.bindings.some(binding => binding.id === condition.property) && !pair.bindings.some(binding => binding.name === condition.property && binding.id !== binding.name)),
    'every condition names the property by id, never by name');
  const twenty = {schema: {type: 'object', properties: {Tags: {type: 'array', maxItems: 100, items: {type: 'string'}}}, required: [], additionalProperties: false}, bindings: [{name: 'Tags', id: 't', type: 'multi_select'}]};
  assert.equal(run(FILTER, {schema: twenty, where: {Tags: Array.from({length: 20}, (_, index) => `t${index}`)}}).filter.and.length, 20);
  assert.throws(() => run(FILTER, {schema: twenty, where: {Tags: Array.from({length: 21}, (_, index) => `t${index}`)}}), refused('too_many_conditions'));
  assert.throws(() => run(FILTER, {schema: pair, where: {}}), refused('input_invalid'), 'no condition: leave where out instead');
  assert.throws(() => run(FILTER, {schema: pair, where: {Total: 3}}), refused('input_invalid'), 'a read-only property is not in the schema');
  assert.throws(() => own(FILTER, {schema: {schema: {type: 'object', properties: {T: {type: 'number'}}, required: [], additionalProperties: false}, bindings: [{name: 'T', id: 't', type: 'formula'}]}, where: {T: 1}}),
    refused('property_read_only'));
  assert.throws(() => own(FILTER, {schema: pair, where: {Nope: 1}}), refused('property_unknown'));
});

// The 38 pins of step 8 (sorted by id) and the harness pin at 3129ac4: adding the notion family moves none of them (docs/F10.8-BUILD-MAP.md part k).
const STEP_8_PINS = '2f625158a8016c94716f242a8edcf810cee8a70c5f8bfbf705671a3bfa07c062', HARNESS = '7486366c59d0f96b08bcc8ea30ec3943954645aa102528f3f6900b15f8fccba2';
test('seven pins are added and none moved: not step 8\'s 38, not the harness; one re-pin, notion.plainValues@1\'s lines (part 2)', () => {
  const pins = readPins(ROOT), byId = ([a], [b]) => a < b ? -1 : a > b ? 1 : 0;
  const notion = Object.keys(pins.transforms).filter(id => id.startsWith('notion.'));
  // Iteration 9 step 5 adds two, which its Notion triggers read (test/triggers-notion.test.mjs).
  assert.deepEqual(sorted(notion), sorted([...IDS, 'notion.markdownFingerprint@1', 'notion.rowFingerprint@1']));
  // F10.17 adds its own three pins (ids.repoPath@1, text.mentions@1 and collections.stringValues@1) and F10.21 its two (text.slackQuery@1
  // and ids.slackEmoji@1), each pinned by its own churn test.
  const later = new Set(['ids.repoPath@1', 'text.mentions@1', 'collections.stringValues@1', 'text.slackQuery@1', 'ids.slackEmoji@1']);
  later.add('collections.slackReactions@1'); // Iteration 9 step 4's one, pinned by test/transforms-collections.test.mjs.
  later.add('ids.linkPage@1'); // Iteration 9 listed churn (docs/I07-BUILD-MAP.md step 6): its own pin, held by test/triggers-github.test.mjs.
  for (const id of ['collections.gmailHistory@1', 'collections.gmailSentBefore@1']) later.add(id); // Iteration 9 step 7's two, pinned by test/transforms-gmail.test.mjs.
  for (const id of ['collections.calendarGuests@1', 'collections.calendarSelf@1', 'time.isAfter@1', 'time.offsetFromNow@1']) later.add(id); // Iteration 9 step 8's four, pinned by test/triggers-calendar.test.mjs.
  const before = Object.fromEntries(Object.entries(pins.transforms).filter(([id]) => !id.startsWith('notion.') && !later.has(id)).sort(byId));
  assert.equal(Object.keys(before).length, 38);
  assert.equal(createHash('sha256').update(JSON.stringify(before)).digest('hex'), STEP_8_PINS);
  assert.equal(pins.harness, HARNESS);
  // F10.19 part 2: notion.plainValues@1 gained lines (Update database row's Values now) before any shipped action named it, a recorded re-pin.
  assert.deepEqual(pins.repins.slice(8).map(entry => [entry.transform, entry.to, entry.date]), [['notion.plainValues@1', pins.transforms['notion.plainValues@1'], '2026-10-26']]);
});

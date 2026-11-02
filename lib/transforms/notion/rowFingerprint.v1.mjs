// Iteration 9 step 5 (docs/I07-BUILD-MAP.md section 2.7): notion.rowFingerprint@1. Step data `page`, a row as a data source query answers it. Out: {values, changeKind}.
// `values` is what a person wrote in the row: the id and plain text of each writable property, and of a files property, whose text is the files' names (notion/_types.v1.mjs textOf()).
// It leaves out what Notion computes or stamps: formula, rollup, the created and edited times and people, unique id, button and verification. A formula on the time moves with no edit,
// and a raw hash of the properties would fire on every poll, since Notion signs a file's link anew on each read. So a changed row's watch compares this, and two edits inside one
// stamp's minute still differ. Values sit in id order, and a column's name is not among them, so renaming a column moves no row.
// `changeKind` is `created` when the row's two stamps match, else `edited`. Stamps can be minute-grained, so a row edited in the minute it was made reads `created`.
// Past 100 properties it refuses with too_many_properties.
import {MAX_TEXT, WRITABLE, fieldOf, propertiesOf, textOf} from './_types.v1.mjs';

/** The types a person writes. A file is written too, though Fabric cannot write one. */
const WRITTEN = Object.freeze([...WRITABLE, 'files']);
const byId = (a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0;

export const ENTRY = {name: 'notion.rowFingerprint', version: 1, kind: 'map',
  input: {type: 'object', properties: {}, additionalProperties: false},
  pointerArgs: [], stepData: {page: {maxBytes: 2_097_152}}, resolvedValues: {},
  output: {type: 'object', properties: {values: {type: 'array', maxItems: 100, items: {type: 'object', properties: {id: {type: 'string', minLength: 1, maxLength: 256}, text: {type: 'string', maxLength: MAX_TEXT}},
    required: ['id', 'text'], additionalProperties: false}}, changeKind: {type: 'string', enum: ['created', 'edited']}}, required: ['values', 'changeKind'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 2_097_152, usesClock: false, runtimeFacts: [], refuses: ['too_many_properties'], excludes: [],
  example: {input: {page: {object: 'page', created_time: '2026-10-01T09:00:00.000Z', last_edited_time: '2026-10-01T09:05:00.000Z', properties: {Name: {id: 'title', type: 'title', title: [{plain_text: 'Taxi'}]},
    Cost: {id: 'c1', type: 'number', number: 12}}}}, output: {values: [{id: 'c1', text: '12'}, {id: 'title', text: 'Taxi'}], changeKind: 'edited'}},
  run({page}) {
    const created = fieldOf(page, 'created_time'), written = propertiesOf(page).filter(entry => WRITTEN.includes(entry.type));
    return {values: written.map(entry => ({id: entry.id, text: textOf(entry)})).sort(byId), changeKind: typeof created === 'string' && created === fieldOf(page, 'last_edited_time') ? 'created' : 'edited'};
  }};

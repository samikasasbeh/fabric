// F10.19 part 1 (docs/F10.19-BUILD-MAP.md part 1 item 3; docs/F10.8-BUILD-MAP.md part k): notion.title@1. Step data `object`: a page, a
// database, a data source or a search result. Out: {title}, the plain text of every piece of its title joined: a page's title-type
// property when that property holds a rich text list (a page's value), else the object's own title list (a database or data source, whose
// title property is a schema, not a value). An object with neither is untitled, ''. A piece that is not an object refuses with
// input_invalid. Search, Read page and every write's card name a page through it.
import {TransformError} from '../_shared/error.v3.mjs';
import {MAX_TEXT, fieldOf, plainText} from './_types.v1.mjs';

export const ENTRY = {name: 'notion.title', version: 1, kind: 'map',
  input: {type: 'object', properties: {}, additionalProperties: false},
  pointerArgs: [], stepData: {object: {maxBytes: 2_097_152}}, resolvedValues: {},
  output: {type: 'object', properties: {title: {type: 'string', maxLength: MAX_TEXT}}, required: ['title'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 1_048_576, usesClock: false, runtimeFacts: [], refuses: [], excludes: [],
  example: {input: {object: {object: 'page', properties: {Name: {id: 'title', type: 'title', title: [{plain_text: 'Q4 '}, {plain_text: 'plan'}]}}}}, output: {title: 'Q4 plan'}},
  run({object}) {
    if (object === null || typeof object !== 'object' || Array.isArray(object)) throw new TransformError('input_invalid');
    // Read without the property list's bounds: a title is found on a page of any width.
    const properties = fieldOf(object, 'properties'), values = properties !== null && typeof properties === 'object' && !Array.isArray(properties) ? Object.entries(properties).map(([, value]) => value) : [];
    const property = values.find(value => fieldOf(value, 'type') === 'title' && Array.isArray(fieldOf(value, 'title')));
    return {title: plainText(property ? fieldOf(property, 'title') : fieldOf(object, 'title'))};
  }};

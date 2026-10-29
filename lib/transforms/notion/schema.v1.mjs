// F10.19 part 1 (docs/F10.19-BUILD-MAP.md part 1 item 3; docs/F10.8-BUILD-MAP.md part k, decision 3): notion.schema@1, kind schema: the
// derive of every resource-dependent Notion input (Find rows' where, Add database row's and Update page or row's values). Step data
// `dataSource`: a data source, or for a plain page the page itself, whose only property an agent may set is its title. Out: {schema,
// bindings}: one optional property per writable property of the type table (notion/_types.v1.mjs valueSchema()): text up to 200,000
// characters, numbers, true or false, an enum of the option names for select and status, a list of option names for multi-select, a date
// {start, end?}, a link, an address, a phone number, and lists of ids for people and relations; bindings {name, id, type}, sorted by name.
// A property it cannot write is left out, so a value for one refuses before any write. At most 100 properties (too_many_properties) and
// 256 options a property (too_many_options). It keeps the stub's argument name and output shape (test/fixtures/actions/registry.mjs).
import {fieldOf, kindOf, propertiesOf, valueSchema} from './_types.v1.mjs';

export const ENTRY = {name: 'notion.schema', version: 1, kind: 'schema',
  input: {type: 'object', properties: {}, additionalProperties: false},
  pointerArgs: [], stepData: {dataSource: {maxBytes: 2_097_152}}, resolvedValues: {},
  maxInputBytes: 2_097_152, maxOutputBytes: 1_048_576, usesClock: false, runtimeFacts: [], refuses: ['too_many_properties', 'too_many_options'], excludes: [],
  example: {input: {dataSource: {object: 'data_source', properties: {Name: {id: 'title', type: 'title', title: {}}, Cost: {id: 'c1', type: 'number', number: {}},
    Total: {id: 'f1', type: 'formula', formula: {}}}}},
    output: {schema: {type: 'object', properties: {Cost: {type: 'number'}, Name: {type: 'string', maxLength: 200_000}}, required: [], additionalProperties: false},
      bindings: [{name: 'Cost', id: 'c1', type: 'number'}, {name: 'Name', id: 'title', type: 'title'}]}},
  run({dataSource}) {
    const page = fieldOf(dataSource, 'object') === 'page', properties = [], bindings = [];
    for (const entry of propertiesOf(dataSource)) {
      if ((page && entry.type !== 'title') || !kindOf(entry).writable) continue;
      properties.push([entry.name, valueSchema(entry)]);
      bindings.push({name: entry.name, id: entry.id, type: entry.type});
    }
    return {schema: {type: 'object', properties: Object.fromEntries(properties), required: [], additionalProperties: false}, bindings};
  }};

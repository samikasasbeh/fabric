// F10.19 part 1 (docs/F10.19-BUILD-MAP.md part 1 item 3; docs/F10.8-BUILD-MAP.md part k, open point Important 2): notion.describe@1. Step
// data `dataSource`, the data source a read returned. Out: {properties: [{name, id, type, writable, reason?, options?}]}, sorted by name, at
// most 100 (too_many_properties). `writable` and `reason` come from the type table (notion/_types.v1.mjs kindOf()), which notion.schema@1
// reads too, so what this calls writable is exactly what the schema binds. `options` lists a select, status or multi-select property's
// option names, each once, at most 256 (too_many_options), the enum bound of the derived schema. Describe database shows it to an agent.
import {OPTION_TYPES, kindOf, optionsOf, propertiesOf} from './_types.v1.mjs';

const NAME = {type: 'string', minLength: 1, maxLength: 1000};

export const ENTRY = {name: 'notion.describe', version: 1, kind: 'map',
  input: {type: 'object', properties: {}, additionalProperties: false},
  pointerArgs: [], stepData: {dataSource: {maxBytes: 2_097_152}}, resolvedValues: {},
  output: {type: 'object', properties: {properties: {type: 'array', maxItems: 100, items: {type: 'object', properties: {name: NAME, id: {type: 'string', minLength: 1, maxLength: 256},
    type: {type: 'string', minLength: 1, maxLength: 64}, writable: {type: 'boolean'}, reason: {type: 'string', enum: ['read_only', 'unsupported_type', 'no_options']},
    options: {type: 'array', maxItems: 256, items: NAME}}, required: ['name', 'id', 'type', 'writable'], additionalProperties: false}}}, required: ['properties'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 2_097_152, usesClock: false, runtimeFacts: [], refuses: ['too_many_properties', 'too_many_options'], excludes: [],
  example: {input: {dataSource: {object: 'data_source', properties: {Name: {id: 'title', type: 'title', title: {}}, Total: {id: 'f1', type: 'formula', formula: {}},
    Stage: {id: 's1', type: 'select', select: {options: [{name: 'Open'}, {name: 'Done'}]}}}}},
    output: {properties: [{name: 'Name', id: 'title', type: 'title', writable: true}, {name: 'Stage', id: 's1', type: 'select', writable: true, options: ['Open', 'Done']},
      {name: 'Total', id: 'f1', type: 'formula', writable: false, reason: 'read_only'}]}},
  run({dataSource}) {
    return {properties: propertiesOf(dataSource).map(entry => {
      const kind = kindOf(entry);
      return {name: entry.name, id: entry.id, type: entry.type, writable: kind.writable, ...(kind.writable ? {} : {reason: kind.reason}),
        ...(OPTION_TYPES.includes(entry.type) ? {options: optionsOf(entry)} : {})};
    })};
  }};

// F10.19 part 1 (docs/F10.19-BUILD-MAP.md part 1 item 3; docs/F10.8-BUILD-MAP.md part k): notion.filter@1, Find rows' query filter. Step data
// `schema`, the {schema, bindings} pair notion.schema@1 derived; resolved values `where`, plain values keyed by property name, typed by that
// schema. Out: {filter: {and: [...]}}, one condition per given property by its type, naming the property by its id (Notion takes a name
// or an id; an id never collides): `contains` for title, rich text, url, email and phone number, and one `contains` per item for
// multi-select, people and relation lists; `equals` for number, checkbox, select, status and a date's start. Conditions follow the
// property names' order. More than 20 refuse with too_many_conditions; none at all (an empty where) refuses with input_invalid, so a query
// that reads every row leaves where out. A name with no binding refuses with property_unknown, a binding of a type the table cannot filter on
// with property_read_only. No editedAfter: triggers are deferred (spec section 8).
import {TransformError} from '../_shared/error.v3.mjs';
import {WRITABLE, fieldOf} from './_types.v1.mjs';

const MAX_CONDITIONS = 20;
const CONTAINS = ['title', 'rich_text', 'url', 'email', 'phone_number'];
const CONTAINS_ITEMS = ['multi_select', 'people', 'relation'];
const refuse = code => { throw new TransformError(code); };
const closed = (properties, required = Object.keys(properties)) => ({type: 'object', properties, required, additionalProperties: false});
const TEXT = {type: 'string', maxLength: 200_000};
const NAME = {type: 'string', minLength: 1, maxLength: 1000};
const UUID = {type: 'string', format: 'uuid'};
const CONDITION = closed({property: {type: 'string', minLength: 1, maxLength: 256},
  title: closed({contains: TEXT}), rich_text: closed({contains: TEXT}), url: closed({contains: TEXT}), email: closed({contains: TEXT}), phone_number: closed({contains: TEXT}),
  multi_select: closed({contains: NAME}), people: closed({contains: UUID}), relation: closed({contains: UUID}),
  number: closed({equals: {type: 'number'}}), checkbox: closed({equals: {type: 'boolean'}}), select: closed({equals: NAME}), status: closed({equals: NAME}),
  date: closed({equals: {type: 'string', minLength: 10, maxLength: 40}})}, ['property']);
const byName = ([a], [b]) => a < b ? -1 : a > b ? 1 : 0;
const condition = (id, type, test) => Object.fromEntries([['property', id], [type, test]]);

export const ENTRY = {name: 'notion.filter', version: 1, kind: 'map',
  input: {type: 'object', properties: {}, additionalProperties: false},
  pointerArgs: [], stepData: {schema: {maxBytes: 1_048_576}}, resolvedValues: {where: {schemaFrom: 'schema', maxBytes: 1_048_576}},
  output: closed({filter: closed({and: {type: 'array', minItems: 1, maxItems: MAX_CONDITIONS, items: CONDITION}})}),
  maxInputBytes: 2_097_152, maxOutputBytes: 2_097_152, usesClock: false, runtimeFacts: [], refuses: ['too_many_conditions', 'property_unknown', 'property_read_only'], excludes: [],
  example: {input: {schema: {schema: {type: 'object', properties: {Stage: {type: 'string', enum: ['Open', 'Done']}, Cost: {type: 'number'}}, required: [], additionalProperties: false},
    bindings: [{name: 'Stage', id: 'a%3Bb', type: 'select'}, {name: 'Cost', id: 'c1', type: 'number'}]}, where: {Stage: 'Open', Cost: 3}},
    output: {filter: {and: [{property: 'c1', number: {equals: 3}}, {property: 'a%3Bb', select: {equals: 'Open'}}]}}},
  run({schema: pair, where}) {
    const bindings = new Map(pair.bindings.map(binding => [binding.name, binding])), and = [];
    for (const [name, value] of Object.entries(where).sort(byName)) {
      const binding = bindings.get(name);
      if (!binding) refuse('property_unknown');
      const {id, type} = binding;
      if (!WRITABLE.includes(type)) refuse('property_read_only');
      if (CONTAINS_ITEMS.includes(type)) for (const item of value) and.push(condition(id, type, {contains: item}));
      else if (CONTAINS.includes(type)) and.push(condition(id, type, {contains: value}));
      else if (type === 'date') and.push(condition(id, type, {equals: fieldOf(value, 'start')}));
      else and.push(condition(id, type, {equals: value}));
      if (and.length > MAX_CONDITIONS) refuse('too_many_conditions');
    }
    if (and.length === 0) refuse('input_invalid');
    return {filter: {and}};
  }};

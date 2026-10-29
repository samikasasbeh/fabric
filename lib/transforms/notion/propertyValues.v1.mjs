// F10.19 part 1 (docs/F10.19-BUILD-MAP.md part 1 item 3, question 1; docs/F10.8-BUILD-MAP.md part k): notion.propertyValues@1. Step data
// `schema`, the {schema, bindings} pair notion.schema@1 derived; resolved values `values`, plain values keyed by property name, which the
// harness has already typed by that schema. Out: an outputFrom of `schema`, keyed by property id, one reviewed value schema per writable type,
// placed whole at a create or update body's /properties:
//   title, rich_text  {title | rich_text: [{text: {content}}]}, the text cut by text.chunk@1's rule (an empty text clears it)
//   number, checkbox  {number}, {checkbox}          select, status  {select | status: {name}}
//   multi_select      {multi_select: [{name}]}       date            {date: {start, end?}}
//   url, email, phone {url}, {email}, {phone_number} people          {people: [{object: 'user', id}]}      relation  {relation: [{id}]}
// Arrays are sent whole, as given: the agent sends the whole new list, which also removes items (question 1). The transform checks again what
// the harness checked, so it refuses on its own too: a name with no binding (property_unknown), a binding of a read-only or unsupported type
// (property_read_only), an option the property does not list (option_unknown), and a name that folds in ASCII to another property's name
// (property_ambiguous: Status and status are never guessed between). Text over 100 pieces refuses with too_many_chunks.
import {foldAscii} from '../_shared/ascii.v1.mjs';
import {TransformError} from '../_shared/error.v3.mjs';
import {OPTION_TYPES, TEXT_TYPES, UNITS, WRITABLE, chunks, fieldOf} from './_types.v1.mjs';

const refuse = code => { throw new TransformError(code); };
const closed = (properties, required = Object.keys(properties)) => ({type: 'object', properties, required, additionalProperties: false});
const PIECES = {type: 'array', maxItems: 100, items: closed({text: closed({content: {type: 'string', minLength: 1, maxLength: UNITS}})})};
const NAME = {type: 'string', minLength: 1, maxLength: 1000};
const DATE = {type: 'string', minLength: 10, maxLength: 40};
const UUID = {type: 'string', format: 'uuid'};
/** The reviewed value schema of each writable type, as Notion's page property values take them. */
const VALUES = {
  title: closed({title: PIECES}), rich_text: closed({rich_text: PIECES}), number: closed({number: {type: 'number'}}), checkbox: closed({checkbox: {type: 'boolean'}}),
  select: closed({select: closed({name: NAME})}), status: closed({status: closed({name: NAME})}), multi_select: closed({multi_select: {type: 'array', maxItems: 100, items: closed({name: NAME})}}),
  date: closed({date: closed({start: DATE, end: DATE}, ['start'])}), url: closed({url: {type: 'string', minLength: 1, maxLength: 2000}}),
  email: closed({email: {type: 'string', minLength: 3, maxLength: 254}}), phone_number: closed({phone_number: {type: 'string', minLength: 1, maxLength: 100}}),
  people: closed({people: {type: 'array', maxItems: 100, items: closed({object: {type: 'string', enum: ['user']}, id: UUID})}}),
  relation: closed({relation: {type: 'array', maxItems: 100, items: closed({id: UUID})}}),
};
const byName = ([a], [b]) => a < b ? -1 : a > b ? 1 : 0;

/** The options a property's schema lists, or none: a select or status enum, a multi-select's item enum. */
function listed(schema, type) {
  const options = type === 'multi_select' ? fieldOf(fieldOf(schema, 'items'), 'enum') : fieldOf(schema, 'enum');
  return Array.isArray(options) ? options : [];
}
/** One plain value as the typed value its binding's type takes. */
function typed(binding, schema, value) {
  const type = binding.type;
  if (OPTION_TYPES.includes(type)) {
    const options = listed(schema, type), names = type === 'multi_select' ? value : [value];
    if (names.some(name => !options.includes(name))) refuse('option_unknown');
    return type === 'multi_select' ? {multi_select: value.map(name => ({name}))} : Object.fromEntries([[type, {name: value}]]);
  }
  if (TEXT_TYPES.includes(type)) return Object.fromEntries([[type, chunks(value).map(content => ({text: {content}}))]]);
  if (type === 'date') return {date: fieldOf(value, 'end') === undefined ? {start: fieldOf(value, 'start')} : {start: fieldOf(value, 'start'), end: fieldOf(value, 'end')}};
  if (type === 'people') return {people: value.map(id => ({object: 'user', id}))};
  if (type === 'relation') return {relation: value.map(id => ({id}))};
  return Object.fromEntries([[type, value]]);
}

export const ENTRY = {name: 'notion.propertyValues', version: 1, kind: 'map',
  input: {type: 'object', properties: {}, additionalProperties: false},
  pointerArgs: [], stepData: {schema: {maxBytes: 1_048_576}}, resolvedValues: {values: {schemaFrom: 'schema', maxBytes: 1_048_576}},
  outputFrom: {argument: 'schema', values: VALUES}, maxInputBytes: 2_097_152, maxOutputBytes: 2_097_152, usesClock: false, runtimeFacts: [],
  refuses: ['property_unknown', 'property_read_only', 'property_ambiguous', 'option_unknown', 'too_many_chunks'], excludes: [],
  example: {input: {schema: {schema: {type: 'object', properties: {Stage: {type: 'string', enum: ['Open', 'Done']}, Cost: {type: 'number'}}, required: [], additionalProperties: false},
    bindings: [{name: 'Stage', id: 'a%3Bb', type: 'select'}, {name: 'Cost', id: 'c1', type: 'number'}]}, values: {Stage: 'Open', Cost: 3}},
    output: {c1: {number: 3}, 'a%3Bb': {select: {name: 'Open'}}}},
  run({schema: pair, values}) {
    const bindings = new Map(pair.bindings.map(binding => [binding.name, binding])), schemas = new Map(Object.entries(pair.schema.properties)), folds = new Map();
    for (const binding of pair.bindings) folds.set(foldAscii(binding.name), (folds.get(foldAscii(binding.name)) ?? 0) + 1);
    const out = [];
    for (const [name, value] of Object.entries(values).sort(byName)) {
      const binding = bindings.get(name);
      if (!binding) refuse('property_unknown');
      if (folds.get(foldAscii(name)) > 1) refuse('property_ambiguous');
      if (!WRITABLE.includes(binding.type)) refuse('property_read_only');
      out.push([binding.id, typed(binding, schemas.get(name), value)]);
    }
    return Object.fromEntries(out);
  }};

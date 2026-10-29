// F10.19 part 1 (docs/F10.19-BUILD-MAP.md part 1 item 3): the one type table of Notion's property types, written from Notion's reference for
// 2026-03-11 (the property object, page property values and the data source query filter). notion.describe@1, notion.schema@1,
// notion.propertyValues@1, notion.filter@1 and notion.plainValues@1 all read it, so what one calls writable the others bind, write and filter
// on alike.
// - Writable: title, rich_text, number, checkbox, select, status, multi_select, date, url, email, phone_number, people and relation.
// - Read only (reason read_only): formula, rollup, created_time, created_by, last_edited_time, last_edited_by, unique_id, button and
//   verification. Notion computes or stamps them.
// - Anything else (files, place, a type Notion adds later) is unsupported_type, and a select, status or multi-select with no options yet is
//   no_options: Fabric never creates an option.
// - A property named __proto__, prototype or constructor never reaches this table: the harness refuses step data holding such a key before
//   any transform runs (lib/transforms/run.mjs, step 1), and the source scan keeps those words out of this folder.
// It also holds text.chunk@1's chunking rule, copied (a family helper reads no other family): 2,000 UTF-16 units a piece, a surrogate pair
// moved whole to the next piece, at most 100 pieces (too_many_chunks), never truncated. test/transforms-notion.test.mjs holds the two equal.
import {TransformError} from '../_shared/error.v3.mjs';

/** The writable types, in Notion's reference order. */
export const WRITABLE = Object.freeze(['title', 'rich_text', 'number', 'checkbox', 'select', 'status', 'multi_select', 'date', 'url', 'email', 'phone_number', 'people', 'relation']);
/** The types Notion computes or stamps: a write to one is refused. */
export const READ_ONLY = Object.freeze(['formula', 'rollup', 'created_time', 'created_by', 'last_edited_time', 'last_edited_by', 'unique_id', 'button', 'verification']);
/** The types whose values name one of the property's options. */
export const OPTION_TYPES = Object.freeze(['select', 'status', 'multi_select']);
/** The text types: a value is one string, cut into rich text pieces. */
export const TEXT_TYPES = Object.freeze(['title', 'rich_text']);
export const MAX_PROPERTIES = 100;
export const MAX_OPTIONS = 256;
export const UNITS = 2000;
export const MAX_PIECES = 100;
/** The most text one value holds: 100 pieces of 2,000 units, counted in code points as the schemas count. */
export const MAX_TEXT = 200_000;

const TYPE = /^[a-z][a-z0-9_]{0,63}$/;
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const refuse = code => { throw new TransformError(code); };
const byName = (a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
const high = code => code >= 0xd800 && code <= 0xdbff;
/** A field of a provider object, read through a Map so no name reaches a prototype. */
export const fieldOf = (object, name) => record(object) ? new Map(Object.entries(object)).get(name) : undefined;

/**
 * The properties of a data source or a page, as [{name, id, type, property}] sorted by name; an object with no properties has none. More
 * than 100 refuse with too_many_properties. A property that is not {id, type} as Notion documents it refuses with input_invalid.
 */
export function propertiesOf(object) {
  if (!record(object)) refuse('input_invalid');
  const properties = fieldOf(object, 'properties');
  if (properties === undefined) return [];
  if (!record(properties)) refuse('input_invalid');
  const list = Object.entries(properties).map(([name, property]) => {
    if (name === '' || name.length > 1000 || !record(property)) refuse('input_invalid');
    const id = fieldOf(property, 'id'), type = fieldOf(property, 'type');
    if (typeof id !== 'string' || id === '' || id.length > 256 || typeof type !== 'string' || !TYPE.test(type)) refuse('input_invalid');
    return {name, id, type, property};
  });
  if (list.length > MAX_PROPERTIES) refuse('too_many_properties');
  return list.sort(byName);
}

/** The option names of a select, status or multi-select property, each once, in Notion's order; at most 256 (too_many_options). */
export function optionsOf({type, property}) {
  const holder = fieldOf(property, type), options = fieldOf(holder, 'options') ?? [];
  if (!Array.isArray(options)) refuse('input_invalid');
  if (options.length > MAX_OPTIONS) refuse('too_many_options');
  const names = new Set();
  for (const option of options) {
    const name = fieldOf(option, 'name');
    if (typeof name !== 'string' || name === '' || name.length > 1000) refuse('input_invalid');
    names.add(name);
  }
  return [...names];
}

/** What Fabric may do with one property: {writable: true}, or {writable: false, reason}. */
export function kindOf(entry) {
  if (READ_ONLY.includes(entry.type)) return {writable: false, reason: 'read_only'};
  if (!WRITABLE.includes(entry.type)) return {writable: false, reason: 'unsupported_type'};
  if (OPTION_TYPES.includes(entry.type) && optionsOf(entry).length === 0) return {writable: false, reason: 'no_options'};
  return {writable: true};
}

const DATE = {type: 'string', minLength: 10, maxLength: 40};
const IDS = {type: 'array', maxItems: 100, items: {type: 'string', format: 'uuid'}};
/** The schema of the plain value one writable property takes: what an agent sends, and what a where condition names. */
export function valueSchema(entry) {
  const type = entry.type;
  if (TEXT_TYPES.includes(type)) return {type: 'string', maxLength: MAX_TEXT};
  if (type === 'number') return {type: 'number'};
  if (type === 'checkbox') return {type: 'boolean'};
  if (type === 'select' || type === 'status') return {type: 'string', enum: optionsOf(entry)};
  if (type === 'multi_select') return {type: 'array', maxItems: 100, items: {type: 'string', enum: optionsOf(entry)}};
  if (type === 'date') return {type: 'object', properties: {start: DATE, end: DATE}, required: ['start'], additionalProperties: false};
  if (type === 'url') return {type: 'string', minLength: 1, maxLength: 2000};
  if (type === 'email') return {type: 'string', minLength: 3, maxLength: 254};
  if (type === 'phone_number') return {type: 'string', minLength: 1, maxLength: 100};
  return IDS;
}

/** text.chunk@1's rule: the text in order, each piece at most 2,000 UTF-16 units with a surrogate pair kept whole, at most 100 pieces. */
export function chunks(text) {
  if (!text.isWellFormed()) refuse('input_invalid');
  const pieces = [];
  for (let start = 0; start < text.length;) {
    let end = Math.min(start + UNITS, text.length);
    if (end < text.length && high(text.charCodeAt(end - 1))) end--;
    if (pieces.length === MAX_PIECES) refuse('too_many_chunks');
    pieces.push(text.slice(start, end));
    start = end;
  }
  return pieces;
}

/** The plain text of a rich text array, every piece joined: its plain_text, else its text content. Absent or null is ''. */
export function plainText(pieces) {
  if (pieces === undefined || pieces === null) return '';
  if (!Array.isArray(pieces)) refuse('input_invalid');
  return pieces.map(piece => {
    if (!record(piece)) refuse('input_invalid');
    const plain = fieldOf(piece, 'plain_text'), content = fieldOf(fieldOf(piece, 'text'), 'content');
    return typeof plain === 'string' ? plain : typeof content === 'string' ? content : '';
  }).join('');
}

const stringOr = value => typeof value === 'string' ? value : '';
const listOf = (value, field) => Array.isArray(value) ? value.map(item => stringOr(fieldOf(item, field))).filter(text => text !== '').join(', ') : '';
/** A date value as text: its start, or "start to end". */
function dateText(value) {
  const start = fieldOf(value, 'start'), end = fieldOf(value, 'end');
  if (typeof start !== 'string') return '';
  return typeof end === 'string' && end !== '' ? `${start} to ${end}` : start;
}
/** A formula's computed value as text. */
function formulaText(value) {
  const kind = fieldOf(value, 'type'), result = fieldOf(value, kind);
  if (kind === 'date') return dateText(result);
  if (typeof result === 'number') return String(result);
  if (typeof result === 'boolean') return result ? 'true' : 'false';
  return stringOr(result);
}

/**
 * One page property value as plain text: rich text joined, a number as written, select and status names, multi-select names joined by ", ",
 * a date as its start or "start to end", a checkbox as true or false, people and relations as their ids, a formula or rollup as its computed
 * value, a unique id as PREFIX-NUMBER. A file property gives the files' names only, never a link to one. `nested` reads one level of a
 * rollup's array.
 */
export function textOf({type, property}, nested = false) {
  const value = fieldOf(property, type);
  if (TEXT_TYPES.includes(type)) return plainText(value);
  if (type === 'number') return typeof value === 'number' ? String(value) : '';
  if (type === 'checkbox') return value === true ? 'true' : 'false';
  if (type === 'select' || type === 'status') return stringOr(fieldOf(value, 'name'));
  if (type === 'multi_select') return listOf(value, 'name');
  if (type === 'date') return dateText(value);
  if (type === 'url' || type === 'email' || type === 'phone_number' || type === 'created_time' || type === 'last_edited_time') return stringOr(value);
  if (type === 'people' || type === 'relation') return listOf(value, 'id');
  if (type === 'created_by' || type === 'last_edited_by') return stringOr(fieldOf(value, 'id'));
  if (type === 'formula') return formulaText(value);
  if (type === 'files') return listOf(value, 'name');
  if (type === 'verification') return stringOr(fieldOf(value, 'state'));
  if (type === 'unique_id') {
    const number = fieldOf(value, 'number'), prefix = fieldOf(value, 'prefix');
    if (typeof number !== 'number') return '';
    return typeof prefix === 'string' && prefix !== '' ? `${prefix}-${number}` : String(number);
  }
  if (type === 'rollup' && !nested) {
    const kind = fieldOf(value, 'type'), result = fieldOf(value, kind);
    if (kind === 'array') return Array.isArray(result) ? result.map(item => textOf({type: stringOr(fieldOf(item, 'type')), property: item}, true)).filter(text => text !== '').join(', ') : '';
    if (kind === 'date') return dateText(result);
    return typeof result === 'number' ? String(result) : '';
  }
  return '';
}

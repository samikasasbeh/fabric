// F10.8 part j (docs/F10.8-BUILD-MAP.md): collections.findBy@1. Step data: `list`, a provider's list answer, at most 2 MiB. Closed: the
// pointers `items` (the list in the answer; '' for a list at the root, as a paged step's joined pages are, open point Minor 8), `field`,
// `id` and `label?` (each read in an item), declared as pointerArgs so step 9 takes them only as constants with no secret-shaped token
// (R11); `value`, `fold` ('none' or 'ascii') and `require` ('one' or 'any'). Out: {matches: [{id, label?}]}, at most 100, in list order.
// - An item matches when its field is a string equal to the value, folded A to Z only with 'ascii'. A field that is no string never
//   matches. A matched item's id must be a string; its label is kept when it is one.
// - An absent list is empty, as Calendar leaves out attendees when there are none; a value there that is no list refuses with
//   input_invalid. More than 1,000 items, or more than 100 matches, refuse with too_many_items: never truncated.
// - With require 'one', no match refuses with match_none and several with match_many: it never guesses (spec line 1467).
import {TransformError} from '../_shared/error.v1.mjs';
import {foldAscii} from '../_shared/ascii.v1.mjs';
import {pointerReader} from '../_shared/pointer.v1.mjs';

const MAX_ITEMS = 1000;
const MAX_MATCHES = 100;
const POINTER = {type: 'string', maxLength: 512};
const refuse = code => { throw new TransformError(code); };

export const ENTRY = {name: 'collections.findBy', version: 1, kind: 'map',
  input: {type: 'object', properties: {items: POINTER, field: POINTER, id: POINTER, label: POINTER, value: {type: 'string', maxLength: 1000},
    fold: {type: 'string', enum: ['none', 'ascii']}, require: {type: 'string', enum: ['one', 'any']}}, required: ['items', 'field', 'id', 'value', 'fold', 'require'],
    additionalProperties: false},
  pointerArgs: ['items', 'field', 'id', 'label'], stepData: {list: {maxBytes: 2_097_152}}, resolvedValues: {},
  output: {type: 'object', properties: {matches: {type: 'array', maxItems: MAX_MATCHES, items: {type: 'object', properties: {id: {type: 'string', minLength: 1, maxLength: 1000},
    label: {type: 'string', maxLength: 1000}}, required: ['id'], additionalProperties: false}}}, required: ['matches'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 262_144, usesClock: false, runtimeFacts: [], refuses: ['match_none', 'match_many', 'too_many_items'], excludes: [],
  example: {input: {list: {members: [{id: 'U1', profile: {email: 'Ann@Example.com', real_name: 'Ann'}}, {id: 'U2', profile: {email: 'bob@example.com'}}]}, items: '/members',
    field: '/profile/email', id: '/id', label: '/profile/real_name', value: 'ann@example.com', fold: 'ascii', require: 'one'}, output: {matches: [{id: 'U1', label: 'Ann'}]}},
  run(input) {
    const at = pointerReader(ENTRY, input), fold = input.fold === 'ascii' ? foldAscii : text => text;
    const found = at(input.list, 'items'), items = found === undefined ? [] : found;
    if (!Array.isArray(items)) refuse('input_invalid');
    if (items.length > MAX_ITEMS) refuse('too_many_items');
    const wanted = fold(input.value), matches = [];
    for (const item of items) {
      const value = at(item, 'field');
      if (typeof value !== 'string' || fold(value) !== wanted) continue;
      if (matches.length === MAX_MATCHES) refuse('too_many_items');
      const id = at(item, 'id'), label = input.label === undefined ? undefined : at(item, 'label');
      if (typeof id !== 'string' || id === '') refuse('input_invalid');
      matches.push(typeof label === 'string' ? {id, label} : {id});
    }
    if (input.require === 'one' && matches.length === 0) refuse('match_none');
    if (input.require === 'one' && matches.length > 1) refuse('match_many');
    return {matches};
  }};

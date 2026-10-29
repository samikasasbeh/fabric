// F10.8 part j (docs/F10.8-BUILD-MAP.md, R20): collections.missing@1, Create label's find-or-create (spec line 1222). Step data: `list`,
// a provider's list answer, at most 2 MiB. Closed: the pointers `items` and `field`, declared as pointerArgs, so step 9 takes them only as
// constants with no secret-shaped token (R11); `name`, and `fold` ('none' or 'ascii', A to Z only). Out: {missing: [name]} when no item's
// field equals the name, folded as asked, else {missing: []}. The POST that creates the label runs over /missing as its forEach list, so it
// runs zero or one time, and Create label never makes a second label in another case. A field that is no string never matches. An absent
// list is empty; a value there that is no list refuses with input_invalid; more than 1,000 items refuse with too_many_items.
import {TransformError} from '../_shared/error.v1.mjs';
import {foldAscii} from '../_shared/ascii.v1.mjs';
import {pointerReader} from '../_shared/pointer.v1.mjs';

const MAX_ITEMS = 1000;
const POINTER = {type: 'string', maxLength: 512};
const NAME = {type: 'string', minLength: 1, maxLength: 1000};

export const ENTRY = {name: 'collections.missing', version: 1, kind: 'map',
  input: {type: 'object', properties: {items: POINTER, field: POINTER, name: NAME, fold: {type: 'string', enum: ['none', 'ascii']}}, required: ['items', 'field', 'name', 'fold'],
    additionalProperties: false},
  pointerArgs: ['items', 'field'], stepData: {list: {maxBytes: 2_097_152}}, resolvedValues: {},
  output: {type: 'object', properties: {missing: {type: 'array', maxItems: 1, items: NAME}}, required: ['missing'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 8192, usesClock: false, runtimeFacts: [], refuses: ['too_many_items'], excludes: [],
  example: {input: {list: {labels: [{id: 'Label_2', name: 'Work'}]}, items: '/labels', field: '/name', name: 'work', fold: 'ascii'}, output: {missing: []}},
  run(input) {
    const at = pointerReader(ENTRY, input), fold = input.fold === 'ascii' ? foldAscii : text => text;
    const found = at(input.list, 'items'), items = found === undefined ? [] : found;
    if (!Array.isArray(items)) throw new TransformError('input_invalid');
    if (items.length > MAX_ITEMS) throw new TransformError('too_many_items');
    const wanted = fold(input.name);
    const present = items.some(item => {
      const value = at(item, 'field');
      return typeof value === 'string' && fold(value) === wanted;
    });
    return {missing: present ? [] : [input.name]};
  }};

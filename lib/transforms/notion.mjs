// F10.19 part 1 (docs/F10.19-BUILD-MAP.md part 1 item 3): the notion family list. It imports the ENTRY of each version module under notion/ and
// lists it with its file, and nothing else. lib/transforms/index.mjs checks every entry at import, and the source scan holds a list to its own
// folder's modules.
import {ENTRY as describe1} from './notion/describe.v1.mjs';
import {ENTRY as filter1} from './notion/filter.v1.mjs';
import {ENTRY as plainValues1} from './notion/plainValues.v1.mjs';
import {ENTRY as propertyValues1} from './notion/propertyValues.v1.mjs';
import {ENTRY as schema1} from './notion/schema.v1.mjs';
import {ENTRY as title1} from './notion/title.v1.mjs';

export const ENTRIES = Object.freeze([
  {file: 'notion/describe.v1.mjs', entry: describe1},
  {file: 'notion/filter.v1.mjs', entry: filter1},
  {file: 'notion/plainValues.v1.mjs', entry: plainValues1},
  {file: 'notion/propertyValues.v1.mjs', entry: propertyValues1},
  {file: 'notion/schema.v1.mjs', entry: schema1},
  {file: 'notion/title.v1.mjs', entry: title1},
]);

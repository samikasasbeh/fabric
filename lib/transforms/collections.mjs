// F10.8 parts b and j (docs/F10.8-BUILD-MAP.md): the collections family list. It imports the ENTRY of each version module under
// collections/ and lists it with its file, and nothing else. lib/transforms/index.mjs checks every entry at import, and the source scan
// holds a list to its own folder's modules.
import {ENTRY as diff1} from './collections/diff.v1.mjs';
import {ENTRY as findBy1} from './collections/findBy.v1.mjs';
import {ENTRY as labelIds1} from './collections/labelIds.v1.mjs';
import {ENTRY as mergeEmails1} from './collections/mergeEmails.v1.mjs';
import {ENTRY as missing1} from './collections/missing.v1.mjs';
import {ENTRY as oneOf1} from './collections/oneOf.v1.mjs';
import {ENTRY as stringValues1} from './collections/stringValues.v1.mjs';

export const ENTRIES = Object.freeze([
  {file: 'collections/diff.v1.mjs', entry: diff1},
  {file: 'collections/findBy.v1.mjs', entry: findBy1},
  {file: 'collections/labelIds.v1.mjs', entry: labelIds1},
  {file: 'collections/mergeEmails.v1.mjs', entry: mergeEmails1},
  {file: 'collections/missing.v1.mjs', entry: missing1},
  {file: 'collections/oneOf.v1.mjs', entry: oneOf1},
  {file: 'collections/stringValues.v1.mjs', entry: stringValues1},
]);

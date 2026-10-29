// F10.8 parts b and f (docs/F10.8-BUILD-MAP.md): the html family list. It imports the ENTRY of each version module under html/ and lists it
// with its file, and nothing else. lib/transforms/index.mjs checks every entry at import, and the source scan holds a list to its own
// folder's modules.
import {ENTRY as toText1} from './html/toText.v1.mjs';

export const ENTRIES = Object.freeze([{file: 'html/toText.v1.mjs', entry: toText1}]);

// F10.8 parts b and d (docs/F10.8-BUILD-MAP.md): the encoding family list. It imports the ENTRY of each version module under encoding/ and
// lists it with its file, and nothing else. lib/transforms/index.mjs checks every entry at import, and the source scan holds a list to its
// own folder's modules.
import {ENTRY as base64Decode1} from './encoding/base64Decode.v1.mjs';
import {ENTRY as base64Encode1} from './encoding/base64Encode.v1.mjs';
import {ENTRY as base64urlDecode1} from './encoding/base64urlDecode.v1.mjs';
import {ENTRY as base64urlEncode1} from './encoding/base64urlEncode.v1.mjs';

export const ENTRIES = Object.freeze([
  {file: 'encoding/base64Decode.v1.mjs', entry: base64Decode1},
  {file: 'encoding/base64Encode.v1.mjs', entry: base64Encode1},
  {file: 'encoding/base64urlDecode.v1.mjs', entry: base64urlDecode1},
  {file: 'encoding/base64urlEncode.v1.mjs', entry: base64urlEncode1},
]);

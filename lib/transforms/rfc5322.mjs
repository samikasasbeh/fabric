// F10.8 parts b and e (docs/F10.8-BUILD-MAP.md): the rfc5322 family list. It imports the ENTRY of each version module under rfc5322/ and lists
// it with its file, and nothing else. lib/transforms/index.mjs checks every entry at import, and the source scan holds a list to its own
// folder's modules.
import {ENTRY as build1} from './rfc5322/build.v1.mjs';
import {ENTRY as decodeGmailPayload1} from './rfc5322/decodeGmailPayload.v1.mjs';
import {ENTRY as decodeHeader1} from './rfc5322/decodeHeader.v1.mjs';
import {ENTRY as decodeRaw1} from './rfc5322/decodeRaw.v1.mjs';
import {ENTRY as parseAddresses1} from './rfc5322/parseAddresses.v1.mjs';
import {ENTRY as replyHeaders1} from './rfc5322/replyHeaders.v1.mjs';

export const ENTRIES = Object.freeze([
  {file: 'rfc5322/build.v1.mjs', entry: build1},
  {file: 'rfc5322/decodeGmailPayload.v1.mjs', entry: decodeGmailPayload1},
  {file: 'rfc5322/decodeHeader.v1.mjs', entry: decodeHeader1},
  {file: 'rfc5322/decodeRaw.v1.mjs', entry: decodeRaw1},
  {file: 'rfc5322/parseAddresses.v1.mjs', entry: parseAddresses1},
  {file: 'rfc5322/replyHeaders.v1.mjs', entry: replyHeaders1},
]);

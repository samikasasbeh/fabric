// F10.8 parts b and h (docs/F10.8-BUILD-MAP.md): the text family list. It imports the ENTRY of each version module under text/ and lists it
// with its file, and nothing else. lib/transforms/index.mjs checks every entry at import, and the source scan holds a list to its own
// folder's modules.
import {ENTRY as chunk1} from './text/chunk.v1.mjs';
import {ENTRY as githubQuery1} from './text/githubQuery.v1.mjs';
import {ENTRY as gmailQuery1} from './text/gmailQuery.v1.mjs';
import {ENTRY as joinList1} from './text/joinList.v1.mjs';
import {ENTRY as mentions1} from './text/mentions.v1.mjs';
import {ENTRY as slackEscape1} from './text/slackEscape.v1.mjs';
import {ENTRY as slackQuery1} from './text/slackQuery.v1.mjs';
import {ENTRY as truncate1} from './text/truncate.v1.mjs';

export const ENTRIES = Object.freeze([
  {file: 'text/chunk.v1.mjs', entry: chunk1},
  {file: 'text/githubQuery.v1.mjs', entry: githubQuery1},
  {file: 'text/gmailQuery.v1.mjs', entry: gmailQuery1},
  {file: 'text/joinList.v1.mjs', entry: joinList1},
  {file: 'text/mentions.v1.mjs', entry: mentions1},
  {file: 'text/slackEscape.v1.mjs', entry: slackEscape1},
  {file: 'text/slackQuery.v1.mjs', entry: slackQuery1},
  {file: 'text/truncate.v1.mjs', entry: truncate1},
]);

// F10.8 parts b and j (docs/F10.8-BUILD-MAP.md): the collections family list. It imports the ENTRY of each version module under
// collections/ and lists it with its file, and nothing else. lib/transforms/index.mjs checks every entry at import, and the source scan
// holds a list to its own folder's modules.
import {ENTRY as calendarGuests1} from './collections/calendarGuests.v1.mjs';
import {ENTRY as calendarSelf1} from './collections/calendarSelf.v1.mjs';
import {ENTRY as diff1} from './collections/diff.v1.mjs';
import {ENTRY as findBy1} from './collections/findBy.v1.mjs';
import {ENTRY as gmailHistory1} from './collections/gmailHistory.v1.mjs';
import {ENTRY as gmailSentBefore1} from './collections/gmailSentBefore.v1.mjs';
import {ENTRY as labelIds1} from './collections/labelIds.v1.mjs';
import {ENTRY as mergeEmails1} from './collections/mergeEmails.v1.mjs';
import {ENTRY as missing1} from './collections/missing.v1.mjs';
import {ENTRY as oneOf1} from './collections/oneOf.v1.mjs';
import {ENTRY as slackReactions1} from './collections/slackReactions.v1.mjs';
import {ENTRY as stringValues1} from './collections/stringValues.v1.mjs';

export const ENTRIES = Object.freeze([
  {file: 'collections/calendarGuests.v1.mjs', entry: calendarGuests1},
  {file: 'collections/calendarSelf.v1.mjs', entry: calendarSelf1},
  {file: 'collections/diff.v1.mjs', entry: diff1},
  {file: 'collections/findBy.v1.mjs', entry: findBy1},
  {file: 'collections/gmailHistory.v1.mjs', entry: gmailHistory1},
  {file: 'collections/gmailSentBefore.v1.mjs', entry: gmailSentBefore1},
  {file: 'collections/labelIds.v1.mjs', entry: labelIds1},
  {file: 'collections/mergeEmails.v1.mjs', entry: mergeEmails1},
  {file: 'collections/missing.v1.mjs', entry: missing1},
  {file: 'collections/oneOf.v1.mjs', entry: oneOf1},
  {file: 'collections/slackReactions.v1.mjs', entry: slackReactions1},
  {file: 'collections/stringValues.v1.mjs', entry: stringValues1},
]);

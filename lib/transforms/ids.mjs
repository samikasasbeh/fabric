// F10.8 parts b and i (docs/F10.8-BUILD-MAP.md): the ids family list. It imports the ENTRY of each version module under ids/ and lists it
// with its file, and nothing else. lib/transforms/index.mjs checks every entry at import, and the source scan holds a list to its own
// folder's modules.
import {ENTRY as gitRefName1} from './ids/gitRefName.v1.mjs';
import {ENTRY as linkPage1} from './ids/linkPage.v1.mjs';
import {ENTRY as notionId1} from './ids/notionId.v1.mjs';
import {ENTRY as ownerRepo1} from './ids/ownerRepo.v1.mjs';
import {ENTRY as slackEmoji1} from './ids/slackEmoji.v1.mjs';
import {ENTRY as repoPath1} from './ids/repoPath.v1.mjs';
import {ENTRY as slackLink1} from './ids/slackLink.v1.mjs';

export const ENTRIES = Object.freeze([
  {file: 'ids/gitRefName.v1.mjs', entry: gitRefName1},
  {file: 'ids/linkPage.v1.mjs', entry: linkPage1},
  {file: 'ids/notionId.v1.mjs', entry: notionId1},
  {file: 'ids/ownerRepo.v1.mjs', entry: ownerRepo1},
  {file: 'ids/slackEmoji.v1.mjs', entry: slackEmoji1},
  {file: 'ids/repoPath.v1.mjs', entry: repoPath1},
  {file: 'ids/slackLink.v1.mjs', entry: slackLink1},
]);

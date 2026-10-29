// F10.17 part 1 (docs/F10.17-BUILD-MAP.md part 1, F10.8 map part k): text.mentions@1. In: {text?}, at most 65,536 code points; absent
// text gives none, so an optional body never refuses a card. Out: {mentions, more?}: what GitHub notifies when it parses the text, for the
// card line "Mentions (GitHub notifies them)" of every write that carries an issue or pull request body, a comment or a review (spec line
// 1434). A mention is @login (1 to 39 letters, digits or single inner hyphens) or @org/team, where the @ is not preceded by a letter, a
// digit or one of _ - / . ` (so an address, a path or a code span's edge is no mention). Each once, compared with ASCII folding, in order,
// at most 50, with more: true past them. It only flags and refuses nothing (F10.8 part k): mentions in code are flagged too, more, never
// fewer.
import {foldAscii} from '../_shared/ascii.v1.mjs';

const MAX_MENTIONS = 50;

export const ENTRY = {name: 'text.mentions', version: 1, kind: 'map',
  input: {type: 'object', properties: {text: {type: 'string', maxLength: 65_536}}, required: [], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {mentions: {type: 'array', maxItems: MAX_MENTIONS, items: {type: 'string', minLength: 2, maxLength: 141}}, more: {type: 'boolean', enum: [true]}},
    required: ['mentions'], additionalProperties: false},
  maxInputBytes: 262_400, maxOutputBytes: 16_384, usesClock: false, runtimeFacts: [], refuses: [], excludes: [],
  example: {input: {text: 'Thanks @octo-a and @org/team'}, output: {mentions: ['@octo-a', '@org/team']}},
  run(input) {
    const mention = /(?<![A-Za-z0-9_\-/.`])@([A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38})(?:\/([A-Za-z0-9][A-Za-z0-9_-]{0,99}))?/g;
    const seen = new Set(), mentions = [];
    for (const match of (input.text ?? '').matchAll(mention)) {
      const shown = match[2] === undefined ? `@${match[1]}` : `@${match[1]}/${match[2]}`, key = foldAscii(shown);
      if (seen.has(key)) continue;
      seen.add(key);
      if (mentions.length === MAX_MENTIONS) return {mentions, more: true};
      mentions.push(shown);
    }
    return {mentions};
  }};

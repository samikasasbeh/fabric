// F10.21 part 1 e (docs/F10.21-BUILD-MAP.md part 1 e; docs/F10.8-BUILD-MAP.md line 433): text.slackQuery@1 (unicode). In: `words` (the
// person's words, required) and the optional `channel`, `from`, `after` and `before`. Out: {query}, Slack's search.messages query, written
// in this fixed order:
//   "words" in:<#C...> from:<@U...> after:YYYY-MM-DD before:YYYY-MM-DD
// - The words are one quoted phrase, so a modifier a person types (in:, from:, has:, a minus) stays part of the phrase. Words that could
//   leave their quotes (a double quote, a backslash, a control, a hidden or direction character, a lone surrogate) refuse with
//   query_value_invalid, by the rule text.gmailQuery@1 and text.githubQuery@1 quote by. More than 1,000 characters (code points) refuse
//   with query_too_long. Nothing is ever cut.
// - `channel` is a public or private channel id (C or G, then 8 to 20 capitals and digits) and `from` a user id (U or W, the same), each
//   written in Slack's own reference form; anything else refuses with query_value_invalid, so a name or a second modifier never gets in.
// - `after` and `before` are real calendar days, YYYY-MM-DD; Slack reads them as the days themselves, excluded.
import {TransformError} from '../_shared/error.v1.mjs';
import {utcMillis} from '../_shared/utc.v1.mjs';
import {quotable, quote} from './_quote.v1.mjs';

const MAX_WORDS = 1000;
const CHANNEL = /^[CG][A-Z0-9]{8,20}$/;
const USER = /^[UW][A-Z0-9]{8,20}$/;
const DAY = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/;
const refuse = code => { throw new TransformError(code); };
const id = (value, pattern) => pattern.test(value) ? value : refuse('query_value_invalid');
function day(value) {
  const match = DAY.exec(value);
  if (!match || utcMillis({year: Number(match[1]), month: Number(match[2]), day: Number(match[3])}) === null) refuse('query_value_invalid');
  return value;
}

export const ENTRY = {name: 'text.slackQuery', version: 1, kind: 'map',
  input: {type: 'object', properties: {words: {type: 'string', minLength: 1, maxLength: 4000}, channel: {type: 'string', maxLength: 64}, from: {type: 'string', maxLength: 64},
    after: {type: 'string', maxLength: 32}, before: {type: 'string', maxLength: 32}}, required: ['words'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {query: {type: 'string', maxLength: 4096}}, required: ['query'], additionalProperties: false},
  maxInputBytes: 65_536, maxOutputBytes: 65_536, usesClock: false, runtimeFacts: ['unicode'], refuses: ['query_value_invalid', 'query_too_long'], excludes: [],
  example: {input: {words: 'x in:#secret', channel: 'C024BE91L', after: '2026-10-01'}, output: {query: '"x in:#secret" in:<#C024BE91L> after:2026-10-01'}},
  run(input) {
    if (!quotable(input.words)) refuse('query_value_invalid');
    if ([...input.words].length > MAX_WORDS) refuse('query_too_long');
    const parts = [quote(input.words)];
    if (input.channel !== undefined) parts.push(`in:<#${id(input.channel, CHANNEL)}>`);
    if (input.from !== undefined) parts.push(`from:<@${id(input.from, USER)}>`);
    if (input.after !== undefined) parts.push(`after:${day(input.after)}`);
    if (input.before !== undefined) parts.push(`before:${day(input.before)}`);
    return {query: parts.join(' ')};
  }};

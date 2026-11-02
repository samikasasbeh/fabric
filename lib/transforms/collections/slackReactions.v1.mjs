// Iteration 9 step 4 (docs/I07-BUILD-MAP.md section 2.7 and step 4): collections.slackReactions@1, what `reaction-recent` reads. Step data: `list`, the `messages` of a
// conversations.history answer, at most 2 MiB. Out: {items: [{name, count, parent: {ts, user?}}]}, one item for each reaction of each message, in list order, at most 1,000.
// - count is Slack's own number. Slack cuts `users` short of it in a history answer, so a length here would miss a rise past the cut.
// - A message with no `reactions` gives none. A value that is no list refuses with input_invalid, as the harness does for no value at all.
// - A message from a bot has no user, so its parent holds only ts. An entry that cannot be told (no ts, no name, a count that is no whole number within the event's
//   range) is left out, as one odd entry must not stop a watch. Slack sends none of these.
// - More than 1,000 messages or reactions refuse with too_many_items: never truncated, since a reaction cut here would read as one nobody ever made.
import {TransformError} from '../_shared/error.v1.mjs';

const MAX_MESSAGES = 1000, MAX_ITEMS = 1000, MAX_COUNT = 1_000_000, MAX_NAME = 116, MAX_TS = 17, MAX_USER = 64;
const text = (value, max) => typeof value === 'string' && value.length >= 1 && value.length <= max;

export const ENTRY = {name: 'collections.slackReactions', version: 1, kind: 'map',
  input: {type: 'object', properties: {}, additionalProperties: false},
  pointerArgs: [], stepData: {list: {maxBytes: 2_097_152}}, resolvedValues: {},
  output: {type: 'object', properties: {items: {type: 'array', maxItems: MAX_ITEMS, items: {type: 'object', properties: {name: {type: 'string', minLength: 1, maxLength: MAX_NAME},
    count: {type: 'integer', minimum: 0, maximum: MAX_COUNT}, parent: {type: 'object', properties: {ts: {type: 'string', minLength: 1, maxLength: MAX_TS}, user: {type: 'string', minLength: 1, maxLength: MAX_USER}},
      required: ['ts'], additionalProperties: false}}, required: ['name', 'count', 'parent'], additionalProperties: false}}}, required: ['items'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 1_048_576, usesClock: false, runtimeFacts: [], refuses: ['too_many_items'], excludes: [],
  example: {input: {list: [{ts: '1761490000.000100', user: 'U0ADA0001', reactions: [{name: 'tada', users: ['U0ADA0001'], count: 1}]}, {ts: '1761489000.000100', text: 'No reactions'}]},
    output: {items: [{name: 'tada', count: 1, parent: {ts: '1761490000.000100', user: 'U0ADA0001'}}]}},
  run(input) {
    if (!Array.isArray(input.list)) throw new TransformError('input_invalid');
    if (input.list.length > MAX_MESSAGES) throw new TransformError('too_many_items');
    const items = [];
    for (const message of input.list) {
      if (!text(message?.ts, MAX_TS) || !Array.isArray(message.reactions)) continue;
      const parent = {ts: message.ts, ...(text(message.user, MAX_USER) ? {user: message.user} : {})};
      for (const reaction of message.reactions) {
        if (!text(reaction?.name, MAX_NAME) || !Number.isSafeInteger(reaction.count) || reaction.count < 0 || reaction.count > MAX_COUNT) continue;
        if (items.length === MAX_ITEMS) throw new TransformError('too_many_items');
        items.push({name: reaction.name, count: reaction.count, parent});
      }
    }
    return {items};
  }};

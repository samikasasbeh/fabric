// F10.21 part 1 e (docs/F10.21-BUILD-MAP.md part 1 e; docs/F10.8-BUILD-MAP.md line 434): ids.slackEmoji@1. In: {name}, an emoji name as
// reactions.add takes it (thumbsup) or as a person writes it (:thumbsup:). Out: {name, code}: `name` is the bare name reactions.add and
// reactions.remove take, and `code` is the :name: form users.profile.set takes for status_emoji.
// A name is 1 to 100 of a to z, 0 to 9, _, -, + and ', with an optional skin tone ::skin-tone-2 to ::skin-tone-6. Anything else refuses with
// emoji_invalid: a Unicode emoji (Slack names emoji by name, so a pasted character would be refused by Slack or read as another), capitals,
// spaces, colons inside the name, an empty name and 101 characters. ASCII only, so no Unicode table is read.
import {TransformError} from '../_shared/error.v4.mjs';

const NAME = /^[a-z0-9_+'-]{1,100}(?:::skin-tone-[2-6])?$/;

export const ENTRY = {name: 'ids.slackEmoji', version: 1, kind: 'map',
  input: {type: 'object', properties: {name: {type: 'string', maxLength: 300}}, required: ['name'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {name: {type: 'string', minLength: 1, maxLength: 116}, code: {type: 'string', minLength: 3, maxLength: 118}}, required: ['name', 'code'],
    additionalProperties: false},
  maxInputBytes: 1024, maxOutputBytes: 1024, usesClock: false, runtimeFacts: [], refuses: ['emoji_invalid'], excludes: [],
  example: {input: {name: ':white_check_mark:'}, output: {name: 'white_check_mark', code: ':white_check_mark:'}},
  run(input) {
    const colons = input.name.length > 2 && input.name.startsWith(':') && input.name.endsWith(':');
    const name = colons ? input.name.slice(1, -1) : input.name;
    if (!NAME.test(name)) throw new TransformError('emoji_invalid');
    return {name, code: `:${name}:`};
  }};

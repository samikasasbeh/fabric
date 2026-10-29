// F10.8 part h (docs/F10.8-BUILD-MAP.md): text.slackEscape@1. In: {text}. Out: {text}, with &, then <, then > escaped exactly as
// toSlack() escapes card text (lib/cards.mjs:165). That neutralises <!channel>, <!here>, <!everyone>, <@U...>, <#C...> and <url|label>
// links (spec line 693): Slack reads none of them once their brackets are entities. Escaped text over 40,000 UTF-16 code units refuses
// with text_too_long, so Slack never cuts text the owner approved (open question 20); counting code units, never fewer than code points,
// keeps on the safe side of how Slack counts. A lone surrogate has no form Slack can store, so it refuses with input_invalid.
import {TransformError} from '../_shared/error.v1.mjs';

const MAX_UNITS = 40_000;

export const ENTRY = {name: 'text.slackEscape', version: 1, kind: 'map',
  input: {type: 'object', properties: {text: {type: 'string', maxLength: 1_000_000}}, required: ['text'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {text: {type: 'string', maxLength: MAX_UNITS}}, required: ['text'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 262_144, usesClock: false, runtimeFacts: [], refuses: ['text_too_long'], excludes: [],
  example: {input: {text: '<!channel> R&D is <here>'}, output: {text: '&lt;!channel&gt; R&amp;D is &lt;here&gt;'}},
  run(input) {
    if (!input.text.isWellFormed()) throw new TransformError('input_invalid');
    const text = input.text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    if (text.length > MAX_UNITS) throw new TransformError('text_too_long');
    return {text};
  }};

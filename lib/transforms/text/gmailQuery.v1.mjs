// F10.8 part h (docs/F10.8-BUILD-MAP.md): text.gmailQuery@1 (unicode). In: plain fields, each optional: from, to, subject, label and words
// (text of 1 to 1,000 code points), hasAttachment, and after and before (integer epoch seconds, picked from
// time.rfc3339ToEpochSeconds@1's /seconds). Out: {q}, Gmail's search query, written in this fixed order:
//   from:"..." to:"..." subject:"..." label:"..." has:attachment (or -has:attachment for false) "words" after:N before:N
// Each text value sits inside double quotes, so an operator inside it ("x OR in:trash") stays part of one quoted phrase. A value that
// could leave its quotes (a double quote, a backslash, a control, a hidden or direction character, a lone surrogate) refuses with
// query_value_invalid; so does an after or before earlier than 1970, which Gmail could read as a negated term. This replaces the
// adapter's concatenation (examples/connect-broker/fabric_broker.py:522). An agent never writes its own operators.
import {TransformError} from '../_shared/error.v1.mjs';
import {quotable, quote} from './_quote.v1.mjs';

const VALUE = {type: 'string', minLength: 1, maxLength: 1000};
// Years 0000 to 9999 at any offset: the range of time.rfc3339ToEpochSeconds@1's /seconds, so its output always fits here.
const SECONDS = {type: 'integer', minimum: -62_167_305_540, maximum: 253_402_387_139};
const refuse = () => { throw new TransformError('query_value_invalid'); };
const quoted = text => quotable(text) ? quote(text) : refuse();
const seconds = value => value >= 0 ? String(value) : refuse();

export const ENTRY = {name: 'text.gmailQuery', version: 1, kind: 'map',
  input: {type: 'object', properties: {from: VALUE, to: VALUE, subject: VALUE, label: VALUE, hasAttachment: {type: 'boolean'}, words: VALUE, after: SECONDS, before: SECONDS},
    additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {q: {type: 'string', maxLength: 8192}}, required: ['q'], additionalProperties: false},
  maxInputBytes: 65_536, maxOutputBytes: 65_536, usesClock: false, runtimeFacts: ['unicode'], refuses: ['query_value_invalid'], excludes: [],
  example: {input: {from: 'ann@example.com', subject: 'x OR in:trash', after: 1_792_504_800}, output: {q: 'from:"ann@example.com" subject:"x OR in:trash" after:1792504800'}},
  run(input) {
    const parts = [];
    for (const [operator, value] of [['from:', input.from], ['to:', input.to], ['subject:', input.subject], ['label:', input.label]]) {
      if (value !== undefined) parts.push(operator + quoted(value));
    }
    if (input.hasAttachment !== undefined) parts.push(input.hasAttachment ? 'has:attachment' : '-has:attachment');
    if (input.words !== undefined) parts.push(quoted(input.words));
    if (input.after !== undefined) parts.push(`after:${seconds(input.after)}`);
    if (input.before !== undefined) parts.push(`before:${seconds(input.before)}`);
    return {q: parts.join(' ')};
  }};

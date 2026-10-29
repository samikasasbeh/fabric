// F10.8 part e (docs/F10.8-BUILD-MAP.md): rfc5322.decodeHeader@1. In: {value}, a header value. Out: {text}: folds undone, and RFC 2047
// encoded-words decoded where each is well formed and its charset decodes its bytes exactly (open question 19). White space between two
// encoded-words goes; an RFC 2231 language tag is ignored. A word in an unknown charset (or in utf-7), with bad hex or base64, or with bytes
// its charset does not allow, stays as written (RFC 2047 section 6.3). At most 10,000 words decode; any after stay as written.
import {decodeWords} from './_mime.v1.mjs';

export const ENTRY = {name: 'rfc5322.decodeHeader', version: 1, kind: 'map',
  input: {type: 'object', properties: {value: {type: 'string', maxLength: 1_000_000}}, required: ['value'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {text: {type: 'string', maxLength: 1_000_000}}, required: ['text'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 2_097_152, usesClock: false, runtimeFacts: ['charset'], refuses: [], excludes: [],
  example: {input: {value: '=?ISO-8859-1?Q?Andr=E9?= Pirard <PIRARD@vm1.ulg.ac.be>'}, output: {text: 'André Pirard <PIRARD@vm1.ulg.ac.be>'}},
  run(input) {
    return {text: decodeWords(input.value)};
  }};

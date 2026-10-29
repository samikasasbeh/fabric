// F10.8 part d (docs/F10.8-BUILD-MAP.md): encoding.base64urlEncode@1. Padded base64url of UTF-8 text. In: {text}, at most 750,000 bytes as UTF-8. Out: {encoded}, at
// most 1,000,000 characters. Text with a lone surrogate has no UTF-8 form and refuses with utf8_invalid; longer text with input_too_large.
import {TransformError} from '../_shared/error.v1.mjs';
import {ENCODED_OUTPUT, TEXT_INPUT, encodeText} from './_text.v1.mjs';

export const ENTRY = {name: 'encoding.base64urlEncode', version: 1, kind: 'map', input: TEXT_INPUT, pointerArgs: [], stepData: {}, resolvedValues: {}, output: ENCODED_OUTPUT,
  maxInputBytes: 2_097_152, maxOutputBytes: 1_048_576, usesClock: false, runtimeFacts: [], refuses: ['utf8_invalid'], excludes: [],
  example: {input: {text: 'foobar'}, output: {encoded: 'Zm9vYmFy'}},
  run(input) {
    const result = encodeText(input.text, 'base64url');
    if (result.code) throw new TransformError(result.code);
    return result.output;
  }};

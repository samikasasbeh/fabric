// F10.8 part d (docs/F10.8-BUILD-MAP.md): encoding.base64urlDecode@1. Step data `encoded`: strict base64url, checked before Buffer sees it
// (one alphabet, padding correct or absent, canonical trailing bits, no whitespace). No closed arguments. Out: {text}, at most 1,000,000
// code points, or {binary: true, bytes} when the bytes hold a NUL. Other bytes that are not UTF-8 refuse with utf8_invalid.
import {TransformError} from '../_shared/error.v1.mjs';
import {DECODED_OUTPUT, ENCODED_STEP_DATA, decodeText} from './_text.v1.mjs';

export const ENTRY = {name: 'encoding.base64urlDecode', version: 1, kind: 'map', input: {type: 'object', properties: {}, additionalProperties: false},
  pointerArgs: [], stepData: ENCODED_STEP_DATA, resolvedValues: {}, output: DECODED_OUTPUT, maxInputBytes: 1_400_000, maxOutputBytes: 2_097_152, usesClock: false,
  runtimeFacts: [], refuses: ['encoding_invalid', 'utf8_invalid', 'output_too_large'], excludes: [],
  example: {input: {encoded: 'Zm9vYmFy'}, output: {text: 'foobar'}},
  run(input) {
    const result = decodeText(input.encoded, 'base64url', 'none');
    if (result.code) throw new TransformError(result.code);
    return result.output;
  }};

// F10.8 part d (docs/F10.8-BUILD-MAP.md): what the four encoding transforms share. Text becomes bytes only as UTF-8, and bytes become text
// only through the strict UTF-8 decoder, never with replacement characters. Bytes that hold a NUL are reported as binary with their count,
// as git reads a NUL as the mark of a binary file; any other bytes that are not UTF-8 refuse. The caps keep every output within the closed
// schema subset (lib/compiler.mjs:123, 178): 750,000 bytes of text encode to exactly 1,000,000 characters, and decoded text is at most
// 1,000,000 code points. This helper serves one family, so it names the codes and the version module throws them.
import {decodeBase64, encodeBase64} from '../_shared/base64.v1.mjs';
import {decodeUtf8, encodeUtf8} from '../_shared/utf8.v1.mjs';

const MAX_TEXT_BYTES = 750_000;
const MAX_TEXT_CODE_POINTS = 1_000_000;

/** The closed input of the encoders: text of at most 750,000 bytes as UTF-8, a byte rule encodeText checks, so every longer text refuses
 * the same way. The schema bound is the subset's own ceiling of 1,000,000 code points. */
export const TEXT_INPUT = Object.freeze({type: 'object', properties: {text: {type: 'string', maxLength: 1_000_000}}, required: ['text'], additionalProperties: false});
/** The output of the encoders: padded base64 or base64url. */
export const ENCODED_OUTPUT = Object.freeze({type: 'object', properties: {encoded: {type: 'string', maxLength: 1_000_000}}, required: ['encoded'], additionalProperties: false});
/** The output of the decoders: {text}, or {binary: true, bytes} with the decoded byte count. */
export const DECODED_OUTPUT = Object.freeze({type: 'object', properties: {text: {type: 'string', maxLength: MAX_TEXT_CODE_POINTS},
  binary: {type: 'boolean', enum: [true]}, bytes: {type: 'integer', minimum: 0, maximum: 1_050_000}}, additionalProperties: false});
/** The step data of the decoders: the encoded text, at most 1,400,000 bytes as JSON. */
export const ENCODED_STEP_DATA = Object.freeze({encoded: Object.freeze({maxBytes: 1_400_000})});

/** The number of code points in well-formed text. */
function codePoints(text) {
  let count = 0;
  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) index++;
    count++;
  }
  return count;
}

/** {output: {encoded}} for text, or {code} when it has no UTF-8 form or is over 750,000 bytes. */
export function encodeText(text, alphabet) {
  const bytes = encodeUtf8(text);
  if (bytes === null) return {code: 'utf8_invalid'};
  if (bytes.length > MAX_TEXT_BYTES) return {code: 'input_too_large'};
  return {output: {encoded: encodeBase64(bytes, alphabet)}};
}

/** {output: {text} or {binary: true, bytes}} for strict base64 or base64url step data, or {code} for anything else. */
export function decodeText(encoded, alphabet, lineBreaks) {
  if (typeof encoded !== 'string') return {code: 'input_invalid'};
  const bytes = decodeBase64(encoded, alphabet, lineBreaks);
  if (bytes === null) return {code: 'encoding_invalid'};
  if (bytes.includes(0)) return {output: {binary: true, bytes: bytes.length}};
  const text = decodeUtf8(bytes);
  if (text === null) return {code: 'utf8_invalid'};
  if (codePoints(text) > MAX_TEXT_CODE_POINTS) return {code: 'output_too_large'};
  return {output: {text}};
}

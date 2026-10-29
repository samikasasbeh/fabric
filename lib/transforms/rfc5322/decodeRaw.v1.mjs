// F10.8 part e (docs/F10.8-BUILD-MAP.md): rfc5322.decodeRaw@1, for a draft's `raw` (Create draft's readback, Edit draft, Send draft) and the
// card of a built message. Step data `raw`: base64url of a whole message, at most 2,097,152 bytes. Each part's Content-Transfer-Encoding is
// applied (base64, quoted-printable, 7bit, 8bit, binary; any other marks the part unknown_transfer_encoding), then its charset. Out:
// {headers, headersTruncated?, summary, text?, html?, truncated?, attachments, parts} as lib/transforms/rfc5322/_mime.v1.mjs describes.
// Nothing a message says refuses (open point Minor 9); a raw that is not strict base64url refuses with mime_invalid.
import {TransformError} from '../_shared/error.v1.mjs';
import {DECODED, readRaw} from './_mime.v1.mjs';

export const ENTRY = {name: 'rfc5322.decodeRaw', version: 1, kind: 'map', input: {type: 'object', properties: {}, additionalProperties: false},
  pointerArgs: [], stepData: {raw: {maxBytes: 2_097_152}}, resolvedValues: {}, output: DECODED, maxInputBytes: 2_097_152, maxOutputBytes: 2_097_152,
  usesClock: false, runtimeFacts: ['charset'], refuses: ['mime_invalid'], excludes: [],
  example: {input: {raw: 'RnJvbTogQW5uIDxhbm5AZXhhbXBsZS5jb20-DQpTdWJqZWN0OiBIaQ0KDQpIZWxsby4NCg'}, output: {headers: [{name: 'From', value: 'Ann <ann@example.com>'}, {name: 'Subject', value: 'Hi'}],
    summary: {from: [{name: 'Ann', address: 'ann@example.com'}], subject: 'Hi'}, text: 'Hello.\r\n', attachments: [],
    parts: [{partId: '', mimeType: 'text/plain', decoded: true, charset: 'us-ascii'}]}},
  run(input) {
    const result = readRaw(input.raw);
    if (result === null) throw new TransformError('mime_invalid');
    return result;
  }};

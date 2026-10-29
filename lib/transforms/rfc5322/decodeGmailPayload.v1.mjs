// F10.8 part e (docs/F10.8-BUILD-MAP.md): rfc5322.decodeGmailPayload@1, for Find emails (format=metadata, through /summary), Read email and
// Read conversation (format=full). Step data `message`: a Gmail Message, at most 2,097,152 bytes, the assertJson() cap (lib/compiler.mjs:7).
// Gmail's body.data is base64url of a part's already decoded bytes, so no Content-Transfer-Encoding is applied again (applying it would
// decode quoted-printable twice and corrupt base64 parts); only the charset is. Out: {headers, headersTruncated?, summary, text?, html?,
// truncated?, attachments, parts} as lib/transforms/rfc5322/_mime.v1.mjs describes; attachments are listed, never fetched. Nothing a message
// says refuses (open point Minor 9); a value with no payload object refuses with mime_invalid.
import {TransformError} from '../_shared/error.v1.mjs';
import {DECODED, readGmail} from './_mime.v1.mjs';

export const ENTRY = {name: 'rfc5322.decodeGmailPayload', version: 1, kind: 'map', input: {type: 'object', properties: {}, additionalProperties: false},
  pointerArgs: [], stepData: {message: {maxBytes: 2_097_152}}, resolvedValues: {}, output: DECODED, maxInputBytes: 2_097_152, maxOutputBytes: 2_097_152,
  usesClock: false, runtimeFacts: ['charset'], refuses: ['mime_invalid'], excludes: [],
  example: {input: {message: {id: 'm1', threadId: 't1', payload: {partId: '', mimeType: 'text/plain', filename: '', headers: [{name: 'From', value: 'Ann <ann@example.com>'},
    {name: 'Subject', value: 'Hi'}, {name: 'Content-Type', value: 'text/plain; charset=UTF-8'}], body: {size: 6, data: 'SGVsbG8u'}}}}, output: {headers: [{name: 'From', value: 'Ann <ann@example.com>'}, {name: 'Subject', value: 'Hi'},
    {name: 'Content-Type', value: 'text/plain; charset=UTF-8'}], summary: {from: [{name: 'Ann', address: 'ann@example.com'}], subject: 'Hi'}, text: 'Hello.',
    attachments: [], parts: [{partId: '', mimeType: 'text/plain', decoded: true, charset: 'UTF-8'}]}},
  run(input) {
    const result = readGmail(input.message);
    if (result === null) throw new TransformError('mime_invalid');
    return result;
  }};

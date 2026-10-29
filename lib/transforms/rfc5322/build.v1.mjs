// F10.8 part e (docs/F10.8-BUILD-MAP.md): rfc5322.build@1, the message Send email, Reply, Create draft and Edit draft send as Gmail's `raw`.
// In: from ({address, name?}), to, cc and bcc (lists of {address, name?}), subject, text, inReplyTo, references and now. Out: {raw, bytes,
// recipientCount}. It writes From, To, Cc and Bcc when given, Subject, Date (from now, RFC 5322 section 3.3 form, in UTC), In-Reply-To and
// References when given, MIME-Version and a text/plain UTF-8 body in base64 lines of 76 characters. It never writes Reply-To (R19: T4 names
// reply-to addresses as a destination an agent must not choose), Message-ID (Gmail assigns it), a group or an obsolete form.
// - Header text holding a control, a hidden or direction character, U+2028, U+2029 or a lone surrogate refuses with header_injection.
// - More than 500 recipients in To, Cc and Bcc together: too_many_recipients. An address that is not ASCII dot-atom of at most 254
//   characters: address_invalid. A message id that is not one well-formed msg-id, or references that are not 1 to 100 of them separated by
//   single spaces: message_id_invalid.
// - Text over 500,000 bytes, or a message over 750,000 bytes, refuses with message_too_large, so raw is at most 1,000,000 characters and a
//   send or draft body stays under the 1,048,576-byte request cap (lib/network.mjs:40). raw is padded base64url, as Gmail's sending guide.
import {encodeBase64} from '../_shared/base64.v1.mjs';
import {TransformError} from '../_shared/error.v1.mjs';
import {encodeUtf8} from '../_shared/utf8.v1.mjs';
import {buildableAddress, validMessageId, validReferences} from './_address.v1.mjs';
import {MAILBOX, MESSAGE_ID, RECIPIENTS, REFERENCES, SUBJECT, dateValue, idsField, injected, mailboxField, unstructuredField} from './_header.v1.mjs';

const MAX_RECIPIENTS = 500;
const MAX_TEXT_BYTES = 500_000;
const MAX_MESSAGE_BYTES = 750_000;
const refuse = code => { throw new TransformError(code); };

/** The base64 of the body in lines of 76 characters, each ending with CRLF (RFC 2045 section 6.8). */
function bodyLines(bytes) {
  const encoded = encodeBase64(bytes, 'base64'), lines = [];
  for (let index = 0; index < encoded.length; index += 76) lines.push(`${encoded.slice(index, index + 76)}\r\n`);
  return lines.join('');
}

export const ENTRY = {name: 'rfc5322.build', version: 1, kind: 'map',
  input: {type: 'object', properties: {from: MAILBOX, to: RECIPIENTS, cc: RECIPIENTS, bcc: RECIPIENTS, subject: SUBJECT, text: {type: 'string', maxLength: 1_000_000},
    inReplyTo: MESSAGE_ID, references: REFERENCES, now: {type: 'integer', minimum: 0, maximum: 8_640_000_000_000_000}}, required: ['from', 'subject', 'text', 'now'],
  additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {raw: {type: 'string', maxLength: 1_000_000}, bytes: {type: 'integer', minimum: 0, maximum: MAX_MESSAGE_BYTES},
    recipientCount: {type: 'integer', minimum: 0, maximum: MAX_RECIPIENTS}}, required: ['raw', 'bytes', 'recipientCount'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 1_048_576, usesClock: true, runtimeFacts: ['unicode'],
  refuses: ['header_injection', 'address_invalid', 'too_many_recipients', 'message_too_large', 'message_id_invalid'], excludes: [],
  example: {input: {from: {address: 'owner@example.com', name: 'Owner'}, to: [{address: 'ann@example.com', name: 'Ann'}], subject: 'Hello', text: 'Hi there',
    now: 1_792_504_800_000}, output: {raw: 'RnJvbTogT3duZXIgPG93bmVyQGV4YW1wbGUuY29tPg0KVG86IEFubiA8YW5uQGV4YW1wbGUuY29tPg0KU3ViamVjdDogSGVsbG8NCkRhdGU6IFR1ZSwgMjAgT2N0IDIwMjYgMTQ6MDA6MDAgKzAwMDANCk1JTUUtVmVyc2lvbjogMS4wDQpDb250ZW50LVR5cGU6IHRleHQvcGxhaW47IGNoYXJzZXQ9VVRGLTgNCkNvbnRlbnQtVHJhbnNmZXItRW5jb2Rpbmc6IGJhc2U2NA0KDQpTR2tnZEdobGNtVT0NCg==',
    bytes: 226, recipientCount: 1}},
  run(input) {
    const lists = [input.to ?? [], input.cc ?? [], input.bcc ?? []], boxes = [input.from, ...lists.flat()];
    const header = [input.subject, input.inReplyTo ?? '', input.references ?? '', ...boxes.flatMap(box => [box.address, box.name ?? ''])];
    if (header.some(injected)) refuse('header_injection');
    const count = lists.reduce((sum, list) => sum + list.length, 0);
    if (count > MAX_RECIPIENTS) refuse('too_many_recipients');
    if (!boxes.every(box => buildableAddress(box.address))) refuse('address_invalid');
    if ((input.inReplyTo !== undefined && !validMessageId(input.inReplyTo)) || (input.references !== undefined && !validReferences(input.references))) refuse('message_id_invalid');
    const body = encodeUtf8(input.text);
    if (body === null) refuse('input_invalid');
    if (body.length > MAX_TEXT_BYTES) refuse('message_too_large');
    const fields = [mailboxField('From', [input.from])];
    for (const [name, list] of [['To', input.to], ['Cc', input.cc], ['Bcc', input.bcc]]) if (list?.length) fields.push(mailboxField(name, list));
    fields.push(unstructuredField('Subject', input.subject), `Date: ${dateValue(input.now)}`);
    if (input.inReplyTo !== undefined) fields.push(idsField('In-Reply-To', [input.inReplyTo]));
    if (input.references !== undefined) fields.push(idsField('References', input.references.split(' ')));
    fields.push('MIME-Version: 1.0', 'Content-Type: text/plain; charset=UTF-8', 'Content-Transfer-Encoding: base64');
    const message = `${fields.join('\r\n')}\r\n\r\n${bodyLines(body)}`;
    const bytes = Buffer.byteLength(message);
    if (bytes > MAX_MESSAGE_BYTES) refuse('message_too_large');
    return {raw: encodeBase64(encodeUtf8(message), 'base64url'), bytes, recipientCount: count};
  }};

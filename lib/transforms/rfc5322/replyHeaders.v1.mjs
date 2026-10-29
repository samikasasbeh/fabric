// F10.8 part e (docs/F10.8-BUILD-MAP.md): rfc5322.replyHeaders@1, the headers of Reply. Step data `parent`: a Gmail Message in format=metadata
// or format=full, at most 2,097,152 bytes. Closed: owner ({address}) and replyAll. Out: {to, cc, subject, inReplyTo, references}, each in the
// exact schema rfc5322.build@1 takes, so each reaches the build through one {pick} (R1).
// - `to` is the parent's Reply-To when it has one, else its From (spec line 1217). A Reply-To that does not parse or names nobody refuses
//   with address_invalid and never falls back to From. This reads a Reply-To; nothing in Fabric writes one (R19).
// - Reply-all adds the parent's To to `to` and its Cc as `cc`, and removes the owner's address, compared with ASCII case folding (spec line
//   1025). An address is listed once. More than 500 recipients refuse with too_many_recipients; an address the builder cannot write, with
//   address_invalid. A display name the builder would refuse (a hidden character, a line break, over 1,000 code points) is dropped and its
//   address kept.
// - The subject gets one "Re: ", never "Re: Re: ": a subject that starts with "re:" in any ASCII case is kept as it is.
// - In-Reply-To is the parent's Message-ID; a missing, repeated or malformed one refuses with message_id_invalid. References is the parent's
//   References (its well-formed ids), else its In-Reply-To when that holds exactly one id, then the parent's Message-ID; past 100 ids the
//   first and the last 99 are kept.
import {foldAscii} from '../_shared/ascii.v1.mjs';
import {TransformError} from '../_shared/error.v1.mjs';
import {buildableAddress, messageIdsIn} from './_address.v1.mjs';
import {MESSAGE_ID, RECIPIENTS, REFERENCES, SUBJECT, writableName} from './_header.v1.mjs';
import {fieldValues, messageFields, summarize} from './_mime.v1.mjs';

const MAX_RECIPIENTS = 500;
const MAX_REFERENCES = 100;
const refuse = code => { throw new TransformError(code); };

export const ENTRY = {name: 'rfc5322.replyHeaders', version: 1, kind: 'map',
  input: {type: 'object', properties: {owner: {type: 'object', properties: {address: {type: 'string', minLength: 1, maxLength: 254}}, required: ['address'],
    additionalProperties: false}, replyAll: {type: 'boolean'}}, required: ['owner', 'replyAll'], additionalProperties: false},
  pointerArgs: [], stepData: {parent: {maxBytes: 2_097_152}}, resolvedValues: {},
  output: {type: 'object', properties: {to: RECIPIENTS, cc: RECIPIENTS, subject: SUBJECT, inReplyTo: MESSAGE_ID, references: REFERENCES},
    required: ['to', 'cc', 'subject', 'inReplyTo', 'references'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 1_048_576, usesClock: false, runtimeFacts: ['charset', 'unicode'],
  refuses: ['address_invalid', 'too_many_recipients', 'message_id_invalid', 'mime_invalid'], excludes: [],
  example: {input: {parent: {id: 'm1', threadId: 't1', payload: {mimeType: 'text/plain', headers: [{name: 'From', value: 'John Doe <jdoe@machine.example>'},
    {name: 'To', value: 'Mary Smith <mary@example.net>'}, {name: 'Subject', value: 'Saying Hello'}, {name: 'Message-ID', value: '<1234@local.machine.example>'}]}},
  owner: {address: 'mary@example.net'}, replyAll: false}, output: {to: [{name: 'John Doe', address: 'jdoe@machine.example'}], cc: [], subject: 'Re: Saying Hello',
    inReplyTo: '<1234@local.machine.example>', references: '<1234@local.machine.example>'}},
  run(input) {
    const fields = messageFields(input.parent);
    if (fields === null) refuse('mime_invalid');
    const summary = summarize(fields), invalid = new Set(summary.invalid ?? []);
    if (summary.messageId === undefined) refuse('message_id_invalid');
    if (invalid.has('subject')) refuse('mime_invalid');
    if (invalid.has('replyTo') || (summary.replyTo !== undefined && !summary.replyTo.length) || (summary.replyTo === undefined && summary.from === undefined)) refuse('address_invalid');
    let to = summary.replyTo ?? summary.from, cc = [];
    if (input.replyAll) {
      if (invalid.has('to') || invalid.has('cc')) refuse('address_invalid');
      to = [...to, ...(summary.to ?? [])];
      cc = summary.cc ?? [];
    }
    const owner = foldAscii(input.owner.address), seen = new Set();
    const tidy = list => list.filter(box => {
      const key = foldAscii(box.address);
      if (seen.has(key) || (input.replyAll && key === owner)) return false;
      seen.add(key);
      return true;
    }).map(box => writableName(box.name) ? {name: box.name, address: box.address} : {address: box.address});
    const toList = tidy(to), ccList = tidy(cc);
    if (toList.length + ccList.length > MAX_RECIPIENTS) refuse('too_many_recipients');
    if (![...toList, ...ccList].every(box => buildableAddress(box.address))) refuse('address_invalid');
    const subject = summary.subject ?? '';
    const chain = fieldValues(fields, 'references').flatMap(value => messageIdsIn(value));
    const replied = fieldValues(fields, 'in-reply-to').flatMap(value => messageIdsIn(value));
    const ids = [...(chain.length ? chain : replied.length === 1 ? replied : []), summary.messageId];
    return {to: toList, cc: ccList, subject: foldAscii(subject).startsWith('re:') ? subject : subject ? `Re: ${subject}` : 'Re:', inReplyTo: summary.messageId,
      references: (ids.length > MAX_REFERENCES ? [ids.at(0), ...ids.slice(1 - MAX_REFERENCES)] : ids).join(' ')};
  }};

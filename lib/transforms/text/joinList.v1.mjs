// F10.8 part h (docs/F10.8-BUILD-MAP.md, open point Important 4): text.joinList@1. F10.9's checkPreview() takes only a string or a number,
// so a list the approval card shows reaches a preview through this one join. In: exactly one of
// - `items`, up to 1,000 non-empty strings: the guests mergeEmails adds or removes (/added, /removed), or label names picked from
//   labelIds' /labels through {each};
// - `mailboxes`, the {address, name?} lists rfc5322.build@1 takes for To, Cc and Bcc, and rfc5322.replyHeaders@1 gives (the same schema).
// Out: {text, count}: one item a line, in the order given, and how many there are. A mailbox is shown by its address only: the address is
// where the message goes, and a display name an agent chose ("Your bank") never decides delivery. An item holding a line feed or a
// carriage return would read as two, so it refuses with input_invalid. Joined text over 50,000 UTF-16 code units, half of what one
// approval block shows (lib/ui-contracts.mjs:178), refuses with text_too_long, so the value and its label always fit one block.
import {TransformError} from '../_shared/error.v1.mjs';

const MAX_UNITS = 50_000;
const LINE_BREAK = /[\r\n]/;
const MAILBOXES = {type: 'array', maxItems: 500, items: {type: 'object', properties: {address: {type: 'string', minLength: 1, maxLength: 1000}, name: {type: 'string', minLength: 1, maxLength: 1000}},
  required: ['address'], additionalProperties: false}};
const refuse = code => { throw new TransformError(code); };

export const ENTRY = {name: 'text.joinList', version: 1, kind: 'map',
  input: {type: 'object', properties: {items: {type: 'array', maxItems: 1000, items: {type: 'string', minLength: 1, maxLength: 1000}}, mailboxes: MAILBOXES}, additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {text: {type: 'string', maxLength: MAX_UNITS}, count: {type: 'integer', minimum: 0, maximum: 1000}}, required: ['text', 'count'],
    additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 393_216, usesClock: false, runtimeFacts: [], refuses: ['text_too_long'], excludes: [],
  example: {input: {mailboxes: [{address: 'ann@example.com', name: 'Ann'}, {address: 'bob@example.com'}]}, output: {text: 'ann@example.com\nbob@example.com', count: 2}},
  run(input) {
    if ((input.items === undefined) === (input.mailboxes === undefined)) refuse('input_invalid');
    const values = input.items ?? input.mailboxes.map(mailbox => mailbox.address);
    if (values.some(value => LINE_BREAK.test(value))) refuse('input_invalid');
    const text = values.join('\n');
    if (text.length > MAX_UNITS) refuse('text_too_long');
    return {text, count: values.length};
  }};

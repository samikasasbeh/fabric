// F10.8 part e (docs/F10.8-BUILD-MAP.md): rfc5322.parseAddresses@1. In: {value}, an address-list header value. Out: {addresses: [{name?,
// address, group?}]}, with groups, comments and the obsolete forms of RFC 5322 section 4.4 read, quoted names unquoted, and names left as
// written: the decoders decode a name's encoded-words after the parse, so a decoded comma or angle bracket never splits a mailbox. Comments
// nested over 32 deep, more than 1,000 addresses, or anything no address list holds refuse with address_invalid.
import {TransformError} from '../_shared/error.v1.mjs';
import {parseAddressList} from './_address.v1.mjs';

const TEXT = {type: 'string'};

export const ENTRY = {name: 'rfc5322.parseAddresses', version: 1, kind: 'map',
  input: {type: 'object', properties: {value: {type: 'string', maxLength: 1_000_000}}, required: ['value'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {addresses: {type: 'array', maxItems: 1000, items: {type: 'object', properties: {name: TEXT, address: TEXT, group: TEXT},
    required: ['address'], additionalProperties: false}}}, required: ['addresses'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 2_097_152, usesClock: false, runtimeFacts: [], refuses: ['address_invalid'], excludes: [],
  example: {input: {value: 'Mary Smith <mary@x.test>, jdoe@example.org'}, output: {addresses: [{name: 'Mary Smith', address: 'mary@x.test'}, {address: 'jdoe@example.org'}]}},
  run(input) {
    const addresses = parseAddressList(input.value);
    if (addresses === null) throw new TransformError('address_invalid');
    return {addresses};
  }};

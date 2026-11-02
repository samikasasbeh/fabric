// Iteration 9 step 7 (docs/I07-BUILD-MAP.md section 2.7): collections.gmailSentBefore@1. Step data: `thread`, threads.get at format=minimal, at most 256 KiB. Closed: `messageId`.
// Out: {sentBefore}: true when a message listed before this one holds SENT. A thread lists its messages in order, so this asks "had you already written here", with no stored set of threads.
// A message sent later does not count, and neither does this message's own label. A thread that does not list the message, or holds anything else, answers false: nothing refuses, since one
// odd thread must not stop a feed.
const SENT = 'SENT';
const holdsSent = message => Array.isArray(message?.labelIds) && message.labelIds.includes(SENT);

export const ENTRY = {name: 'collections.gmailSentBefore', version: 1, kind: 'map',
  input: {type: 'object', properties: {messageId: {type: 'string', minLength: 1, maxLength: 64}}, required: ['messageId'], additionalProperties: false},
  pointerArgs: [], stepData: {thread: {maxBytes: 262_144}}, resolvedValues: {},
  output: {type: 'object', properties: {sentBefore: {type: 'boolean'}}, required: ['sentBefore'], additionalProperties: false},
  maxInputBytes: 262_144, maxOutputBytes: 256, usesClock: false, runtimeFacts: [], refuses: [], excludes: [],
  example: {input: {thread: {id: 't1', messages: [{id: 'm1', labelIds: ['SENT']}, {id: 'm2', labelIds: ['INBOX']}]}, messageId: 'm2'}, output: {sentBefore: true}},
  run({thread, messageId}) {
    const messages = Array.isArray(thread?.messages) ? thread.messages : [], place = messages.findIndex(message => message?.id === messageId);
    return {sentBefore: messages.slice(0, Math.max(place, 0)).some(holdsSent)};
  }};

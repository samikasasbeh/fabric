// Iteration 9 step 7 (docs/I07-BUILD-MAP.md section 2.7): collections.gmailHistory@1. Step data: `list`, the records of one history.list page, at most 2 MiB. Closed: `kind`, 'messagesAdded' or
// 'labelsAdded', and `labelId?`, the label a labelsAdded read watches. Out: {items: [{id, threadId, labelIds?, recordId}], throughRecordId?}, at most 500 items, in record order.
// - A record is never split: past 500 the page stops at the last whole record and names it in throughRecordId, so the next poll starts after it. A first record too large to hold is named with no
//   items, or it would stop the feed for ever, and the runtime reports that with a gap.
// - For labelsAdded an entry counts only when its own labelIds hold labelId. The record's other entries, and other labels, give nothing.
// - Nothing refuses: a refusal here would stop the feed at this record for good. A record, an entry or a labelIds list it cannot read is left out.
const MAX_ITEMS = 500;
const MAX_LABELS = 50;
const ID = {type: 'string', minLength: 1, maxLength: 64};
const HISTORY_ID = /^[0-9]{1,20}$/;
const fits = value => typeof value === 'string' && value.length >= ID.minLength && value.length <= ID.maxLength;
const labelList = value => Array.isArray(value) && value.length <= MAX_LABELS && value.every(fits);

/** The items one record gives, each naming that record. */
function itemsOf(record, kind, labelId) {
  const listed = kind === 'labelsAdded' ? record.labelsAdded : record.messagesAdded, items = [];
  for (const entry of Array.isArray(listed) ? listed : []) {
    const message = entry?.message;
    if (!fits(message?.id) || !fits(message?.threadId)) continue;
    if (kind === 'labelsAdded' && (!Array.isArray(entry.labelIds) || !entry.labelIds.includes(labelId))) continue;
    const labels = kind === 'labelsAdded' ? entry.labelIds : message.labelIds;
    items.push({id: message.id, threadId: message.threadId, ...(labelList(labels) ? {labelIds: labels} : {}), recordId: record.id});
  }
  return items;
}

export const ENTRY = {name: 'collections.gmailHistory', version: 1, kind: 'map',
  input: {type: 'object', properties: {kind: {type: 'string', enum: ['messagesAdded', 'labelsAdded']}, labelId: {type: 'string', minLength: 1, maxLength: 256}}, required: ['kind'], additionalProperties: false},
  pointerArgs: [], stepData: {list: {maxBytes: 2_097_152}}, resolvedValues: {},
  output: {type: 'object', properties: {items: {type: 'array', maxItems: MAX_ITEMS, items: {type: 'object', properties: {id: ID, threadId: ID, labelIds: {type: 'array', maxItems: MAX_LABELS, items: ID},
    recordId: {type: 'string', minLength: 1, maxLength: 20}}, required: ['id', 'threadId', 'recordId'], additionalProperties: false}}, throughRecordId: {type: 'string', minLength: 1, maxLength: 20}},
    required: ['items'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 2_097_152, usesClock: false, runtimeFacts: [], refuses: [], excludes: [],
  example: {input: {list: [{id: '11', messagesAdded: [{message: {id: 'm1', threadId: 't1'}}]}, {id: '12', labelsAdded: [{message: {id: 'm2', threadId: 't2'}, labelIds: ['STARRED']}]}], kind: 'messagesAdded'},
    output: {items: [{id: 'm1', threadId: 't1', recordId: '11'}]}},
  run({list, kind, labelId}) {
    const items = [];
    let finished;
    for (const record of Array.isArray(list) ? list : []) {
      if (typeof record?.id !== 'string' || !HISTORY_ID.test(record.id)) continue;
      const found = itemsOf(record, kind, labelId);
      if (items.length + found.length > MAX_ITEMS) return {items, throughRecordId: finished ?? record.id};
      items.push(...found);
      finished = record.id;
    }
    return {items};
  }};

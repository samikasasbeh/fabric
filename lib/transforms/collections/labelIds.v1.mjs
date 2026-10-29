// F10.8 part j (docs/F10.8-BUILD-MAP.md): collections.labelIds@1, the label ids Organize email and Auto-label send (spec lines 677, 1026).
// Step data: `list`, Gmail's labels.list answer, {labels: [{id, name, ...}]} as the option source reads it (catalog/options/gmail.json:12-14),
// at most 2 MiB. Closed: `names`, 0 to 100 label names or ids. Out: {labels: [{id, name}], ids}, in the order given, each label once.
// - A name resolves to the label whose id or name equals it with ASCII case folding. None refuses with label_unknown: a label is never
//   created here (spec line 1026). Two labels answering to one name refuse with match_many: it never guesses.
// - Anything whose fold is SENT, DRAFT, TRASH or SPAM, the name asked for or the id or name of the label it resolves to, refuses with
//   label_system (spec line 677).
// - No names gives empty lists, so an action can always send addLabelIds and removeLabelIds, with nothing to add or remove (open point
//   Minor 11).
// - It declares the exclusion on /ids, and the harness checks it on every output (open point Minor 6). A {pick} of /ids is what reaches
//   addLabelIds or removeLabelIds, and step 9 uses the exclusion to prove that value never hits a body route (R1). /labels is for the
//   card, through text.joinList@1 (open point Important 4).
// - An absent labels list is empty; one that is no list, or a label with no string id and name, refuses with input_invalid. More than
//   1,000 labels refuse with too_many_items.
import {TransformError} from '../_shared/error.v1.mjs';
import {foldAscii} from '../_shared/ascii.v1.mjs';

const MAX_LABELS = 1000;
const SYSTEM = new Set(['SENT', 'DRAFT', 'TRASH', 'SPAM'].map(foldAscii));
/** True when a label name or id is SENT, DRAFT, TRASH or SPAM in any ASCII case. */
const system = text => SYSTEM.has(foldAscii(text));
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const refuse = code => { throw new TransformError(code); };

export const ENTRY = {name: 'collections.labelIds', version: 1, kind: 'map',
  input: {type: 'object', properties: {names: {type: 'array', maxItems: 100, items: {type: 'string', minLength: 1, maxLength: 1000}}}, required: ['names'], additionalProperties: false},
  pointerArgs: [], stepData: {list: {maxBytes: 2_097_152}}, resolvedValues: {},
  output: {type: 'object', properties: {labels: {type: 'array', maxItems: 100, items: {type: 'object', properties: {id: {type: 'string', minLength: 1, maxLength: 1000},
    name: {type: 'string', minLength: 1, maxLength: 1000}}, required: ['id', 'name'], additionalProperties: false}},
  ids: {type: 'array', maxItems: 100, items: {type: 'string', minLength: 1, maxLength: 1000}}}, required: ['labels', 'ids'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 262_144, usesClock: false, runtimeFacts: [], refuses: ['label_unknown', 'label_system', 'match_many', 'too_many_items'],
  excludes: [{pointer: '/ids', items: true, values: ['SENT', 'DRAFT', 'TRASH', 'SPAM'], fold: 'ascii'}],
  example: {input: {list: {labels: [{id: 'INBOX', name: 'INBOX', type: 'system'}, {id: 'Label_1', name: 'Receipts', type: 'user'}]}, names: ['receipts']},
    output: {labels: [{id: 'Label_1', name: 'Receipts'}], ids: ['Label_1']}},
  run(input) {
    if (!record(input.list)) refuse('input_invalid');
    const labels = input.list.labels === undefined ? [] : input.list.labels;
    if (!Array.isArray(labels)) refuse('input_invalid');
    if (labels.length > MAX_LABELS) refuse('too_many_items');
    // One pass: each folded id and name to the labels that answer to it.
    const answers = new Map();
    for (const label of labels) {
      if (!record(label) || typeof label.id !== 'string' || typeof label.name !== 'string' || !label.id || !label.name) refuse('input_invalid');
      for (const key of new Set([foldAscii(label.id), foldAscii(label.name)])) {
        if (answers.has(key)) answers.get(key).push(label);
        else answers.set(key, [label]);
      }
    }
    const chosen = [], seen = new Set();
    for (const name of input.names) {
      const key = foldAscii(name);
      if (system(name)) refuse('label_system');
      const found = answers.get(key) ?? [];
      if (found.length === 0) refuse('label_unknown');
      if (found.length > 1) refuse('match_many');
      const [label] = found;
      if (system(label.id) || system(label.name)) refuse('label_system');
      if (seen.has(label.id)) continue;
      seen.add(label.id);
      chosen.push({id: label.id, name: label.name});
    }
    return {labels: chosen, ids: chosen.map(label => label.id)};
  }};

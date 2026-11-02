// Iteration 9 step 5 (docs/I07-BUILD-MAP.md): Notion's seeded faults, in the format of test/faults/registry.mjs. `from` is copied exactly from the current file and occurs there once; `to` is the faulty
// replacement the named tests must catch. A fault in Notion's trigger file lists only test/triggers-notion.test.mjs, whose worlds recompute ids, so it is caught by behaviour and not by the id check.
// Data only: nothing here reads or changes a file.
const STEP = 'I07';
const FILE = 'catalog/triggers/notion.json', ROW = 'lib/transforms/notion/rowFingerprint.v1.mjs', MARKDOWN = 'lib/transforms/notion/markdownFingerprint.v1.mjs', TESTS = ['test/triggers-notion.test.mjs'];
const SIM = 'test/fixtures/provider-simulators/notion.mjs', SIM_TESTS = ['test/provider-simulator-notion.test.mjs'];
const RUNTIME = 'lib/trigger-runtime.mjs', ENGINE = 'lib/trigger-engine.mjs';
const NO_RESYNC = '"statusIn": []\n    },\n    "minIntervalSeconds": 120,\n    "itemId": {\n     "item": "/id"\n    },\n';

export const FAULTS = Object.freeze([
  {id: 'i07-notion-fingerprint-formula', step: STEP, name: 'A row\'s fingerprint holds a formula, so a formula that moves with no edit fires.',
    file: ROW, from: "const WRITTEN = Object.freeze([...WRITABLE, 'files']);", to: "const WRITTEN = Object.freeze([...WRITABLE, 'files', 'formula']);", tests: TESTS},
  {id: 'i07-notion-fingerprint-link', step: STEP, name: 'A page\'s fingerprint keeps the signed query, so every poll fires.',
    file: MARKDOWN, from: 'signsFiles(run.slice(start + 8, query).split(\'/\', 1)[0]) ? run.slice(0, query) : run;', to: 'signsFiles(run.slice(start + 8, query).split(\'/\', 1)[0]) ? run : run;', tests: TESTS},
  {id: 'i07-notion-share-cursor', step: STEP, name: 'New row keeps changed row\'s mark on last_edited_time, so an old row edited reads as new.',
    file: FILE, from: '"timestamp": "created_time",\n           "direction": "descending"', to: '"timestamp": "last_edited_time",\n           "direction": "descending"',
    also: [{from: '"pointer": "/results/0/created_time"', to: '"pointer": "/results/0/last_edited_time"'},
      {from: '"timestamp": {\n            "const": "created_time"\n           },\n           "created_time": {', to: '"timestamp": {\n            "const": "last_edited_time"\n           },\n           "last_edited_time": {'},
      {from: '"timestamp": "created_time",\n            "direction": "ascending"', to: '"timestamp": "last_edited_time",\n            "direction": "ascending"'},
      {from: '"pointer": "/created_time",\n     "format": "rfc3339"\n    },\n    "order": "asc"', to: '"pointer": "/last_edited_time",\n     "format": "rfc3339"\n    },\n    "order": "asc"'}], tests: TESTS},
  {id: 'i07-notion-404-resync', step: STEP, name: 'A 404 resyncs a row watch, so lost access reads as a gap and no pause.',
    file: FILE, from: `${NO_RESYNC}    "itemVersion": null`, to: `${NO_RESYNC.replace('[]', '[404]')}    "itemVersion": null`,
    also: [{from: `${NO_RESYNC}    "itemVersion": "/last_edited_time"`, to: `${NO_RESYNC.replace('[]', '[404]')}    "itemVersion": "/last_edited_time"`}], tests: TESTS},
  {id: 'i07-sim-notion-grain', step: STEP, name: 'The simulator keeps stamps to the millisecond, so an edit in one minute shows a new stamp.',
    file: SIM, from: "stampGrain = 60_000, tieSeed = 'ties'", to: "stampGrain = 1, tieSeed = 'ties'", tests: TESTS},
  {id: 'i07-sim-notion-imports', step: STEP, name: 'The simulator imports the transform it is meant to test.',
    file: SIM, from: "import {createHash} from 'node:crypto';\n", to: "import {createHash} from 'node:crypto';\nimport {ENTRY} from '../../../lib/transforms/notion/rowFingerprint.v1.mjs';\n", tests: SIM_TESTS},
  // Four more, for what step 5 added to the shared engine beyond its table.
  {id: 'i07-seed-partial', step: STEP, name: 'A seed whose newest row is partial reads as an empty list, so every row is new.',
    file: RUNTIME, from: "if ((value === undefined || value === null) && record(seedItem(state, got.answer, seed.cursor.pointer))) throw new Stop('backoff', {code: 'seed_partial'});", to: '', tests: TESTS},
  {id: 'i07-seed-partial-time', step: STEP, name: 'Any field a seed finds missing reads as a partial row, so a Slack thread with no replies never starts.',
    file: RUNTIME, from: 'return item === undefined || field !== state.poll.itemTime?.pointer ? undefined : resolvePointer(answer.data, item);', to: 'return item === undefined ? undefined : resolvePointer(answer.data, item);', tests: ['test/triggers-slack.test.mjs']},
  {id: 'i07-notion-blocked', step: STEP, name: 'public_api_request_blocked in a 429 waits for ever, and in a 403 loses its code.',
    file: RUNTIME, from: "  if (refusedCode(context.appId, answer)) return {is: 'refused', detail: refusedCode(context.appId, answer)};\n", to: '', tests: TESTS},
  {id: 'i07-notion-run-note', step: STEP, name: 'A query that stopped at Notion\'s cap leaves no note on its run.',
    file: RUNTIME, from: "if (answer.data?.request_status?.type === 'incomplete') state.note = 'incomplete';", to: "if (answer.data?.request_status?.type === 'never') state.note = 'incomplete';", tests: TESTS},
  {id: 'i07-name-no-size', step: STEP, name: 'A column named constructor reads as too much data, so the owner is sent to the wrong fix.',
    file: 'lib/actions-runtime.mjs', from: "new TransformError(/unsafe property/.test(error.message) ? 'value_unreadable' : 'input_too_large')", to: "new TransformError('input_too_large')", tests: TESTS},
  {id: 'i07-wait-round', step: STEP, name: 'A feed already chosen sends past a limit its round just met, and clears the wait.',
    file: ENGINE, from: "      if ((this.store.get('triggerFeeds', feed.id)?.wait?.until ?? 0) > this.clock()) continue;\n", to: '', tests: TESTS},
]);

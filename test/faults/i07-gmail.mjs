// Iteration 9 step 7 (docs/I07-BUILD-MAP.md, step 7): Gmail's seeded faults, in the format of test/faults/registry.mjs. `from` is copied exactly from the current file and occurs there once; `to` is the
// faulty replacement the named tests must catch. A fault in the trigger file names test/triggers-gmail.test.mjs alone: test/triggers-gmail-file.test.mjs would catch any edit of the file by its id, which
// proves nothing about what the fault does. Data only: nothing here reads or changes a file.
const STEP = 'I07';
const HISTORY = 'lib/transforms/collections/gmailHistory.v1.mjs', SENT = 'lib/transforms/collections/gmailSentBefore.v1.mjs', FILE = 'catalog/triggers/gmail.json', RUNTIME = 'lib/trigger-runtime.mjs';
const SIM = 'test/fixtures/provider-simulators/gmail.mjs', TRANSFORM_TESTS = ['test/transforms-gmail.test.mjs'], TESTS = ['test/triggers-gmail.test.mjs'], SIM_TESTS = ['test/provider-simulator-gmail-history.test.mjs'];
const lines = (...text) => text.join('\n');
/** The start of label-added's poll, from the one block only it has, to the feed's query. */
const LABEL_FEED = lines('   "choices": [', '    {', '     "input": "labelId",', '     "source": "labels"', '    }', '   ],', '   "resource": [],', '   "poll": {', '    "seed": {', '     "step": {', '      "id": "profile",',
  '      "method": "GET",', '      "path": "/gmail/v1/users/{userId}/profile",', '      "maxResponseBytes": 4096,', '      "expect": {', '       "status": [', '        200', '       ],', '       "require": []', '      }', '     },',
  '     "cursor": {', '      "name": "history",', '      "pointer": "/historyId"', '     }', '    },', '    "source": {', '     "steps": [', '      {', '       "id": "history",', '       "method": "GET",',
  '       "path": "/gmail/v1/users/{userId}/history",', '       "query": {', '        "startHistoryId": {');
/** The value `to` reads in email-sent, which the catalog's other sources do not have. */
const DECODED_TO = lines('         "transform": "rfc5322.decodeGmailPayload@1",', '         "args": {', '          "message": {', '           "step": "meta",', '           "pointer": ""', '          }', '         }', '        },', '        "pointer": "/summary/to/0/address"');
const TO_TEST = lines('     "to": {', '      "when": {', '       "present": {', '        "pick": {', DECODED_TO, '       }', '      },');
const TO_TEST_TRUNCATED = lines('     "to": {', '      "when": {', '       "present": {', '        "pick": {', '         "transform": "text.truncate@1",', '         "args": {', '          "text": {"pick": {"transform": "rfc5322.decodeGmailPayload@1", "args": {"message": {"step": "meta", "pointer": ""}}}, "pointer": "/summary/to/0/address"},',
  '          "max": {"const": 256}', '         }', '        },', '        "pointer": "/text"', '       }', '      },');

export const FAULTS = Object.freeze([
  // ---- the transforms --------------------------------------------------------------------------------------------------------------------------------------------------------
  {id: 'i07-gmail-history-split', step: STEP, name: 'A record is split at the limit.',
    file: HISTORY, from: '      if (items.length + found.length > MAX_ITEMS) return {items, throughRecordId: finished ?? record.id};', to: '      if (items.length + found.length > MAX_ITEMS) return {items: [...items, ...found].slice(0, MAX_ITEMS), throughRecordId: record.id};',
    tests: [...TRANSFORM_TESTS, ...TESTS]},
  {id: 'i07-gmail-history-type', step: STEP, name: '`labelsAdded` returns all labels.',
    file: HISTORY, from: "    if (kind === 'labelsAdded' && (!Array.isArray(entry.labelIds) || !entry.labelIds.includes(labelId))) continue;\n", to: '', tests: [...TRANSFORM_TESTS, ...TESTS]},
  {id: 'i07-gmail-sent-after', step: STEP, name: '`sentBefore` reads later messages.',
    file: SENT, from: 'return {sentBefore: messages.slice(0, Math.max(place, 0)).some(holdsSent)};', to: 'return {sentBefore: place >= 0 && messages.some(holdsSent)};', tests: [...TRANSFORM_TESTS, ...TESTS]},

  // ---- the trigger file ------------------------------------------------------------------------------------------------------------------------------------------------------
  {id: 'i07-gmail-feed-query', step: STEP, name: 'A block adds `labelId`, so one source reads its own feed and a shared cursor would lose events.',
    file: FILE, from: LABEL_FEED, to: LABEL_FEED.replace('       "query": {\n', '       "query": {\n        "labelId": {\n         "const": "INBOX"\n        },\n'), tests: TESTS},
  {id: 'i07-gmail-optional', step: STEP, name: 'A missing header refuses the event: the test reads the truncated value, not the value.',
    file: FILE, from: TO_TEST, to: TO_TEST_TRUNCATED, tests: TESTS},

  // ---- the runtime -----------------------------------------------------------------------------------------------------------------------------------------------------------
  {id: 'i07-gmail-wedge', step: STEP, name: 'One 404 or oversized enrich ends the poll, so one mail holds the feed.',
    file: RUNTIME, from: "  if (failure === 'response_too_large') { state.skipped++; giveUp(state, lens, at); return null; }", to: "  if (failure === 'response_too_large') { enrichFailed(state, lens, at, {outcome: 'backoff', code: failure}); return null; }",
    also: [{from: "  if (verdict.is === 'ok') { state.answers.set(key, answer); return answer; }", to: "  if (verdict.is === 'ok' && answer.status === 404) { enrichFailed(state, lens, at, {outcome: 'backoff', code: 'http_404'}); return null; }\n  if (verdict.is === 'ok') { state.answers.set(key, answer); return answer; }"}],
    tests: TESTS},
  {id: 'i07-enrich-transient', step: STEP, name: 'A 503 on an enrich skips the item, so a mail is lost for good.',
    file: RUNTIME, from: "  else enrichFailed(state, lens, at, {outcome: 'backoff', code: verdict.detail ?? 'not_modified'});", to: '  else state.skipped++;', tests: TESTS},
  {id: 'i07-gmail-lens-share', step: STEP, name: 'One lens may spend a whole poll, so a lens after it reads nothing and the cursor never moves.',
    file: RUNTIME, from: '  if (state.requests >= lens.until) { lens.stopped = true; return null; }\n', to: '', tests: TESTS},
  {id: 'i07-gmail-turned-down', step: STEP, name: 'An item a read turned down takes no seen row, so it is read again each poll.',
    file: RUNTIME, from: "    if (kept === false) turnedDown(state, lens, frame, {key, row, generation});\n", to: '', tests: TESTS},
  {id: 'i07-late-filter-refusal', step: STEP, name: 'One mail a stranger shaped stops the watch: a refusal in a filter that reads an enrich answer drops the lens, and every Resume stops on the same mail.',
    file: RUNTIME, from: '    giveUp(state, lens, at);\n    return null;\n', to: "    dropLens(state, lens, 'output_invalid');\n    return null;\n", tests: TESTS},
  {id: 'i07-gmail-gone-row', step: STEP, name: 'An item that has gone takes a seen row, as one turned down does.',
    file: RUNTIME, from: '  if (!row && lens.enrichBlock.steps.every(step => frame.steps.get(step.id).status < 300)) put(', to: '  if (!row) put(', tests: ['test/trigger-runtime.test.mjs']},
  {id: 'i07-gmail-record-silent', step: STEP, name: 'A record too large to hold whole is passed over in silence.',
    file: RUNTIME, from: '  if (through !== undefined && !items.length && lens.live && !state.silent) noteStall(state);\n', to: '', tests: TESTS},
  {id: 'i07-gmail-unread-silent', step: STEP, name: 'A search cut by its bound says nothing of the mail past it.',
    file: RUNTIME, from: "    } else if (state.window.seconds && poll.order === 'unordered' && !silent) noteUnread(state, out);\n", to: '    }\n', tests: TESTS},
  {id: 'i07-gmail-unread-reach', step: STEP, name: 'A window with no set reach owes a gap at each cut read too.',
    file: RUNTIME, from: "    } else if (state.window.seconds && poll.order === 'unordered' && !silent) noteUnread(state, out);\n", to: "    } else if (poll.order === 'unordered' && !silent) noteUnread(state, out);\n", tests: TESTS},
  {id: 'i07-gmail-unread-every-poll', step: STEP, name: 'An unread tail is told at every poll, so a long list buries real events.',
    file: RUNTIME, from: '  if (told !== null && state.now - told < UNREAD_TOLD_MS) return;\n', to: '', tests: TESTS},
  {id: 'i07-gmail-unread-baseline', step: STEP, name: 'A silent read of a long list owes a gap of its own.',
    file: RUNTIME, from: "    } else if (state.window.seconds && poll.order === 'unordered' && !silent) noteUnread(state, out);\n", to: "    } else if (state.window.seconds && poll.order === 'unordered') noteUnread(state, out);\n", tests: TESTS},

  // ---- the simulator ---------------------------------------------------------------------------------------------------------------------------------------------------------
  {id: 'i07-sim-gmail-gaps', step: STEP, name: 'History ids count by one, so a test could not tell a compare that counts from one that reads the id.',
    file: SIM, from: '    const gap = BigInt(parseInt(hex(`history:${state.next.history++}`).slice(0, 4), 16) % 97 + 1);', to: '    const gap = 1n;', tests: SIM_TESTS},
  {id: 'i07-sim-gmail-imports', step: STEP, name: 'The simulator imports lib/.',
    file: SIM, from: "import {createHash} from 'node:crypto';", to: "import {createHash} from 'node:crypto';\nimport '../../../lib/triggers.mjs';", tests: ['test/provider-simulator-gmail.test.mjs']},
]);

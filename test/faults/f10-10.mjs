// F10.10 reviewed reads in actions (docs/F10.10-BUILD-MAP.md section 4): seeded faults in the format of test/faults/registry.mjs. `from`
// is copied exactly from the current file and occurs there once; `to` is the faulty replacement the named tests must catch. The two F10.9
// entries that copied the old stepEffect() text (f109-effect-reviewed-read and f109-effect-rpc-post) are re-pointed in place in
// test/faults/f10-9.mjs. Data only: nothing here reads or changes a file.
const STEP = 'F10.10';
const VAL = ['test/actions-validator.test.mjs'], PLACE = ['test/actions-placement.test.mjs'], CHOICES = ['test/actions-choices.test.mjs'], TRIG = ['test/triggers-format.test.mjs'];
const EXPR = 'lib/action-expressions.mjs', PLACEMENT = 'lib/action-placement.mjs', ACTIONS = 'lib/actions.mjs';
const OFF = 'if (false) fail(';

export const FAULTS = Object.freeze([
  // ---- part a: the source rule (lib/action-expressions.mjs) -----------------------------------------------------------------------
  {id: 'f1010-sources-jobkey', step: STEP, name: 'A job key counts as a read source, so a reviewed-read POST that sends one is a read.',
    file: EXPR, from: "export const READ_SOURCES = Object.freeze(['constant', 'input', 'account', 'clock', 'cursor', 'resolved']);",
    to: "export const READ_SOURCES = Object.freeze(['constant', 'input', 'account', 'clock', 'cursor', 'resolved', 'jobKey']);", tests: [...VAL, ...TRIG]},
  {id: 'f1010-sources-registration', step: STEP, name: 'The four registration names count as read sources (the F10.10 check pins readsOnly() itself).',
    file: EXPR, from: "export const READ_SOURCES = Object.freeze(['constant', 'input', 'account', 'clock', 'cursor', 'resolved']);",
    to: "export const READ_SOURCES = Object.freeze(['constant', 'input', 'account', 'clock', 'cursor', 'resolved', 'receiver', 'secret', 'kept', 'subscriptionKey']);", tests: VAL,
    note: 'Only registration steps read these names, and they place with fromReads false, so the direct readsOnly() test catches it.'},
  {id: 'f1010-reads-steps', step: STEP, name: '`readsOnly()` drops the step-id check, so any step\'s answer, a write\'s included, counts as built from reads.',
    file: EXPR, from: ' && [...fact.steps].every(id => stepIsRead(id));', to: ';', tests: VAL},
  {id: 'f1010-reads-label', step: STEP, name: '`readsOnly()` judges step answers by their source label, so a verify read of the written id launders a write\'s answer.',
    file: EXPR, from: ' && [...fact.steps].every(id => stepIsRead(id));', to: " && ![...fact.sources].some(source => source === 'perform-write' || source === 'resolving');", tests: VAL,
    note: 'Shares its from with f1010-reads-steps; only the transitive test (a verify POST fed by a verify GET of the written id) catches it.'},

  // ---- part b: the placement field and stepEffect() (lib/action-placement.mjs) -------------------------------------------------------
  {id: 'f1010-effect-post', step: STEP, name: 'A listed member that is not a POST counts as a read when built from reads (a listed PATCH).',
    file: PLACEMENT, from: "const read = placement.method === 'POST' && placement.reviewedRead === true && placement.fromReads === true;",
    to: 'const read = placement.reviewedRead === true && placement.fromReads === true;', tests: PLACE},
  {id: 'f1010-place-default', step: STEP, name: '`placeStep()` defaults `fromReads` to true, so a caller that forgets it gets a read.',
    file: PLACEMENT, from: 'access = null, fromReads = false, where} = {}) {', to: 'access = null, fromReads = true, where} = {}) {', tests: PLACE},
  {id: 'f1010-place-field', step: STEP, name: 'The placement records any truthy `fromReads`, not only a proven true.',
    file: PLACEMENT, from: 'effect: null, fromReads: fromReads === true, reviewedRead,', to: 'effect: null, fromReads: Boolean(fromReads), reviewedRead,', tests: PLACE},
  {id: 'f1010-place-routed', step: STEP, name: 'A reviewed-read POST that a constant body route moves into another read row is still a reviewed read, so a read.',
    file: PLACEMENT, from: "const reviewedRead = !routedFrom && source.effect === 'read'", to: "const reviewedRead = source.effect === 'read'", tests: PLACE},

  // ---- part c: the validator wiring (lib/actions.mjs) ----------------------------------------------------------------------------------
  {id: 'f1010-file-body-only', step: STEP, name: 'Provenance is read from the body slot only, so a path parameter fed by a write passes.',
    file: ACTIONS, from: 'const fromReads = slots.every(([, fact]) => readsOnly(fact,', to: "const fromReads = slots.filter(([name]) => name === 'body').every(([, fact]) => readsOnly(fact,", tests: VAL},
  {id: 'f1010-file-steps-of', step: STEP, name: '`stepsOf` records `fromReads` without `effect === \'read\'`, so a write built from inputs feeds a read.',
    file: ACTIONS, from: "fromReads: fromReads && effect === 'read', label: where});", to: 'fromReads, label: where});', tests: VAL},
  {id: 'f1010-file-lookup', step: STEP, name: '`placeLookup()` leaves `fromReads` out, so a lookup on a reviewed-read POST is refused as a write.',
    file: ACTIONS, from: "phase: 'lookup', fromReads: true, where: label});", to: "phase: 'lookup', where: label});", tests: CHOICES},

  // ---- part d: the body continuation (lib/actions.mjs page(), pageRoutes() and rawPositions()) ------------------------------------------
  {id: 'f1010-page-key', step: STEP, name: '`page.into.body` may land on a key the step\'s body writes (Notion `/query`).',
    file: ACTIONS, from: 'if (keys.has(tokens[0])) fail(', to: OFF, tests: VAL},
  // The F10.10 check: a whole input or a transform result writes its closed schema's keys, and a body whose keys are not known takes no cursor.
  {id: 'f1010-page-typed', step: STEP, name: 'A whole input or a transform result writes no key, so the cursor may land on one its closed schema names.',
    file: ACTIONS, from: "    else if (result.type?.type === 'object' && result.type.additionalProperties === false && record(result.type.properties)) keys = Object.keys(result.type.properties);",
    to: "    else if (result.type?.type === 'object' && result.type.additionalProperties === false && record(result.type.properties)) keys = [];", tests: VAL},
  {id: 'f1010-page-object', step: STEP, name: 'A body whose keys are not known (a scalar, a list, an outputMap result) takes the cursor anyway.',
    file: ACTIONS, from: 'if (keys === null) fail(', to: 'if (keys === null) return; if (false) fail(', tests: VAL},
  {id: 'f1010-page-reserved', step: STEP, name: '`page.into.body` may name a field the app reserves (`/erase_content`, Notion `/in_trash`).',
    file: ACTIONS, from: 'if (!tokens.length || tokens.some(token => reserved.includes(token))) fail(', to: OFF, tests: VAL},
  {id: 'f1010-page-whole', step: STEP, name: '`page.into.body` may be the empty pointer, so the provider\'s cursor replaces the whole body.',
    file: ACTIONS, from: 'if (!tokens.length || tokens.some(token => reserved.includes(token)))', to: 'if (tokens.some(token => reserved.includes(token)))', tests: VAL},
  {id: 'f1010-page-notion', step: STEP, name: 'Notion\'s reserved keys and `in_trash` are left out of the continuation rule.',
    file: ACTIONS, from: "...(appId === NOTION_APP ? [...NOTION_RESERVED, 'in_trash'] : [])];", to: '];', tests: VAL,
    equivalent: 'The shipped Notion proxy settings reserve the same fields (catalog/proxy/notion.json), so the rule holds through config.reservedBodyFields; f1010-page-notion-both removes both.'},
  {id: 'f1010-page-notion-both', step: STEP, name: 'Neither Notion\'s proxy settings nor the continuation rule reserve `in_trash`, so a cursor may land there.',
    file: ACTIONS, from: "...(appId === NOTION_APP ? [...NOTION_RESERVED, 'in_trash'] : [])];", to: '];',
    also: [{file: 'catalog/proxy/notion.json', from: '"reservedBodyFields": [\n  "in_trash",\n', to: '"reservedBodyFields": [\n'}], tests: VAL},
  {id: 'f1010-page-get', step: STEP, name: 'A GET may page into a body it does not have.', file: ACTIONS, from: "if (step.method === 'GET') fail(", to: OFF, tests: VAL},
  {id: 'f1010-page-route', step: STEP, name: '`page.into.body` may sit on, above or below a body-route pointer of the step\'s member.',
    file: ACTIONS, from: 'if (tokens.slice(0, shared).every((token, index) => token === other[index])) {', to: 'if (false) {', tests: VAL},
  {id: 'f1010-page-rawat', step: STEP, name: 'The body continuation is left out of rawAt, so a provider\'s next cursor is never held to a scalar.',
    file: ACTIONS, from: "    if (typeof step?.page?.into?.body === 'string') out.push(`/body${step.page.into.body}`);\n", to: '', tests: [...VAL, ...TRIG]},
]);

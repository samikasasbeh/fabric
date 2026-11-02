// Iteration 9 step 6 (docs/I07-BUILD-MAP.md step 6): GitHub's seeded faults, in the format of test/faults/registry.mjs. The ten of the step's table, then four on what the step added to the guarded path.
// Each names the smallest test file that holds its line, so a run takes seconds. Data only: nothing here reads or changes a file.
const STEP = 'I07';
const LINK = 'lib/transforms/ids/linkPage.v1.mjs', LINK_TESTS = ['test/transforms-ids.test.mjs'];
const RUNTIME = 'lib/trigger-runtime.mjs', ENGINE = 'lib/trigger-engine.mjs', WALK_TESTS = ['test/triggers-github-walk.test.mjs'];
const SIM = 'test/fixtures/provider-simulators/github.mjs', SIM_TESTS = ['test/provider-simulator-github.test.mjs'];
const WHOLE_WALK = 'if (state.pages > 1 || state.cut !== null) { delete cursors[cursor.name]; return; }', PART_WALK = 'if (state.cut !== null) { delete cursors[cursor.name]; return; }';

export const FAULTS = Object.freeze([
  {id: 'i07-link-origin', step: STEP, name: 'A next URL on another origin is followed.',
    file: LINK, from: 'target.host !== request.host || ', to: '', tests: LINK_TESTS},
  {id: 'i07-link-url', step: STEP, name: 'The URL is kept, not the page.',
    file: LINK, from: 'return {page: Number(value)};', to: 'return {page: Number(value), url: nexts[0].target};',
    also: [{from: 'properties: {page: {type: \'integer\', minimum: 1, maximum: 100_000}}', to: 'properties: {page: {type: \'integer\', minimum: 1, maximum: 100_000}, url: {type: \'string\'}}'},
      {from: 'output: {page: 2}},', to: 'output: {page: 2, url: \'https://api.fixture.test/items?page=2\'}},'}], tests: LINK_TESTS},
  {id: 'i07-link-repositories', step: STEP, name: 'The id form reads as the end of the list.',
    file: LINK, from: 'if (target === null || request === null || target.host !== request.host || !samePath(target.path, request.path)) refuse();',
    to: 'if (target === null || request === null || target.host !== request.host) refuse(); if (target.path !== request.path) return {};', tests: LINK_TESTS},
  {id: 'i07-github-etag-last', step: STEP, name: 'The last page\'s etag is stored.',
    file: RUNTIME, from: WHOLE_WALK, to: PART_WALK, also: [{from: 'const value = state.first.headers[cursor.next.header];', to: 'const value = state.last.headers[cursor.next.header];'}], tests: WALK_TESTS},
  {id: 'i07-etag-multipage', step: STEP, name: 'A multi-page walk keeps page 1\'s etag.',
    file: RUNTIME, from: WHOLE_WALK, to: PART_WALK, tests: WALK_TESTS},
  {id: 'i07-github-reset', step: STEP, name: 'A limit 403 ignores x-ratelimit-reset.',
    file: RUNTIME, from: 'headers[\'x-ratelimit-remaining\'] === \'0\' && reset !== null ? reset * 1000 : now + 60_000', to: 'now + 60_000', tests: WALK_TESTS},
  {id: 'i07-github-410', step: STEP, name: '410 resyncs.',
    file: 'catalog/triggers/github.json', from: '"statusIn": []\n    },\n    "minIntervalSeconds": 60,\n    "itemId": {\n     "item": "/number"', to: '"statusIn": [410]\n    },\n    "minIntervalSeconds": 60,\n    "itemId": {\n     "item": "/number"', tests: WALK_TESTS},
  {id: 'i07-sim-github-304', step: STEP, name: 'A matching condition answers in full, so the simulator never gives a 304.',
    file: SIM, from: 'return headers[\'if-none-match\'] === etag || (modified !== undefined && headers[\'if-modified-since\'] === modified) ? {status: 304, headers: bare, data: null} : {...answer, headers: {...answer.headers, etag}};',
    to: 'void bare; return {...answer, headers: {...answer.headers, etag}};', tests: SIM_TESTS},
  {id: 'i07-sim-github-rate-304', step: STEP, name: 'A 304 spends the limit.',
    file: SIM, from: 'if (answer.status !== 304 && rate.used < RATE_LIMIT) rate.used++;', to: 'if (rate.used < RATE_LIMIT) rate.used++;', tests: SIM_TESTS},
  {id: 'i07-sim-github-imports', step: STEP, name: 'The simulator imports from lib/, so a trigger bug and a simulator bug could cancel out.',
    file: SIM, from: 'import {createHash} from \'node:crypto\';', to: 'import {createHash} from \'node:crypto\';\nimport {LIMITS} from \'../../../lib/trigger-rules.mjs\';', tests: SIM_TESTS},
  // ---- what the step added ------------------------------------------------------------------------------------------------------------------
  {id: 'i07-window-tail', step: STEP, name: 'A window over a list out of order finds a new item on its last page read, and says nothing of what may lie past it.',
    file: RUNTIME, from: 'else if (cut === \'bounds\' && poll.order === \'unordered\' && state.lenses.some(lens => lens.firedAtEnd)) {', to: 'else if (false) {', tests: WALK_TESTS},
  {id: 'i07-window-noise', step: STEP, name: 'A long list gives a gap with every event.',
    file: RUNTIME, from: 'lens.firedAtEnd = lens.events.length > fired;', to: 'lens.firedAtEnd = lens.events.length > 0;', tests: WALK_TESTS},
  {id: 'i07-window-filled', step: STEP, name: 'A full page with no next link reads as the whole list, so a burst past it is lost in silence.',
    file: RUNTIME, from: 'const filled = cut === null && Boolean(state.window) && state.pollStep.page === undefined && state.items >= state.bounds.items;', to: 'const filled = false;', tests: WALK_TESTS},
  {id: 'i07-window-every-tick', step: STEP, name: 'A window cut by its bound polls again at the next tick, though reading it again gets no further, so a busy repository spends the owner\'s token up to its bucket.',
    file: ENGINE, from: 'onward = !discard && result.onward === true,', to: "onward = !discard && result.outcome === 'cut',", tests: WALK_TESTS},
  {id: 'i07-cut-waits', step: STEP, name: 'A walk with a place to come back to waits a whole interval between pages, so a backlog takes hours to drain.',
    file: ENGINE, from: 'onward = !discard && result.onward === true,', to: 'onward = false,', tests: ['test/trigger-engine.test.mjs']},
  {id: 'i07-cut-no-progress', step: STEP, name: 'A cut walk that kept its place comes back at the next tick, up to its bucket.',
    file: RUNTIME, from: "const onward = cut !== null && !out.edge && (place.some(({name}) => cursors[name] !== feed.cursors?.[name]) || (out.page?.token ?? null) !== (feed.page?.token ?? null));", to: 'const onward = cut !== null && !out.edge;', tests: ['test/trigger-engine.test.mjs']},
  {id: 'i07-cut-edge', step: STEP, name: 'A mark that jumped to the present comes back at the next tick, though nothing lies ahead of it.',
    file: RUNTIME, from: "const onward = cut !== null && !out.edge && (place.some(", to: 'const onward = cut !== null && (place.some(', tests: ['test/trigger-engine.test.mjs']},
  {id: 'i07-cut-token', step: STEP, name: 'A sync walk with a next page waits a whole interval, since only its cursors count as a place.',
    file: RUNTIME, from: ' || (out.page?.token ?? null) !== (feed.page?.token ?? null));', to: ');', tests: ['test/trigger-engine.test.mjs']},
  {id: 'i07-bound-every-poll', step: STEP, name: 'More threads inside the overlap than a walk reads repeat a gap at every poll.',
    file: RUNTIME, from: "if (!silent && (state.newKey || next !== stored || (poll.order !== 'desc' && (state.feed.unreadTo ?? null) === null))) { noteGap(state, 'bound'); out.unreadTo = state.now; }", to: "if (!silent && (poll.order !== 'desc' || state.newKey || next !== stored)) noteGap(state, 'bound');", tests: WALK_TESTS},
  {id: 'i07-sim-github-release-body', step: STEP, name: 'A simulated release holds no notes, so a list near the size limit is never tried.',
    file: SIM, from: "name: null, body, draft, prerelease: false,", to: "name: null, body: null, draft, prerelease: false,", tests: SIM_TESTS},
  {id: 'i07-github-repository', step: STEP, name: 'A repository is not read at subscribe, so .. is stored and a watch backs off for good.',
    file: RUNTIME, from: ', github: {transform: OWNER_REPO, read: ({owner, repo}) => `${owner}/${repo}`.toLowerCase()}', to: '', tests: WALK_TESTS},
]);

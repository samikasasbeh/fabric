import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createHash, randomBytes} from 'node:crypto';
import {existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createApp} from '../server.mjs';
import {CERTIFICATION_PORT} from '../lib/certification.mjs';
import {createGuard, newRunId, refuseRequest, synthetic, GUARD_WORDS, RULES} from '../lib/live-guard.mjs';
import {CALLER_HEADERS} from '../lib/proxy-request.mjs';
import {RESPONSE_HEADERS as PROXY_HEADERS} from '../lib/proxy-runtime.mjs';
import {checkPlan, checkPlanShape, runLiveTests, openRunState, runStateFile, evidenceRecords, assertEvidenceSafe, writeEvidence, writeIntrospection, fillPlaceholders, pendingUndos, PLAN_LIMITS, PLACEHOLDERS, PROBE_HEADERS, TOKEN_PREFIXES} from '../lib/live-certify.mjs';
import {harnessPort, readOwner, resumedOwner, main, introspectOnce, parseArgs, CERTIFICATION_OWNER, PLANS, PROBES_DONE, USAGE} from '../scripts/live-certify.mjs';
import {evidencePasses, loadActionCatalog, seedActions, triggerEvidencePasses} from '../lib/action-catalog.mjs';
import {validateActionFile} from '../lib/actions.mjs';
import {PermissionManager} from '../lib/permissions.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {FabricProtocol} from '../lib/fabric-protocol.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {PINS as SHIPPED_PINS} from '../lib/transform-pins.mjs';
import {templateChecks} from '../scripts/app-template-check.mjs';
import {actionHarness, OWNER, TOKEN} from './fixtures/actions/runtime-fixture.mjs';
import {fixtureChoices, fixtureMap, fixtureSignIn, withIds} from './fixtures/actions/fixture-app.mjs';
import {TRANSFORMS, PINS} from './fixtures/actions/registry.mjs';
import {googleMap} from './fixtures/access/google-maps.mjs';
import {freePort} from './fixtures/signin-fixture.mjs';
import {calendarHarness} from './fixtures/actions/calendar-harness.mjs';
import {githubHarness} from './fixtures/actions/github-harness.mjs';
import {gmailHarness} from './fixtures/actions/gmail-harness.mjs';
import {slackHarness, IDS, OWNER as SLACK_OWNER} from './fixtures/actions/slack-harness.mjs';
import {triggerHarness} from './fixtures/actions/trigger-fixture.mjs';
import {triggerWorld} from './fixtures/actions/trigger-harness.mjs';

// F10.12 part 2 (docs/F10.12-BUILD-MAP.md section 3, test/live-certify.test.mjs): the harness, its plans and its evidence. The fake app of
// step 11 (test/fixtures/actions) runs behind its provider simulator with a test rule set for the live guard; a scripted owner (Muse) reads
// what the runner prints and does what a person does on the approve page and the app page. Test 11 runs the shipped Calendar rows through
// createApp() with scripted Google answers. Nothing here listens on 4188 or 4320 or reaches a real provider.

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const ORIGIN = 'http://127.0.0.1:4320';
const OWNER_EMAIL = 'owner@fixture.test', ZONE = 'America/Toronto', RUN_DATE = '2026-10-23';
const RECORDED = Object.freeze({draftId: 'D1', tableId: 'T1', eventStart: '2026-10-28T10:00:00Z', eventEnd: '2026-10-28T10:30:00Z'});
const fixturePlan = () => JSON.parse(readFileSync(new URL('./fixtures/live-tests/fixture.json', import.meta.url), 'utf8'));
const sha256 = text => createHash('sha256').update(text).digest('hex');
/** The fake app's live-test rules: reads anywhere; the writes its actions send, with synthetic text where they carry text; a delete of an
 *  item only during the one-time Ask on "Delete items". */
const FIXTURE_RULES = Object.freeze({fixture: Object.freeze({appId: 'fixture', base: 'https://api.fixture.test',
  allowlist: Object.freeze([{method: 'GET', path: '+any'}, {method: 'PATCH', path: 'items/:item'}, {method: 'DELETE', path: 'items/:item/labels/:name'}, {method: 'PUT', path: 'files/+path'},
    {method: 'PATCH', path: 'events/:event'}, {method: 'POST', path: 'drafts/:draft/send'}, {method: 'POST', path: 'items'}, {method: 'DELETE', path: 'items/:item'}]),
  route(request, view) {
    const [first, , third] = request.segments, count = request.segments.length, method = request.method;
    if (method === 'GET') return {write: false};
    if (method === 'PATCH' && first === 'items' && count === 2) return {write: true};
    if (method === 'DELETE' && first === 'items' && third === 'labels' && count === 4) return {write: true};
    if (method === 'PUT' && first === 'files' && count >= 2) { if (!synthetic(view, request.body?.message)) refuseRequest('text'); return {write: true}; }
    if (method === 'PATCH' && first === 'events' && count === 2) return {write: true};
    if (method === 'POST' && first === 'drafts' && third === 'send' && count === 3) return {write: true};
    if (method === 'POST' && first === 'items' && count === 1) { if (!synthetic(view, request.body?.properties?.title?.title?.[0]?.text?.content)) refuseRequest('text'); return {write: true, creates: 'item'}; }
    if (method === 'DELETE' && first === 'items' && count === 2) { if (view.oneTimeAsk !== 'fixture.items.delete') refuseRequest('one_time_ask'); return {write: true}; }
    return refuseRequest('not_allowlisted');
  }})});

function temp(t, prefix = 'fabric-live-certify-') {
  const folder = mkdtempSync(path.join(tmpdir(), prefix));
  t.after(() => rmSync(folder, {recursive: true, force: true}));
  return folder;
}
const entryKey = entry => `${entry.key}@${entry.version}`;
/** The fake app's validated entries, all or only the named ones (key@version). */
function fixtureEntries(h, keys) {
  const all = [...h.catalog.entries.values()].filter(item => item.appId === 'fixture').map(item => item.entry);
  return keys ? all.filter(entry => keys.includes(entryKey(entry))) : all;
}
/** The plan with only the named tests, in their order. */
const only = (plan, ids) => ({...plan, tests: plan.tests.filter(item => ids.includes(item.id))});

/**
 * The scripted owner (Muse). It reads every line the runner prints: an approve link is approved on the owner's own path, one at a time
 * (each after the one before has finished, as a person clicks), and "Set ... to Ask" and "Reset ... to Never" are done on the app page a few
 * waits later. It answers prompts from `answers`. Each wait moves the harness clock one second. The certification runtime's own approve()
 * is replaced by one that throws, so a runner that approved anything would fail the test.
 */
function scriptedOwner(h, runtime, proxyPolicy, {approve = true, answers = [], askMode = 'ask', rowDelay = 3, waitLimit = 3000, onLine = () => {}, onWait = () => {}} = {}) {
  const lines = [], links = [], approvals = [], sets = [];
  const ownerApprove = runtime.approve.bind(runtime), ownerSet = proxyPolicy.set.bind(proxyPolicy);
  runtime.approve = () => { throw new Error('Only the owner approves.'); };
  let byRunner = 0, chain = Promise.resolve(), waits = 0, rowTask = null, owning = false;
  proxyPolicy.set = (...args) => { if (!owning) byRunner++; return ownerSet(...args); };
  const setRow = (label, mode) => {
    const entry = proxyPolicy.view(h.account).find(row => row.label === label);
    owning = true;
    try { ownerSet({connectionId: h.account, row: entry.row, mode, confirmAllow: true}); sets.push([label, mode, h.now]); } finally { owning = false; }
  };
  const muse = {lines, links, approvals, sets, answers, setRow, get waits() { return waits; }, get byRunner() { return byRunner; }, done: () => chain,
    say(line) {
      lines.push(String(line));
      const link = /^Approve: http:\/\/127\.0\.0\.1:4320\/approve\/([0-9a-f-]{36})$/m.exec(line);
      if (link) {
        links.push(link[1]);
        if (approve) chain = chain.then(() => ownerApprove(link[1], h.store.get('jobs', link[1]).approvalDigest, OWNER)).then(job => approvals.push([link[1], job.status]), error => approvals.push([link[1], `error: ${error.message}`]));
      }
      const set = /^Set "(.+)" to Ask/.exec(line), reset = /^Reset "(.+)" to Never/.exec(line);
      if (set) rowTask = {label: set[1], mode: askMode, in: rowDelay};
      if (reset) rowTask = {label: reset[1], mode: 'deny', in: rowDelay};
      onLine(line, muse);
    },
    async prompt(words) { lines.push(String(words)); return answers.length ? answers.shift() : ''; },
    async wait() {
      if (++waits > waitLimit) throw new Error('The runner waited too long.');
      h.advance(1000);
      if (rowTask && --rowTask.in <= 0) { const task = rowTask; rowTask = null; setRow(task.label, task.mode); }
      const frozen = onWait(muse);
      if (frozen) return frozen;
      await new Promise(resolve => setImmediate(resolve));
    }};
  return muse;
}

/** A certification run on the fake app: candidates (no evidence), the guard with the test rules in front of the simulator, a certification
 *  Runtime and FabricProtocol over the harness's store, and the harness port the command gives the runner. */
function fakeRun(t, {plan = fixturePlan(), keys, owner = {}, folder = temp(t), runId = newRunId(), key = randomBytes(32), h = actionHarness(t, {designated: true, evidence: () => ({})}), recorded = RECORDED, superseded = []} = {}) {
  if (!h.simulator.data.items.some(item => item.id === 'T1')) h.simulator.data.items.push({id: 'T1', name: 'Costs', kind: 'table', labels: [], in_trash: false, updated: '2026-10-01T09:00:00.000Z', properties: {Name: {id: 'title', type: 'title'}}});
  // Rename or label acts only on an open item (its guard after the read).
  for (const item of h.simulator.data.items) item.status ??= 'open';
  const guard = createGuard({appId: 'fixture', runId, folder, key, rules: FIXTURE_RULES, clock: () => h.now});
  guard.setOwner({email: OWNER_EMAIL, timeZone: ZONE, runDate: RUN_DATE, recorded});
  const permissions = new PermissionManager({store: h.store, groups: h.groups, configs: h.configs});
  const proxyPolicy = new ProxyPolicy({store: h.store, permissions, groups: h.groups, configs: h.configs});
  const runtime = new Runtime({store: h.store, permissions, proxyPolicy, connections: h.connections, request: guard.wrap(h.simulator.request), clock: () => h.now, actions: h.catalog, ownerPrincipal: OWNER, certification: true});
  const protocol = new FabricProtocol({store: h.store, runtime, clock: () => h.now, origin: ORIGIN});
  runtime.authorizeSource = job => protocol.authorizeJob(job);
  const port = harnessPort({store: h.store, runtime, protocol, origin: ORIGIN}, {owner: OWNER});
  const entries = fixtureEntries(h, keys);
  const checked = checkPlan(plan, {entries, superseded, groups: h.groups.get('fixture'), config: h.configs.get('fixture'), rules: FIXTURE_RULES});
  const state = openRunState(folder, 'fixture', runId, {runDate: RUN_DATE, timeZone: ZONE, recorded});
  const muse = scriptedOwner(h, runtime, proxyPolicy, owner);
  const run = (options = {}) => runLiveTests(port, checked, {guard, state, prompt: muse.prompt, say: muse.say, clock: () => h.now, wait: muse.wait, ...options});
  const evidence = (options = {}) => evidenceRecords(state.data, {key, entries: fixtureEntries(h), trace: id => guard.trace(id), job: id => port.job(id), pins: PINS,
    codeHashes: ids => Object.fromEntries(ids.map(id => [id, PINS[id]])), groups: h.groups, configs: h.configs, maps: new Map([['fixture', fixtureMap()]]), ...options});
  return {h, guard, port, checked, state, muse, folder, key, runId, runtime, protocol, proxyPolicy, permissions, entries, run, evidence};
}
const writes = h => h.simulator.writes().map(call => `${call.method} ${call.path}`);
const grants = h => h.store.list('clientGrants');

// ---- 1. the plan validator ----------------------------------------------------------------------------------------------------------
test('harness 1: the plan validator refuses unknown fields and step kinds, an action not in the file or superseded, a name used before it is saved, a day outside 7 to 13, a read that is not GET or outside the prefixes, a write test without undo, an uncalled action, a duplicate test id, an undeclared recorded name and a write the guard cannot pass', t => {
  const h = actionHarness(t, {designated: true, evidence: () => ({})}), entries = fixtureEntries(h);
  const deps = {entries, superseded: ['fixture.action.old-items.v1.0123456789abcdef01234567'], groups: h.groups.get('fixture'), config: h.configs.get('fixture'), rules: FIXTURE_RULES};
  const checked = checkPlan(fixturePlan(), deps);
  assert.deepEqual([checked.appId, checked.plan.tests.map(item => item.id), [...checked.actions.keys()].sort()], ['fixture', ['T0', 'T1', 'T2', 'T3', 'T4', 'T5', 'T6'], entries.map(entryKey).sort()]);
  assert.equal(checked.actions.get('put-file@1').id, entries.find(entry => entry.key === 'put-file').id);
  assert.ok(Object.isFrozen(checked.plan), 'the checked plan is frozen');
  const refused = (change, words, note) => {
    const plan = fixturePlan();
    change(plan);
    assert.throws(() => checkPlan(plan, deps), words, note);
  };
  const step = (plan, testId, index = 0) => plan.tests.find(item => item.id === testId).steps[index];
  refused(plan => { plan.extra = 1; }, /extra is not a field of a live test plan/, 'a top-level field');
  refused(plan => { plan.tests[0].owner = 'me'; }, /tests\[0\]: owner is not a field of a test/, 'a test field');
  refused(plan => { step(plan, 'T0').call.wait = 2; }, /wait is not a field of call/, 'a call field');
  refused(plan => { plan.tests[0].steps.push({sleep: {ms: 1}}); }, /a step is exactly one of call, race, read, owner, oneTimeAsk or ask/, 'an unknown step kind');
  refused(plan => { plan.tests[0].steps.push({call: {action: 'list-items@1', args: {kind: 'all'}}, read: {path: '/items'}}); }, /a step is exactly one of/, 'two kinds in one step');
  refused(plan => { step(plan, 'T0').call.checks.push({pointer: '/items', longest: 3}); }, /a check is one of/, 'an unknown check');
  refused(plan => { step(plan, 'T0').call.args.kind = {$env: 'HOME'}; }, /\$env is not a placeholder/, 'an unknown placeholder');
  refused(plan => { step(plan, 'T0').call.action = 'list-everything@1'; }, /list-everything@1 is not an action of fixture/, 'an action not in the file');
  refused(plan => { step(plan, 'T0').call.action = 'list-items@2'; }, /list-items@2 is not an action of fixture/, 'another version');
  refused(plan => { step(plan, 'T0').call.action = 'list-items'; }, /key@version/, 'no version');
  refused(plan => { step(plan, 'T0').call.action = 'old-items@1'; }, /old-items@1 is superseded/, 'a superseded action');
  refused(plan => { step(plan, 'T1').call.save = {}; }, /\$saved: item is used before a step saves it/, 'a name used before it is saved');
  refused(plan => { plan.tests[1].steps.unshift({read: {path: '/items/{item}', params: {item: {$saved: 'item'}}}}); }, /\$saved: item is used before a step saves it/, 'used in an earlier step');
  refused(plan => { step(plan, 'T3').call.args.start = {$at: {day: 6, time: '10:00'}}; }, /\$at: day is 7 to 13/, 'day 6');
  refused(plan => { step(plan, 'T3').call.args.end = {$at: {day: 14, time: '10:00'}}; }, /\$at: day is 7 to 13/, 'day 14');
  refused(plan => { step(plan, 'T3').call.args.start = {$day: 15}; }, /\$day is 7 to 13/, 'a $day of 15');
  refused(plan => { step(plan, 'T3').call.args.start = {$at: {day: 9, time: '25:00'}}; }, /\$at: time is HH:MM/, 'an hour 25');
  refused(plan => { step(plan, 'T1', 1).read.method = 'POST'; }, /a read is a GET/, 'a read that is not GET');
  refused(plan => { step(plan, 'T1', 1).read.path = 'items/{item}'; }, /starts with \//, 'a path without its slash');
  refused(plan => { step(plan, 'T1', 1).read.path = '/items/{other}'; }, /\{other\} has no params entry/, 'a slot with no value');
  refused(plan => { delete plan.tests[1].undo; }, /T1 writes, so it needs an undo/, 'a write test without undo');
  refused(plan => { plan.tests[3].undo = {test: 'T0'}; }, /T3: undo names T0, which is not a later test/, 'an undo test that ran before');
  refused(plan => { plan.tests[3].undo = {}; }, /undo is exactly one of test, steps or none/, 'an empty undo');
  refused(plan => { plan.tests = plan.tests.filter(item => item.id !== 'T4'); }, /send-draft@1 is called by no test, so it would get no evidence/, 'an action no test calls');
  refused(plan => { plan.tests[2].id = 'T1'; }, /test id T1 is used twice/, 'a duplicate test id');
  refused(plan => { delete plan.recorded.draftId; }, /\$recorded: draftId is not declared in recorded/, 'an undeclared recorded name');
  refused(plan => { plan.readRows = ['fixture.items.edit']; }, /readRows: fixture\.items\.edit is not a read row of fixture/, 'a write row as a read row');
  assert.throws(() => checkPlan({...fixturePlan(), appId: 'other'}, {...deps, rules: {...FIXTURE_RULES, other: FIXTURE_RULES.fixture}}), /the entries are not this plan's app/, 'another app');
  // Every write placement of a called action fits a method and path the guard's list for the app names; the guard decides the content.
  const narrow = {fixture: {...FIXTURE_RULES.fixture, allowlist: FIXTURE_RULES.fixture.allowlist.filter(item => item.method !== 'PUT')}};
  assert.throws(() => checkPlan(fixturePlan(), {...deps, rules: narrow}), /put-file@1: PUT \/files\/\{\+path\} fits nothing on the live guard's list for fixture/);
  assert.throws(() => checkPlan(fixturePlan(), {...deps, rules: {}}), /fixture has no live-test rules/);
  // The structure check alone needs no entries: the command runs it before anything opens.
  assert.equal(checkPlanShape(fixturePlan()).tests.length, 7);
  assert.throws(() => checkPlanShape({...fixturePlan(), schemaVersion: 2}), /schemaVersion is 1/);
  assert.deepEqual([PLAN_LIMITS.firstDay, PLAN_LIMITS.lastDay, PLAN_LIMITS.grantSeconds], [7, 13, 4 * 60 * 60]);
});

// ---- 2. end to end on the fake app ----------------------------------------------------------------------------------------------------
test('harness 2: end to end on the fake app: each test\'s write, readback and undo run after the owner\'s approvals; each link is printed once; the runner never approves or sets a row', async t => {
  const r = fakeRun(t);
  const run = await r.run();
  await r.muse.done();
  assert.equal(run.stopped, null, JSON.stringify(run.stopped));
  assert.deepEqual(run.order, ['T0', 'T1', 'T2', 'T3', 'T4', 'T5', 'T6']);
  for (const id of run.order) assert.equal(run.results[id].passed, true, `${id}: ${run.results[id].words} ${JSON.stringify(run.results[id].checks)}`);
  // Each link once, one per stop, each approved by the owner; the runner never approved (approve() throws for it) and set no row.
  assert.equal(new Set(r.muse.links).size, r.muse.links.length, 'no link is printed twice');
  // One stop each: T0, T1 and its undo, the race's two cards, T3, T4, T5 and T6. Every read before a card ran at its Allow row.
  assert.equal(r.muse.links.length, 9);
  assert.ok(r.muse.approvals.every(([, status]) => ['succeeded', 'failed'].includes(status)), JSON.stringify(r.muse.approvals));
  assert.equal(r.muse.byRunner, 0);
  // Every write was sent once, the race's twice: one landed and one was refused.
  assert.deepEqual(writes(r.h), ['PATCH /items/I1', 'DELETE /items/I1/labels/Later', 'PUT /files/docs/a.md', 'PUT /files/docs/a.md', 'PATCH /events/E1', 'POST /drafts/D1/send', 'POST /items', 'PATCH /events/E1']);
  assert.equal(r.h.simulator.state().events.E1.start, RECORDED.eventStart, 'T6 put the event back');
  assert.deepEqual(r.h.simulator.state().items.find(item => item.id === 'I1').labels, [], 'the undo took the label off');
  // Saved values, the run state file and the request ids.
  assert.deepEqual(Object.keys(run.saved).sort(), ['etag', 'first', 'item', 'label', 'row']);
  const file = runStateFile(r.folder, 'fixture', r.runId);
  assert.equal(statSync(file).mode & 0o777, 0o600);
  const stored = readFileSync(file, 'utf8');
  assert.ok(!stored.includes(r.key.toString('hex')) && !stored.includes(TOKEN) && !stored.includes('fab_client.'), 'no key, token or client token in the run state');
  assert.ok(Object.keys(run.requests).every(id => id.startsWith(`${r.runId}.`)) && Object.values(run.requests).every(Boolean));
  // Every job came from a client grant, with its request id.
  for (const job of r.h.store.list('jobs')) assert.equal(job.source.kind, 'client', job.id);
});

// ---- 3. a card the guard refuses --------------------------------------------------------------------------------------------------
test('harness 3: a card whose prepared bytes the guard refuses prints no link: the run stops with "Reject this card" and nothing is sent', async t => {
  const plan = {...fixturePlan(), tests: [{id: 'T8', name: 'A write with plain text', steps: [{call: {action: 'put-file@1', args: {path: 'docs/b.md', content: 'plain', message: 'plain words', kind: 'file'}}}],
    undo: {none: 'Nothing is sent.'}}]};
  const r = fakeRun(t, {plan, keys: ['put-file@1']});
  const run = await r.run();
  assert.deepEqual(r.muse.links, []);
  assert.ok(r.muse.lines.includes(`Reject this card: ${GUARD_WORDS.text}`), r.muse.lines.join('\n'));
  assert.deepEqual([run.stopped.test, run.results.T8.passed], ['T8', false]);
  assert.deepEqual(writes(r.h), []);
  const job = r.h.store.list('jobs').find(item => item.kind === 'action');
  assert.equal(job.status, 'awaiting_approval', 'the card waits for the owner to reject it; the runner cannot');
});

// ---- 4. the race ------------------------------------------------------------------------------------------------------------------
test('harness 4: a race prepares one action twice before either card is approved: one job succeeds, one fails with the status, the readback equals the one that landed, and both are in the evidence; two successes fail it', async t => {
  const plan = only(fixturePlan(), ['T2']), r = fakeRun(t, {plan, keys: ['put-file@1']});
  // Both cards are printed before the owner approves either.
  let jobsAtFirstLink = null;
  r.muse.say = (say => line => { if (/^Approve:/.test(line) && jobsAtFirstLink === null) jobsAtFirstLink = r.h.store.list('jobs').filter(job => job.kind === 'action').length; say(line); })(r.muse.say);
  const run = await r.run();
  assert.equal(jobsAtFirstLink, 2);
  assert.equal(run.results.T2.passed, true, run.results.T2.words);
  const [jobA, jobB] = run.results.T2.calls[0].jobs.map(id => r.port.job(id));
  assert.deepEqual([jobA.status, jobB.status, jobB.providerStatus], ['succeeded', 'failed', 409]);
  assert.equal(r.h.simulator.state().files['docs/a.md'].sha, jobA.result.data.sha);
  const {records} = r.evidence();
  const record = records[r.checked.actions.get('put-file@1').id];
  assert.deepEqual(record.tests[0].jobs.map(job => job.status), ['succeeded', 'failed']);
  assert.deepEqual(record.tests[0].jobs.map(job => job.errorCode), [null, 'provider_failed']);
  assert.equal(record.passed, true);
  // Two successes: the first PUT answers 200 with the current version and changes nothing, so the second lands too. The race fails.
  const twice = fakeRun(t, {plan, keys: ['put-file@1']});
  const current = twice.h.simulator.state().files['docs/a.md'];
  twice.h.simulator.fail('PUT /files/{+path}', {status: 200, data: {content: {path: current.path, sha: current.sha}, commit: {message: 'x'}}});
  const failed = await twice.run();
  assert.deepEqual(failed.results.T2.calls[0].jobs.map(id => twice.port.job(id).status), ['succeeded', 'succeeded']);
  assert.equal(failed.results.T2.passed, false);
  assert.match(failed.results.T2.words, /one job must succeed and one must fail with 409/);
});

// ---- 5. the one-time Ask on a Never row ---------------------------------------------------------------------------------------------
const askPlan = () => ({...fixturePlan(), recorded: {}, tests: [{id: 'T9', name: 'Delete an item through the one-time Ask', steps: [
  {oneTimeAsk: {row: 'fixture.items.delete', requests: [{method: 'DELETE', path: '/items/{item}', params: {item: 'I5'}}]}},
  {read: {path: '/items/{item}', params: {item: 'I5'}, checks: [{gone: true}]}}], undo: {none: 'The fake app starts fresh each run.'}}]});
test('harness 5: the one-time Ask: the runner prints Set, waits for Ask, sends the one call after its approval, prints Reset, waits for Never and records both; Allow stops the run; a stop resets the row first; the runner never sets a row', async t => {
  const r = fakeRun(t, {plan: askPlan(), keys: [], recorded: {}});
  r.muse.setRow('Delete items', 'deny');
  const run = await r.run();
  await r.muse.done();
  assert.equal(run.results.T9.passed, true, run.results.T9.words);
  const text = r.muse.lines.join('\n');
  assert.match(text, /^Set "Delete items" to Ask: http:\/\/127\.0\.0\.1:4320\/connectors\/fixture$/m);
  assert.ok(text.indexOf('Set "Delete items" to Ask') < text.indexOf('Approve: ') && text.indexOf('Approve: ') < text.indexOf('Reset "Delete items" to Never'), text);
  assert.deepEqual(writes(r.h), ['DELETE /items/I5']);
  const [row] = run.rows;
  const [[, , setAsk], [, , setNever]] = r.muse.sets.slice(1);
  assert.deepEqual([row.row, row.label, Date.parse(row.askSeenAt) >= setAsk, Date.parse(row.neverSeenAt) >= setNever, row.allowSeenAt], ['fixture.items.delete', 'Delete items', true, true, null]);
  assert.equal(r.port.rowMode(r.h.account, 'fixture.items.delete'), 'deny');
  assert.equal(r.muse.byRunner, 0, 'the runner never sets a row');
  for (const member of ['approve', 'decide', 'set', 'setRow', 'reset', 'promote']) assert.equal(Object.hasOwn(r.port, member), false, member);
  assert.ok(grants(r.h).every(grant => grant.status === 'revoked'));
  assert.ok(grants(r.h).some(grant => grant.proxy?.[0]?.rows.map(item => item.row).join() === 'group:fixture.items.delete'), 'a grant with that one row');
  // Allow stops the run, and the stop still resets the row and waits for Never. A delete row never offers Allow to the proxy, so this one
  // opens "Manage labels", a write row that does.
  const allowPlan = askPlan();
  allowPlan.tests[0].steps = [{oneTimeAsk: {row: 'fixture.labels.write', requests: [{method: 'POST', path: '/labels'}]}}];
  const allowed = fakeRun(t, {plan: allowPlan, keys: [], recorded: {}, owner: {askMode: 'allow'}});
  allowed.muse.setRow('Manage labels', 'deny');
  const stopped = await allowed.run();
  assert.deepEqual([stopped.results.T9.passed, stopped.stopped.test], [false, 'T9']);
  assert.ok(allowed.muse.lines.includes('Set it to Ask, not Allow.'), allowed.muse.lines.join('\n'));
  assert.match(allowed.muse.lines.join('\n'), /^Reset "Manage labels" to Never$/m);
  assert.deepEqual(writes(allowed.h), []);
  assert.ok(stopped.rows[0].allowSeenAt && stopped.rows[0].neverSeenAt && !stopped.rows[0].askSeenAt, JSON.stringify(stopped.rows));
  assert.ok(Date.parse(stopped.rows[0].neverSeenAt) >= allowed.muse.sets.at(-1)[2], 'Never was read after the owner reset it');
  assert.equal(allowed.port.rowMode(allowed.h.account, 'fixture.labels.write'), 'deny');
  // The proxy call fails: the stop prints Reset, waits for Never and records it before the run returns.
  const failing = fakeRun(t, {plan: askPlan(), keys: [], recorded: {}});
  failing.muse.setRow('Delete items', 'deny');
  failing.h.simulator.fail('DELETE /items/{item_id}', {status: 500, data: {error: 'boom'}});
  const broken = await failing.run();
  await failing.muse.done();
  assert.equal(broken.results.T9.passed, false);
  const lines = failing.muse.lines;
  assert.ok(lines.findIndex(line => /^Reset "Delete items" to Never/.test(line)) > lines.findIndex(line => /^Approve:/.test(line)));
  assert.ok(broken.rows[0].neverSeenAt, 'recorded before exit');
  assert.equal(failing.port.rowMode(failing.h.account, 'fixture.items.delete'), 'deny');
});

// ---- 6. an owner step that waits for its read ---------------------------------------------------------------------------------------
test('harness 6: an owner step with until waits for its read: it passes once the read holds, and fails after 5 minutes when it never does', async t => {
  const plan = {...fixturePlan(), recorded: {}, tests: [{id: 'T7', name: 'Muse renames an item by hand', steps: [{owner: {words: 'Rename item I3 to Done by hand.',
    until: {path: '/items/{item}', params: {item: 'I3'}, checks: [{pointer: '/name', equals: 'Done'}]}}}]}]};
  const r = fakeRun(t, {plan, keys: [], recorded: {}, owner: {onWait: muse => { if (muse.waits === 4) r.h.simulator.data.items.find(item => item.id === 'I3').name = 'Done'; }}});
  const run = await r.run();
  assert.equal(run.results.T7.passed, true, run.results.T7.words);
  assert.ok(r.muse.lines.includes('Rename item I3 to Done by hand.'));
  assert.ok(r.h.simulator.reads().filter(call => call.path === '/items/I3').length >= 3, 'it polled');
  // About 300 one-second waits make 5 minutes; 400 at most, so a runner that never gives up fails fast.
  const never = fakeRun(t, {plan, keys: [], recorded: {}, owner: {waitLimit: 400}});
  const late = await never.run();
  assert.equal(late.results.T7.passed, false);
  assert.match(late.results.T7.words, /did not happen within 5 minutes/);
  assert.ok(never.muse.waits >= 300 && never.muse.waits < 320, String(never.muse.waits));
});

// ---- 7. a failed test stops the run; crash and resume ----------------------------------------------------------------------------
test('harness 7: the first failed test stops the run; a crash after a write\'s 2xx resumes from that test, reusing the stored job by its request id, with the guard\'s counts, the run id and saved values kept, the stale grant revoked and a new key', async t => {
  const failing = fixturePlan();
  failing.tests[0].steps[0].call.checks[1].equals = 'Someone else';
  const r = fakeRun(t, {plan: failing});
  const stopped = await r.run();
  assert.deepEqual([stopped.order, stopped.results.T0.passed, stopped.stopped.test], [['T0'], false, 'T0']);
  assert.deepEqual(stopped.results.T0.checks.map(check => check.passed), [true, true, true, false]);
  assert.deepEqual(writes(r.h), [], 'no later test ran');
  assert.equal(r.evidence().records[r.checked.actions.get('list-items@1').id].passed, false);
  // A crash: the runner freezes for good right after update-item's PATCH has landed, before it reads the outcome.
  const plan = only(fixturePlan(), ['T0', 'T1']), keys = ['list-items@1', 'update-item@1', 'remove-labels@1'];
  const first = fakeRun(t, {plan, keys, owner: {onWait: () => r2Crash(first)}});
  const r2Crash = run => run.h.store.list('jobs').some(job => job.capabilityId === run.checked.actions.get('update-item@1').id) ? new Promise(() => {}) : null;
  void first.run();
  for (let turns = 0; turns < 2000 && !first.h.store.list('jobs').some(job => job.status === 'succeeded' && job.capabilityId === first.checked.actions.get('update-item@1').id); turns++) await new Promise(resolve => setImmediate(resolve));
  for (let turns = 0; turns < 20; turns++) await new Promise(resolve => setImmediate(resolve));
  const staleGrant = first.state.data.grant;
  assert.ok(staleGrant, 'the crashed run left its grant in the run state');
  assert.equal(first.h.store.get('clientGrants', staleGrant).status, 'active');
  assert.deepEqual(writes(first.h), ['PATCH /items/I1']);
  const counted = first.guard.counts();
  // The resume: the same store and folder, a new guard and state read from their files, a new key, a new runtime and protocol.
  const newKey = randomBytes(32);
  const second = fakeRun(t, {plan, keys, h: first.h, folder: first.folder, runId: first.runId, key: newKey});
  assert.deepEqual(second.guard.counts(), counted, 'the guard\'s counters come back from its file');
  assert.deepEqual(second.state.data.saved, first.state.data.saved, 'saved values are kept');
  const resumed = await second.run({from: 'T1'});
  await second.muse.done();
  assert.equal(resumed.results.T1.passed, true, resumed.results.T1.words);
  assert.equal(first.h.store.get('clientGrants', staleGrant).status, 'revoked', 'the stale grant is revoked first');
  assert.deepEqual(writes(first.h), ['PATCH /items/I1', 'DELETE /items/I1/labels/Later'], 'the create was sent once');
  assert.equal(resumed.runId, first.runId);
  assert.deepEqual([resumed.results.T0.passed, typeof resumed.saved.first, resumed.saved.item], [true, 'string', 'I1']);
  assert.notDeepEqual(newKey, first.key);
  assert.equal(second.guard.counts().writes, counted.writes + 1);
  // A request id an earlier attempt used for another request is never reused for this one: nothing is sent.
  const changedPlan = only(fixturePlan(), ['T0', 'T1']);
  changedPlan.tests[1].steps[0].call.args.labels = ['Work'];
  const fourth = fakeRun(t, {plan: changedPlan, keys, h: first.h, folder: first.folder, runId: first.runId});
  const mismatched = await fourth.run({from: 'T1'});
  assert.equal(mismatched.results.T1.passed, false);
  assert.match(mismatched.results.T1.words, new RegExp(`${first.runId}\\.T1\\.1 named another request in an earlier attempt`));
  assert.deepEqual(writes(first.h), ['PATCH /items/I1', 'DELETE /items/I1/labels/Later']);
  // A value the plan saves must be in the answer.
  const unsaved = only(fixturePlan(), ['T0']);
  unsaved.tests[0].steps[0].call.save = {first: '/nowhere'};
  const nosave = fakeRun(t, {plan: unsaved, keys: ['list-items@1']});
  const missed = await nosave.run();
  assert.match(missed.results.T0.words, /\/nowhere is not in the answer, so first cannot be saved/);
  assert.deepEqual(missed.results.T0.checks.map(check => [check.name, check.passed]), [['step 1: list-items@1 succeeded', true], ['step 1: saves first', false]]);
  // A job that ended uncertain is never sent again: a resume stops at it for the owner to check by hand.
  const lost = fakeRun(t, {plan: only(fixturePlan(), ['T1']), keys: ['update-item@1', 'remove-labels@1']});
  lost.h.simulator.drop('PATCH /items/{item_id}');
  const dropped = await lost.run();
  assert.equal(lost.port.job(dropped.results.T1.calls[0].jobs[0]).status, 'uncertain');
  const again = fakeRun(t, {plan: only(fixturePlan(), ['T1']), keys: ['update-item@1', 'remove-labels@1'], h: lost.h, folder: lost.folder, runId: lost.runId});
  const halted = await again.run({from: 'T1'});
  assert.equal(halted.results.T1.passed, false);
  assert.match(halted.results.T1.words, /uncertain: check it by hand/);
  assert.deepEqual(writes(lost.h), ['PATCH /items/I1'], 'never sent again');
});

// ---- 8. the evidence --------------------------------------------------------------------------------------------------------------
test('harness 8: the evidence passes evidencePasses() and check 6 for every called action, says passed: false when a code hash moved, and holds no token, plain or hashed address, body or header', async t => {
  const r = fakeRun(t);
  const run = await r.run();
  await r.muse.done();
  const evidence = r.evidence();
  for (const entry of r.entries) {
    const record = evidence.records[entry.id];
    assert.ok(record, entry.key);
    assert.equal(evidencePasses(entry, record, PINS), true, `${entry.key}: ${JSON.stringify(record).slice(0, 400)}`);
    assert.deepEqual([record.schemaVersion, record.runId, record.definitionHash, Object.keys(record.runtime).sort()], [1, r.runId, entry.definitionHash, ['icu', 'node', 'tz', 'unicode']]);
    assert.match(record.harnessHash, /^[0-9a-f]{64}$/);
  }
  const put = evidence.records[r.checked.actions.get('put-file@1').id], update = evidence.records[r.checked.actions.get('update-item@1').id];
  assert.deepEqual(put.tests[0].requests.map(item => `${item.method} ${item.template} ${item.status}`), ['GET /files/{+path} 200', 'GET /files/{+path} 200', 'PUT /files/{+path} 200', 'GET /files/{+path} 200', 'PUT /files/{+path} 409', 'GET /files/{+path} 200']);
  assert.ok(put.tests[0].requests.filter(item => item.method === 'PUT').every(item => /^[0-9a-f]{64}$/.test(item.bodyHmac)));
  assert.deepEqual(update.tests[0].undo.checks.map(check => check.passed), [true, true, true]);
  assert.ok(update.tests[0].undo.requests.some(item => item.method === 'DELETE' && item.template === '/items/{item_id}/labels/{name}'));
  assert.ok(update.tests[0].jobs[0].approvals.length === 1 && update.tests[0].jobs[0].approvals[0].phase === 'final');
  assert.deepEqual(evidence.records[r.checked.actions.get('reschedule-event@1').id].tests.map(item => [item.test, item.undo]), [['T3', {test: 'T6'}], ['T6', {none: 'It is the undo of T3.'}]]);
  // Written to a temporary app root: check 6 counts every record.
  const root = temp(t, 'fabric-live-evidence-root-');
  for (const dir of ['catalog/actions', 'catalog/choices']) mkdirSync(path.join(root, dir), {recursive: true});
  writeFileSync(path.join(root, 'catalog/actions/fixture.json'), JSON.stringify(r.h.file));
  writeFileSync(path.join(root, 'catalog/choices/fixture.json'), JSON.stringify(fixtureChoices()));
  const text = writeEvidence(root, 'fixture', evidence, {emails: [OWNER_EMAIL, 'friend@fixture.test'], tokens: [TOKEN]});
  assert.equal(readFileSync(path.join(root, 'docs/live-evidence/fixture/actions.json'), 'utf8'), text);
  assert.ok(text.endsWith('}\n') && text.startsWith('{\n "'), 'one-space indent and a final newline');
  const deps = {groups: r.h.groups, configs: r.h.configs, maps: new Map([['fixture', fixtureMap()]]), transforms: TRANSFORMS, pins: PINS};
  const check6 = () => templateChecks('fixture', {root, definitions: [fixtureSignIn()], groups: r.h.groups.get('fixture'), scopeFacts: {apps: {}}, actionDeps: deps, codeHashes: ids => Object.fromEntries(ids.map(id => [id, PINS[id]]))}).find(item => item.id === 'live-evidence');
  assert.equal(check6().pass, true, check6().reason);
  // Nothing secret: no token, header, body, plain or unsalted address, and the draft's raw message (which names an address) only as an HMAC.
  const draftRaw = r.h.simulator.calls.find(call => call.route === 'POST /drafts/{draft_id}/send').body;
  for (const banned of [TOKEN, 'Authorization', 'Bearer', OWNER_EMAIL, 'friend@fixture.test', sha256(OWNER_EMAIL), sha256('friend@fixture.test'), sha256(JSON.stringify(draftRaw)), draftRaw.raw, 'bodySha256', 'fab_client']) {
    assert.ok(!text.includes(banned), banned);
  }
  // Records of other actions are kept; this run's are replaced; the run key holds the run's own facts.
  const other = {passed: true, note: 'kept'};
  writeFileSync(path.join(root, 'docs/live-evidence/fixture/actions.json'), JSON.stringify({'fixture.action.gone.v1.0123456789abcdef01234567': other, [r.entries[0].id]: {passed: false}}));
  const merged = JSON.parse(writeEvidence(root, 'fixture', evidence, {emails: [OWNER_EMAIL]}));
  assert.deepEqual([merged['fixture.action.gone.v1.0123456789abcdef01234567'], merged[r.entries[0].id].passed, merged.run.runId, merged.run.appId], [other, true, r.runId, 'fixture']);
  assert.deepEqual(Object.keys(merged.run).sort(), ['appId', 'finishedAt', 'harnessHash', 'rows', 'runId', 'runtime', 'startedAt', 'tests']);
  // Evidence that would hold an address is refused and the file is left as it was.
  const before = readFileSync(path.join(root, 'docs/live-evidence/fixture/actions.json'), 'utf8');
  assert.throws(() => writeEvidence(root, 'fixture', {records: {'fixture.action.x.v1.0123456789abcdef01234567': {note: 'mail someone@else.test'}}, run: {}}), /an email address/);
  assert.equal(readFileSync(path.join(root, 'docs/live-evidence/fixture/actions.json'), 'utf8'), before);
  // A run-time code hash that differs from its pin: passed false, and evidencePasses() refuses it.
  const moved = r.entries.find(entry => entry.transforms.length);
  const repinned = r.evidence({codeHashes: ids => Object.fromEntries(ids.map(id => [id, id === moved.transforms[0] ? 'e'.repeat(64) : PINS[id]]))}).records[moved.id];
  assert.deepEqual([repinned.passed, repinned.transforms[moved.transforms[0]], evidencePasses(moved, repinned, PINS)], [false, 'e'.repeat(64), false]);
  // A failed undo makes the action's record fail.
  const failedUndo = structuredClone(run);
  failedUndo.results.T1.undo.passed = false;
  const undoRecord = evidenceRecords(failedUndo, {key: r.key, entries: r.entries, trace: id => r.guard.trace(id), job: id => r.port.job(id), pins: PINS, codeHashes: ids => Object.fromEntries(ids.map(id => [id, PINS[id]])),
    groups: r.h.groups, configs: r.h.configs, maps: new Map([['fixture', fixtureMap()]])}).records;
  assert.equal(undoRecord[r.checked.actions.get('update-item@1').id].passed, false);
  assert.equal(undoRecord[r.checked.actions.get('remove-labels@1').id].passed, false);
  // An email-shaped identity is an HMAC: equal within a run, different across runs. C9- and Gmail-shaped bodies built with the address match
  // nothing in the evidence, by sha256 in any case.
  const title = (guard, id) => ({title: {title: [{text: {content: `[SYNTHETIC] Fabric T5 ${guard.runId} row`}}]}, id});
  const c9 = guard => JSON.stringify({properties: title(guard), attendeesOmitted: true, attendees: [{email: OWNER_EMAIL, responseStatus: 'accepted'}]});
  const gmail = guard => JSON.stringify({properties: title(guard), raw: Buffer.from(`To: ${OWNER_EMAIL}\r\nSubject: [SYNTHETIC] Fabric G1 ${guard.runId}\r\n\r\nHi`).toString('base64url')});
  const created = async key => {
    const guard = createGuard({appId: 'fixture', runId: newRunId(), folder: temp(t), key, rules: FIXTURE_RULES});
    guard.setOwner({email: OWNER_EMAIL, timeZone: ZONE, runDate: RUN_DATE});
    const send = guard.wrap(async () => ({status: 200, headers: {}, data: {id: 'row-1@fixture.test'}}));
    guard.begin('T5');
    for (const body of [c9(guard), gmail(guard)]) await send({url: 'https://api.fixture.test/items', method: 'POST', body});
    guard.end();
    return guard;
  };
  const keyA = randomBytes(32), runA = await created(keyA), runB = await created(randomBytes(32));
  const [a1, a2] = runA.trace('T5').map(item => item.identity), [b1] = runB.trace('T5').map(item => item.identity);
  assert.ok(a1.startsWith('hmac:') && a1 === a2 && a1 !== b1, `${a1} ${a2} ${b1}`);
  const addRow = r.checked.actions.get('add-row@1');
  const lone = {appId: 'fixture', runId: runA.runId, startedAt: run.startedAt, finishedAt: run.finishedAt, order: ['T5'], rows: [],
    results: {T5: {id: 'T5', passed: true, words: null, calls: [{action: 'add-row@1', actionId: addRow.id, jobs: []}], proxies: [], reads: [], checks: [], undo: {kind: 'none', why: 'test'}}}};
  const loneText = JSON.stringify(evidenceRecords(lone, {key: keyA, entries: r.entries, trace: id => runA.trace(id), job: () => null, pins: PINS, codeHashes: ids => Object.fromEntries(ids.map(id => [id, PINS[id]])),
    groups: r.h.groups, configs: r.h.configs, maps: new Map([['fixture', fixtureMap()]])}));
  assert.ok(loneText.includes(a1) && !loneText.includes('row-1@fixture.test'));
  // A request in a test's trace that fits no placement of its actions and no read of its plan fails the test.
  const stray = createGuard({appId: 'fixture', runId: newRunId(), folder: temp(t), key: keyA, rules: FIXTURE_RULES});
  stray.setOwner({email: OWNER_EMAIL, timeZone: ZONE, runDate: RUN_DATE});
  const strays = stray.wrap(async () => ({status: 200, headers: {}, data: {id: 'I9'}}));
  stray.begin('T5');
  await strays({url: 'https://api.fixture.test/items', method: 'POST', body: JSON.stringify({properties: title(stray)})});
  await strays({url: 'https://api.fixture.test/labels', method: 'GET'});
  stray.end();
  const strayRecord = evidenceRecords({...lone, runId: stray.runId}, {key: keyA, entries: r.entries, trace: id => stray.trace(id), job: () => null, pins: PINS, codeHashes: ids => Object.fromEntries(ids.map(id => [id, PINS[id]])),
    groups: r.h.groups, configs: r.h.configs, maps: new Map([['fixture', fixtureMap()]])}).records[addRow.id];
  assert.deepEqual([strayRecord.passed, strayRecord.tests[0].passed, strayRecord.tests[0].requests.map(item => item.template)], [false, false, ['/items', null]]);
  for (const body of [c9(runA), gmail(runA)]) for (const form of [sha256(body), sha256(body).toUpperCase(), sha256(body.toLowerCase())]) assert.ok(!loneText.includes(form) && !text.includes(form));
  assert.doesNotThrow(() => assertEvidenceSafe(loneText, {emails: [OWNER_EMAIL]}));
  // assertEvidenceSafe() refuses each kind of secret.
  assert.deepEqual([...TOKEN_PREFIXES].sort(), ['1//', 'gho_', 'ghp_', 'ghr_', 'ghs_', 'ghu_', 'github_pat_', 'ntn_', 'secret_', 'xoxb-', 'xoxe-', 'xoxp-', 'ya29.'].sort());
  for (const prefix of TOKEN_PREFIXES) assert.throws(() => assertEvidenceSafe(JSON.stringify({value: `${prefix}abc123`})), /a token/, prefix);
  for (const [value, words] of [[OWNER_EMAIL.toUpperCase(), /a known address/], [sha256(OWNER_EMAIL), /hash of a known address/], [sha256(OWNER_EMAIL).toUpperCase(), /hash of a known address/],
    ['someone@else.test', /an email address/], ['bodySha256', /a body hash/], ['Bearer abc', /a bearer credential/], ['xyz-known-token', /a token/]]) {
    assert.throws(() => assertEvidenceSafe(JSON.stringify({value}), {emails: [OWNER_EMAIL], tokens: ['xyz-known-token']}), words, value);
  }
});

// ---- 9. grants ----------------------------------------------------------------------------------------------------------------------
test('harness 9: each test\'s grant names only its own actions and read rows, expires within 4 hours, is the only one active while its test runs, and is revoked when the test ends', async t => {
  const actives = [];
  const r = fakeRun(t, {owner: {onLine: line => { if (/^Approve:/.test(line)) actives.push(grants(r.h).filter(grant => grant.status === 'active').map(grant => grant.name)); }}});
  await r.run();
  await r.muse.done();
  assert.ok(actives.length >= 9 && actives.every(names => names.length === 1), JSON.stringify(actives));
  const all = grants(r.h);
  assert.ok(all.length === 7 && all.every(grant => grant.status === 'revoked'), JSON.stringify(all.map(grant => [grant.name, grant.status])));
  const ids = key => r.checked.actions.get(key).id;
  const of = testId => all.find(grant => grant.name === `Live test ${testId} ${r.runId}`);
  assert.deepEqual(of('T1').bindings.map(binding => binding.capabilityId).sort(), [ids('update-item@1'), ids('remove-labels@1')].sort());
  assert.deepEqual(of('T2').bindings.map(binding => binding.capabilityId), [ids('put-file@1')]);
  for (const grant of all) {
    assert.ok(Date.parse(grant.expiresAt) - Date.parse(grant.createdAt) <= 4 * 60 * 60 * 1000, grant.name);
    assert.deepEqual(grant.proxy.map(entry => entry.rows.map(row => row.row)), [['group:fixture.items.read']], grant.name);
    assert.ok(grant.bindings.every(binding => binding.connectionId === r.h.account));
  }
  assert.equal(r.state.data.grant, null);
});

// ---- 10. the command --------------------------------------------------------------------------------------------------------------
test('harness 10: --check starts nothing and sends nothing; the command ignores FABRIC_DATA_DIR and FABRIC_PORT, needs --folder, refuses unknown flags and refused folders before it locks anything', async t => {
  const calls = [], say = [];
  const deps = {createApp: async options => { calls.push(['createApp', options]); throw new Error('stop here'); }, lockDataDir: async folder => { calls.push(['lockDataDir', folder]); return async () => { calls.push(['release', folder]); }; }};
  const go = (argv, options = {}) => main(argv, {say: line => say.push(String(line)), prompt: async () => '', deps, ...options});
  const fetched = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (...args) => { fetched.push(args); throw new Error('no network'); };
  t.after(() => { globalThis.fetch = realFetch; });
  // --check: the shipped plans check offline (F10.13 listed churn: Calendar's plan ships with step 13; F10.15, F10.19 and F10.21 listed churn:
  // Gmail's, Notion's and Slack's with steps 15, 19 and 21); an app with none says so; nothing starts.
  assert.equal(await go(['--check']), 0);
  assert.deepEqual(say.slice(-4), ['gmail: 12 tests check, calling 13 actions.', 'google-calendar: 14 tests check, calling 13 actions.', 'notion: 13 tests check, calling 16 actions.',
    'slack: 7 tests check, calling 13 actions.']);
  assert.equal(await go(['notion', '--check']), 0);
  assert.equal(say.at(-1), 'notion: 13 tests check, calling 16 actions.');
  assert.equal(await go(['slack', '--check']), 0);
  assert.equal(await go(['google-calendar', '--check']), 0);
  assert.equal(await go(['gmail', '--check']), 0);
  assert.match(say.at(-1), /^gmail: 12 tests check, calling 13 actions\.$/);
  assert.equal(await go(['fixture', '--check']), 1);
  assert.match(say.at(-1), /^No live test plan for fixture yet\.$/);
  assert.equal(await go(['--check'], {plans: temp(t)}), 0);
  assert.match(say.at(-1), /^No app has a live test plan yet\.$/);
  // With a plans folder, --check checks each plan offline against the shipped catalog and rules.
  const plans = temp(t);
  writeFileSync(path.join(plans, 'fixture.json'), JSON.stringify(fixturePlan()));
  assert.equal(await go(['fixture', '--check'], {plans}), 1);
  assert.match(say.at(-1), /fixture: .*fixture has no live-test rules/);
  writeFileSync(path.join(plans, 'broken.json'), '{');
  assert.equal(await go(['--check'], {plans}), 1);
  assert.deepEqual([calls, fetched], [[], []]);
  // The folder: required, absolute, never from the environment; refused before any lock.
  const env = {FABRIC_DATA_DIR: path.join(temp(t), 'from-env'), FABRIC_PORT: '4188'}, saved = {FABRIC_DATA_DIR: process.env.FABRIC_DATA_DIR, FABRIC_PORT: process.env.FABRIC_PORT};
  Object.assign(process.env, env);
  t.after(() => { for (const [name, value] of Object.entries(saved)) { if (value === undefined) delete process.env[name]; else process.env[name] = value; } });
  assert.equal(await go(['google-calendar']), 2);
  assert.match(say.at(-1), /--folder/);
  assert.equal(existsSync(env.FABRIC_DATA_DIR), false);
  for (const argv of [['google-calendar', '--port', '4188'], ['google-calendar', '--folder'], ['--folder', '/tmp/x'], ['google-calendar', '--folder', 'relative/dir']]) {
    assert.notEqual(await go(argv), 0, argv.join(' '));
  }
  assert.equal(await go(['google-calendar', '--folder', ROOT]), 2);
  assert.match(say.at(-1), /main data folder|repository/);
  assert.equal(await go(['google-calendar', '--folder', path.join(ROOT, '.fabric')]), 2);
  assert.deepEqual(calls, [], 'refused before any lock or start');
  // A folder the harness may use: locked, then Fabric is made there on 4320 with a designated store and the guard, whatever the environment says.
  const folder = path.join(temp(t), 'harness');
  assert.equal(await go(['fixture', '--folder', folder], {plans}), 2);
  assert.match(say.at(-1), /--record draftId=<value>/, 'every recorded value is given before anything opens');
  assert.deepEqual(calls, []);
  const records = Object.entries(RECORDED).flatMap(([name, value]) => ['--record', `${name}=${value}`]);
  assert.equal(await go(['fixture', '--folder', folder, ...records], {plans}), 1);
  const [[lock, locked], [start, options], [release]] = calls;
  assert.deepEqual([lock, locked, start, release], ['lockDataDir', folder, 'createApp', 'release']);
  assert.deepEqual([options.dataDir, options.port, options.localAuthority.mode, options.localAuthority.ownerPrincipal, Object.keys(options.certification)], [folder, CERTIFICATION_PORT, 'new', CERTIFICATION_OWNER, ['guard']]);
  assert.equal(typeof options.certification.guard.wrap, 'function');
  assert.deepEqual(fetched, []);
});

// ---- 11. wiring on createApp() with the shipped Calendar rows -------------------------------------------------------------------------
const CALENDAR_OWNER = 'cal-owner@fabric-owner.test', SUB = 'google-sub-cert-7731', RUN_A = 'run-a-7c1@group.calendar.google.com';
const ACCESS = ['ya29.cert-access-first', 'ya29.cert-access-renewed'], REFRESH = '1//cert-refresh-token';
const calendarActions = () => ({schemaVersion: 1, appId: 'google-calendar', specVersion: 'fabric/0.2', reviewStatus: 'candidate', pinnedParameters: {}, actions: [
  {id: `google-calendar.action.list-calendars.v1.${'0'.repeat(24)}`, key: 'list-calendars', version: 1, name: 'List my calendars', description: 'Lists the calendars on your list.', effect: 'read',
    row: 'google-calendar.calendars.read', hints: {readOnly: true, destructive: false, idempotent: true, openWorld: true},
    inputSchema: {type: 'object', properties: {}, required: [], additionalProperties: false}, outputSchema: {type: 'object', properties: {first: {type: 'string', maxLength: 200}}, required: ['first'], additionalProperties: false},
    guards: [], prepare: [], perform: [{id: 'list', method: 'GET', path: '/users/me/calendarList', expect: {status: [200], require: []}}], output: {first: {step: 'list', pointer: '/items/0/summary'}}, preview: [], definitive: [404]},
  {id: `google-calendar.action.create-calendar.v1.${'0'.repeat(24)}`, key: 'create-calendar', version: 1, name: 'Create a calendar', description: 'Creates a calendar in a time zone.', effect: 'write',
    row: 'google-calendar.calendars.write', hints: {readOnly: false, destructive: false, idempotent: false, openWorld: true},
    inputSchema: {type: 'object', properties: {summary: {type: 'string', minLength: 1, maxLength: 200}, timeZone: {type: 'string', minLength: 1, maxLength: 64}}, required: ['summary', 'timeZone'], additionalProperties: false},
    outputSchema: {type: 'object', properties: {id: {type: 'string', maxLength: 300}}, required: ['id'], additionalProperties: false},
    guards: [], prepare: [], perform: [{id: 'create', method: 'POST', path: '/calendars', body: {object: {summary: {input: '/summary'}, timeZone: {input: '/timeZone'}}}, expect: {status: [200], require: []}}],
    verify: {requests: [{id: 'check', method: 'GET', path: '/calendars/{calendarId}', params: {calendarId: {step: 'create', pointer: '/id'}}, expect: {status: [200], require: []}}],
      identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {step: 'create', pointer: '/id'}}], assert: []},
    output: {id: {step: 'create', pointer: '/id'}}, preview: [{label: 'Name', expr: {input: '/summary'}}], definitive: [400, 404]}]});
const calendarPlan = () => ({schemaVersion: 1, appId: 'google-calendar', note: 'Test 11: a C1-like create and a C13-like delete on the shipped Calendar rows.', recorded: {},
  readRows: ['google-calendar.calendars.read', 'google-calendar.settings.read'], timeZone: {path: '/users/me/settings/timezone', pointer: '/value'}, tests: [
    {id: 'C0', name: 'Read pass', steps: [{call: {action: 'list-calendars@1', args: {}, checks: [{pointer: '/first', present: true}]}}]},
    {id: 'C1', name: 'Create calendar A', steps: [{owner: {words: 'Press Enter to create calendar A.'}},
      {call: {action: 'create-calendar@1', args: {summary: {$text: 'A'}, timeZone: {$owner: 'timeZone'}}, save: {calendarA: '/id'}}},
      {read: {path: '/calendars/{cal}', params: {cal: {$saved: 'calendarA'}}, checks: [{status: 200}, {pointer: '/id', equals: {$saved: 'calendarA'}}]}}], undo: {test: 'C13'}},
    {id: 'C13', name: 'Delete calendar A through the one-time Ask', steps: [
      {oneTimeAsk: {row: 'google-calendar.permanent.delete', requests: [{method: 'DELETE', path: '/calendars/{cal}', params: {cal: {$saved: 'calendarA'}}}]}},
      {read: {path: '/calendars/{cal}', params: {cal: {$saved: 'calendarA'}}, checks: [{status: 404}]}}], undo: {none: 'It is the undo of C1.'}}]});
/** Google as a script: the token and identity endpoints, and the Calendar calls the plan makes. Each call is recorded by URL. */
function scriptedGoogle() {
  const calls = [], calendars = new Map();
  const answer = (options, status, data) => ({status, headers: {'content-type': 'application/json; charset=utf-8'}, data: options.responseType === 'buffer' ? Buffer.from(data === null ? '' : JSON.stringify(data)) : data});
  const scopes = () => [...new Set(['openid', 'email', ...definitionFor('google').apps.find(app => app.appId === 'google-calendar').access.levels.full.required,
    ...definitionFor('google').apps.find(app => app.appId === 'google-calendar').access.levels.full.optional])];
  return {calls, scopes, async request(options) {
    const url = new URL(options.url), method = options.method ?? 'GET';
    calls.push(`${method} ${url.origin}${url.pathname}`);
    if (url.href === 'https://oauth2.googleapis.com/token') return answer(options, 200, {access_token: ACCESS[1], expires_in: 3600, scope: scopes().join(' '), token_type: 'Bearer'});
    if (url.href === 'https://openidconnect.googleapis.com/v1/userinfo') return answer(options, 200, {sub: SUB, email: CALENDAR_OWNER, email_verified: true});
    const route = url.pathname.replace('/calendar/v3', '');
    if (method === 'GET' && route === '/users/me/settings/timezone') return answer(options, 200, {kind: 'calendar#setting', id: 'timezone', value: 'America/Toronto'});
    if (method === 'GET' && route === '/users/me/calendarList') return answer(options, 200, {items: [{id: CALENDAR_OWNER, summary: 'Mine'}]});
    if (method === 'POST' && route === '/calendars') { const body = JSON.parse(options.body); calendars.set(RUN_A, {id: RUN_A, ...body}); return answer(options, 200, calendars.get(RUN_A)); }
    const match = /^\/calendars\/([^/]+)$/.exec(route), id = match && decodeURIComponent(match[1]);
    if (match && method === 'GET') return calendars.has(id) ? answer(options, 200, calendars.get(id)) : answer(options, 404, {error: {code: 404}});
    if (match && method === 'DELETE') { calendars.delete(id); return answer(options, 204, null); }
    return answer(options, 404, {error: {code: 404, message: 'not scripted'}});
  }};
}
test('harness 11: on createApp() with the shipped Calendar rows: a C1-like create with its readback and a C13-like delete through the one-time Ask; a token refresh inside C1 never enters its trace or the evidence', async t => {
  const root = temp(t, 'fabric-live-calendar-'), folder = path.join(temp(t), 'harness');
  const directory = path.join(root, 'catalog', 'actions'), map = googleMap('google-calendar');
  mkdirSync(directory, {recursive: true});
  const deps = {groups: PERMISSION_GROUPS, configs: PROXY_CONFIGS, identities: new Map([['google-calendar', definitionFor('google')]]), maps: new Map([['google-calendar', map]])};
  writeFileSync(path.join(directory, 'google-calendar.json'), JSON.stringify(withIds(calendarActions(), deps)));
  let now = Date.parse('2026-10-24T13:00:00.000Z');
  const key = randomBytes(32), runId = newRunId(), google = scriptedGoogle(), reached = [];
  const guard = createGuard({appId: 'google-calendar', runId, folder, key, clock: () => now});
  const app = await createApp({dataDir: folder, port: CERTIFICATION_PORT, localAuthority: {mode: 'new', ownerPrincipal: CERTIFICATION_OWNER}, certification: {guard},
    request: async options => { reached.push(options.url); return google.request(options); }, clock: () => now, actions: {directory, evidenceRoot: root, codeHashes: ids => Object.fromEntries(ids.map(id => [id, SHIPPED_PINS.transforms[id]]))}});
  t.after(() => app.close());
  // The account, its tokens (expiring in 30 minutes) and the discovered map, as Muse's sign-in and the app page's Discover leave them.
  const scopes = google.scopes(), at = new Date(now).toISOString();
  app.store.put('connections', {id: 'cal-account', appId: 'google-calendar', providerId: 'google', driver: 'http', authMethod: 'oauth', authRevision: 'r1', status: 'ready', label: 'Calendar',
    identity: {id: SUB, displayName: CALENDAR_OWNER, email: CALENDAR_OWNER}, scopes, grantCeiling: scopes, allowedOrigins: ['https://www.googleapis.com'], createdAt: at, signedInAt: at, expiresAt: now + 30 * 60_000, refreshAvailable: true});
  app.vault.set('cal-account', {accessToken: ACCESS[0], refreshToken: REFRESH, expiresAt: now + 30 * 60_000, scopes});
  app.oauth.clientId = 'cert-client'; app.oauth.clientSecret = 'cert-secret';
  app.store.put('applicationMaps', {id: 'google-calendar', ...structuredClone(map)});
  app.actions.reload('google-calendar', map);
  app.actions.seed(app.store, {appId: 'google-calendar'});
  const entries = [...app.actions.entries.values()].filter(item => item.appId === 'google-calendar').map(item => item.entry);
  assert.deepEqual(entries.map(entry => [entry.key, entry.unplaced === true]).sort(), [['create-calendar', false], ['list-calendars', false]]);
  // The owner's facts: the address from the account, the zone from the plan's read inside a setup test, the run date in that zone.
  const port = harnessPort(app);
  const lines = [], ownerApprove = app.runtime.approve.bind(app.runtime);
  app.runtime.approve = () => { throw new Error('Only the owner approves.'); };
  const plan = calendarPlan();
  const facts = await readOwner(port, checkPlanShape(plan), {guard, clock: () => now});
  assert.deepEqual(facts, {email: CALENDAR_OWNER, timeZone: 'America/Toronto', runDate: '2026-10-24'});
  guard.setOwner({...facts, recorded: {}});
  assert.deepEqual(guard.trace('setup').map(item => `${item.method} ${item.path}`), ['GET /calendar/v3/users/me/settings/timezone']);
  const checked = checkPlan(plan, {entries, groups: PERMISSION_GROUPS.get('google-calendar'), config: PROXY_CONFIGS.get('google-calendar'), rules: RULES});
  const state = openRunState(folder, 'google-calendar', runId, {...facts, recorded: {}});
  // The owner on the app page, through Fabric's own route and session, as a person clicks.
  const web = await listen(t, app);
  const setOnPage = async (label, mode) => {
    const view = (await web.owned('GET', '/api/ui/apps/google-calendar')).json, row = view.sections.flatMap(section => section.rows).find(item => item.label === label);
    const answer = await web.owned('POST', `/api/ui/apps/google-calendar/accounts/${encodeURIComponent(view.selectedAccountRef)}/permissions`, {groupId: row.groupId, mode, etag: row.etag});
    assert.equal(answer.status, 200, answer.text);
  };
  let chain = Promise.resolve(), task = null, refreshAt = null;
  const say = line => {
    lines.push(line);
    const link = /^Approve: http:\/\/127\.0\.0\.1:4320\/approve\/([0-9a-f-]{36})$/.exec(line);
    if (link) chain = chain.then(() => ownerApprove(link[1], app.store.get('jobs', link[1]).approvalDigest, CERTIFICATION_OWNER));
    if (/^Set "Permanently delete calendars or clear all events" to Ask/.test(line)) task = ['Permanently delete calendars or clear all events', 'ask'];
    if (/^Reset "Permanently delete calendars or clear all events" to Never/.test(line)) task = ['Permanently delete calendars or clear all events', 'deny'];
  };
  const prompt = async words => { lines.push(words); if (/create calendar A/.test(words)) { now = app.vault.get('cal-account').expiresAt - 30_000; refreshAt = google.calls.length; } return ''; };
  const wait = async () => { now += 1000; if (task) { const [label, mode] = task; task = null; await setOnPage(label, mode); } await new Promise(resolve => setImmediate(resolve)); };
  const run = await runLiveTests(port, checked, {guard, state, prompt, say, clock: () => now, wait});
  await chain;
  for (const id of ['C0', 'C1', 'C13']) assert.equal(run.results[id].passed, true, `${id}: ${run.results[id].words} ${JSON.stringify(run.results[id].checks)}`);
  // The refresh happened inside C1: Google's token and identity endpoints were reached, through the guard, and neither is in C1's trace.
  const refreshCalls = google.calls.slice(refreshAt);
  assert.ok(refreshCalls.includes('POST https://oauth2.googleapis.com/token') && refreshCalls.includes('GET https://openidconnect.googleapis.com/v1/userinfo'), refreshCalls.join('\n'));
  assert.deepEqual(guard.trace('C1').map(item => `${item.method} ${decodeURIComponent(item.path)}`), ['POST /calendar/v3/calendars', `GET /calendar/v3/calendars/${RUN_A}`, `GET /calendar/v3/calendars/${RUN_A}`]);
  assert.deepEqual(guard.trace('C13').map(item => `${item.method} ${item.status}`), ['DELETE 204', 'GET 404']);
  assert.equal(app.vault.get('cal-account').accessToken, ACCESS[1], 'the account renewed');
  assert.ok(!reached.some(url => url.includes('/revoke')), 'no revocation');
  assert.equal(run.rows[0].row, 'google-calendar.permanent.delete');
  assert.ok(run.rows[0].askSeenAt && run.rows[0].neverSeenAt);
  // The evidence: both actions pass, C13 sits under the run key with its row change, and nothing from sign-in is in it.
  const evidence = evidenceRecords(run, {key, entries, trace: id => guard.trace(id), job: id => port.job(id), maps: new Map([['google-calendar', map]])});
  const text = writeEvidence(root, 'google-calendar', evidence, {emails: [CALENDAR_OWNER], tokens: [...ACCESS, REFRESH]});
  const written = JSON.parse(text);
  for (const entry of entries) assert.equal(evidencePasses(entry, written[entry.id], SHIPPED_PINS.transforms), true, entry.key);
  assert.deepEqual(written.run.tests.map(item => [item.test, item.passed]), [['C13', true]]);
  assert.deepEqual(written.run.tests[0].requests.map(item => `${item.method} ${item.template} ${item.status}`), ['DELETE /calendars/{cal} 204', 'GET /calendars/{cal} 404']);
  assert.deepEqual(written.run.rows.map(item => [item.row, item.label]), [['google-calendar.permanent.delete', 'Permanently delete calendars or clear all events']]);
  const create = written[entries.find(entry => entry.key === 'create-calendar').id];
  assert.match(create.tests[0].requests[0].identity, /^hmac:[0-9a-f]{32}$/);
  for (const banned of [SUB, CALENDAR_OWNER, RUN_A, 'oauth2.googleapis.com', 'userinfo', 'openidconnect', ...ACCESS, REFRESH]) assert.ok(!text.includes(banned), banned);
});
/** Listens on a free port (never 4188 or 4320) and calls the app as the owner's browser does, with the Host header of 127.0.0.1:4320. */
async function listen(t, app) {
  await new Promise((resolve, reject) => { app.server.once('error', reject); app.server.listen(0, '127.0.0.1', resolve); });
  const port = app.server.address().port;
  assert.ok(![4188, CERTIFICATION_PORT].includes(port));
  const send = (method, route, {data, cookie, csrf} = {}) => new Promise((resolve, reject) => {
    const body = data === undefined ? null : JSON.stringify(data);
    const request = http.request({host: '127.0.0.1', port, method, path: route, headers: {host: `127.0.0.1:${CERTIFICATION_PORT}`, ...(body ? {'content-type': 'application/json', 'content-length': Buffer.byteLength(body)} : {}),
      ...(cookie ? {cookie} : {}), ...(csrf ? {'x-fabric-csrf': csrf} : {})}}, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); let json = null; try { json = JSON.parse(text); } catch {} resolve({status: response.statusCode, headers: response.headers, text, json}); });
    });
    request.on('error', reject);
    if (body) request.write(body);
    request.end();
  });
  const state = await send('GET', '/api/state');
  const session = {cookie: String(state.headers['set-cookie']).split(';')[0], csrf: state.json.csrfToken};
  return {send, owned: (method, route, data) => send(method, route, {data, ...session})};
}

// ---- 12. a stop with pending undos --------------------------------------------------------------------------------------------------
test('harness 12: a stop between a test and its later undo lists the pending undos, runs each after its approval on Muse\'s yes and only then returns; on a no it prints the items left', async t => {
  const r = fakeRun(t, {owner: {answers: ['yes']}});
  r.h.simulator.fail('POST /drafts/{draft_id}/send', {status: 400, data: {error: 'invalid'}});
  const run = await r.run();
  await r.muse.done();
  assert.deepEqual([run.stopped.test, run.results.T4.passed, Object.hasOwn(run.results, 'T5')], ['T4', false, false]);
  assert.deepEqual(run.results.T4.checks, [{name: 'step 1: send-draft@1 succeeded', passed: false}]);
  assert.match(run.results.T4.words, /^send-draft@1 ended failed \(provider_failed\), not as the plan expects\.$/);
  const text = r.muse.lines.join('\n');
  assert.match(text, /^Pending undo: T6 \(it undoes T3\)$/m);
  assert.match(text, /^Run the pending undos now\? Type yes or no\.$/m);
  assert.equal(run.results.T6.passed, true, run.results.T6.words);
  assert.equal(r.h.simulator.state().events.E1.start, RECORDED.eventStart, 'the undo ran after its approval');
  assert.ok(run.order.indexOf('T6') > run.order.indexOf('T4'));
  // On a no: nothing more runs, and the items left are printed.
  const no = fakeRun(t, {owner: {answers: ['no']}});
  no.h.simulator.fail('POST /drafts/{draft_id}/send', {status: 400, data: {error: 'invalid'}});
  const left = await no.run();
  assert.equal(Object.hasOwn(left.results, 'T6'), false);
  assert.match(no.muse.lines.join('\n'), /^Left in place: T6 \(it undoes T3\) was not run\.$/m);
  assert.deepEqual(left.left, ['T6 (it undoes T3) was not run.']);
  assert.notEqual(no.h.simulator.state().events.E1.start, RECORDED.eventStart);
});

// ---- 13. two stops of one action ----------------------------------------------------------------------------------------------------
test('harness 13: an action whose reads ask stops twice: the runner prints the same link again for the final stop, once for each stop', async t => {
  const r = fakeRun(t, {plan: only(fixturePlan(), ['T1']), keys: ['update-item@1', 'remove-labels@1']});
  r.muse.setRow('Access items', 'ask');
  const run = await r.run();
  await r.muse.done();
  assert.equal(run.results.T1.passed, true, run.results.T1.words);
  const update = run.results.T1.calls[0].jobs[0], job = r.port.job(update);
  assert.deepEqual(job.action.decisions.map(decision => [decision.phase, decision.decision]), [['reads', 'approved'], ['final', 'approved']]);
  assert.deepEqual(r.muse.links.filter(id => id === update).length, 2, 'the same link for both stops');
  const first = r.muse.lines.findIndex(line => line.endsWith(update)), second = r.muse.lines.findLastIndex(line => line.endsWith(update));
  assert.ok(first >= 0 && second > first);
  assert.equal(new Set(r.muse.links.filter(id => id !== update)).size, r.muse.links.filter(id => id !== update).length, 'every other link once');
});

// ---- 14. checks that do not hold ------------------------------------------------------------------------------------------------------
test('harness 14: a check that does not hold fails its test: gone on an item that is still there, and a card nobody approves lapses after its window', async t => {
  const plan = {...fixturePlan(), recorded: {}, tests: [{id: 'T7', name: 'An item that is still there', steps: [{read: {path: '/items/{item}', params: {item: 'I2'}, checks: [{gone: true}]}}]}]};
  const r = fakeRun(t, {plan, keys: [], recorded: {}});
  const run = await r.run();
  assert.deepEqual([run.results.T7.passed, run.results.T7.checks], [false, [{name: 'step 1: gone', passed: false}]]);
  // In the trash, with the plan's gone, it reads as gone.
  r.h.simulator.data.items.find(item => item.id === 'I2').in_trash = true;
  const again = fakeRun(t, {plan, keys: [], recorded: {}, h: r.h});
  assert.equal((await again.run()).results.T7.passed, true);
  // Nobody approves: the card lapses after its 10-minute window and the test fails with nothing sent.
  const idle = fakeRun(t, {plan: only(fixturePlan(), ['T1']), keys: ['update-item@1', 'remove-labels@1'], owner: {approve: false}});
  const lapsed = await idle.run();
  assert.match(lapsed.results.T1.words, /^The card lapsed before it was approved, so the test fails\.$/);
  assert.ok(idle.muse.waits >= 600 && idle.muse.waits < 620, String(idle.muse.waits));
  assert.deepEqual([idle.muse.links.length, writes(idle.h)], [1, []]);
});

// ---- 15. step 13's placeholders (docs/F10.13-BUILD-MAP.md question 13) ---------------------------------------------------------------
test('harness 15 (F10.13): $local gives a wall time on a day of the window in the owner\'s zone; $text with {words, day} puts that day\'s date where {date} stands; both are checked like $at', t => {
  const h = actionHarness(t, {designated: true, evidence: () => ({})}), entries = fixtureEntries(h);
  const deps = {entries, superseded: [], groups: h.groups.get('fixture'), config: h.configs.get('fixture'), rules: FIXTURE_RULES};
  const plan = fixturePlan();
  plan.tests.find(item => item.id === 'T3').steps[0].call.args.start = {$local: {day: 9, time: '10:00'}};
  plan.tests.find(item => item.id === 'T5').steps[0].call.args.values.Name = {$text: {words: 'row on {date}', day: 10}};
  assert.equal(checkPlan(plan, deps).appId, 'fixture');
  const refused = (value, words, note) => {
    const changed = fixturePlan();
    changed.tests.find(item => item.id === 'T3').steps[0].call.args.start = value;
    assert.throws(() => checkPlanShape(changed), words, note);
  };
  refused({$local: {day: 6, time: '10:00'}}, /\$local: day is 7 to 13/, 'day 6');
  refused({$local: {day: 14, time: '10:00'}}, /\$local: day is 7 to 13/, 'day 14');
  refused({$local: {day: 9, time: '24:00'}}, /\$local: time is HH:MM/, 'an hour 24');
  refused({$local: {day: 9}}, /\$local is \{day, time\}/, 'no time');
  refused({$text: {words: 'no date here', day: 9}}, /\$text: words hold \{date\} once/, 'no {date}');
  refused({$text: {words: '{date} and {date}', day: 9}}, /\$text: words hold \{date\} once/, 'two {date}');
  refused({$text: {words: 'on {date}', day: 15}}, /\$text: day is 7 to 13/, 'day 15');
  refused({$text: {words: 'on {date}', day: 9, extra: 1}}, /\$text is words, or \{words, day\}/, 'an extra field');
  // At run time: the wall time and the date in the owner's zone on that day, the synthetic marker first; a skipped wall time refuses.
  const run = {runId: 'ABCDEFGH', runDate: '2026-10-23', timeZone: ZONE, saved: {}, recorded: {}}, test = {id: 'C5'};
  assert.equal(fillPlaceholders({$local: {day: 9, time: '10:00'}}, {run, account: {}}, test), '2026-11-01T10:00:00');
  assert.equal(fillPlaceholders({$at: {day: 9, time: '10:00'}}, {run, account: {}}, test), '2026-11-01T10:00:00-05:00');
  assert.equal(fillPlaceholders({$text: {words: 'quick add on {date} at 3pm to 3:30pm', day: 10}}, {run, account: {}}, test),
    '[SYNTHETIC] Fabric C5 ABCDEFGH quick add on 2026-11-02 at 3pm to 3:30pm');
  assert.throws(() => fillPlaceholders({$local: {day: 7, time: '02:30'}}, {run: {...run, runDate: '2026-03-01'}, account: {}}, test), /does not exist in America\/Toronto/);
  assert.ok(PLACEHOLDERS.includes('$local'));
});

// ---- 16. F10.19 part 2: Notion's token introspection, once before N0 -------------------------------------------------------------------
test('harness 16 (F10.19): introspection runs once before N0, only for an app whose provider has one; its evidence keeps seven fields and never a token', async t => {
  const root = temp(t), asked = [], said = [], at = '2026-10-26T12:00:00.000Z';
  let answer = {active: true, scope: 'read_content insert_content', iat: 1761480000, request_id: 'req-1'};
  const port = {introspect: async appId => { asked.push(appId); return answer; }};
  const file = path.join(root, 'docs', 'live-evidence', 'notion', 'introspection.json'), read = () => JSON.parse(readFileSync(file, 'utf8'));
  const record = await introspectOnce(port, {appId: 'notion'}, {runId: 'ABCDEFGH', at, root, emails: ['avery@example.com'], say: line => said.push(line)});
  assert.deepEqual([asked, record], [['notion'], {schemaVersion: 1, appId: 'notion', runId: 'ABCDEFGH', at, active: true, scope: 'read_content insert_content', listsCapabilities: true}]);
  assert.deepEqual(read(), record);
  assert.equal(readFileSync(file, 'utf8'), `${JSON.stringify(read(), Object.keys(read()).sort(), 1)}\n`, 'sorted keys, one-space indent, a final newline');
  assert.deepEqual(said, ['notion token introspection: active; its scope lists the integration\'s capabilities.']);
  // A scope that is absent, or names none of the attested capabilities, does not list them.
  for (const scope of [undefined, null, 'read', 'pages:read']) {
    answer = {active: false, ...(scope === undefined ? {} : {scope})};
    assert.equal((await introspectOnce(port, {appId: 'notion'}, {runId: 'ABCDEFGH', at, root})).listsCapabilities, false, String(scope));
    assert.equal(read().scope, typeof scope === 'string' ? scope : null);
  }
  // Calendar's provider has no introspection: nothing is asked and nothing written.
  asked.length = 0;
  assert.equal(await introspectOnce(port, {appId: 'google-calendar'}, {runId: 'ABCDEFGH', at, root}), null);
  assert.equal(asked.length, 0);
  assert.equal(existsSync(path.join(root, 'docs', 'live-evidence', 'google-calendar')), false);
  // The writer keeps its seven fields whatever it is handed, and refuses a token or an address.
  writeIntrospection(root, 'notion', {schemaVersion: 1, appId: 'notion', runId: 'ABCDEFGH', at, active: true, scope: 'x', listsCapabilities: false, iat: 1, request_id: 'r', token: 'abc'});
  assert.deepEqual(Object.keys(read()).sort(), ['active', 'appId', 'at', 'listsCapabilities', 'runId', 'schemaVersion', 'scope']);
  assert.throws(() => writeIntrospection(root, 'notion', {runId: 'ABCDEFGH', at, active: true, scope: 'ntn_leaked-token', listsCapabilities: false}), /token/);
  assert.throws(() => writeIntrospection(root, 'notion', {runId: 'ABCDEFGH', at, active: true, scope: 'avery@example.com', listsCapabilities: false}), /address/);
  // The command asks once on a new run, after the owner's facts and before the first test, and never on a resume.
  const source = main.toString(), once = source.indexOf('introspectOnce(');
  assert.ok(once > source.indexOf('guard.setOwner({...facts') && once < source.indexOf('runLiveTests('), 'between the owner\'s facts and the tests');
  assert.equal(source.split('introspectOnce(').length, 2, 'once');
});

test('harness 17 (F10.19): the port\'s introspect() asks the account\'s own sign-in once and hands back only {active, scope}; an app with no introspection gets null', async t => {
  const asked = [];
  const connections = [{id: 'notion-b', appId: 'notion', status: 'ready', createdAt: '2026-10-02T00:00:00.000Z', identity: {}}, {id: 'notion-a', appId: 'notion', status: 'ready', createdAt: '2026-10-01T00:00:00.000Z', identity: {}},
    {id: 'cal-a', appId: 'google-calendar', status: 'ready', createdAt: '2026-10-01T00:00:00.000Z', identity: {}}];
  const app = {store: {list: () => connections, get: () => null}, connections: {providers: {resolve: ({providerId, appId}) => ({introspect: async id => { asked.push([providerId, appId, id]); return {active: true, scope: 's', iat: 9, token: 'never'}; }})}}};
  const port = harnessPort(app);
  assert.deepEqual(await port.introspect('notion'), {active: true, scope: 's'});
  assert.deepEqual(asked, [['notion', 'notion', 'notion-a']], 'the oldest ready account, as account() picks it');
  assert.equal(await port.introspect('google-calendar'), null);
  assert.equal(asked.length, 1);
  connections.length = 0;
  assert.equal(await port.introspect('notion'), null, 'no ready account');
});

// ---- 18. step 21's placeholder (docs/F10.21-BUILD-MAP.md part 2) ----------------------------------------------------------------------
test('harness 18 (F10.21): $in gives the UTC instant 1 to 1,440 whole minutes after the step runs, from the run\'s clock; it is checked like the others', t => {
  const h = actionHarness(t, {designated: true, evidence: () => ({})}), entries = fixtureEntries(h);
  const deps = {entries, superseded: [], groups: h.groups.get('fixture'), config: h.configs.get('fixture'), rules: FIXTURE_RULES};
  const plan = fixturePlan();
  plan.tests.find(item => item.id === 'T3').steps[0].call.args.start = {$in: {minutes: 120}};
  assert.equal(checkPlan(plan, deps).appId, 'fixture');
  const refused = (value, words, note) => {
    const changed = fixturePlan();
    changed.tests.find(item => item.id === 'T3').steps[0].call.args.start = value;
    assert.throws(() => checkPlanShape(changed), words, note);
  };
  for (const [value, note] of [[{$in: {minutes: 0}}, 'none'], [{$in: {minutes: 1441}}, 'a day and a minute'], [{$in: {minutes: 1.5}}, 'a fraction'], [{$in: {minutes: '10'}}, 'text'],
    [{$in: {}}, 'no minutes'], [{$in: {minutes: 10, day: 7}}, 'an extra field'], [{$in: 10}, 'a bare number']]) refused(value, /\$in is \{minutes\}, 1 to 1,440/, note);
  const run = {runId: 'ABCDEFGH', runDate: '2026-10-26', timeZone: ZONE, saved: {}, recorded: {}}, test = {id: 'S1'};
  let now = Date.parse('2026-10-26T15:00:30.250Z');
  assert.equal(fillPlaceholders({$in: {minutes: 120}}, {run, account: {}, clock: () => now}, test), '2026-10-26T17:00:30Z');
  now += 60_000;
  assert.equal(fillPlaceholders({at: {$in: {minutes: 1440}}}, {run, account: {}, clock: () => now}, test).at, '2026-10-27T15:01:30Z', 'read from the clock when the step runs');
  assert.throws(() => fillPlaceholders({$in: {minutes: 10}}, {run, account: {}}, test), /\$in needs the run's clock/);
  assert.ok(PLACEHOLDERS.includes('$in'));
});

// ---- 19 and 20. F10.17's $branch placeholder and ask step (docs/F10.17-BUILD-MAP.md part 2) --------------------------------------------
test('harness 19 (F10.17): $branch gives this run\'s branch, fabric/test-<runId>, or fabric/test-<runId>-<suffix>; a suffix is 1 to 16 lowercase letters or digits', t => {
  const h = actionHarness(t, {designated: true, evidence: () => ({})}), entries = fixtureEntries(h);
  const deps = {entries, superseded: [], groups: h.groups.get('fixture'), config: h.configs.get('fixture'), rules: FIXTURE_RULES};
  const plan = fixturePlan();
  plan.tests.find(item => item.id === 'T2').steps[0].race.args.path = {$branch: 'race2'};
  assert.equal(checkPlan(plan, deps).appId, 'fixture');
  for (const [value, note] of [['Base', 'an uppercase letter'], ['a-b', 'a hyphen'], ['x'.repeat(17), '17 characters'], [1, 'a number'], [null, 'nothing'], [{suffix: 'a'}, 'an object']]) {
    const changed = fixturePlan();
    changed.tests.find(item => item.id === 'T2').steps[0].race.args.path = {$branch: value};
    assert.throws(() => checkPlanShape(changed), /\$branch is "" or 1 to 16 lowercase letters or digits/, note);
  }
  const run = {runId: 'ABCDEFGH', runDate: '2026-10-23', timeZone: ZONE, saved: {}, recorded: {}}, test = {id: 'H7'};
  assert.equal(fillPlaceholders({$branch: ''}, {run, account: {}}, test), 'fabric/test-ABCDEFGH');
  assert.equal(fillPlaceholders({$branch: 'head'}, {run, account: {}}, test), 'fabric/test-ABCDEFGH-head');
  assert.deepEqual(fillPlaceholders({name: {$branch: 'base'}, from: 'main'}, {run, account: {}}, {id: 'H9'}), {name: 'fabric/test-ABCDEFGH-base', from: 'main'});
  assert.ok(PLACEHOLDERS.includes('$branch'));
});

const askStepPlan = (row = 'fixture.items.delete') => ({...fixturePlan(), recorded: {}, tests: [{id: 'T9', name: 'Remove a label on a row that already asks', steps: [
  {ask: {row, requests: [{method: 'DELETE', path: '/items/{item}/labels/{name}', params: {item: 'I4', name: 'Later'}}]}}], undo: {none: 'The fake app starts fresh each run.'}}]});
test('harness 20 (F10.17): an ask step sends each request on a grant of its one row after its approval, with no Set or Reset and no row change; the plan refuses a Never or locked row; Never refuses it at run time and Allow stops the run, nothing sent', async t => {
  const r = fakeRun(t, {plan: askStepPlan(), keys: [], recorded: {}});
  const run = await r.run();
  await r.muse.done();
  assert.equal(run.results.T9.passed, true, run.results.T9.words);
  assert.deepEqual(writes(r.h), ['DELETE /items/I4/labels/Later']);
  const text = r.muse.lines.join('\n');
  assert.match(text, /^Approve: /m);
  assert.doesNotMatch(text, /^(Set|Reset) "/m, 'an ask step asks the owner to change no row');
  assert.deepEqual([run.rows, r.muse.sets, r.muse.byRunner, r.port.rowMode(r.h.account, 'fixture.items.delete')], [[], [], 0, 'ask'], 'no row changed or recorded');
  assert.ok(grants(r.h).some(grant => grant.proxy?.[0]?.rows.map(item => item.row).join() === 'group:fixture.items.delete'), 'a grant with that one row');
  assert.ok(grants(r.h).every(grant => grant.status === 'revoked'));
  assert.deepEqual(run.results.T9.checks.map(check => [check.name, check.passed]), [['step 1: DELETE /items/{item}/labels/{name} answered', true]]);
  // The plan check: a row that defaults to Never takes a oneTimeAsk, and a locked row takes nothing; an ask step writes, so its test needs an undo.
  const deps = {entries: fixtureEntries(r.h, []), superseded: [], groups: r.h.groups.get('fixture'), config: r.h.configs.get('fixture'), rules: FIXTURE_RULES};
  assert.throws(() => checkPlan(askStepPlan('fixture.access.grant'), deps), /fixture\.access\.grant is locked by Fabric, so no ask step can use it/);
  const never = structuredClone(r.h.groups.get('fixture'));
  never.groups.find(group => group.id === 'fixture.items.delete').defaultMode = 'deny';
  assert.throws(() => checkPlan(askStepPlan(), {...deps, groups: never}), /fixture\.items\.delete is Never by default: an ask step opens no row, so it takes a oneTimeAsk/);
  const noUndo = askStepPlan();
  delete noUndo.tests[0].undo;
  assert.throws(() => checkPlan(noUndo, deps), /T9 writes, so it needs an undo/);
  // An ask step may undo a test, as H9's branches are deleted.
  const undo = {...fixturePlan(), recorded: {}, tests: [{id: 'T9', name: 'Read, then undo with an ask step', steps: [{read: {path: '/items/{item}', params: {item: 'I4'}, checks: [{status: 200}]}}],
    undo: {steps: askStepPlan().tests[0].steps}}]};
  assert.equal(checkPlan(undo, deps).appId, 'fixture');
  // At run time: the owner set "Delete items" to Never, so the step is refused; set "Manage labels" to Allow (a delete row never offers the
  // proxy Allow), and the run stops. Nothing is sent either way, and the runner changes no row.
  for (const [row, label, mode, words] of [['fixture.items.delete', 'Delete items', 'deny', /"Delete items" is Never, so this step was refused and nothing was sent\./],
    ['fixture.labels.write', 'Manage labels', 'allow', /"Manage labels" is Allow, not Ask, so the run stopped and nothing was sent\./]]) {
    const plan = askStepPlan(row);
    if (row === 'fixture.labels.write') plan.tests[0].steps[0].ask.requests = [{method: 'POST', path: '/labels'}];
    const other = fakeRun(t, {plan, keys: [], recorded: {}});
    other.muse.setRow(label, mode);
    const stopped = await other.run();
    assert.deepEqual([stopped.results.T9.passed, stopped.stopped.test, writes(other.h), stopped.rows], [false, 'T9', [], []], mode);
    assert.match(stopped.results.T9.words, words);
    assert.equal(other.port.rowMode(other.h.account, row), mode, 'the runner changed no row');
  }
});

// ---- 21. the owner's address where the sign-in reads none (docs/F10.17-BUILD-MAP.md section 9, docs/F10.21-BUILD-MAP.md question 16) ----
test('harness 21 (F10.17, F10.21): an app whose sign-in reads no address (GitHub, Slack) asks the owner to type one at a new run\'s start and a resume reuses the saved one; an app whose sign-in reads one never asks; anything but one address refuses', async t => {
  const clock = () => Date.parse('2026-10-29T12:00:00.000Z'), portOf = email => ({account: () => ({connectionId: 'acct', email})});
  for (const appId of ['github', 'slack']) {
    const asked = [], prompt = async words => { asked.push(words); return '  Avery@Example.COM '; };
    assert.equal((await readOwner(portOf(null), {appId}, {clock, prompt})).email, 'avery@example.com', appId);
    assert.equal(asked.length, 1, appId);
    assert.ok(asked[0].startsWith(`${definitionFor(appId).displayName} gives Fabric no email address.`), asked[0]);
    // The account's own address comes first, and nothing is asked.
    assert.equal((await readOwner(portOf('own@example.com'), {appId}, {clock, prompt})).email, 'own@example.com');
    assert.equal(asked.length, 1, `${appId}: asked once in all`);
    for (const typed of ['', null, 'avery', 'a@b c@d', `${'a'.repeat(320)}@b.co`]) {
      await assert.rejects(readOwner(portOf(null), {appId}, {clock, prompt: async () => typed}), /not one email address/, `${appId}: ${typed}`);
    }
  }
  // Gmail, Calendar and Notion read an address at sign-in: an account without one refuses before anything is asked.
  for (const appId of ['gmail', 'google-calendar', 'notion']) {
    let asked = 0;
    await assert.rejects(readOwner(portOf(null), {appId}, {clock, prompt: async () => { asked++; return 'avery@example.com'; }}), /has no email address Fabric can read/, appId);
    assert.equal(asked, 0, appId);
  }
  // A resume never asks: the run's guard saved the typed address, and a new guard on the same run reads it back.
  const folder = temp(t), runId = newRunId(), data = {timeZone: 'UTC', runDate: '2026-10-29', recorded: {}};
  const first = createGuard({appId: 'github', runId, folder, key: randomBytes(32), clock});
  assert.equal(first.owner(), null);
  first.setOwner({email: 'avery@example.com', ...data});
  const again = createGuard({appId: 'github', runId, folder, key: randomBytes(32), clock});
  assert.deepEqual(resumedOwner(portOf(null), {appId: 'github'}, again, data), {email: 'avery@example.com', ...data});
  again.setOwner(resumedOwner(portOf(null), {appId: 'github'}, again, data));
  assert.equal(resumedOwner(portOf('own@example.com'), {appId: 'github'}, again, data).email, 'own@example.com', 'the account\'s address first');
  assert.throws(() => resumedOwner(portOf(null), {appId: 'github'}, createGuard({appId: 'github', runId: newRunId(), folder, key: randomBytes(32), clock}), data), /saved none/);
  const copy = again.owner();
  copy.email = 'other@example.com'; copy.recorded.extra = 'x';
  assert.deepEqual(again.owner(), {email: 'avery@example.com', ...data}, 'owner() hands back a copy');
  // The command asks through its prompt on a new run, resumes through resumedOwner(), and keeps the run's owner out of the evidence.
  const source = main.toString();
  assert.ok(source.includes('readOwner(port, plan, {guard, clock, prompt})') && source.includes('guard.setOwner(resumedOwner(port, plan, guard, state.data))'));
  assert.match(source, /writeEvidence\([^\n]*guard\.owner\(\)\?\.email/);
});

// ---- 22. the order of the pending undos (live run TOQJPGEU) ------------------------------------------------------------------------------
test('harness 22: the pending undos are offered newest test first, so a moved event is put back and cancelled before its calendar is deleted', () => {
  const write = {effect: 'write', status: 'uncertain'}, nothing = {proxies: [], calls: []};
  const results = {C1: {...nothing, undo: {kind: 'test', test: 'C13'}}, C2: {...nothing, undo: {kind: 'test', test: 'C12'}}, C3: {...nothing, undo: {kind: 'test', test: 'C12'}},
    C8: {proxies: [], calls: [{jobs: ['j8']}], undo: {kind: 'steps', ran: false}}};
  const ctx = {run: {order: ['C1', 'C2', 'C3', 'C8'], results}, port: {job: id => id === 'j8' ? write : null}};
  assert.deepEqual(pendingUndos(ctx).map(item => item.words), ['the undo of C8', 'C12 (it undoes C2)', 'C13 (it undoes C1)']);
  // An undo test that already ran, and undo steps that ran or changed nothing, are not offered.
  results.C12 = {...nothing, undo: {kind: 'none'}};
  results.C8.undo.ran = true;
  assert.deepEqual(pendingUndos(ctx).map(item => item.words), ['C13 (it undoes C1)']);
});

// ---- 23. a read that checks something is gone (live run MBIDCUUG, C13) -----------------------------------------------------------------
test('harness 23: a read that checks something is gone asks again a poll apart, up to five reads in all (Google answers a calendar it just deleted for a moment); a check of anything else reads once', async t => {
  const goneRead = (checks = [{gone: true}]) => { const plan = only(fixturePlan(), ['T0']); plan.tests[0].steps.push({read: {path: '/items/{item}', params: {item: 'GONE'}, checks}}); return plan; };
  const reads = r => r.h.simulator.calls.filter(call => call.method === 'GET' && call.path === '/items/GONE').length;
  // The reads seen at each of the runner's waits: a wait between every two reads puts both 1 and 2 among them.
  const readsAtWaits = [];
  const late = fakeRun(t, {plan: goneRead(), keys: ['list-items@1'], owner: {onWait: () => { readsAtWaits.push(reads(late)); }}});
  late.h.simulator.fail('GET /items/{item_id}', {status: 200, data: {id: 'GONE', in_trash: false}}, {times: 2});
  const settled = await late.run();
  await late.muse.done();
  assert.equal(settled.results.T0.passed, true, JSON.stringify(settled.results.T0.checks));
  assert.equal(reads(late), 3, 'two answers that it is still there, then the 404');
  assert.ok([1, 2].every(count => readsAtWaits.includes(count)), `a poll apart: ${readsAtWaits}`);
  // A 404 or 410 status check, alone or as a list of only those, asks again the same way.
  for (const checks of [[{status: 404}], [{status: [404, 410]}]]) {
    const status = fakeRun(t, {plan: goneRead(checks), keys: ['list-items@1']});
    status.h.simulator.fail('GET /items/{item_id}', {status: 200, data: {id: 'GONE', in_trash: false}}, {times: 2});
    const answered = await status.run();
    await status.muse.done();
    assert.deepEqual([answered.results.T0.passed, reads(status)], [true, 3], JSON.stringify(checks));
  }
  const never = fakeRun(t, {plan: goneRead(), keys: ['list-items@1']});
  never.h.simulator.fail('GET /items/{item_id}', {status: 200, data: {id: 'GONE', in_trash: false}}, {times: 10});
  const stuck = await never.run();
  await never.muse.done();
  assert.equal(stuck.results.T0.passed, false);
  assert.equal(reads(never), 5, 'five reads, then the check fails');
  // A check that something is there is read once: a wrong answer fails at once.
  const present = only(fixturePlan(), ['T0']);
  present.tests[0].steps.push({read: {path: '/items/{item}', params: {item: 'GONE'}, checks: [{status: 200}]}});
  const once = fakeRun(t, {plan: present, keys: ['list-items@1']});
  const failed = await once.run();
  await once.muse.done();
  assert.deepEqual([failed.results.T0.passed, reads(once)], [false, 1]);
});

// ---- 24. undo tests that are undone in turn (review of the Gmail cleanup move) ------------------------------------------------------------
test('harness 24: after a stop, an undo test that is itself undone by a later test runs that one too, and an undo test that fails is named as left in place', async t => {
  const chained = (cleanup = [{pointer: '/id', equals: 'E1'}]) => {
    const plan = fixturePlan();
    plan.tests.find(item => item.id === 'T6').undo = {test: 'T7'};
    plan.tests.push({id: 'T7', name: 'Read the event back after T6', steps: [{read: {path: '/events/{event}', params: {event: 'E1'}, checks: cleanup}}]});
    return plan;
  };
  const r = fakeRun(t, {plan: chained(), owner: {answers: ['yes']}});
  r.h.simulator.fail('POST /drafts/{draft_id}/send', {status: 400, data: {error: 'invalid'}});
  const run = await r.run();
  await r.muse.done();
  assert.equal(run.stopped.test, 'T4');
  assert.match(r.muse.lines.join('\n'), /^Pending undo: T6 \(it undoes T3\)$/m);
  assert.deepEqual([run.results.T6?.passed, run.results.T7?.passed], [true, true], 'T6 ran, then T7, which undoes it');
  assert.ok(run.order.indexOf('T7') > run.order.indexOf('T6'));
  assert.deepEqual(run.left, []);
  // T7 fails: it is named as left in place, and nothing else is.
  const bad = fakeRun(t, {plan: chained([{pointer: '/id', equals: 'not E1'}]), owner: {answers: ['yes']}});
  bad.h.simulator.fail('POST /drafts/{draft_id}/send', {status: 400, data: {error: 'invalid'}});
  const failed = await bad.run();
  await bad.muse.done();
  assert.deepEqual([failed.results.T6?.passed, failed.results.T7?.passed], [true, false]);
  assert.deepEqual(failed.left, ['T7 (it undoes T6) failed.']);
  assert.match(bad.muse.lines.join('\n'), /^Left in place: T7 \(it undoes T6\) failed\.$/m);
});

// ---- 25. request ids stay put whatever a gone read or an owner step reads (review of the gone-read retry) ----------------------------------
test('harness 25: a gone read\'s re-reads and an owner step\'s polls count apart, so the call after them keeps its request id however many reads Google needed', async t => {
  const gone = {path: '/items/{item}', params: {item: 'GONE'}, checks: [{gone: true}]};
  const reading = {read: gone}, waiting = {owner: {words: 'Delete the item, then press Enter.', until: gone}};
  const plan = step => { const value = only(fixturePlan(), ['T0']); value.tests[0].steps.push(step, {call: {action: 'list-items@1', args: {kind: 'all'}}}); return value; };
  const lastId = async (stale, runId, step = reading) => {
    const r = fakeRun(t, {plan: plan(step), keys: ['list-items@1'], runId});
    if (stale) r.h.simulator.fail('GET /items/{item_id}', {status: 200, data: {id: 'GONE', in_trash: false}}, {times: stale});
    const run = await r.run();
    await r.muse.done();
    assert.equal(run.results.T0.passed, true, JSON.stringify(run.results.T0.checks));
    return r.port.job(run.results.T0.calls.at(-1).jobs[0]).source.requestId;
  };
  const runId = newRunId(), direct = await lastId(0, runId), after = await lastId(3, runId);
  assert.equal(after, direct, 'three re-reads moved no later id');
  assert.match(direct, new RegExp(`^${runId}\\.T0\\.\\d+$`));
  assert.equal(await lastId(3, runId, waiting), await lastId(0, runId, waiting), 'three polls moved no later id');
});

// ---- 26. cleanup the owner may leave (Sami, 2026-10-29: a test account keeps what a run made) ----------------------------------------------
test('harness 26: a cleanup test calls no action, undoes nothing and comes last; with leave it is not run and is named as left, also when a stop would offer it', async t => {
  const tidy = {id: 'T7', name: 'Tidy the event', cleanup: true, steps: [{read: {path: '/events/{event}', params: {event: 'E1'}, checks: [{status: 200}]}}]};
  const withTidy = (edit = () => {}) => { const plan = fixturePlan(); plan.tests.push(structuredClone(tidy)); edit(plan); return plan; };
  const r0 = fakeRun(t);
  const check = plan => checkPlan(plan, {entries: r0.entries, superseded: [], groups: r0.h.groups.get('fixture'), config: r0.h.configs.get('fixture'), rules: FIXTURE_RULES});
  assert.equal(check(withTidy()).plan.tests.at(-1).cleanup, true);
  assert.throws(() => check(withTidy(plan => { plan.tests.at(-1).cleanup = 'yes'; })), /cleanup is true or absent/);
  assert.throws(() => check(withTidy(plan => { plan.tests.at(-1).steps.push({call: {action: 'list-items@1', args: {kind: 'all'}}}); })), /T7 is cleanup, so it calls no action/);
  assert.throws(() => check(withTidy(plan => { plan.tests.at(-1).undo = {test: 'T6'}; })), /T7 is cleanup, so it undoes nothing/);
  assert.throws(() => check(withTidy(plan => { plan.tests.push({id: 'T8', name: 'Read again', steps: [{read: {path: '/items'}}]}); })), /T8 comes after a cleanup test: cleanup tests come last/);
  // A finished run with leave: T7 is not run and is named; without leave it runs.
  const left = fakeRun(t, {plan: withTidy()});
  const ran = await left.run({leave: true});
  await left.muse.done();
  assert.deepEqual([Object.hasOwn(ran.results, 'T7'), ran.stopped], [false, null]);
  assert.deepEqual(ran.left, ['T7 (Tidy the event) was not run: the owner chose to leave what this run made.']);
  const full = fakeRun(t, {plan: withTidy()});
  const all = await full.run();
  await full.muse.done();
  assert.deepEqual([all.results.T7?.passed, all.left], [true, []]);
  // A stop with leave: the cleanup test a pending undo names is not offered, and no question is asked for it.
  const stop = fakeRun(t, {plan: withTidy(plan => { plan.tests.find(item => item.id === 'T3').undo = {test: 'T7'}; }), owner: {answers: ['yes']}});
  stop.h.simulator.fail('POST /drafts/{draft_id}/send', {status: 400, data: {error: 'invalid'}});
  const stopped = await stop.run({leave: true});
  await stop.muse.done();
  assert.equal(stopped.stopped.test, 'T4');
  assert.equal(Object.hasOwn(stopped.results, 'T7'), false);
  assert.doesNotMatch(stop.muse.lines.join('\n'), /Run the pending undos now\?/);
  assert.deepEqual(stopped.left, ['T7 (Tidy the event) was not run: the owner chose to leave what this run made.']);
  // The command takes --leave, off unless given.
  assert.deepEqual([parseArgs(['gmail', '--folder', '/tmp/x', '--leave']).leave, parseArgs(['gmail', '--folder', '/tmp/x']).leave], [true, false]);
});

// ---- Iteration 9 part 3g: read probes (docs/I07-BUILD-MAP.md part 3g) ------------------------------------------------------------------
// A probes plan asks the provider questions with reads alone, so a simulator can be written from an answer and not from a guess. Nothing here reaches a provider: the
// fake app runs on its simulator, and the shipped files are checked against the real rows and the real guard, and run on Slack's simulator through the command.
const PROBE_FILES = Object.freeze({slack: 'slack.probes.json', github: 'github.probes.json', gmail: 'gmail.probes.json', 'google-calendar': 'google-calendar.probes.json'});
const shippedProbes = appId => JSON.parse(readFileSync(path.join(PLANS, 'triggers', PROBE_FILES[appId]), 'utf8'));
const probesPlan = (tests, more = {}) => ({schemaVersion: 1, appId: 'fixture', probes: true, note: 'Read probes of the fake app.', recorded: {}, readRows: ['fixture.items.read'], tests, ...more});
const question = (id, name, read) => ({id, name, steps: [{read}]});

test('probes 1: a plan marked probes owes no action evidence, holds reads alone, and only such a plan may send a header or read one', t => {
  const h = actionHarness(t, {designated: true, evidence: () => ({})}), entries = fixtureEntries(h);
  const deps = {entries, superseded: [], groups: h.groups.get('fixture'), config: h.configs.get('fixture'), rules: FIXTURE_RULES};
  const plan = probesPlan([question('P1', 'Does the list answer?', {path: '/items', checks: [{status: 200}]})]);
  const checked = checkPlan(plan, deps);
  assert.deepEqual([checked.plan.probes, [...checked.actions.keys()]], [true, []], 'it calls nothing, and it is not refused for that');
  // The same plan without the mark owes every action, so the mark is what exempts it.
  const {probes: _, ...ordinary} = plan;
  assert.throws(() => checkPlan(ordinary, deps), /is called by no test, so it would get no evidence/);
  for (const value of [false, 'true', 1, null]) assert.throws(() => checkPlanShape(probesPlan(plan.tests, {probes: value})), /probes is true or absent/, String(value));
  // Reads alone: a probe never writes, so it owes no undo and leaves nothing behind.
  for (const [step, note] of [[{call: {action: 'list-items@1', args: {}}}, 'a call'], [{owner: {words: 'Do something.'}}, 'an owner step'], [{ask: {row: 'fixture.items.write', requests: [{method: 'GET', path: '/items'}]}}, 'an ask'],
    [{oneTimeAsk: {row: 'fixture.items.delete', requests: [{method: 'DELETE', path: '/items/I1'}]}}, 'a one-time Ask'], [{race: {action: 'list-items@1', status: 412, readback: {path: '/items', pointer: '', output: ''}}}, 'a race']]) {
    assert.throws(() => checkPlanShape(probesPlan([{id: 'P1', name: 'A probe', steps: [step]}])), /a step is exactly one of read/, note);
  }
  assert.throws(() => checkPlanShape(probesPlan([{...plan.tests[0], undo: {none: 'Nothing.'}}])), /a probe undoes nothing/);
  assert.throws(() => checkPlanShape(probesPlan([{...plan.tests[0], cleanup: true}])), /a probe undoes nothing/);
  // The headers a probe may send and read are closed.
  const read = fields => probesPlan([question('P1', 'A probe', {path: '/items', ...fields})]);
  for (const name of ['Accept', 'If-None-Match', 'If-Modified-Since']) assert.equal(checkPlanShape(read({headers: {[name]: 'x'}})).tests.length, 1, name);
  for (const headers of [{Authorization: 'Bearer x'}, {'If-Match': 'x'}, {'X-Other': 'x'}, 'If-None-Match', {Accept: 7}]) assert.throws(() => checkPlanShape(read({headers})), /a probe sends only Accept, If-None-Match or If-Modified-Since/, JSON.stringify(headers));
  for (const name of ['etag', 'last-modified', 'link', 'x-ratelimit-remaining']) {
    for (const check of [{header: name, present: true}, {header: name, includes: '/x'}, {header: name, equals: 'x'}]) assert.equal(checkPlanShape(read({checks: [check]})).tests.length, 1, JSON.stringify(check));
  }
  // x-poll-interval never comes back through the proxy, so a check of it could only ever answer no.
  for (const check of [{header: 'x-poll-interval', present: true}, {header: 'authorization', present: true}, {header: 'etag'}, {header: 'etag', includes: 7}, {header: 'etag', includes: ''}, {header: 'etag', present: 'yes'}]) {
    assert.throws(() => checkPlanShape(read({checks: [check]})), /a check is one of/, JSON.stringify(check));
  }
  for (const saveHeaders of [{tag: 'etag'}, {tag: '/authorization'}, {tag: '/x-poll-interval'}]) assert.throws(() => checkPlanShape(read({saveHeaders})), /saveHeaders names a header a probe may read/, JSON.stringify(saveHeaders));
  assert.equal(checkPlanShape(probesPlan([question('P1', 'A probe', {path: '/items', saveHeaders: {tag: '/etag'}}), question('P2', 'A probe', {path: '/items', headers: {'If-None-Match': {$saved: 'tag'}}})])).tests.length, 2, 'a saved header stands in a later probe');
  assert.throws(() => checkPlanShape(read({headers: {'If-None-Match': {$saved: 'tag'}}})), /\$saved: tag is used before a step saves it/);
  // An ordinary plan's evidence stays what it was: none of this reaches one.
  for (const [fields, note] of [[{headers: {Accept: 'application/json'}}, 'headers'], [{saveHeaders: {tag: '/etag'}}, 'saveHeaders'], [{checks: [{header: 'etag', present: true}]}, 'a header check']]) {
    const {probes: __, ...plain} = read(fields);
    assert.throws(() => checkPlanShape(plain), note === 'a header check' ? /a check is one of/ : new RegExp(`${note} is for a probes plan`), note);
  }
});

test('probes 2: every read of a shipped probes file is allowed by the real guard, sits on a row the plan names, and reads Allow by default', async t => {
  const harnesses = {slack: slackHarness, github: githubHarness, gmail: gmailHarness, 'google-calendar': calendarHarness};
  for (const [appId, harness] of Object.entries(harnesses)) {
    const plan = shippedProbes(appId), h = harness(t), folder = temp(t), key = randomBytes(32), runId = newRunId();
    assert.deepEqual([plan.probes, plan.appId], [true, appId]);
    const entries = [...h.catalog.entries.values()].filter(item => item.appId === appId).map(item => item.entry);
    const checked = checkPlan(plan, {entries, superseded: [], groups: PERMISSION_GROUPS.get(appId), config: PROXY_CONFIGS.get(appId), rules: RULES});
    const guard = createGuard({appId, runId, folder, key, rules: RULES, clock: () => h.now});
    const recorded = Object.fromEntries(Object.keys(plan.recorded).map(name => [name, appId === 'slack' ? 'C0FABTEST1' : `${name}@group.calendar.google.com`]));
    guard.setOwner({email: OWNER_EMAIL, timeZone: ZONE, runDate: RUN_DATE, recorded});
    const run = {runId, runDate: RUN_DATE, timeZone: ZONE, recorded, saved: Object.fromEntries(checked.plan.tests.flatMap(item => item.steps.flatMap(step => Object.keys({...step.read.save, ...step.read.saveHeaders}))).map(name => [name, '12345']))};
    const rows = new Set(plan.readRows.map(row => `group:${row}`));
    for (const item of checked.plan.tests) {
      guard.begin(item.id);
      for (const {read} of item.steps) {
        const ctx = {run, account: {email: OWNER_EMAIL}}, query = Object.fromEntries(Object.entries(fillPlaceholders(read.query ?? {}, ctx, item)).map(([name, value]) => [name, String(value)]));
        const route = read.path.replace(/\{\+?([A-Za-z0-9_]+)\}/g, (_, slot) => encodeURIComponent(fillPlaceholders(read.params[slot], ctx, item)));
        const request = {method: 'GET', path: route, query, ...(read.headers ? {headers: fillPlaceholders(read.headers, ctx, item)} : {})};
        const decision = h.proxyPolicy.decide(h.account, request), verdict = guard.check({method: 'GET', url: decision.request.url});
        assert.equal(verdict.allowed, true, `${appId} ${item.id}: ${verdict.words}`);
        assert.equal(verdict.write, false, `${appId} ${item.id} is a read`);
        assert.ok(rows.has(decision.row), `${appId} ${item.id}: ${decision.row} is not in readRows`);
        assert.equal(decision.effect, 'read', `${appId} ${item.id}`);
        assert.equal(decision.mode, 'allow', `${appId} ${item.id}: a probe runs with no card, unless the owner moved its row`);
      }
      guard.end();
    }
  }
  assert.deepEqual(readdirSync(path.join(PLANS, 'triggers')).filter(name => name === 'README.md' || name.endsWith('.probes.json')).sort(), ['README.md', ...Object.values(PROBE_FILES)].sort(), 'a probes file for each app that has probes owed before its simulator');
  for (const name of PROBE_HEADERS.read) assert.ok(PROXY_HEADERS.includes(name), `a probe reads through the proxy, whose answer keeps ${name}`);
  assert.deepEqual(PROBE_HEADERS.send, ['Accept', 'If-None-Match', 'If-Modified-Since'].filter(name => CALLER_HEADERS.includes(name)), 'each is one the proxy lets a caller send');
});

test('probes 3: a run asks every question: a no is an answer, a read that fails is no answer, and neither stops the next probe, sends a write or leaves a stop to resume', async t => {
  const h = triggerHarness(t, {designated: true});
  h.simulator.seed(3);
  const list = {path: '/feed', query: {limit: '5'}};
  const plan = probesPlan([
    question('P1', 'Does the feed answer with an etag?', {...list, checks: [{status: 200}, {header: 'etag', present: true}, {header: 'etag', includes: 'W/'}], saveHeaders: {tag: '/etag'}}),
    question('P2', 'Is the next read a 304?', {...list, headers: {'If-None-Match': {$saved: 'tag'}}, checks: [{status: 304}, {header: 'etag', equals: {$saved: 'tag'}}]}),
    question('P3', 'Does the etag name something it does not?', {...list, checks: [{header: 'etag', includes: 'no such text'}]}),
    question('P4', 'Is a header there that is not?', {...list, checks: [{header: 'link', present: true}]}),
    question('P5', 'Is it missing, as it is?', {...list, checks: [{header: 'link', present: false}]}),
    question('P6', 'A read whose value cannot be saved', {...list, save: {gone: '/no/such/value'}, checks: [{status: 200}]}),
    question('P7', 'Is a read of what is gone a 404 at the first read?', {path: '/items/{item}', params: {item: 'I2'}, checks: [{status: 404}]}),
    question('P8', 'A read Fabric refuses', {path: '/feed', headers: {Accept: 'text/html'}}),
    question('P9', 'Does a probe after all of those still run?', {...list, checks: [{status: 200}]}),
  ]);
  const r = fakeRun(t, {plan, keys: [], recorded: {}, h}), run = await r.run();
  await r.muse.done();
  const said = id => r.muse.lines.find(line => line.startsWith(`${id}: `) && !line.startsWith(`${id}: ${plan.tests.find(item => item.id === id).name}`));
  assert.deepEqual(['P1', 'P2', 'P3', 'P4', 'P5', 'P7', 'P9'].map(said), ['P1: yes (last answer 200)', 'P2: yes (last answer 304)', 'P3: no (last answer 200)', 'P4: no (last answer 200)', 'P5: yes (last answer 200)', 'P7: no (last answer 200)', 'P9: yes (last answer 200)']);
  assert.match(said('P6'), /^P6: not answered: \/no\/such\/value is not in the answer, so gone cannot be saved\. \(last answer 200\)$/);
  assert.match(said('P8'), /^P8: not answered: Fabric refused the request \(header_not_allowed\)/);
  assert.deepEqual([run.stopped, run.order], [null, plan.tests.map(item => item.id)]);
  assert.equal(run.results.P7.reads.length, 1, 'a probe reads once, so a no is not read five times over');
  assert.deepEqual(r.muse.links, [], 'no card');
  assert.deepEqual(writes(r.h), []);
  assert.equal(r.muse.lines.some(line => /Run the pending undos|To resume/.test(line)), false);
  // An ordinary plan's words and its stop are as they were.
  const ordinary = fakeRun(t, {plan: {...fixturePlan(), recorded: {}, tests: [{id: 'T7', name: 'A check that fails', steps: [{read: {path: '/items/{item}', params: {item: 'I2'}, checks: [{gone: true}]}}]}, {id: 'T8', name: 'After it', steps: [{read: {path: '/items'}}]}]}, keys: [], recorded: {}});
  const stopped = await ordinary.run();
  assert.deepEqual([stopped.stopped.test, Object.hasOwn(stopped.results, 'T8')], ['T7', false]);
  assert.ok(ordinary.muse.lines.includes('T7: failed: A check did not hold.'));
});

/** The command's whole path on Slack's simulator: the shipped rows and guard, a fake app of the harness's parts, and the owner's address typed once. */
async function probeCommand(t, {records, argv = [], plans = PLANS} = {}) {
  const h = slackHarness(t), say = [], folder = path.join(temp(t), 'harness'), evidenceRoot = temp(t);
  const given = records ?? {fabricTest: IDS.fabricTest, selfDm: IDS.selfDm, ownerUser: IDS.owner, synthetic1: '1761490000.000100', beforeSynthetic1: '1761489999.000100', latestReply: '1761490100.000100', reacted: '1761490000.000100', closedDm: 'D0CLOSED01'};
  const protocol = new FabricProtocol({store: h.store, runtime: h.runtime, clock: () => h.now, origin: ORIGIN});
  h.runtime.authorizeSource = job => protocol.authorizeJob(job);
  const deps = {lockDataDir: async () => async () => {}, createApp: async ({certification}) => {
    h.runtime.request = certification.guard.wrap(h.simulator.request);
    return {store: h.store, runtime: h.runtime, origin: ORIGIN, actions: h.catalog, connections: {providers: {resolve: () => ({})}}, start: async () => {}, close: async () => {},
      protocol: {handle: (...args) => protocol.handle(...args), revokeClient: id => protocol.revokeClient(id), createClient: data => protocol.createClient(data, SLACK_OWNER)}};
  }};
  const code = await main(['slack', '--folder', folder, '--probes', ...Object.entries(given).flatMap(([name, value]) => ['--record', `${name}=${value}`]), ...argv],
    {say: line => say.push(String(line)), prompt: async () => 'owner@fabric-owner.test', deps, plans, evidenceRoot, clock: () => h.now});
  return {code, say, folder, evidenceRoot, h};
}

test('probes 4: the command reads the probes file in place of the plan, says each answer, sends no write, and leaves no evidence behind it', async t => {
  const {code, say, evidenceRoot, h} = await probeCommand(t);
  const plan = shippedProbes('slack'), answers = plan.tests.map(item => say.find(line => line.startsWith(`${item.id}: `) && line !== `${item.id}: ${item.name}`));
  assert.equal(code, 0, say.join('\n'));
  for (const [index, line] of answers.entries()) assert.match(line ?? '', /: (yes|no) \(last answer 200\)$/, `${plan.tests[index].id}: every question reached the simulator`);
  assert.ok(say.includes(PROBES_DONE), say.join('\n'));
  assert.deepEqual(readdirSync(evidenceRoot), [], 'nothing under the evidence root: a run of probes would otherwise rewrite actions.json');
  assert.equal(say.some(line => line.startsWith('Evidence:')), false);
  assert.deepEqual(h.simulator.calls.filter(call => call.method !== 'GET').map(call => call.name), [], 'reads alone');
  assert.deepEqual(h.store.list('clientGrants').filter(item => item.status === 'active'), [], 'every grant of the run revoked');
});

test('probes 5: --probes takes its own file only: a probes file needs the flag, the flag needs a probes file, and it refuses what only a plan run means', async t => {
  const calls = [], say = [], deps = {createApp: async () => { calls.push('createApp'); throw new Error('stop here'); }, lockDataDir: async () => { calls.push('lock'); return async () => {}; }};
  const go = (argv, options = {}) => main(argv, {say: line => say.push(String(line)), prompt: async () => '', deps, ...options});
  const folder = path.join(temp(t), 'harness'), plans = temp(t), {probes: _, ...plain} = shippedProbes('slack'), records = Object.keys(plain.recorded).flatMap(name => ['--record', `${name}=x`]);
  mkdirSync(path.join(plans, 'triggers'));
  assert.equal(await go(['slack', '--folder', folder, '--probes'], {plans}), 2);
  assert.equal(say.at(-1), 'No read probes for slack yet.');
  writeFileSync(path.join(plans, 'slack.json'), JSON.stringify({...plain, probes: true}));
  assert.equal(await go(['slack', '--folder', folder, ...records], {plans}), 2);
  assert.match(say.at(-1), /slack\.json is not a plan: its probes run with --probes/);
  writeFileSync(path.join(plans, 'triggers', 'slack.probes.json'), JSON.stringify(plain));
  assert.equal(await go(['slack', '--folder', folder, '--probes', ...records], {plans}), 2);
  assert.match(say.at(-1), /slack\.probes\.json is not marked probes, so it does not run with --probes/);
  writeFileSync(path.join(plans, 'triggers', 'slack.probes.json'), JSON.stringify(shippedProbes('gmail')));
  assert.equal(await go(['slack', '--folder', folder, '--probes'], {plans}), 2);
  assert.match(say.at(-1), /must be named after its appId/);
  writeFileSync(path.join(plans, 'triggers', 'slack.probes.json'), JSON.stringify(shippedProbes('slack')));
  assert.equal(await go(['slack', '--folder', folder, '--probes'], {plans}), 2);
  assert.match(say.at(-1), /--record fabricTest=<value>/, 'its recorded values are given before anything opens');
  assert.deepEqual(calls, [], 'refused before any lock or start');
  // The flag: off unless given, and with nothing that only a plan run means.
  assert.deepEqual([parseArgs(['gmail', '--folder', '/tmp/x', '--probes']).probes, parseArgs(['gmail', '--folder', '/tmp/x']).probes], [true, false]);
  for (const argv of [['gmail', '--check', '--probes'], ['gmail', '--folder', '/tmp/x', '--probes', '--resume', 'ABCDEFGH'], ['gmail', '--folder', '/tmp/x', '--probes', '--leave']]) {
    assert.throws(() => parseArgs(argv), /--probes|--check takes/, argv.join(' '));
  }
  assert.match(USAGE, /--probes/);
  // --check reads only top-level names, so the folder of probes never reads as an app, and what it says of the shipped plans is unchanged.
  say.length = 0;
  assert.equal(await go(['--check']), 0);
  assert.deepEqual(say, ['github: 15 tests check, calling 15 actions.', 'gmail: 12 tests check, calling 13 actions.', 'google-calendar: 14 tests check, calling 13 actions.', 'notion: 13 tests check, calling 16 actions.', 'slack: 7 tests check, calling 13 actions.']);
});

// ---- Iteration 9 part 9a: the command's --triggers path (docs/I07-BUILD-MAP.md part 9a) --------------------------------------------------------------------------------
// test/live-triggers.test.mjs holds the steps, the watch grant and the evidence on the fake app. These hold the command around them: on Slack's simulator, behind the shipped guard and rows.
const SLACK_RECORDED = () => ({fabricTest: IDS.fabricTest, selfDm: IDS.selfDm, ownerUser: IDS.owner, synthetic1: '1761490000.000100', beforeSynthetic1: '1761489999.000100', latestReply: '1761490100.000100', reacted: '1761490000.000100', closedDm: 'D0CLOSED01'});
const subscriptionOf = name => ({subscription: {$saved: name}});
const slackTriggerPlan = (tests = [], more = {}) => ({schemaVersion: 1, appId: 'slack', triggers: true, note: 'One Slack trigger, for the command.', recorded: Object.fromEntries(Object.keys(SLACK_RECORDED()).map(name => [name, `The value of ${name}.`])), readRows: ['slack.messages.read'], tests: [
  {id: 'W1', name: 'Watch the channel', steps: [{watch: {trigger: 'new-message@1', args: {channels: [{$recorded: 'fabricTest'}]}, save: {sub1: '/id'}}}, {poll: {...subscriptionOf('sub1'), events: 0}}]}, ...tests], ...more});
const ONE_MESSAGE = {id: 'T1', name: 'One message', steps: [{owner: {words: 'Post once in #fabric-test.'}}, {poll: {...subscriptionOf('sub1'), events: 1}}, {poll: {...subscriptionOf('sub1'), events: 0}}], undo: {none: 'The channel keeps it.'}};

/** The command's whole trigger path: the app's parts on a world of one Slack trigger, the owner approving each link it prints, and one message posted at each hand step. */
async function triggerCommand(t, {plan, argv = []} = {}) {
  const h = triggerWorld(t, 'slack', {keys: ['new-message'], engine: {certification: true}}), said = [], folder = path.join(temp(t), 'harness'), evidenceRoot = temp(t), plans = temp(t), posted = [];
  mkdirSync(path.join(plans, 'triggers'));
  writeFileSync(path.join(plans, 'triggers', 'slack.json'), JSON.stringify(plan));
  h.runtime.authorizeSource = job => h.protocol.authorizeJob(job);
  const deps = {lockDataDir: async () => async () => {}, createApp: async ({certification}) => {
    h.runtime.request = certification.guard.wrap(h.simulator.request);
    return {store: h.store, runtime: h.runtime, origin: ORIGIN, actions: h.catalog, triggers: h.engine, connections: {providers: {resolve: () => ({})}}, start: async () => {}, close: async () => {},
      protocol: {handle: (...args) => h.protocol.handle(...args), revokeClient: id => h.protocol.revokeClient(id), createClient: data => h.protocol.createClient(data, SLACK_OWNER)}};
  }};
  const say = line => { said.push(String(line)); const link = /^Approve: .+\/approve\/([0-9a-f-]{36})$/.exec(line); if (link) h.approve(link[1]); };
  const prompt = async words => { if (!/Post once/.test(words)) return 'owner@fabric-owner.test'; h.advance(1000); posted.push(h.simulator.post(IDS.fabricTest, {text: 'A message.'})); return ''; };
  const code = await main(['slack', '--folder', folder, '--triggers', ...Object.entries(SLACK_RECORDED()).flatMap(([name, value]) => ['--record', `${name}=${value}`]), ...argv], {say, prompt, deps, plans, evidenceRoot, clock: () => h.now});
  return {code, said, folder, evidenceRoot, h, posted};
}

test('triggers 1: the command reads the trigger plan, writes triggers.json beside no actions.json, honours --leave, and revokes every grant', async t => {
  const tidy = {id: 'C1', name: 'A tidy up', cleanup: true, steps: [{owner: {words: 'This never runs.'}}], undo: {none: 'Nothing to undo.'}};
  const {code, said, evidenceRoot, h, posted} = await triggerCommand(t, {plan: slackTriggerPlan([ONE_MESSAGE, tidy]), argv: ['--leave']});
  assert.equal(code, 0, said.join('\n'));
  assert.equal(posted.length, 1);
  assert.ok(said.includes('Evidence: docs/live-evidence/slack/triggers.json. Commit it only with the owner\'s OK.'), said.join('\n'));
  assert.ok(said.some(line => /^Left in place: C1 /.test(line)), 'the cleanup test is left, as --leave asks');
  assert.ok(said.filter(line => line.startsWith('Approve: ')).length === 1, 'one card');
  const folder = path.join(evidenceRoot, 'docs', 'live-evidence', 'slack');
  assert.deepEqual(readdirSync(folder), ['triggers.json'], 'an action\'s evidence, and N0\'s record, stay as they are');
  const [entry] = h.triggerEntries, evidence = JSON.parse(readFileSync(path.join(folder, 'triggers.json'), 'utf8'));
  assert.equal(evidence[entry.id].tests.at(-1).proof.afterWrite, 1);
  assert.equal(triggerEvidencePasses(entry, evidence[entry.id], SHIPPED_PINS.transforms), true);
  assert.deepEqual(h.store.list('clientGrants').filter(item => item.status === 'active' && item.name.startsWith('Live test')), [], 'every grant of the run revoked');
});

test('triggers 2: a stop says how to resume with --triggers, and writes what it has', async t => {
  const {code, said, evidenceRoot} = await triggerCommand(t, {plan: slackTriggerPlan([{...ONE_MESSAGE, steps: [ONE_MESSAGE.steps[0], {poll: {...subscriptionOf('sub1'), events: 2}}]}]), argv: ['--leave']});
  assert.equal(code, 1);
  assert.ok(said.some(line => /^To resume: .* --triggers --leave --resume [A-Z2-7]{8} --from T1$/.test(line)), said.join('\n'));
  assert.ok(existsSync(path.join(evidenceRoot, 'docs', 'live-evidence', 'slack', 'triggers.json')));
});

test('triggers 3: --triggers takes its own file only, and the flag and a mark on the file go together', async t => {
  const calls = [], say = [], deps = {createApp: async () => { calls.push('createApp'); throw new Error('stop here'); }, lockDataDir: async () => { calls.push('lock'); return async () => {}; }};
  const go = (argv, options = {}) => main(argv, {say: line => say.push(String(line)), prompt: async () => '', deps, ...options});
  const folder = path.join(temp(t), 'harness'), plans = temp(t), plan = slackTriggerPlan([ONE_MESSAGE]), {triggers: _, ...unmarked} = {...plan, tests: [{id: 'T1', name: 'A read', steps: [{read: {path: '/conversations.list'}}]}]};
  const records = Object.keys(plan.recorded).flatMap(name => ['--record', `${name}=x`]);
  mkdirSync(path.join(plans, 'triggers'));
  assert.equal(await go(['slack', '--folder', folder, '--triggers'], {plans}), 2);
  assert.equal(say.at(-1), 'No trigger plan for slack yet.');
  writeFileSync(path.join(plans, 'slack.json'), JSON.stringify(plan));
  assert.equal(await go(['slack', '--folder', folder, ...records], {plans}), 2);
  assert.match(say.at(-1), /slack\.json is a trigger plan: it runs with --triggers/);
  writeFileSync(path.join(plans, 'triggers', 'slack.json'), JSON.stringify(unmarked));
  assert.equal(await go(['slack', '--folder', folder, '--triggers', ...records], {plans}), 2);
  assert.match(say.at(-1), /slack\.json is not marked triggers, so it does not run with --triggers/);
  writeFileSync(path.join(plans, 'triggers', 'slack.json'), JSON.stringify({...plan, appId: 'gmail'}));
  assert.equal(await go(['slack', '--folder', folder, '--triggers', ...records], {plans}), 2);
  assert.match(say.at(-1), /must be named after its appId/);
  writeFileSync(path.join(plans, 'triggers', 'slack.json'), JSON.stringify(plan));
  assert.equal(await go(['slack', '--folder', folder, '--triggers'], {plans}), 2);
  assert.match(say.at(-1), /--record fabricTest=<value>/, 'its recorded values are given before anything opens');
  assert.deepEqual(calls, [], 'refused before any lock or start');
  assert.deepEqual([parseArgs(['gmail', '--folder', '/tmp/x', '--triggers']).triggers, parseArgs(['gmail', '--folder', '/tmp/x']).triggers], [true, false]);
  assert.equal(parseArgs(['gmail', '--folder', '/tmp/x', '--triggers', '--leave', '--resume', 'ABCDEFGH', '--from', 'T1']).resume, 'ABCDEFGH', 'a trigger run resumes, as an action run does');
  assert.throws(() => parseArgs(['gmail', '--check', '--triggers']), /--check takes/);
  assert.throws(() => parseArgs(['gmail', '--folder', '/tmp/x', '--triggers', '--probes']), /--probes and --triggers/);
  assert.match(USAGE, /--triggers/);
  // N0's record belongs to the action plan's run, so a trigger run asks nothing and rewrites nothing.
  let asked = 0;
  assert.equal(await introspectOnce({introspect: async () => { asked++; return {active: true}; }}, {appId: 'notion', triggers: true}, {runId: 'R', at: 'now', root: temp(t)}), null);
  assert.equal(asked, 0);
});

test('triggers 4: the port holds no approve, and reads a watch through its standing and its runs alone, with no cursor', t => {
  const h = triggerHarness(t), port = harnessPort({store: h.store, origin: ORIGIN, triggers: {pollNow: async () => {}, ageCursor: async (id, value) => `aged ${id} ${value}`}});
  assert.deepEqual(Object.keys(port).filter(name => /approve|decide|decline|resume|pause|remove|reset|promote|^set/i.test(name)), []);
  assert.equal(port.watch('none'), null);
  assert.deepEqual(port.lastRuns('none'), []);
  const at = new Date(h.now).toISOString(), watch = {...h.watch('feed-logged', {status: 'paused', reason: 'owner_paused', approvalExpiresAt: at}), feeds: ['feed-a', 'feed-b']};
  h.store.put('subscriptions', watch);
  h.store.put('triggerFeeds', {id: 'feed-a', connectionId: h.account, cursors: {history: '7'}});
  h.store.put('triggerRuns', {id: 'feed-a', connectionId: h.account, runs: [{at: 1, outcome: 'done', status: 200, requests: 1, items: 2, skipped: 0, events: {}}, {at: 2, outcome: 'done', status: 304, requests: 1, items: 0, skipped: 0, events: {}}]});
  assert.deepEqual(port.watch(watch.id), {status: 'paused', reason: 'owner_paused', approvalExpiresAt: at});
  assert.deepEqual(port.lastRuns(watch.id), [{at: 2, outcome: 'done', status: 304, requests: 1, items: 0, skipped: 0, events: {}}, null], 'the last run of each feed, and null for one that has none');
  assert.equal(JSON.stringify([port.watch(watch.id), port.lastRuns(watch.id)]).includes('history'), false);
});

test('triggers 5: writeEvidence() names its file, and writes actions.json when told nothing', t => {
  const root = temp(t), folder = path.join(root, 'docs', 'live-evidence', 'fixture');
  writeEvidence(root, 'fixture', {records: {a: {passed: true}}, run: {runId: 'A'}});
  writeEvidence(root, 'fixture', {records: {b: {passed: true}}, run: {runId: 'B'}}, {}, 'triggers.json');
  assert.deepEqual(readdirSync(folder).sort(), ['actions.json', 'triggers.json']);
  assert.deepEqual(Object.keys(JSON.parse(readFileSync(path.join(folder, 'actions.json'), 'utf8'))).sort(), ['a', 'run']);
  assert.deepEqual(Object.keys(JSON.parse(readFileSync(path.join(folder, 'triggers.json'), 'utf8'))).sort(), ['b', 'run']);
});

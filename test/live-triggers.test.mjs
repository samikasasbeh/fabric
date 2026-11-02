import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {triggerEvidencePasses} from '../lib/action-catalog.mjs';
import {FabricProtocol} from '../lib/fabric-protocol.mjs';
import {createGuard, guardFile, newRunId} from '../lib/live-guard.mjs';
import {PermissionManager} from '../lib/permissions.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {SubscriptionService} from '../lib/subscriptions.mjs';
import {TriggerEngine} from '../lib/trigger-engine.mjs';
import {PAUSE_REASONS} from '../lib/trigger-rules.mjs';
import {checkPlanShape, checkTriggerPlan, fillPlaceholders, openRunState, runLiveTests, triggerEvidenceRecords, writeEvidence, PLACEHOLDERS, PLAN_LIMITS, STEP_KINDS, WATCH_KINDS} from '../lib/live-certify.mjs';
import {harnessPort} from '../scripts/live-certify.mjs';
import {fixtureMap} from './fixtures/actions/fixture-app.mjs';
import {OWNER} from './fixtures/actions/runtime-fixture.mjs';
import {feedTriggers, REGISTRY_PINS, triggerHarness} from './fixtures/actions/trigger-fixture.mjs';

// Iteration 9 part 9a (docs/I07-BUILD-MAP.md step 9): the trigger steps of a live plan, on the fake app (test/fixtures/actions/trigger-fixture.mjs), behind the live guard with a certification
// Runtime and engine. Nothing here listens on a port or reaches a provider. The owner is scripted, and only the owner's own path approves.

const ORIGIN = 'http://127.0.0.1:4320', OWNER_EMAIL = 'owner@fixture.test', ZONE = 'America/Toronto', RUN_DATE = '2026-10-23';
/** What a provider's item holds: words no evidence, run file or printed line may carry. */
const TITLE = 'A private title about owner@fixture.test';
const WATCHED = Object.freeze(['feed-logged', 'feed-listed']);
/** A plan of the fake app's triggers, as catalog/live-tests/triggers/<appId>.json holds one. */
const triggerPlan = (tests, more = {}) => ({schemaVersion: 1, appId: 'fixture', triggers: true, note: 'The fake app\'s trigger plan.', recorded: {}, readRows: ['fixture.items.read'], tests, ...more});
const saved = name => ({$saved: name});
const watch = (trigger, name, args) => ({watch: {trigger, ...(args ? {args} : {}), save: {[name]: '/id'}}});
const poll = (name, fields) => ({poll: {subscription: saved(name), ...fields}});
/** The test a plan opens with: each trigger watched, and its first poll asserts 0. */
const opening = (keys = WATCHED) => ({id: 'W1', name: 'Watch the feed', steps: [...keys.flatMap((key, index) => [watch(`${key}@1`, `sub${index + 1}`), poll(`sub${index + 1}`, {events: 0})])]});

// ---- the plan ------------------------------------------------------------------------------------------------------------------------------
test('plan 1: only a plan marked triggers holds watch, poll, unwatch or age, and no undo does', () => {
  assert.deepEqual([...WATCH_KINDS], ['watch', 'poll', 'unwatch', 'age']);
  assert.deepEqual([...STEP_KINDS], ['call', 'race', 'read', 'owner', 'oneTimeAsk', 'ask'], 'an action plan\'s steps are as they were, so its evidence means what it did');
  const plan = triggerPlan([opening()]);
  assert.equal(checkPlanShape(plan).tests.length, 1);
  const {triggers: _, ...plain} = plan;
  assert.throws(() => checkPlanShape(plain), /a step is exactly one of call, race, read, owner, oneTimeAsk or ask/, 'an action plan holds no watch');
  for (const kind of WATCH_KINDS) assert.throws(() => checkPlanShape({...plain, tests: [{id: 'T1', name: 'A test', steps: [{[kind]: {}}]}]}), /a step is exactly one of call, race, read, owner, oneTimeAsk or ask/, kind);
  assert.throws(() => checkPlanShape(triggerPlan([{id: 'T1', name: 'A test', steps: [{sleep: {ms: 1}}]}])), /a step is exactly one of call, race, read, owner, oneTimeAsk, ask, watch, poll, unwatch or age/);
  for (const value of [false, 'true', 1, null]) assert.throws(() => checkPlanShape(triggerPlan([opening()], {triggers: value})), /triggers is true or absent/, String(value));
  assert.throws(() => checkPlanShape(triggerPlan([opening()], {probes: true})), /a plan is probes or triggers, not both/);
  assert.throws(() => checkPlanShape(triggerPlan([{...opening(), undo: {steps: [poll('sub1', {events: 0})]}}])), /a step is exactly one of call, read, owner or ask/, 'an undo tidies, so it asserts nothing about a watch');
});

test('plan 2: each trigger step holds its closed form', () => {
  const start = [watch('feed-logged@1', 'sub1')];
  const refused = (step, words, note) => assert.throws(() => checkPlanShape(triggerPlan([{id: 'T1', name: 'A test', steps: [...start, step]}])), words, note);
  const passes = step => checkPlanShape(triggerPlan([{id: 'T1', name: 'A test', steps: [...start, step]}]));
  passes(watch('feed-listed@1', 'sub2', {kinds: ['note']}));
  refused({watch: {save: {sub2: '/id'}}}, /a trigger is named key@version/, 'no trigger');
  refused({watch: {trigger: 'feed-listed', save: {sub2: '/id'}}}, /a trigger is named key@version/, 'no version');
  refused({watch: {trigger: 'feed-listed@1', args: [], save: {sub2: '/id'}}}, /args is an object/);
  refused({watch: {trigger: 'feed-listed@1', args: {after: saved('later')}, save: {sub2: '/id'}}}, /\$saved: later is used before a step saves it/);
  refused({watch: {trigger: 'feed-listed@1'}}, /a watch saves its \/id under one name/, 'a watch nothing can name');
  refused({watch: {trigger: 'feed-listed@1', save: {sub2: '/subscriptionId'}}}, /a watch saves its \/id under one name/, 'the old pointer');
  refused({watch: {trigger: 'feed-listed@1', save: {sub2: '/id', sub3: '/id'}}}, /a watch saves its \/id under one name/);
  refused({watch: {trigger: 'feed-listed@1', save: {sub2: '/id'}, cursor: '1'}}, /cursor is not a field of watch/, 'no step sets a cursor at subscribe');
  passes(poll('sub1', {events: 1, gaps: 1, within: 120, itemsRead: 1, where: {'/fields/id': 'F1'}, checks: [{status: 200}, {pointer: '/events/0/fields/id', equals: 'F1'}]}));
  passes(poll('sub1', {paused: 'permission_changed'}));
  passes(poll('sub1', {events: 1, floor: 30}));
  for (const value of [0, -1, 1.5, '30', PLAN_LIMITS.withinSeconds + 1]) refused(poll('sub1', {events: 0, floor: value}), /floor is a whole number of seconds/, String(value));
  refused({poll: {events: 0}}, /subscription is \{\$saved: <a watch's name>\}/, 'no subscription');
  refused({poll: {subscription: 'abc', events: 0}}, /subscription is \{\$saved: <a watch's name>\}/, 'a literal id');
  refused({poll: {subscription: {$recorded: 'sub1'}, events: 0}}, /subscription is \{\$saved: <a watch's name>\}/);
  refused(poll('later', {events: 0}), /\$saved: later is used before a step saves it/);
  refused(poll('sub1', {}), /a poll says how many events it reads, or names the reason a watch paused/);
  refused(poll('sub1', {events: 1, paused: 'permission_changed'}), /a poll says how many events it reads, or names the reason a watch paused/);
  for (const value of [-1, 1.5, '1', PLAN_LIMITS.events + 1]) refused(poll('sub1', {events: value}), /events is a whole number/, String(value));
  for (const value of [-1, 1.5, '1']) refused(poll('sub1', {events: 0, gaps: value}), /gaps is a whole number/, String(value));
  for (const value of [-1, 1.5, PLAN_LIMITS.withinSeconds + 1]) refused(poll('sub1', {events: 0, within: value}), /within is a whole number of seconds/, String(value));
  for (const value of [0, -1, 1.5]) refused(poll('sub1', {events: 0, itemsRead: value}), /itemsRead is a whole number from 1/, String(value));
  for (const value of [[], {}, 'x', {x: 1}]) refused(poll('sub1', {events: 0, where: value}), /where maps pointers to values/, JSON.stringify(value));
  refused(poll('sub1', {events: 0, where: {'/fields/id': saved('later')}}), /\$saved: later is used before a step saves it/);
  refused(poll('sub1', {events: 0, checks: [{header: 'etag', present: true}]}), /a check is one of/, 'a header check is for a probes plan');
  for (const reason of ['paused', 'no_reason', 1]) refused(poll('sub1', {paused: reason}), new RegExp(`paused is one of ${PAUSE_REASONS[0]}`), String(reason));
  for (const field of [{within: 10}, {gaps: 0}, {itemsRead: 1}, {floor: 30}, {where: {'/x': 1}}, {checks: []}]) refused(poll('sub1', {paused: 'permission_changed', ...field}), /a poll that names a pause holds nothing else/, JSON.stringify(field));
  passes({unwatch: {subscription: saved('sub1')}});
  refused({unwatch: {subscription: 'abc'}}, /subscription is \{\$saved: <a watch's name>\}/);
  refused({unwatch: {subscription: saved('sub1'), now: true}}, /now is not a field of unwatch/);
  passes({age: {subscription: saved('sub1'), value: '1'}});
  passes({age: {subscription: saved('sub1'), value: {$saved: 'sub1'}}});
  refused({age: {subscription: saved('sub1')}}, /value is the stale cursor, as text or a placeholder/, 'no value');
  refused({age: {subscription: saved('sub1'), value: 1}}, /value is the stale cursor, as text or a placeholder/);
  refused({age: {subscription: saved('sub1'), value: ''}}, /value is the stale cursor, as text or a placeholder/);
  refused({age: {subscription: saved('sub1'), value: {$saved: 'later'}}}, /\$saved: later is used before a step saves it/);
});

test('plan 3: an ask step or a one-time Ask may send a body, an object its placeholders fill, and never on a GET', () => {
  const steps = request => [{ask: {row: 'fixture.items.edit', requests: [{method: 'POST', path: '/items', ...request}]}}];
  const shape = request => checkPlanShape(triggerPlan([{id: 'T1', name: 'A test', steps: steps(request), undo: {none: 'Nothing.'}}]));
  assert.equal(shape({body: {title: {$text: 'one'}}}).tests.length, 1);
  assert.throws(() => shape({body: {title: saved('later')}}), /\$saved: later is used before a step saves it/);
  assert.throws(() => shape({body: 'text'}), /a request's body is an object, and a GET has none/);
  assert.throws(() => shape({body: {}, method: 'GET'}), /a request's body is an object, and a GET has none/);
});

test('plan 5: `$mention` writes the marker and one recorded member, and `$localIn` a wall time minutes from now in the run\'s zone, and neither reads anything else', () => {
  const use = (value, recorded = {member: 'The member.'}) => checkPlanShape(triggerPlan([{id: 'TR3', name: 'A test', steps: [{ask: {row: 'fixture.items.edit', requests: [{method: 'POST', path: '/items', body: {text: value}}]}}], undo: {none: 'Nothing.'}}], {recorded}));
  assert.ok(['$mention', '$localIn'].every(name => PLACEHOLDERS.includes(name)));
  assert.equal(use({$mention: 'member'}).tests.length, 1);
  for (const value of ['other', 1, null, {name: 'member'}]) assert.throws(() => use({$mention: value}), /\$mention names a recorded value/, JSON.stringify(value));
  assert.equal(use({$localIn: {minutes: 10}}).tests.length, 1);
  for (const value of [{minutes: 0}, {minutes: 1441}, {minutes: 1.5}, {hours: 1}, {minutes: 5, day: 7}, 5]) assert.throws(() => use({$localIn: value}), /\$localIn is \{minutes\}, 1 to 1,440 whole minutes after the step runs/, JSON.stringify(value));
  const ctx = {run: {runId: 'ABCDEFGH', runDate: RUN_DATE, timeZone: ZONE, saved: {}, recorded: {member: 'U0OWNER01'}}, account: {}, clock: () => Date.parse('2026-10-23T16:30:45.500Z')}, test = {id: 'TR3'};
  assert.equal(fillPlaceholders({$mention: 'member'}, ctx, test), '[SYNTHETIC] Fabric TR3 ABCDEFGH <@U0OWNER01>');
  assert.throws(() => fillPlaceholders({$mention: 'other'}, ctx, test), /\$mention: other was not given for this run/);
  assert.equal(fillPlaceholders({$localIn: {minutes: 10}}, ctx, test), '2026-10-23T12:40:45', 'Toronto is four hours behind UTC that day, and the seconds stay whole');
  assert.equal(fillPlaceholders({$localIn: {minutes: 10}}, {...ctx, run: {...ctx.run, timeZone: 'UTC'}}, test), '2026-10-23T16:40:45');
  assert.throws(() => fillPlaceholders({$localIn: {minutes: 10}}, {...ctx, clock: undefined}, test), /\$localIn needs the run's clock/);
});

/** The fake app's guard rules in a run: any read, and a label's change on an item. */
const RULES = Object.freeze({fixture: Object.freeze({appId: 'fixture', base: 'https://api.fixture.test', allowlist: Object.freeze([{method: 'GET', path: '+any'}, {method: 'PATCH', path: 'items/:item'}, {method: 'DELETE', path: 'items/:item/labels/:name'}]),
  route: request => ['GET', 'PATCH', 'DELETE'].includes(request.method) ? {write: request.method !== 'GET'} : {write: true}})});
const appEntries = (h, kind) => [...h.catalog[kind].values()].filter(item => item.appId === 'fixture').map(item => item.entry);
/** A candidate file of these triggers, the only state a live run may read them in, on a designated store as a certification Fabric has. */
const candidates = (t, keys = WATCHED) => triggerHarness(t, {designated: true, reviewed: false, triggers: feedTriggers().filter(item => keys.includes(item.key))});
/** What checkTriggerPlan() needs of the app. */
const planDeps = h => ({entries: appEntries(h, 'entries'), triggers: appEntries(h, 'triggers'), superseded: [], groups: h.groups.get('fixture'), config: h.configs.get('fixture'), rules: RULES});
const write = {call: {action: 'update-item@1', args: {itemId: 'I1', change: 'label', labels: ['Later']}}};

test('plan 4: checkTriggerPlan() asks that every trigger of the file is watched and read, every write undone, and no action called for its own sake', t => {
  const deps = planDeps(candidates(t)), checked = checkTriggerPlan(triggerPlan([opening()]), deps);
  assert.deepEqual([...checked.triggers.keys()].sort(), ['feed-listed@1', 'feed-logged@1']);
  assert.equal(checked.triggers.get('feed-logged@1').id, deps.triggers.find(entry => entry.key === 'feed-logged').id);
  assert.deepEqual([...checked.actions.keys()], [], 'an action plan\'s rule that every action is called does not hold here');
  assert.deepEqual([checked.appId, checked.plan.tests.length], ['fixture', 1]);
  assert.ok(Object.isFrozen(checked));
  const refused = (tests, words, note, more) => assert.throws(() => checkTriggerPlan(triggerPlan(tests, more), deps), words, note);
  refused([opening(['feed-logged'])], /feed-listed@1 is watched by no step, so it would get no evidence/, 'a trigger with no watch');
  refused([{...opening(), steps: [...opening().steps, watch('feed-gone@1', 'sub3'), poll('sub3', {events: 0})]}], /feed-gone@1 is not a trigger of fixture/, 'a trigger not in the file');
  refused([{...opening(), steps: [...opening().steps, watch('feed-logged@2', 'sub3'), poll('sub3', {events: 0})]}], /feed-logged@2 is not a trigger of fixture/, 'another version');
  refused([opening(), {id: 'T1', name: 'A write', steps: [write, poll('sub1', {events: 1})]}], /T1 writes, so it needs an undo/, 'every write has its undo');
  const checkedWrite = checkTriggerPlan(triggerPlan([opening(), {id: 'T1', name: 'A write', steps: [write, poll('sub1', {events: 1})], undo: {none: 'The fake app keeps it.'}}]), deps);
  assert.deepEqual([...checkedWrite.actions.keys()], ['update-item@1']);
  refused([opening(), {id: 'T1', name: 'A call', steps: [{call: {action: 'no-such@1', args: {}}}], undo: {none: 'Nothing.'}}], /no-such@1 is not an action of fixture/);
  refused([{id: 'W1', name: 'Watch', steps: [watch('feed-logged@1', 'sub1'), poll('sub1', {events: 1}), watch('feed-listed@1', 'sub2'), poll('sub2', {events: 0})]}], /the first poll of sub1 asserts 0/, 'a baseline that may emit');
  refused([{id: 'W1', name: 'Watch', steps: [watch('feed-logged@1', 'sub1'), poll('sub1', {paused: 'permission_changed'}), watch('feed-listed@1', 'sub2'), poll('sub2', {events: 0})]}], /the first poll of sub1 asserts 0/, 'a pause proves no baseline');
  refused([{id: 'W1', name: 'Watch', steps: [watch('feed-logged@1', 'sub1'), watch('feed-listed@1', 'sub2'), poll('sub2', {events: 0})]}], /sub1 is watched and never polled/, 'a watch nothing reads');
  refused([{...opening(), steps: [...opening().steps, {read: {path: '/items', save: {found: '/account'}}}, poll('found', {events: 0})]}], /found is saved by no watch/, 'a poll of a value no watch saved');
  refused([{...opening(), steps: [...opening().steps, {read: {path: '/items', save: {found: '/account'}}}, {age: {subscription: saved('found'), value: '1'}}]}], /found is saved by no watch/);
  refused([{...opening(), steps: [...opening().steps, {read: {path: '/items', save: {found: '/account'}}}, {unwatch: {subscription: saved('found')}}]}], /found is saved by no watch/);
  assert.throws(() => checkTriggerPlan(triggerPlan([opening()], {readRows: []}), deps), /the watch grant holds the account through readRows, so a trigger plan names at least one/);
  assert.throws(() => checkTriggerPlan(triggerPlan([{id: 'T1', name: 'A read', steps: [{read: {path: '/items'}}]}], {triggers: undefined}), deps), /this plan is not marked triggers/);
  assert.throws(() => checkTriggerPlan(triggerPlan([opening()]), {...deps, triggers: [{id: 'other.trigger.x.v1.abc', key: 'x', version: 1}]}), /the triggers are not this plan's app/);
  assert.throws(() => checkTriggerPlan(triggerPlan([opening()]), {...deps, triggers: undefined}), /the triggers are not this plan's app/);
  assert.throws(() => checkTriggerPlan(triggerPlan([opening()]), {...deps, rules: {}}), /fixture has no live-test rules/, 'checkPlan()\'s own checks still run');
  assert.throws(() => checkTriggerPlan(triggerPlan([{...opening(), steps: [...opening().steps, {read: {path: '/items'}}]}], {readRows: ['fixture.items.edit']}), deps), /fixture\.items\.edit is not a read row of fixture/);
});

// ---- a run -----------------------------------------------------------------------------------------------------------------------------------
function temp(t) {
  const folder = mkdtempSync(path.join(tmpdir(), 'fabric-live-triggers-'));
  t.after(() => rmSync(folder, {recursive: true, force: true}));
  return folder;
}
/** A hand step's write, and a waited-out write: one provider item, as a person's change makes one. */
const handWrite = {owner: {words: 'Make one change in the app.'}};
/** The action a plan calls. The provider also logs it as an item of the feed, as a real write shows in a real change feed. */
const callWrite = {call: {action: 'update-item@1', args: {itemId: 'I1', change: 'label', labels: ['Later']}}};
const KEPT = {none: 'The fake app keeps what a test makes.'};

/**
 * One certification run of the fake app: a candidate trigger file, the guard in front of the simulator, a certification Runtime and engine, fabric/0.1, the service and the port the command gives the runner.
 * The owner reads each printed link and approves it on the owner's own path. The runner's own reach to either approve throws, so a runner that approved anything would fail the test. Each wait moves the clock
 * by what it asks for. `onPrompt` and `onWait` are the owner's and the world's turns. `approve: false` leaves each card for the test.
 */
function triggerRun(t, {plan, keys = WATCHED, h = candidates(t, keys), approve = true, onPrompt = () => {}, onWait = () => {}, folder = temp(t), runId = newRunId(), key = randomBytes(32), waitLimit = 5000} = {}) {
  for (const item of h.simulator.data.items) item.status ??= 'open';
  const guard = createGuard({appId: 'fixture', runId, folder, key, rules: RULES, clock: () => h.now});
  guard.setOwner({email: OWNER_EMAIL, timeZone: ZONE, runDate: RUN_DATE, recorded: {}});
  const provider = async options => {
    const answer = await h.simulator.request(options);
    if (String(options.method).toUpperCase() === 'PATCH') h.simulator.write({name: TITLE});
    return answer;
  };
  const permissions = new PermissionManager({store: h.store, groups: h.groups, configs: h.configs}), proxyPolicy = new ProxyPolicy({store: h.store, permissions, groups: h.groups, configs: h.configs});
  const runtime = new Runtime({store: h.store, permissions, proxyPolicy, connections: h.connections, request: guard.wrap(provider), clock: () => h.now, actions: h.catalog, ownerPrincipal: OWNER, certification: true});
  runtime.wait = async ms => { h.advance(ms); };
  const protocol = new FabricProtocol({store: h.store, runtime, clock: () => h.now, origin: ORIGIN});
  runtime.authorizeSource = job => protocol.authorizeJob(job);
  const engine = new TriggerEngine({store: h.store, runtime, clock: () => h.now, random: () => 0, certification: true});
  const subscriptions = new SubscriptionService({store: h.store, runtime, protocol, triggers: engine, clock: () => h.now, origin: ORIGIN, appName: id => id});
  protocol.subscriptions = subscriptions;
  engine.notify = clientId => subscriptions.notify(clientId);
  t.after(() => subscriptions.close());
  const port = harnessPort({store: h.store, runtime, protocol, origin: ORIGIN, triggers: engine}, {owner: OWNER});
  const checked = plan ? checkTriggerPlan(plan, planDeps(h)) : null, state = openRunState(folder, 'fixture', runId, {runDate: RUN_DATE, timeZone: ZONE, recorded: {}});
  const approveJob = runtime.approve.bind(runtime), approveWatch = subscriptions.approve.bind(subscriptions);
  runtime.approve = () => { throw new Error('Only the owner approves.'); };
  subscriptions.approve = () => { throw new Error('Only the owner approves.'); };
  const r = {h, guard, port, runtime, protocol, engine, subscriptions, checked, state, folder, key, runId, permissions, proxyPolicy, lines: [], links: [], prompts: [], waits: [], approvals: [],
    feedReads: () => h.simulator.reads().filter(call => call.path === '/feed').length,
    /** The owner's approval, on the owner's own path, of a watch at the digest the page shows now. */
    approveWatch: id => approveWatch(id, subscriptions.ownerFacts(subscriptions.record(id)).digest, OWNER),
    run: (options = {}) => runLiveTests(port, checked, {guard, state, prompt: r.prompt, say: r.say, clock: () => h.now, wait: r.wait, ...options}),
    done: () => chain,
    say(line) {
      r.lines.push(String(line));
      const link = /^Approve: http:\/\/127\.0\.0\.1:4320\/approve\/([0-9a-f-]{36})$/.exec(line);
      if (!link) return;
      r.links.push(link[1]);
      if (!approve) return;
      if (subscriptions.record(link[1])) r.approvals.push(r.approveWatch(link[1]).status);
      else chain = chain.then(() => approveJob(link[1], h.store.get('jobs', link[1]).approvalDigest, OWNER)).then(job => r.approvals.push(job.status));
    },
    async prompt(words) { r.prompts.push(String(words)); return onPrompt(r, words) ?? ''; },
    async wait(ms) {
      if (r.waits.push(ms) > waitLimit) throw new Error('The runner waited too long.');
      h.advance(ms);
      onWait(r);
      await new Promise(resolve => setImmediate(resolve));
    }};
  let chain = Promise.resolve();
  return r;
}
const passedAll = run => { assert.equal(run.stopped, null, JSON.stringify(run.stopped)); for (const id of run.order) assert.equal(run.results[id].passed, true, `${id}: ${run.results[id].words}`); };
const stoppedAt = (run, id, words) => { assert.equal(run.stopped?.test, id, JSON.stringify(run.stopped)); assert.match(run.stopped.words, words); };
const watchOf = (r, name) => r.h.store.get('subscriptions', r.state.data.saved[name]);
/** A write of a hand, and one poll that tells it: the plan's plainest test. */
const oneWrite = (id, name = 'sub1') => ({id, name: 'One write', steps: [handWrite, poll(name, {events: 1})], undo: KEPT});

test('run 1: a watch reaches active through its one card, a write gives one event, a re-poll gives zero, and the owner alone approved', async t => {
  const r = triggerRun(t, {onPrompt: ({h}) => { h.simulator.write({name: TITLE}); }, plan: triggerPlan([opening(), {id: 'T1', name: 'A write on an action', steps: [callWrite, poll('sub1', {events: 1, checks: [{pointer: '/events/0/fields/id', present: true}, {status: 200}]}), poll('sub1', {events: 0})], undo: KEPT},
    {id: 'T2', name: 'A hand write', steps: [handWrite, poll('sub2', {events: 2}), poll('sub2', {events: 0, itemsRead: 2})], undo: KEPT}])});
  const run = await r.run();
  await r.done();
  passedAll(run);
  assert.deepEqual(r.links.length, 3, 'two watches and one write, each with one link');
  assert.deepEqual(r.approvals, ['starting', 'starting', 'succeeded']);
  assert.deepEqual(run.order, ['W1', 'T1', 'T2']);
  assert.ok(r.guard.trace('W1').length > 0 && r.guard.trace('T1').some(item => item.method === 'PATCH'), 'each request ran inside its test, so the guard saw it');
  assert.equal(new Set(Object.values(run.saved)).size, 2, 'two watches, each saved under its own name');
});

test('run 2: a watch outlives each test\'s grant, on its own grant, which the run revokes at its end', async t => {
  const during = [], r = triggerRun(t, {plan: triggerPlan([opening(), {id: 'T1', name: 'While it runs', steps: [handWrite, poll('sub1', {events: 1})], undo: KEPT}]), onPrompt(r) {
    r.h.simulator.write({name: TITLE});
    const grant = r.state.data.watchGrant;
    during.push(grant, r.h.store.get('clientGrants', grant).status, watchOf(r, 'sub1').clientId, watchOf(r, 'sub1').status, r.h.store.get('clientGrants', r.state.data.grant).name);
  }});
  const run = await r.run();
  passedAll(run);
  assert.deepEqual([during[1], during[3]], ['active', 'active'], 'W1\'s test grant has gone, and the watch still stands');
  assert.equal(during[2], during[0], 'the watch belongs to the run\'s grant');
  assert.match(r.h.store.get('clientGrants', during[0]).name, /^Live test watches /);
  assert.match(during[4], /^Live test T1 /, 'a test still has its own');
  assert.equal(run.watchGrant, null);
  assert.equal(r.h.store.get('clientGrants', during[0]).status, 'revoked', 'its own end');
  assert.deepEqual(r.h.store.list('clientGrants').filter(item => item.status === 'active' && item.name.startsWith('Live test')), []);
  // An action plan has no slot, so its run file is as it was.
  const plain = triggerRun(t, {plan: null});
  assert.equal(Object.hasOwn(plain.state.data, 'watchGrant'), false);
});

test('run 3: `watch` sends nothing before the owner approves, and ends only at active', async t => {
  const late = triggerRun(t, {keys: ['feed-logged'], approve: false, plan: triggerPlan([opening(['feed-logged'])]), onWait(r) {
    if (r.links.length && r.waits.length === 5) { r.seenBefore = r.feedReads(); r.approveWatch(r.links[0]); }
  }});
  passedAll(await late.run());
  assert.equal(late.seenBefore, 0, 'nothing read before the card was approved');
  assert.equal(late.links.length, 1, 'one card, however long the owner takes');
  assert.ok(late.feedReads() > 0);
  // A baseline that fails stays at starting, so the step polls again, a poll's spacing apart, and ends only when the watch is active.
  const slow = triggerRun(t, {keys: ['feed-logged'], plan: triggerPlan([opening(['feed-logged'])])});
  slow.h.simulator.fail('GET /feed', {status: 500, data: {error: 'busy'}}, {times: 2});
  passedAll(await slow.run());
  assert.ok(slow.waits.filter(ms => ms === PLAN_LIMITS.feedPollMs).length >= 2, JSON.stringify(slow.waits));
  assert.equal(slow.state.data.results.W1.checks.filter(check => /is active/.test(check.name)).every(check => check.passed), true);
  // A baseline that never ends fails, and does not pass as a watch.
  const never = triggerRun(t, {keys: ['feed-logged'], plan: triggerPlan([opening(['feed-logged'])])});
  never.h.simulator.fail('GET /feed', {status: 500, data: {error: 'busy'}}, {times: Infinity});
  stoppedAt(await never.run(), 'W1', /did not reach active within 5 minutes/);
});

test('run 4: a card declined, or one that lapses, fails the test, and so does a watch that pauses on its way to active', async t => {
  const declined = triggerRun(t, {keys: ['feed-logged'], approve: false, plan: triggerPlan([opening(['feed-logged'])]), onWait(r) { if (r.links.length && r.waits.length === 3) r.subscriptions.decline(r.links[0], OWNER); }});
  stoppedAt(await declined.run(), 'W1', /The watch ended declined, not active/);
  const lapsed = triggerRun(t, {keys: ['feed-logged'], approve: false, plan: triggerPlan([opening(['feed-logged'])]), onWait(r) { if (r.links.length) r.h.advance(3_600_000); }});
  stoppedAt(await lapsed.run(), 'W1', /The card lapsed before it was approved/);
  const paused = triggerRun(t, {keys: ['feed-logged'], plan: triggerPlan([opening(['feed-logged'])])});
  paused.h.simulator.fail('GET /feed', {status: 403, data: {error: 'refused'}}, {times: Infinity});
  stoppedAt(await paused.run(), 'W1', /The watch ended paused \(provider_refused\), not active/);
});

test('run 5: `poll` counts exactly, a poll\'s spacing apart until `within` ends, and with a zero it waits `within` out, then polls once', async t => {
  // An event that lands late is waited for, ten seconds apart, and the step stops as soon as the count is reached.
  const late = triggerRun(t, {keys: ['feed-logged'], plan: triggerPlan([opening(['feed-logged']), {id: 'T1', name: 'Late', steps: [handWrite, poll('sub1', {events: 1, within: 120})], undo: KEPT}]), onWait(r) { if (r.waits.filter(ms => ms === PLAN_LIMITS.feedPollMs).length === 3 && !r.wrote) { r.wrote = true; r.h.simulator.write({name: TITLE}); } }});
  passedAll(await late.run());
  assert.deepEqual(late.waits.filter(ms => ms === PLAN_LIMITS.feedPollMs).length, 3, 'three waits, then the count');
  // One that never lands fails at the end of `within`, with its count, and no more polls than that fits.
  const none = triggerRun(t, {keys: ['feed-logged'], plan: triggerPlan([opening(['feed-logged']), {id: 'T1', name: 'Never', steps: [handWrite, poll('sub1', {events: 1, within: 60})], undo: KEPT}])});
  const reads = await none.run();
  stoppedAt(reads, 'T1', /The poll read 0 events, not 1/);
  assert.equal(none.waits.filter(ms => ms === PLAN_LIMITS.feedPollMs).length, 6);
  // Exact: one more than the plan says fails.
  const extra = triggerRun(t, {keys: ['feed-logged'], onPrompt: ({h}) => { h.simulator.write({name: TITLE}); h.simulator.write({name: TITLE}); }, plan: triggerPlan([opening(['feed-logged']), oneWrite('T1')])});
  stoppedAt(await extra.run(), 'T1', /The poll read 2 events, not 1/);
  // A zero waits `within` out once, then polls once, and an event that landed in that wait fails it.
  const quiet = triggerRun(t, {keys: ['feed-logged'], plan: triggerPlan([opening(['feed-logged']), {id: 'T1', name: 'Quiet', steps: [poll('sub1', {events: 0, within: 90})]}])});
  const before = [];
  quiet.engine.pollNow = (original => id => { before.push(quiet.h.now); return original(id); })(quiet.engine.pollNow.bind(quiet.engine));
  passedAll(await quiet.run());
  assert.ok(quiet.waits.includes(90_000), JSON.stringify(quiet.waits));
  assert.equal(before.at(-1) - before.at(-2) >= 90_000, true, 'the last poll came after the wait');
  const landed = triggerRun(t, {keys: ['feed-logged'], plan: triggerPlan([opening(['feed-logged']), {id: 'T1', name: 'Not quiet', steps: [poll('sub1', {events: 0, within: 90})]}]), onWait(r) { if (r.waits.includes(90_000) && !r.wrote) { r.wrote = true; r.h.simulator.write({name: TITLE}); } }});
  stoppedAt(await landed.run(), 'T1', /The poll read 1 events, not 0/);
});

test('run 6: a zero passes only if the provider answered', async t => {
  const zero = (arrange, more = {}) => {
    const r = triggerRun(t, {keys: ['feed-logged'], plan: triggerPlan([opening(['feed-logged']), {id: 'T1', name: 'A zero', steps: [handWrite, poll('sub1', {events: 0})], undo: KEPT}]), onPrompt: arrange, ...more});
    return r.run();
  };
  // Each of these read nothing, so a zero proves nothing: a skip sends no request, and a limit, a server's failure and a lost connection read no list.
  stoppedAt(await zero(({h}) => { h.store.put('connections', {...h.store.get('connections', h.account), status: 'reconnect_required'}); }), 'T1', /no provider answer/);
  stoppedAt(await zero(({h}) => { h.simulator.fail('GET /feed', {status: 429, headers: {'retry-after': '1'}, data: {error: 'slow'}}); }), 'T1', /no provider answer/);
  stoppedAt(await zero(({h}) => { h.simulator.fail('GET /feed', {status: 503, data: {error: 'busy'}}); }), 'T1', /no provider answer/);
  stoppedAt(await zero(({h}) => { h.simulator.drop('GET /feed'); }), 'T1', /no provider answer/);
  // A watch that paused sends nothing, and the run the feed last kept is an older poll's.
  stoppedAt(await zero(({h}) => { h.setRow('fixture.items.read', 'deny'); }), 'T1', /no provider answer/);
  const passing = await zero(() => {});
  passedAll(passing);
  const check = passing.results.T1.checks.find(item => /the provider answered/.test(item.name));
  assert.equal(check?.passed, true);
  // A 304 is an answer, and a check can ask for one.
  const cached = triggerRun(t, {keys: ['feed-tagged'], plan: triggerPlan([opening(['feed-tagged']), {id: 'T1', name: 'Nothing changed', steps: [poll('sub1', {events: 0, checks: [{status: 304}]})]}])});
  passedAll(await cached.run());
  assert.equal(cached.h.store.get('triggerRuns', watchOf(cached, 'sub1').feeds[0]).runs.at(-1).outcome, 'not_modified');
});

test('run 7: a poll reads its own watch: `itemsRead` asks that the read saw the items again, `gaps` is exact, `where` narrows the count, and its checks read the events', async t => {
  const r = triggerRun(t, {keys: ['feed-listed', 'feed-logged'], onPrompt: ({h}) => { h.simulator.write({name: TITLE}); }, plan: triggerPlan([opening(['feed-listed', 'feed-logged']), {id: 'T1', name: 'A write', steps: [handWrite,
    poll('sub1', {events: 1, where: {'/fields/name': TITLE}, checks: [{pointer: '/events/0/fields/name', equals: TITLE}, {pointer: '/events', count: 1}, {pointer: '/gaps', count: 0}]}),
    poll('sub2', {events: 1}), poll('sub1', {events: 0, itemsRead: 1})], undo: KEPT}])});
  passedAll(await r.run());
  // Each poll took only its own watch's rows out of the one client feed the two share.
  const wrongItems = triggerRun(t, {keys: ['feed-listed', 'feed-logged'], plan: triggerPlan([opening(['feed-listed', 'feed-logged']), {id: 'T1', name: 'An empty list', steps: [poll('sub1', {events: 0, itemsRead: 1})]}])});
  stoppedAt(await wrongItems.run(), 'T1', /read 0 items, not at least 1/);
  const otherName = triggerRun(t, {keys: ['feed-listed', 'feed-logged'], onPrompt: ({h}) => { h.simulator.write({name: TITLE}); }, plan: triggerPlan([opening(['feed-listed', 'feed-logged']), {id: 'T1', name: 'Not this name', steps: [handWrite, poll('sub1', {events: 0, where: {'/fields/name': 'Another'}})], undo: KEPT}])});
  passedAll(await otherName.run());
  const wrongCheck = triggerRun(t, {keys: ['feed-listed', 'feed-logged'], onPrompt: ({h}) => { h.simulator.write({name: TITLE}); }, plan: triggerPlan([opening(['feed-listed', 'feed-logged']), {id: 'T1', name: 'A check', steps: [handWrite, poll('sub1', {events: 1, checks: [{pointer: '/events/0/fields/name', equals: 'Another'}]})], undo: KEPT}])});
  stoppedAt(await wrongCheck.run(), 'T1', /A check did not hold/);
  assert.equal(wrongCheck.state.data.results.T1.checks.some(check => check.passed === false), true);
  // A gap nobody planned for fails the count: a gap says something was not told.
  const stray = triggerRun(t, {keys: ['feed-logged'], plan: triggerPlan([opening(['feed-logged']), {id: 'T1', name: 'A stray gap', steps: [handWrite, poll('sub1', {events: 0})], undo: KEPT}]), onPrompt: ({h}) => { h.simulator.expireCursors(); }});
  stoppedAt(await stray.run(), 'T1', /The poll read 1 gaps, not 0/);
});

test('run 13: `floor` asks that the wait a provider named reached the feed, and the port tells it as a time alone', async t => {
  const FLOORED = ['feed-modified'], plan = floor => triggerPlan([opening(FLOORED), {id: 'T1', name: 'A floor', steps: [handWrite, poll('sub1', {events: 1, floor})], undo: KEPT}]);
  const played = seconds => {
    const r = triggerRun(t, {keys: FLOORED, plan: plan(30), onPrompt: ({h}) => { h.simulator.write({name: TITLE}); }});
    if (seconds) r.h.simulator.pollInterval(seconds);
    return r;
  };
  const kept = played(60);
  passedAll(await kept.run());
  assert.deepEqual(kept.state.data.results.T1.checks.filter(check => /floor/.test(check.name)).map(check => check.passed), [true]);
  const [at] = kept.port.floors(kept.state.data.saved.sub1);
  assert.equal(at, kept.h.store.get('triggerFeeds', watchOf(kept, 'sub1').feeds[0]).notBefore, 'a time, and no cursor');
  assert.ok(at > kept.h.now);
  stoppedAt(await played(0).run(), 'T1', /The provider's interval holds this watch 0 seconds, not at least 30/);
  stoppedAt(await played(10).run(), 'T1', /The provider's interval holds this watch 10 seconds, not at least 30/);
  assert.deepEqual(kept.port.floors('none'), []);
  // A watch that holds no feed has no floor, whatever a plan asks: a client's end takes its feeds, and a floor must not pass on nothing.
  const gone = played(60), stale = {...gone.port, floors: () => []};
  gone.run = options => runLiveTests(stale, gone.checked, {guard: gone.guard, state: gone.state, prompt: gone.prompt, say: gone.say, clock: () => gone.h.now, wait: gone.wait, ...options});
  stoppedAt(await gone.run(), 'T1', /The provider's interval holds this watch 0 seconds, not at least 30/);
});

test('run 8: `poll` with `paused` passes on no request, that reason and no provider answer, and turns round on anything else', async t => {
  const never = ({h}) => { h.setRow('fixture.items.read', 'deny'); };
  const plan = (reason, keys = ['feed-logged']) => triggerPlan([opening(keys), {id: 'T8', name: 'Never', steps: [{owner: {words: 'Set the row to Never.'}}, poll('sub1', {paused: reason}), poll('sub1', {paused: reason})], undo: KEPT}]);
  const r = triggerRun(t, {keys: ['feed-logged'], plan: plan('permission_changed'), onPrompt: never}), run = await r.run();
  passedAll(run);
  assert.deepEqual(run.results.T8.checks.map(check => [check.name, check.passed]), [['step 2: paused permission_changed, no request and no answer', true], ['step 3: paused permission_changed, no request and no answer', true]]);
  assert.equal(r.guard.trace('T8').length, 0, 'zero requests, and the second poll stays paused');
  // The wrong reason, or a watch that still runs, fails.
  stoppedAt(await triggerRun(t, {keys: ['feed-logged'], plan: plan('background_off'), onPrompt: never}).run(), 'T8', /paused \(permission_changed\), and the plan asks for background_off/);
  stoppedAt(await triggerRun(t, {keys: ['feed-logged'], plan: plan('permission_changed')}).run(), 'T8', /active/);
  // A request sent fails it, even with the right reason: another watch on the feed keeps its reads going.
  const shared = triggerRun(t, {keys: ['feed-logged', 'feed-logged-keys'], onPrompt: ({h}) => { h.setRow('fixture.keys.read', 'deny'); }, h: (() => { const h = candidates(t, ['feed-logged', 'feed-logged-keys']); h.setRow('fixture.keys.read', 'allow'); return h; })(),
    plan: triggerPlan([opening(['feed-logged', 'feed-logged-keys']), {id: 'T8', name: 'Never', steps: [{owner: {words: 'Set the row to Never.'}}, poll('sub2', {paused: 'permission_changed'})], undo: KEPT}])});
  stoppedAt(await shared.run(), 'T8', /1 request/);
});

test('run 9: a tick in a certification Fabric sends nothing: the engine starts no timer, and between tests the guard refuses', async t => {
  const r = triggerRun(t, {keys: ['feed-logged']});
  r.engine.start();
  assert.equal(r.engine.timer, null, 'no timer');
  const grant = r.port.grant({name: 'A grant', connectionId: r.h.account, rows: ['fixture.items.read'], expiresInSeconds: 600});
  const {result} = await r.port.call(grant.id, 'triggers.subscribe', {triggerId: r.h.triggerId('feed-logged'), connectionId: r.h.account, args: {}}, 'tick-1');
  r.approveWatch(result.id);
  r.h.advance(5000);
  await r.engine.tick();
  assert.equal(r.feedReads(), 0, 'no request reached the provider');
  const [run] = r.h.store.get('triggerRuns', r.h.store.get('subscriptions', result.id).feeds[0]).runs;
  assert.deepEqual([run.status, run.outcome], [null, 'backoff'], 'the guard refused it before it left this machine, and no store moved');
  assert.deepEqual(r.h.store.get('subscriptions', result.id).status, 'starting', 'nothing it read turned the watch on');
});

test('run 10: a resume revokes the grant it finds and runs the opening watch test again, on a new grant, then goes on from the test that stopped', async t => {
  let writes = 0;
  const r = triggerRun(t, {keys: ['feed-logged'], onPrompt: ({h}) => { if (writes++ > 0) h.simulator.write({name: TITLE}); }, plan: triggerPlan([opening(['feed-logged']), oneWrite('T1')])});
  const first = await r.run();
  stoppedAt(first, 'T1', /The poll read 0 events, not 1/);
  const firstWatch = first.saved.sub1, firstGrant = watchOf(r, 'sub1').clientId;
  assert.equal(r.h.store.get('clientGrants', firstGrant).status, 'revoked', 'a run that stopped holds no grant');
  // An earlier process died with its grant in the run file.
  const left = r.port.grant({name: 'Left by a process that died', connectionId: r.h.account, rows: ['fixture.items.read'], expiresInSeconds: 600});
  first.watchGrant = left.id;
  r.state.save();
  const second = await r.run();
  passedAll(second);
  assert.equal(r.h.store.get('clientGrants', left.id).status, 'revoked');
  assert.notEqual(second.saved.sub1, firstWatch, 'a new watch');
  assert.notEqual(watchOf(r, 'sub1').clientId, firstGrant, 'on a new grant');
  assert.equal(r.links.length, 2, 'one card each');
  assert.equal(second.order.join(), 'W1,T1');
  // A later test that had passed is not run again: its write has gone.
  let asked = 0;
  const done = triggerRun(t, {keys: ['feed-logged'], onPrompt: ({h}) => { asked++; h.simulator.write({name: TITLE}); }, plan: triggerPlan([opening(['feed-logged']), oneWrite('T1'), {id: 'T2', name: 'Stops', steps: [poll('sub1', {events: 1})]}])});
  stoppedAt(await done.run(), 'T2', /The poll read 0 events, not 1/);
  const resumed = await done.run();
  assert.equal(asked, 1, 'T1 did not run again');
  stoppedAt(resumed, 'T2', /The poll read 0 events, not 1/);
  // With --from the same holds: the opening test runs, then that test.
  const from = await done.run({from: 'T2'});
  stoppedAt(from, 'T2', /The poll read 0 events, not 1/);
  assert.equal(asked, 1);
  assert.equal(done.links.length, 3, 'a card for each opening');
  // A run with nothing left to run binds nothing.
  const passing = triggerRun(t, {keys: ['feed-logged'], plan: triggerPlan([opening(['feed-logged'])])});
  passedAll(await passing.run());
  const count = passing.h.store.list('clientGrants').length;
  passedAll(await passing.run());
  assert.equal(passing.h.store.list('clientGrants').length, count);
});

test('run 11: `unwatch` removes the watch through the agent\'s own call, and its feed goes with it', async t => {
  const r = triggerRun(t, {keys: ['feed-logged'], plan: triggerPlan([opening(['feed-logged']), {id: 'T1', name: 'Remove', steps: [{unwatch: {subscription: saved('sub1')}}]}])});
  const feed = () => r.h.store.list('triggerFeeds').length;
  passedAll(await r.run());
  assert.deepEqual([watchOf(r, 'sub1').status, feed()], ['removed', 0]);
  const gone = triggerRun(t, {keys: ['feed-logged'], plan: triggerPlan([opening(['feed-logged']), {id: 'T1', name: 'Remove twice', steps: [{unwatch: {subscription: saved('sub1')}}, poll('sub1', {events: 0})]}])});
  stoppedAt(await gone.run(), 'T1', /no provider answer/);
});

test('run 12: an ask step\'s request carries its body, filled, as the card shows it and the guard reads it', async t => {
  const h = candidates(t, ['feed-logged']);
  h.setRow('fixture.items.edit', 'ask');
  const seen = [], r = triggerRun(t, {h, plan: triggerPlan([opening(['feed-logged']), {id: 'T1', name: 'An ask', steps: [{ask: {row: 'fixture.items.edit', requests: [{method: 'PATCH', path: '/items/{item}', params: {item: 'I1'}, body: {name: {$text: 'renamed'}}}]}}], undo: KEPT}])});
  r.h.simulator.request = (original => options => { if (options.method === 'PATCH') seen.push(JSON.parse(String(options.body))); return original(options); })(r.h.simulator.request.bind(r.h.simulator));
  passedAll(await r.run());
  await r.done();
  assert.deepEqual(seen, [{name: `[SYNTHETIC] Fabric T1 ${r.runId} renamed`}]);
});

// ---- ageCursor --------------------------------------------------------------------------------------------------------------------------------
test('age 1: ageCursor() runs only in a certification Fabric', async t => {
  const h = triggerHarness(t), engine = new TriggerEngine({store: h.store, runtime: h.runtime, clock: () => h.now, random: () => 0}), watched = h.watch('feed-logged', {status: 'starting'});
  engine.attach(watched);
  const before = h.store.get('triggerFeeds', h.store.get('subscriptions', watched.id).feeds[0]);
  await assert.rejects(engine.ageCursor(watched.id, '1'), /Only a certification Fabric can age a cursor/);
  assert.deepEqual(h.store.get('triggerFeeds', before.id), before, 'nothing was written');
  const handed = new TriggerEngine({store: h.store, runtime: h.runtime, clock: () => h.now, certification: 'yes'});
  await assert.rejects(handed.ageCursor(watched.id, '1'), /Only a certification Fabric can age a cursor/, 'the flag is the boolean the server sets');
});

test('age 2: it writes a value over a watch\'s own sync or history cursor, and nothing else, and refuses what has no such cursor', async t => {
  const r = triggerRun(t, {keys: ['feed-logged', 'feed-posted', 'feed-synced']});
  const grant = r.port.grant({name: 'A grant', connectionId: r.h.account, rows: ['fixture.items.read'], expiresInSeconds: 600});
  const watched = async key => { const {result} = await r.port.call(grant.id, 'triggers.subscribe', {triggerId: r.h.triggerId(key), connectionId: r.h.account, args: {}}, `age-${key}`); r.approveWatch(result.id); return result.id; };
  r.guard.begin('A1');
  t.after(() => r.guard.end());
  const logged = await watched('feed-logged'), synced = await watched('feed-synced'), posted = await watched('feed-posted');
  await assert.rejects(r.engine.ageCursor(logged, '1'), /This watch is not running/, 'a watch still catching up has no place to lose');
  for (const id of [logged, synced, posted]) await r.engine.pollNow(id);
  const feedOf = id => r.h.store.get('triggerFeeds', r.h.store.get('subscriptions', id).feeds[0]), stored = feedOf(logged), other = feedOf(synced);
  // A walk cut part way would read on from its page, and never send the value.
  r.h.store.put('triggerFeeds', {...stored, page: {token: 'next', walk: 'delta'}});
  const answer = await r.engine.ageCursor(logged, '1');
  assert.equal(answer.id, logged);
  assert.deepEqual(feedOf(logged), {...stored, cursors: {history: '1'}, page: null});
  assert.deepEqual(feedOf(synced), other, 'another watch\'s feed is left alone');
  await r.engine.ageCursor(synced, 'stale-token');
  assert.equal(feedOf(synced).cursors.sync, 'stale-token');
  await assert.rejects(r.engine.ageCursor(posted, '1'), /This watch has no cursor a stale value can age/, 'a time mark has no resync to prove');
  await assert.rejects(r.engine.ageCursor('no-such-watch', '1'), /This watch is not running/);
  for (const value of ['', 1, null, 'x'.repeat(2049)]) await assert.rejects(r.engine.ageCursor(logged, value), /A cursor value is text/, String(value));
});

test('age 3: an `age` step gives each watch on the feed one gap, repeats nothing, and proves the resync', async t => {
  const keys = ['feed-logged', 'feed-logged-detail'], r = triggerRun(t, {keys, onPrompt: ({h}) => { h.simulator.write({name: TITLE}); }, plan: triggerPlan([opening(keys), {id: 'TG7', name: 'A stale cursor', steps: [handWrite, poll('sub1', {events: 1}), poll('sub2', {events: 1}), handWrite,
    {age: {subscription: saved('sub1'), value: '1'}}, poll('sub1', {events: 0, gaps: 1, checks: [{pointer: '/gaps/0/fields/reason', equals: 'resync'}]}), poll('sub2', {events: 0, gaps: 1}), handWrite, poll('sub1', {events: 1}), poll('sub1', {events: 0})], undo: KEPT}])});
  const run = await r.run();
  passedAll(run);
  assert.ok(r.guard.trace('TG7').some(item => item.status === 404), 'the provider refused the stale value');
  const polls = run.results.TG7.polls, gapped = polls.filter(item => item.gaps > 0);
  assert.deepEqual(gapped.map(item => [item.gaps, item.resyncStatus, item.duplicates]), [[1, 404, 0], [1, 404, 0]]);
});

test('age 4: a poll after an `age` fails on an event told twice', async t => {
  const r = triggerRun(t, {keys: ['feed-logged'], onPrompt: ({h}) => { h.simulator.write({name: TITLE}); }, plan: triggerPlan([opening(['feed-logged']), {id: 'T1', name: 'Twice', steps: [handWrite, poll('sub1', {events: 1}), {age: {subscription: saved('sub1'), value: '1'}}, poll('sub1', {events: 1, gaps: 1})], undo: KEPT}])});
  // A resync that repeats what the first poll told, as a new row of the same item.
  const read = r.engine.pollNow.bind(r.engine);
  r.engine.pollNow = async id => {
    const answer = await read(id), {clientId, feeds} = r.h.store.get('subscriptions', id), told = r.h.store.listEvents(clientId, 0, 100).find(row => row.kind === 'trigger.event');
    if (r.state.data.results.T1?.aged !== undefined) r.h.store.appendPoll({feedId: feeds[0], events: [{clientId, subscriptionId: id, dedupeKey: 'again', connectionId: told.connectionId, userRecordId: null, kind: 'trigger.event', createdAt: r.h.now, expiresAt: r.h.now + 3_600_000, payload: told.payload}]});
    return answer;
  };
  stoppedAt(await r.run(), 'T1', /1 events were told twice/);
});

// ---- the evidence ---------------------------------------------------------------------------------------------------------------------------------
/** A finished run's records, with the fake app's pins and rows. */
const evidenceOf = (r, options = {}) => triggerEvidenceRecords(r.state.data, {key: r.key, entries: appEntries(r.h, 'triggers'), actions: appEntries(r.h, 'entries'), trace: id => r.guard.trace(id), job: id => r.port.job(id), pins: REGISTRY_PINS,
  codeHashes: ids => Object.fromEntries(ids.map(id => [id, REGISTRY_PINS[id]])), groups: r.h.groups, configs: r.h.configs, maps: new Map([['fixture', fixtureMap()]]), ...options});
const proved = keys => triggerPlan([opening(keys), ...keys.map((_key, index) => ({id: `T${index + 1}`, name: 'One write, then none', steps: [callWrite, poll(`sub${index + 1}`, {events: 1}), poll(`sub${index + 1}`, {events: 0})], undo: KEPT}))]);

test('evidence 1: one record per trigger id, holding what a run proved in counts, statuses and keyed ids, and it certifies a trigger', async t => {
  const r = triggerRun(t, {keys: ['feed-synced'], plan: proved(['feed-synced'])});
  const run = await r.run();
  await r.done();
  passedAll(run);
  const entry = appEntries(r.h, 'triggers')[0], {records, run: facts} = evidenceOf(r), record = records[entry.id];
  assert.deepEqual(Object.keys(records), [entry.id]);
  assert.deepEqual(Object.keys(record).sort(), ['harnessHash', 'passed', 'ranAt', 'runId', 'runtime', 'schemaVersion', 'tests', 'transforms']);
  assert.deepEqual([record.schemaVersion, record.passed, record.runId, record.ranAt], [1, true, r.runId, run.finishedAt]);
  assert.deepEqual(record.tests.map(item => item.test), ['W1', 'T1']);
  const [watching, wrote] = record.tests;
  assert.deepEqual(Object.keys(wrote).sort(), ['passed', 'proof', 'requests', 'test', 'write']);
  assert.deepEqual(wrote.proof, {baseline: 0, afterWrite: 1, repoll: 0});
  assert.deepEqual(watching.proof, {baseline: 0});
  assert.equal(watching.write, null);
  assert.equal(wrote.write.action, 'update-item@1');
  assert.deepEqual(wrote.write.jobs.map(job => job.status), ['succeeded']);
  assert.match(wrote.write.jobs[0].id, /^hmac:[0-9a-f]{32}$/, 'a job id as a keyed hash');
  const seen = new Set(wrote.requests.map(item => `${item.method} ${item.template} ${item.status}`));
  for (const line of ['GET /feed 200', 'PATCH /items/{item_id} 200']) assert.ok(seen.has(line), [...seen].join());
  assert.ok(wrote.requests.every(item => Object.keys(item).sort().join() === 'method,status,template' && item.template !== null), JSON.stringify(wrote.requests));
  assert.deepEqual(facts.tests, [], 'every test here belongs to a trigger');
  assert.deepEqual([facts.runId, facts.appId], [r.runId, 'fixture']);
  assert.equal(triggerEvidencePasses(entry, record, REGISTRY_PINS), true, 'what the start reads certifies it');
});

test('evidence 2: a record certifies nothing without a write\'s one event and a re-poll\'s zero, without its current pins, or for a history trigger without a resync', async t => {
  const noRepoll = triggerRun(t, {keys: ['feed-synced'], plan: triggerPlan([opening(['feed-synced']), {id: 'T1', name: 'One write', steps: [callWrite, poll('sub1', {events: 1})], undo: KEPT}])});
  passedAll(await noRepoll.run());
  await noRepoll.done();
  const [entry] = appEntries(noRepoll.h, 'triggers'), record = evidenceOf(noRepoll).records[entry.id];
  assert.deepEqual(record.tests.at(-1).proof, {baseline: 0, afterWrite: 1});
  assert.equal(triggerEvidencePasses(entry, record, REGISTRY_PINS), false);
  // A poll of nothing written proves nothing, however it reads.
  const noWrite = triggerRun(t, {keys: ['feed-synced'], plan: triggerPlan([opening(['feed-synced']), {id: 'T1', name: 'No write', steps: [poll('sub1', {events: 0}), poll('sub1', {events: 0})]}])});
  passedAll(await noWrite.run());
  assert.equal(triggerEvidencePasses(appEntries(noWrite.h, 'triggers')[0], evidenceOf(noWrite).records[appEntries(noWrite.h, 'triggers')[0].id], REGISTRY_PINS), false);
  // A write the watch told nothing of proves nothing: the re-poll of a zero is no certificate.
  const noEvent = triggerRun(t, {keys: ['feed-synced'], plan: triggerPlan([opening(['feed-synced']), {id: 'T1', name: 'Nothing told', steps: [handWrite, poll('sub1', {events: 0}), poll('sub1', {events: 0})], undo: KEPT}])});
  passedAll(await noEvent.run());
  assert.deepEqual(evidenceOf(noEvent).records[appEntries(noEvent.h, 'triggers')[0].id].tests.at(-1).proof, {baseline: 0, afterWrite: 0, repoll: 0});
  // A moved pin fails the record, and a history trigger owes a resync.
  const moved = triggerRun(t, {keys: ['feed-logged'], plan: proved(['feed-logged'])});
  passedAll(await moved.run());
  await moved.done();
  const [logged] = appEntries(moved.h, 'triggers'), loggedRecord = evidenceOf(moved).records[logged.id];
  assert.equal(loggedRecord.passed, true);
  assert.equal(triggerEvidencePasses(logged, loggedRecord, REGISTRY_PINS), false, 'one write and one zero do not prove a stale cursor');
  const pin = logged.transforms[0], stale = evidenceOf(moved, {codeHashes: ids => Object.fromEntries(ids.map(id => [id, 'moved']))}).records[logged.id];
  assert.equal(typeof pin, 'string');
  assert.equal(stale.passed, false);
  // With its resync, it passes.
  const keys = ['feed-logged'], aged = triggerRun(t, {keys, onPrompt: ({h}) => { h.simulator.write({name: TITLE}); }, plan: triggerPlan([opening(keys), {id: 'TG7', name: 'One write, a stale cursor', steps: [handWrite, poll('sub1', {events: 1}), poll('sub1', {events: 0}), {age: {subscription: saved('sub1'), value: '1'}}, poll('sub1', {events: 0, gaps: 1}), poll('sub1', {events: 0})], undo: KEPT}])});
  passedAll(await aged.run());
  const agedRecord = evidenceOf(aged).records[appEntries(aged.h, 'triggers')[0].id];
  assert.deepEqual(agedRecord.tests.at(-1).proof, {baseline: 0, afterWrite: 1, repoll: 0, resync: {status: 404, gapEvents: 1, duplicates: 0}});
  assert.equal(triggerEvidencePasses(appEntries(aged.h, 'triggers')[0], agedRecord, REGISTRY_PINS), true);
});

test('evidence 3: two watches of one trigger in one test keep apart, so a zero on one is no re-poll of the other', async t => {
  const r = triggerRun(t, {keys: ['feed-updated'], onPrompt: ({h}) => { h.simulator.write({kind: 'note', name: TITLE}); }, plan: triggerPlan([{id: 'W1', name: 'Two watches', steps: [watch('feed-updated@1', 'sub1', {kinds: ['note']}), poll('sub1', {events: 0}), watch('feed-updated@1', 'sub2', {kinds: ['task']}), poll('sub2', {events: 0})]},
    {id: 'T1', name: 'One write', steps: [handWrite, poll('sub1', {events: 1}), poll('sub2', {events: 0})], undo: KEPT}])});
  passedAll(await r.run());
  const [entry] = appEntries(r.h, 'triggers'), proof = evidenceOf(r).records[entry.id].tests.at(-1).proof;
  assert.equal(proof.repoll, undefined, JSON.stringify(proof));
});

test('evidence 4: a re-poll is the next poll with no write between, so a zero after another write proves nothing of the first', async t => {
  const r = triggerRun(t, {keys: ['feed-synced'], onPrompt: ({h}, words) => { if (words === handWrite.owner.words) h.simulator.write({name: TITLE}); }, plan: triggerPlan([opening(['feed-synced']), {id: 'T1', name: 'Two writes', steps: [handWrite, poll('sub1', {events: 1}), {owner: {words: 'A change this watch does not hear.'}}, poll('sub1', {events: 0})], undo: KEPT}])});
  passedAll(await r.run());
  const [entry] = appEntries(r.h, 'triggers'), {proof, write} = evidenceOf(r).records[entry.id].tests.at(-1);
  assert.deepEqual(proof, {baseline: 0, afterWrite: 1});
  assert.deepEqual(write, {action: 'owner', jobs: []}, 'the hand step it followed');
});

test('evidence 5: `afterWrite` is the first poll that told something, a pause is no re-poll, and only a stale value the run wrote proves a resync', async t => {
  const proofIn = r => evidenceOf(r).records[appEntries(r.h, 'triggers')[0].id].tests.at(-1).proof;
  // T5's shape: a write this watch does not hear, then one it does.
  const later = triggerRun(t, {keys: ['feed-synced'], onPrompt: ({h}, words) => { if (words === handWrite.owner.words) h.simulator.write({name: TITLE}); }, plan: triggerPlan([opening(['feed-synced']), {id: 'T1', name: 'Quiet, then told', steps: [{owner: {words: 'A change this watch does not hear.'}}, poll('sub1', {events: 0}), handWrite, poll('sub1', {events: 1}), poll('sub1', {events: 0})], undo: KEPT}])});
  passedAll(await later.run());
  assert.deepEqual(proofIn(later), {baseline: 0, afterWrite: 1, repoll: 0});
  // A watch that paused read nothing, so it is no re-poll, though it reads as a zero.
  const stopped = triggerRun(t, {keys: ['feed-synced'], onPrompt: ({h}) => { h.simulator.write({name: TITLE}); }, plan: triggerPlan([opening(['feed-synced']), {id: 'T1', name: 'Told, then Never', steps: [handWrite, poll('sub1', {events: 1}), poll('sub1', {paused: 'permission_changed'})], undo: KEPT}])});
  const read = stopped.engine.pollNow.bind(stopped.engine);
  stopped.engine.pollNow = id => { if (stopped.state.data.results.T1?.polls?.length === 1) stopped.h.setRow('fixture.items.read', 'deny'); return read(id); };
  passedAll(await stopped.run());
  assert.deepEqual(proofIn(stopped), {baseline: 0, afterWrite: 1});
  // A provider's own expiry is a true gap, and it is no proof: only a run that wrote the stale value knows what it asked.
  const natural = triggerRun(t, {keys: ['feed-logged'], onPrompt: ({h}) => { h.simulator.write({name: TITLE}); h.simulator.expireCursors(); }, plan: triggerPlan([opening(['feed-logged']), {id: 'T1', name: 'A cursor that lapsed', steps: [handWrite, poll('sub1', {events: 0, gaps: 1})], undo: KEPT}])});
  passedAll(await natural.run());
  assert.equal(natural.guard.trace('T1').some(item => item.status === 404), true);
  assert.equal(proofIn(natural).resync, undefined);
});

test('evidence 9: a resync\'s status is the one its block names, so a limit on another read after the `age` is no refusal of the stale value', async t => {
  const keys = ['feed-logged', 'feed-listed'], r = triggerRun(t, {keys, onPrompt: ({h}, words) => {
    if (words !== handWrite.owner.words) h.simulator.fail('GET /feed', {status: 429, headers: {'retry-after': '1'}, data: {error: 'slow'}});
    h.simulator.write({name: TITLE});
  }, plan: triggerPlan([opening(keys), {id: 'T1', name: 'A stale value, and a limit first', steps: [handWrite, poll('sub1', {events: 1}), poll('sub2', {events: 1}), {age: {subscription: saved('sub1'), value: '1'}}, {owner: {words: 'The next read is limited.'}},
    poll('sub2', {events: 1, within: 30}), poll('sub1', {events: 0, gaps: 1, checks: [{pointer: '/gaps/0/fields/reason', equals: 'resync'}]})], undo: KEPT}])});
  const run = await r.run();
  passedAll(run);
  assert.deepEqual(r.guard.trace('T1').map(item => item.status).filter(status => status >= 400), [429, 404], 'the limit came first');
  assert.deepEqual(evidenceOf(r).records[appEntries(r.h, 'triggers').find(entry => entry.key === 'feed-logged').id].tests.at(-1).proof.resync, {status: 404, gapEvents: 1, duplicates: 0});
});

test('evidence 10: a gap of another reason is no resync, so a proof reads only a gap that says the cursor was lost', async t => {
  const stale = reason => {
    const r = triggerRun(t, {keys: ['feed-logged'], onPrompt: ({h}) => { h.simulator.write({name: TITLE}); }, plan: triggerPlan([opening(['feed-logged']), {id: 'T1', name: 'A stale value', steps: [handWrite, poll('sub1', {events: 1}), {age: {subscription: saved('sub1'), value: '1'}}, poll('sub1', {events: 0, gaps: 1})], undo: KEPT}])});
    const seen = {...r.port, call: async (...args) => {
      const answer = await r.port.call(...args);
      for (const event of answer.result?.events ?? []) if (event.type === 'trigger.gap') event.fields.reason = reason;
      return answer;
    }};
    r.run = options => runLiveTests(seen, r.checked, {guard: r.guard, state: r.state, prompt: r.prompt, say: r.say, clock: () => r.h.now, wait: r.wait, ...options});
    return r;
  };
  const proofOf = async r => { passedAll(await r.run()); return evidenceOf(r).records[appEntries(r.h, 'triggers')[0].id].tests.at(-1).proof; };
  assert.deepEqual((await proofOf(stale('resync'))).resync, {status: 404, gapEvents: 1, duplicates: 0});
  assert.equal((await proofOf(stale('stall'))).resync, undefined);
});

test('evidence 6: a watch that never ran stays in its trigger\'s record, as a failure', async t => {
  const r = triggerRun(t, {keys: ['feed-synced'], approve: false, plan: triggerPlan([opening(['feed-synced'])]), onWait(r) { if (r.links.length && r.waits.length === 3) r.subscriptions.decline(r.links[0], OWNER); }});
  stoppedAt(await r.run(), 'W1', /The watch ended declined, not active/);
  const [entry] = appEntries(r.h, 'triggers'), {records, run} = evidenceOf(r);
  assert.deepEqual(records[entry.id].tests.map(item => [item.test, item.passed, item.proof]), [['W1', false, {}]]);
  assert.equal(records[entry.id].passed, false);
  assert.deepEqual(run.tests, [], 'it touched a trigger, so it does not read as a test of nothing');
});

test('evidence 7: a request nothing placed fails its test, a test with no trigger sits under run, and a failed test fails its record', async t => {
  const r = triggerRun(t, {keys: ['feed-synced'], plan: triggerPlan([{id: 'T0', name: 'Before any watch', steps: [{read: {path: '/items'}}]}, opening(['feed-synced']), {id: 'T1', name: 'Stops', steps: [handWrite, poll('sub1', {events: 1})], undo: KEPT}])});
  const run = await r.run();
  stoppedAt(run, 'T1', /The poll read 0 events, not 1/);
  const [entry] = appEntries(r.h, 'triggers'), {records, run: facts} = evidenceOf(r);
  assert.deepEqual(facts.tests.map(item => item.test), ['T0']);
  assert.equal(facts.tests[0].requests[0].template, '/items');
  assert.equal(records[entry.id].passed, false, 'the stop reached its record');
  assert.deepEqual(records[entry.id].tests.map(item => [item.test, item.passed]), [['W1', true], ['T1', false]]);
  const placed = evidenceOf(r, {trace: () => [{method: 'GET', path: '/somewhere/else', status: 200}]}).records[entry.id];
  assert.deepEqual([placed.tests[0].requests[0].template, placed.tests[0].passed, placed.passed], [null, false, false]);
  // A register step is never sent, so a request that only such a step could place fits nothing (T4).
  const held = appEntries(r.h, 'triggers').map(item => ({...item, placements: item.placements.map(placement => ({...placement, phase: 'register'}))}));
  assert.equal(evidenceOf(r, {entries: held}).records[entry.id].tests[0].requests.every(item => item.template === null), true);
});

test('evidence 8: no title, subject, address or token reaches the evidence, the run file or a printed line, and the writer files it apart from actions.json', async t => {
  const r = triggerRun(t, {keys: ['feed-listed'], plan: proved(['feed-listed'])});
  passedAll(await r.run());
  await r.done();
  assert.ok(JSON.stringify(r.h.store.listEvents(r.h.store.get('subscriptions', r.state.data.saved.sub1)?.clientId ?? '', 0, 100)).includes('A private title'), 'the watch did read the title');
  const evidence = evidenceOf(r), root = temp(t), [entry] = appEntries(r.h, 'triggers');
  const text = writeEvidence(root, 'fixture', evidence, {emails: [OWNER_EMAIL]}, 'triggers.json');
  for (const [where, value] of [['evidence', text], ['run file', readFileSync(r.state.file, 'utf8')], ['printed lines', r.lines.join('\n')]]) {
    assert.equal(value.includes('A private title'), false, where);
    assert.equal(value.includes(OWNER_EMAIL), false, where);
  }
  assert.equal(readFileSync(guardFile(r.folder, 'fixture', r.runId), 'utf8').includes('A private title'), false, 'the guard keeps the owner\'s address in its own file, and nothing an event held');
  const file = path.join(root, 'docs', 'live-evidence', 'fixture');
  assert.deepEqual(JSON.parse(readFileSync(path.join(file, 'triggers.json'), 'utf8'))[entry.id].passed, true);
  assert.equal(existsSync(path.join(file, 'actions.json')), false, 'an action\'s evidence is its own file');
  // The writer's own check stands: a value that slipped in stops the write.
  const leaked = structuredClone(evidence);
  leaked.records[entry.id].tests[0].subject = 'mail from person@example.com';
  assert.throws(() => writeEvidence(root, 'fixture', leaked, {}, 'triggers.json'), /holds an email address/);
  // Records of other ids stay, and `run` is replaced, as actions.json works.
  writeEvidence(root, 'fixture', {records: {other: {passed: false}}, run: {runId: 'NEXT'}}, {}, 'triggers.json');
  const merged = JSON.parse(readFileSync(path.join(file, 'triggers.json'), 'utf8'));
  assert.deepEqual([merged.other.passed, merged[entry.id].passed, merged.run.runId], [false, true, 'NEXT']);
});

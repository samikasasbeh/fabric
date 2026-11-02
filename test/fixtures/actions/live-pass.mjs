// Iteration 9 part 9b (docs/I07-BUILD-MAP.md step 9): one app's shipped trigger plan, played through on that app's simulator, as a certification run would play it: the shipped candidate triggers, the shipped rows,
// a designated store, the real guard with its real rules in front of the simulator, and the port the command gives the runner. The owner is scripted: each hand step of the plan is one change on the simulator, and each
// printed link is approved on the owner's own path. Nothing here listens on a port or reaches a provider. Test data only: nothing in lib/ imports it.
import {randomBytes} from 'node:crypto';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createGuard, newRunId, RULES} from '../../../lib/live-guard.mjs';
import {checkTriggerPlan, openRunState, runDateOf, runLiveTests, triggerEvidenceRecords} from '../../../lib/live-certify.mjs';
import {PROXY_CONFIGS} from '../../../lib/proxy-config.mjs';
import {harnessPort} from '../../../scripts/live-certify.mjs';
import {triggerWorld} from './trigger-harness.mjs';

const ROOT = new URL('../../../', import.meta.url);
/** A shipped trigger plan, as written. */
export const shippedPlan = appId => JSON.parse(readFileSync(new URL(`catalog/live-tests/triggers/${appId}.json`, ROOT), 'utf8'));
/** What checkTriggerPlan() reads of an app, from its world. */
export function planDeps(h, appId) {
  const items = kind => [...h.catalog[kind].values()].filter(item => item.appId === appId).map(item => item.entry);
  return {entries: items('entries'), triggers: items('triggers'), superseded: [...h.catalog.superseded.keys()], groups: h.groups.get(appId), config: PROXY_CONFIGS.get(appId), rules: RULES};
}

/**
 * One app's pass. `recorded` gives each value the plan records, as a function of the world, `hands` maps each owner step's words (a regular expression's source, first match wins) to that hand's change on the world, and
 * `world` and `timeZone` are the world's options and the owner's zone. With `stopAt`, a regular expression's source, the owner steps away at the first hand step whose words match, the run stops there, and a new process resumes it from that test, as the printed line says, with a new guard and port on the same folder: `stopped` is where it stopped. It answers {h, run, guard, port, evidence, lines, hands: [what each hand step matched], folder, stopped}.
 */
export async function livePass(t, appId, {plan = shippedPlan(appId), recorded = () => ({}), hands = [], world = {}, email = 'owner@fabric-owner.test', timeZone = 'UTC', setup = () => {}, onWait = () => {}, leave = true, stopAt = null} = {}) {
  const h = triggerWorld(t, appId, {candidate: true, designated: true, engine: {certification: true}, ...world});
  const folder = mkdtempSync(path.join(tmpdir(), 'fabric-live-pass-')), runId = newRunId(), key = randomBytes(32), owner = h.principal;
  t.after(() => rmSync(folder, {recursive: true, force: true}));
  await setup(h);
  const guard = createGuard({appId, runId, folder, key, clock: () => h.now}), values = recorded(h), runDate = runDateOf(h.now, timeZone);
  guard.setOwner({email, timeZone, runDate, recorded: values});
  h.runtime.permissions.certification = true;
  h.runtime.request = guard.wrap(h.simulator.request);
  h.runtime.authorizeSource = job => h.protocol.authorizeJob(job);
  const app = {store: h.store, runtime: h.runtime, origin: 'http://127.0.0.1:59992', triggers: h.engine, protocol: {handle: (...args) => h.protocol.handle(...args), revokeClient: id => h.protocol.revokeClient(id), createClient: (data, principal) => h.protocol.createClient(data, principal)}};
  const port = harnessPort(app, {owner}), state = openRunState(folder, appId, runId, {runDate, timeZone, recorded: values});
  const checked = checkTriggerPlan(plan, planDeps(h, appId)), lines = [], used = [];
  let chain = Promise.resolve();
  const pass = {h, guard, port, state, runId, key, lines, used, folder};
  const say = line => {
    lines.push(String(line));
    const link = /\/approve\/([0-9a-f-]{36})$/.exec(line);
    if (!link) return;
    if (h.store.get('subscriptions', link[1])) { h.approve(link[1]); return; }
    chain = chain.then(() => h.runtime.approve(link[1], h.store.get('jobs', link[1]).approvalDigest, owner));
  };
  let away = stopAt;
  const prompt = async words => {
    if (/^Run the pending undos/.test(words)) return 'no';
    if (away && new RegExp(away).test(words)) { away = null; throw new Error('The owner stepped away.'); }
    const hand = hands.find(([pattern]) => new RegExp(pattern).test(words));
    if (!hand) throw new Error(`No hand is scripted for: ${words}`);
    used.push(hand[0]);
    await hand[1](pass);
    return '';
  };
  const wait = async ms => { h.advance(ms); await onWait(pass, ms); await new Promise(resolve => setImmediate(resolve)); };
  pass.run = await runLiveTests(port, checked, {guard, state, prompt, say, clock: () => h.now, wait, leave});
  await chain;
  if (stopAt) {
    pass.stopped = pass.run.stopped;
    Object.assign(pass, {guard: createGuard({appId, runId, folder, key, clock: () => h.now}), port: harnessPort(app, {owner}), state: openRunState(folder, appId, runId)});
    h.runtime.request = pass.guard.wrap(h.simulator.request);
    pass.run = await runLiveTests(pass.port, checked, {guard: pass.guard, state: pass.state, prompt, say, clock: () => h.now, wait, leave, from: pass.stopped.test});
    await chain;
  }
  const items = kind => [...h.catalog[kind].values()].filter(item => item.appId === appId).map(item => item.entry);
  pass.triggers = items('triggers');
  pass.evidence = triggerEvidenceRecords(pass.run, {key, entries: pass.triggers, actions: items('entries'), trace: id => pass.guard.trace(id), job: id => pass.port.job(id), groups: h.groups, maps: new Map(h.store.get('applicationMaps', appId) ? [[appId, h.store.get('applicationMaps', appId)]] : [])});
  return pass;
}

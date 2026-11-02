// Iteration 9 part 3h (docs/I07-BUILD-MAP.md step 3): the harness steps 4 to 8 share. It wraps an app's own run harness (slackHarness() and its four siblings), so a trigger runs on the shipped
// rows, the shipped proxy settings and that app's simulator. It adds what an owner and a certification pass would have given: a temp copy of the app's trigger file with computed ids, with
// reviewStatus 'reviewed' and each trigger's `certified` key set in that copy only, and temp evidence that passes triggerEvidencePasses(). On top of those sit fabric/0.1, the engine and the
// subscription service, wired as server.mjs wires them. An agent's calls go through protocol.handle() and an owner's through the service, so a test walks the path a person would, and nothing
// listens on a port. Test data only: nothing in lib/ imports it, and nothing here reaches a provider. The fixture app's own harness stays test/fixtures/actions/trigger-fixture.mjs.
import {randomUUID} from 'node:crypto';
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import path from 'node:path';
import {FabricProtocol, FABRIC_PROTOCOL} from '../../../lib/fabric-protocol.mjs';
import {SubscriptionService} from '../../../lib/subscriptions.mjs';
import {TriggerEngine} from '../../../lib/trigger-engine.mjs';
import {PINS} from '../../../lib/transform-pins.mjs';
import {triggerIds, validateTriggerFile} from '../../../lib/triggers.mjs';
import {calendarDeps, calendarHarness} from './calendar-harness.mjs';
import {githubDeps, githubHarness, OWNER as GITHUB_OWNER} from './github-harness.mjs';
import {gmailDeps, gmailHarness} from './gmail-harness.mjs';
import {notionDeps, notionHarness} from './notion-harness.mjs';
import {slackDeps, slackHarness, OWNER as SLACK_OWNER} from './slack-harness.mjs';

const ROOT = new URL('../../../', import.meta.url), ORIGIN = 'http://127.0.0.1:59992';
/** What a passing trigger record proves: one event after a write, none on the re-poll, and on a history cursor one gap and no duplicate. */
const PROOF = Object.freeze({afterWrite: 1, repoll: 0, resync: Object.freeze({gapEvents: 1, duplicates: 0})});
/** Each app's run harness, the validator's dependencies, and the owner of a designated store (Slack's and GitHub's are; the other three are plain, so they take no principal). */
const APPS = Object.freeze({slack: {harness: slackHarness, depsOf: slackDeps, owner: SLACK_OWNER}, notion: {harness: notionHarness, depsOf: notionDeps}, github: {harness: githubHarness, depsOf: githubDeps, owner: GITHUB_OWNER},
  gmail: {harness: gmailHarness, depsOf: gmailDeps}, 'google-calendar': {harness: calendarHarness, depsOf: calendarDeps}});
export const TRIGGER_APPS = Object.freeze(Object.keys(APPS));

/** A fresh copy of the app's trigger file: the shipped one once its step lands it, and until then its draft (docs/drafts/triggers). */
export function shippedTriggers(appId) {
  const shipped = new URL(`catalog/triggers/${appId}.json`, ROOT);
  return JSON.parse(readFileSync(existsSync(shipped) ? shipped : new URL(`test/fixtures/docs/trigger-drafts/${appId}.json`, ROOT), 'utf8'));
}

/**
 * Builds one app's world. Options: `file` (the trigger file as written; shippedTriggers() by default), `keys` (only these trigger keys: until a step ships a transform, its triggers cannot load),
 * `candidate` (true leaves the copy as it ships, unreviewed and uncertified, as a live pass finds it), `designated` (on an app whose store is plain, a designated one, as a certification Fabric has),
 * `engine` (more options for the engine, such as `budgets` or `windows`, the seams section 12 names), and any option of the app's run harness.
 * It adds to that harness, whose store, simulator, setRow and advance stay as they are:
 *   triggerFile, triggerEntries, triggerId(key)    the copy written, its validated entries, and a key's computed id
 *   protocol, engine, subscriptions, client        what server.mjs wires, and one agent that holds the account
 *   call(method, params, id)                       an agent's call, answering {result} or {error}
 *   subscribe(key, args, more)                     triggers.subscribe on the account, answering the result, and throwing on a refusal with its `code`
 *   approve(id), resume(id)                        the owner's decision with the digest the page shows now, answering the decision
 *   pause(id), decline(id), remove(id)             the owner's other decisions
 *   record(id), pollNow(id)                        the stored watch, and one poll of each of its feeds, which answers the watch as it stands
 *   events(params)                                 events.list from where the last page ended, unless `after` says otherwise
 *   ticking(ms)                                    the scheduler alone for this long on the fake clock, one tick a second as start() runs it
 * A provider's wait passes on the fake clock, so pollNow() never sits out a real one. To run the scheduler's own choice of feeds, advance the clock and call engine.tick().
 */
export function triggerWorld(t, appId, {file = shippedTriggers(appId), keys, engine: engineOptions = {}, candidate = false, ...options} = {}) {
  const {harness, depsOf, owner = options.designated ? SLACK_OWNER : undefined} = APPS[appId], h = harness(t, options), deps = depsOf({groups: h.groups}), evidenceFile = `docs/live-evidence/${appId}/triggers.json`;
  const copy = {...structuredClone(file), reviewStatus: candidate ? file.reviewStatus : 'reviewed'};
  copy.triggers = copy.triggers.filter(item => !keys || keys.includes(item.key)).map(item => candidate ? item : ({...item, certified: {evidence: evidenceFile}}));
  const ids = triggerIds(copy, deps), triggerFile = {...copy, triggers: copy.triggers.map(item => ({...item, id: ids.get(`${item.key} v${item.version}`)}))};
  const triggerEntries = validateTriggerFile(triggerFile, deps).triggers, folder = path.join(h.root, 'catalog', 'triggers'), evidence = path.join(h.root, evidenceFile);
  for (const directory of [folder, path.dirname(evidence)]) mkdirSync(directory, {recursive: true});
  writeFileSync(path.join(folder, `${appId}.json`), JSON.stringify(triggerFile));
  writeFileSync(evidence, JSON.stringify(Object.fromEntries(triggerEntries.map(entry => [entry.id,
    {passed: true, transforms: Object.fromEntries(entry.transforms.map(id => [id, PINS.transforms[id]])), tests: [{test: 'harness', passed: true, proof: PROOF}]}]))));
  h.catalog.reload(appId, deps.maps.get(appId) ?? null);
  // The wiring of server.mjs, with a clock that moves only when a test moves it and a jitter of none.
  const clock = () => h.now, appName = id => id, {store, runtime} = h;
  const protocol = new FabricProtocol({store, runtime, clock, origin: ORIGIN, appName});
  const engine = new TriggerEngine({store, runtime, clock, random: () => 0, ...engineOptions});
  const subscriptions = new SubscriptionService({store, runtime, protocol, triggers: engine, clock, origin: ORIGIN, appName});
  protocol.subscriptions = subscriptions;
  engine.notify = clientId => subscriptions.notify(clientId);
  runtime.wait = async ms => { h.advance(ms); };
  t.after(() => subscriptions.close());
  // A binding is how a grant holds an account on a plain store as on a designated one, since only a designated store takes a proxy entry.
  const {client, token} = protocol.createClient({name: 'Harness agent', bindings: [{connectionId: h.account, capabilityId: h.entries[0].id}]}, owner);
  const call = (method, params = {}, id = randomUUID()) => protocol.handle(`Bearer ${token}`, {protocol: FABRIC_PROTOCOL, id, method, params});
  const answer = async (method, params) => {
    const {result, error} = await call(method, params);
    if (error) throw Object.assign(new Error(error.message), {code: error.code});
    return result;
  };
  const triggerId = key => triggerEntries.find(entry => entry.key === key).id, record = id => store.get('subscriptions', id);
  /** What the page would show now: an owner's digest is the one computed at the moment they look. */
  const digestOf = id => subscriptions.ownerFacts(record(id)).digest;
  let after = 0;
  return Object.assign(h, {triggerFile, triggerEntries, triggerId, protocol, engine, subscriptions, client, call, record, principal: owner,
    subscribe: (key, args = {}, more = {}) => answer('triggers.subscribe', {triggerId: triggerId(key), connectionId: h.account, args, ...more}),
    approve: id => subscriptions.approve(id, digestOf(id), owner), resume: id => subscriptions.resume(id, digestOf(id), owner),
    pause: id => subscriptions.pause(id, owner), decline: id => subscriptions.decline(id, owner), remove: id => subscriptions.remove(id, owner),
    pollNow: id => engine.pollNow(id),
    async ticking(ms) { for (let left = ms; left > 0; left -= 1000) { h.advance(1000); await engine.tick(); } },
    async events(params = {}) {
      const page = await answer('events.list', {after, ...params});
      after = page.next;
      return page;
    }});
}

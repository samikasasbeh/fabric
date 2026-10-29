// F10.11 part b (docs/F10.11-BUILD-MAP.md part b): the run harness of the action runtime's tests. One call builds a temp store, a
// PermissionManager and a ProxyPolicy over the fixture rows, stores the fixture map, connects a ready token account on the fake app and
// one on its RPC twin, puts the provider simulator (test/fixtures/provider-simulators/fixture.mjs) behind the runtime's network seam,
// loads the action catalog from a temp catalog folder with the fixture transforms, their pins and a code-hash seam, and seeds the
// actions with seedActions(). By default the fixture file is reviewed and every action certified with passing live evidence, so each
// one the validator places is active. Parts i and j add slackHarness(): the Slack direct-message helper, the one resolving write, on a
// scripted Slack. Test data only: nothing in lib/ imports it.
import {mkdirSync, mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {Store} from '../../../lib/store.mjs';
import {LocalRepository} from '../../../lib/repositories/local.mts';
import {PermissionManager} from '../../../lib/permissions.mjs';
import {ProxyPolicy} from '../../../lib/proxy-policy.mjs';
import {Runtime} from '../../../lib/runtime.mjs';
import {validateActionFile} from '../../../lib/actions.mjs';
import {loadActionCatalog, seedActions} from '../../../lib/action-catalog.mjs';
import {PERMISSION_GROUPS} from '../../../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../../../lib/proxy-config.mjs';
import {definitionFor} from '../../../lib/providers/definitions.mjs';
import {validatePrincipal} from '../../../contracts/identity.mts';
import {FixtureSimulator, REST_ORIGIN, RPC_BASE} from '../provider-simulators/fixture.mjs';
import {fixtureGroups, fixtureConfigs, fixtureMap, fixtureChoices, fixtureActions, fixtureSignIn, withIds} from './fixture-app.mjs';
import {TRANSFORMS, PINS} from './registry.mjs';

/** The bearer token the harness accounts send and the simulator accepts. */
export const TOKEN = 'fixture-harness-token-5b9e';
export const OWNER = validatePrincipal({schemaVersion: 1, kind: 'local_owner', id: 'fixture-owner', scope: {schemaVersion: 1, kind: 'local', localOwnerId: 'fixture-owner'}});
const RPC_ORIGIN = new URL(RPC_BASE).origin;
/** Where the fixture app's live evidence lives, as a certified action names it. */
export const EVIDENCE = 'docs/live-evidence/fixture/actions.json';

/** The fixture action file reviewed, with every action certified (its definition hash written as an author writes it). */
export function certifiedFile(change = () => {}) {
  const file = fixtureActions();
  file.reviewStatus = 'reviewed';
  for (const action of file.actions) action.certified = {evidence: EVIDENCE, definitionHash: '0'.repeat(64)};
  change(file);
  return file;
}

/**
 * Builds the harness. Options: `file` (the action file, ids recomputed; certifiedFile() by default), `evidence(entries)` (the evidence
 * file's content from the validated entries; a passing record for each by default), `map` (the stored fixture map, null for none),
 * `codeHashes` (each transform's pin by default), `clock` (a fixed start you can move with advance()), `designated` (a designated
 * authority store with an owner principal, as the owner's own Fabric runs), `rows` (edits the fixture app's rows file before it is
 * validated, for the catalog and the permission decisions alike), `signIn` (the fixture app's reviewed sign-in), `files` (F10.11 part i:
 * more reviewed action files, of the RPC twin, written beside fixture.json with passing evidence) and `rpcSignIn` (the twin's reviewed sign-in;
 * F10.21 gives it an apiSuccessRequire). run(key, input) runs an action on its
 * app's account with the owner's principal; allow(key) sets its own record to Allow.
 */
export function actionHarness(t, {file = certifiedFile(), evidence, map = fixtureMap(), codeHashes = ids => Object.fromEntries(ids.map(id => [id, PINS[id]])), start = '2026-10-23T09:00:00.000Z', designated = false,
  rows = change => change, signIn = fixtureSignIn(), files = [], rpcSignIn = fixtureSignIn('fixture-rpc')} = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-action-harness-'));
  let now = Date.parse(start);
  const clock = () => now;
  const groups = fixtureGroups(rows), configs = fixtureConfigs(groups), identities = new Map([['fixture', signIn], ['fixture-rpc', rpcSignIn]]);
  const maps = new Map(map ? [['fixture', map]] : []), choices = new Map([['fixture', fixtureChoices().sources]]);
  const deps = {groups, configs, transforms: TRANSFORMS, pins: PINS, identities};
  const written = withIds(file, {...deps, maps, choices});
  // The catalog folder: the action file, its choice sources and the live evidence.
  const actions = path.join(root, 'catalog', 'actions'), choiceDir = path.join(root, 'catalog', 'choices'), live = path.join(root, 'docs', 'live-evidence', 'fixture');
  for (const dir of [actions, choiceDir, live]) mkdirSync(dir, {recursive: true});
  writeFileSync(path.join(actions, 'fixture.json'), JSON.stringify(written));
  writeFileSync(path.join(choiceDir, 'fixture.json'), JSON.stringify(fixtureChoices()));
  let entries = [];
  try { entries = validateActionFile(written, {...deps, maps, choices}).actions; } catch {}
  const passing = Object.fromEntries(entries.map(entry => [entry.id, {passed: true, transforms: Object.fromEntries(entry.transforms.map(id => [id, PINS[id]])), definitionHash: entry.definitionHash}]));
  const content = evidence ? evidence(new Map(entries.map(entry => [`${entry.key} v${entry.version}`, entry]))) : passing;
  writeFileSync(path.join(root, EVIDENCE), typeof content === 'string' ? content : JSON.stringify(content));
  for (const more of files) {
    const extra = withIds(more, {...deps, maps, choices: new Map()}), folder = path.join(root, 'docs', 'live-evidence', more.appId);
    mkdirSync(folder, {recursive: true});
    writeFileSync(path.join(actions, `${more.appId}.json`), JSON.stringify(extra));
    const valid = validateActionFile(extra, {...deps, maps, choices: new Map()}).actions;
    writeFileSync(path.join(folder, 'actions.json'), JSON.stringify(Object.fromEntries(valid.map(entry => [entry.id, {passed: true, transforms: Object.fromEntries(entry.transforms.map(id => [id, PINS[id]])),
      definitionHash: entry.definitionHash}]))));
  }
  // The store, the rows, the accounts and the simulator behind the network seam.
  const simulator = new FixtureSimulator({clock, token: TOKEN});
  const plain = new Store({dataDir: path.join(root, 'data'), clock, ...(designated ? {localAuthority: 'new'} : {})});
  const store = designated ? new LocalRepository({store: plain, scope: OWNER.scope}) : plain;
  t.after(() => { store.close(); rmSync(root, {recursive: true, force: true}); });
  if (map) store.put('applicationMaps', {id: 'fixture', ...structuredClone(map)});
  const createdAt = new Date(now).toISOString();
  store.put('connections', {id: 'fixture-account', appId: 'fixture', driver: 'http', authMethod: 'token', authRevision: 'r1', status: 'ready', label: 'Fixture', identity: {id: 'acct-1'}, allowedOrigins: [REST_ORIGIN], createdAt});
  store.put('connections', {id: 'fixture-rpc-account', appId: 'fixture-rpc', driver: 'http', authMethod: 'token', authRevision: 'r1', status: 'ready', label: 'Fixture RPC', identity: {id: 'T1:U0'}, allowedOrigins: [RPC_ORIGIN], createdAt});
  const permissions = new PermissionManager({store, groups, configs});
  const proxyPolicy = new ProxyPolicy({store, permissions, groups, configs});
  const catalog = loadActionCatalog({directory: actions, evidenceRoot: root, maps, deps, codeHashes});
  const connections = {credentials: async id => ({headers: {Authorization: `Bearer ${TOKEN}`}, allowedOrigins: [id === 'fixture-rpc-account' ? RPC_ORIGIN : REST_ORIGIN]})};
  // `actions` is the catalog the runtime reaches the runner through (part e onward); until then the Runtime ignores it.
  const runtime = new Runtime({store, permissions, proxyPolicy, connections, request: simulator.request, clock, actions: catalog, ...(designated ? {ownerPrincipal: OWNER} : {})});
  seedActions(store, catalog);
  const idOf = key => [...catalog.entries.values()].find(item => `${item.entry.key} v${item.entry.version}` === key)?.entry.id;
  const accountOf = key => catalog.entries.get(idOf(key))?.appId === 'fixture-rpc' ? 'fixture-rpc-account' : 'fixture-account';
  return {root, store, simulator, runtime, permissions, proxyPolicy, catalog, groups, configs, file: written, owner: designated ? OWNER : null, directory: actions, deps, maps, codeHashes, connections,
    account: 'fixture-account', rpcAccount: 'fixture-rpc-account', idOf, capability: key => store.get('capabilities', idOf(key)),
    run: (key, input) => runtime.createJob({connectionId: accountOf(key), capabilityId: idOf(key), args: input}, designated ? OWNER : null),
    allow: key => permissions.set({connectionId: accountOf(key), capabilityId: idOf(key), mode: 'allow'}),
    seed: () => seedActions(store, catalog), advance(ms) { now += ms; }, get now() { return now; }};
}

// ---- F10.11 parts i and j: the Slack direct-message helper on a scripted Slack ------------------------------------------------------
// The one reviewed resolving write is Slack's POST /conversations.open (lib/action-placement.mjs RESOLVING_WRITES), and the fake app has
// no reviewed sign-in, so the two-phase cases run Send a direct message on the shipped Slack rows, against a scripted Slack that answers
// four methods and records every call without its Authorization header.

/** The bearer token the Slack harness account sends and the script accepts. */
export const SLACK_TOKEN = 'xoxb-slack-harness-token-7c41';
const SLACK_OK = {status: [200], require: [{equals: {pointer: '/ok', value: {const: true}}}]};
const closed = properties => ({type: 'object', properties, required: Object.keys(properties), additionalProperties: false});
/**
 * Slack Send a direct message (spec line 1480), reviewed and certified: find the person by email (a prepare read), open the direct
 * message (the resolving write, whose users value comes from that read), post to it, and read its permalink back. `change` edits the
 * action before its id is computed.
 */
export function directMessageFile(change = action => action) {
  return {schemaVersion: 1, appId: 'slack', specVersion: 'fabric/0.2', reviewStatus: 'reviewed', pinnedParameters: {}, actions: [change({
    id: `slack.action.send-dm.v1.${'0'.repeat(24)}`, key: 'send-dm', version: 1, name: 'Send a direct message', description: 'Sends one direct message to a person found by email.',
    effect: 'write', row: 'slack.messages.send', hints: {readOnly: false, destructive: false, idempotent: false, openWorld: true},
    inputSchema: closed({email: {type: 'string', minLength: 3, maxLength: 254}, text: {type: 'string', minLength: 1, maxLength: 4000}}),
    outputSchema: closed({channel: {type: 'string', maxLength: 64}, ts: {type: 'string', maxLength: 64}}), guards: [],
    prepare: [{id: 'person', method: 'GET', path: '/users.lookupByEmail', query: {email: {input: '/email'}}, expect: SLACK_OK}],
    perform: [
      {id: 'open', method: 'POST', path: '/conversations.open', body: {object: {users: {step: 'person', pointer: '/user/id'}}}, resolves: true,
        expect: {status: [200], require: [{equals: {pointer: '/ok', value: {const: true}}}, {present: {pointer: '/channel/id'}}]}},
      {id: 'post', method: 'POST', path: '/chat.postMessage', body: {object: {channel: {step: 'open', pointer: '/channel/id'},
        text: {pick: {transform: 'text.slackEscape@1', args: {text: {input: '/text'}}}, pointer: '/text'}}}, expect: SLACK_OK}],
    verify: {requests: [{id: 'link', method: 'GET', path: '/chat.getPermalink', query: {channel: {step: 'post', pointer: '/channel'}, message_ts: {step: 'post', pointer: '/ts'}}, expect: SLACK_OK}],
      identity: [{kind: 'readback', step: 'link', pointer: '/channel', equals: {step: 'post', pointer: '/channel'}}], assert: []},
    output: {channel: {step: 'post', pointer: '/channel'}, ts: {step: 'post', pointer: '/ts'}},
    preview: [{label: 'To', expr: {step: 'person', pointer: '/user/real_name'}}, {label: 'Message', expr: {input: '/text'}}], definitive: [400],
    certified: {evidence: 'docs/live-evidence/slack/actions.json', definitionHash: '0'.repeat(64)}})]};
}

/** A scripted Slack: answers users.lookupByEmail, conversations.open, chat.postMessage and chat.getPermalink as Slack does (HTTP 200, {ok}),
 *  and records each call as {method, name, url, query, headers, body, authorized}, without the Authorization header. `answers` may be replaced. */
export class SlackScript {
  constructor() {
    this.calls = [];
    this.answers = {
      'users.lookupByEmail': ({query}) => query.email === 'grace@example.com' ? {ok: true, user: {id: 'U2', real_name: 'Grace Hopper'}} : {ok: false, error: 'users_not_found'},
      'conversations.open': ({body}) => ({ok: true, channel: {id: `D${body?.users}`}}),
      'chat.postMessage': ({body}) => ({ok: true, channel: body?.channel, ts: '1761210000.000200'}),
      'chat.getPermalink': ({query}) => ({ok: true, channel: query.channel, permalink: `https://example.slack.com/archives/${query.channel}/p1761210000000200`}),
    };
    this.request = this.request.bind(this);
  }
  /** The calls that change something in Slack. */
  writes() { return this.calls.filter(call => ['conversations.open', 'chat.postMessage'].includes(call.name)); }
  async request({url, method = 'GET', headers = {}, body, allowedOrigins}) {
    const target = new URL(url);
    if (!Array.isArray(allowedOrigins) || !allowedOrigins.includes(target.origin)) throw Object.assign(new Error('Request origin is outside the connection grant.'), {sent: false});
    const {Authorization: authorization, ...kept} = headers;
    const call = {method, name: target.pathname.replace(/^\/api\//, ''), url, query: Object.fromEntries(target.searchParams), headers: kept, body: body === undefined ? null : JSON.parse(body),
      authorized: authorization === `Bearer ${SLACK_TOKEN}`};
    this.calls.push(call);
    const answer = !call.authorized ? {ok: false, error: 'not_authed'} : this.answers[call.name]?.(call) ?? {ok: false, error: 'unknown_method'};
    return {status: 200, headers: {'content-type': 'application/json; charset=utf-8'}, data: structuredClone(answer)};
  }
}

/**
 * The Slack harness: a temp store with Send a direct message seeded active from a temp catalog on the shipped Slack rows, one ready Slack
 * token account, and a Runtime whose network is the script. Options: `designated` (a designated authority store with the owner
 * principal), `ceilingOf` (a developer ceiling, as part e's tests give one) and `change` (edits the action, as directMessageFile() takes).
 */
export function slackHarness(t, {designated = false, ceilingOf = null, change, start = '2026-10-23T09:00:00.000Z'} = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-action-slack-harness-'));
  let now = Date.parse(start);
  const clock = () => now;
  const plain = new Store({dataDir: path.join(root, 'data'), clock, ...(designated ? {localAuthority: 'new'} : {})});
  const store = designated ? new LocalRepository({store: plain, scope: OWNER.scope}) : plain;
  t.after(() => { store.close(); rmSync(root, {recursive: true, force: true}); });
  const deps = {groups: PERMISSION_GROUPS, configs: PROXY_CONFIGS, transforms: TRANSFORMS, pins: PINS, choices: new Map(), identities: new Map([['slack', definitionFor('slack')]])};
  const file = withIds(directMessageFile(change), {...deps, maps: new Map()}), directory = path.join(root, 'catalog', 'actions'), live = path.join(root, 'docs', 'live-evidence', 'slack');
  for (const dir of [directory, live]) mkdirSync(dir, {recursive: true});
  writeFileSync(path.join(directory, 'slack.json'), JSON.stringify(file));
  const [{id, definitionHash}] = file.actions;
  writeFileSync(path.join(live, 'actions.json'), JSON.stringify({[id]: {passed: true, transforms: {'text.slackEscape@1': PINS['text.slackEscape@1']}, definitionHash}}));
  const catalog = loadActionCatalog({directory, evidenceRoot: root, deps, codeHashes: ids => Object.fromEntries(ids.map(name => [name, PINS[name]]))});
  store.put('connections', {id: 'slack-account', appId: 'slack', driver: 'http', authMethod: 'token', authRevision: 'r1', status: 'ready', label: 'Slack', identity: {id: 'T1:U1'},
    allowedOrigins: ['https://slack.com'], createdAt: new Date(now).toISOString()});
  const script = new SlackScript(), permissions = new PermissionManager({store, ceilingOf}), proxyPolicy = new ProxyPolicy({store, permissions});
  const connections = {credentials: async () => ({headers: {Authorization: `Bearer ${SLACK_TOKEN}`}, allowedOrigins: ['https://slack.com']})};
  const runtime = new Runtime({store, permissions, proxyPolicy, connections, request: script.request, clock, actions: catalog, ...(designated ? {ownerPrincipal: OWNER} : {})});
  seedActions(store, catalog);
  return {root, store, script, runtime, permissions, proxyPolicy, catalog, connections, account: 'slack-account', id, owner: designated ? OWNER : null, capability: () => store.get('capabilities', id),
    setRow: (groupId, mode) => proxyPolicy.set({connectionId: 'slack-account', row: `group:${groupId}`, mode, confirmAllow: true}), advance(ms) { now += ms; }, get now() { return now; }};
}

// F10.21 part 1 (docs/F10.21-BUILD-MAP.md part 1): the Slack rig of part 1's tests (test/api-success.test.mjs, test/retention.test.mjs,
// test/slack-limits.test.mjs). One call builds a designated temp store with the shipped Slack rows and proxy settings, a ready Slack OAuth
// account (identity with workspaceId and userId, the scopes given), the Slack simulator (test/fixtures/provider-simulators/slack.mjs) behind
// the runtime's network seam, credentials through a stub, and, when `actions` are given, a temp action catalog of them: reviewed, certified
// with temp passing evidence, ids written with withIds(). Part 2's slackHarness() builds the shipped file's harness the same way. Test data
// only: nothing in lib/ imports it, and nothing here reaches Slack.
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
import {TRANSFORMS} from '../../../lib/transforms/index.mjs';
import {PINS} from '../../../lib/transform-pins.mjs';
import {definitionFor} from '../../../lib/providers/definitions.mjs';
import {validatePrincipal} from '../../../contracts/identity.mts';
import {SlackSimulator, ORIGIN, IDS} from '../provider-simulators/slack.mjs';
import {withIds} from './fixture-app.mjs';

export const SLACK_TOKEN = 'xoxp-slack-rig-token-5f1a';
export const OWNER = validatePrincipal({schemaVersion: 1, kind: 'local_owner', id: 'slack-rig-owner', scope: {schemaVersion: 1, kind: 'local', localOwnerId: 'slack-rig-owner'}});
/** The 11 required user scopes and the optional ones the first actions use. */
export const SCOPES = Object.freeze(['channels:read', 'groups:read', 'im:read', 'mpim:read', 'channels:history', 'groups:history', 'im:history', 'mpim:history', 'users:read', 'chat:write', 'im:write',
  'users:read.email', 'users.profile:read', 'users.profile:write', 'search:read', 'reactions:read', 'reactions:write', 'canvases:read']);
/** Slack's success rule as a step's expect.require entry, and the two expects every Slack step uses. */
export const RULE = Object.freeze({equals: {pointer: '/ok', value: {const: true}}});
export const SLACK_OK = Object.freeze({status: [200], require: [RULE]});
const closed = properties => ({type: 'object', properties, required: Object.keys(properties), additionalProperties: false});
const words = (max = 200) => ({type: 'string', minLength: 1, maxLength: max});
/** One test action of the Slack app, reviewed and certified. */
export function slackAction(key, fields) {
  return {id: `slack.action.${key}.v1.${'0'.repeat(24)}`, key, version: 1, name: key, description: `The ${key} action of the step 21 part 1 tests.`, guards: [], prepare: [],
    preview: [{label: 'Channel', expr: {input: '/channel'}}], definitive: [], certified: {evidence: 'docs/live-evidence/slack/actions.json', definitionHash: '0'.repeat(64)}, ...fields};
}
/** Read recent messages of a channel, `limit` of them (a read on "Access messages"). */
export const historyAction = ({expect = SLACK_OK, limit = 15, key = 'history'} = {}) => slackAction(key, {effect: 'read', row: 'slack.messages.read',
  hints: {readOnly: true, destructive: false, idempotent: true, openWorld: true}, inputSchema: closed({channel: words(21)}),
  outputSchema: closed({ok: {type: 'boolean'}}),
  perform: [{id: 'history', method: 'GET', path: '/conversations.history', query: {channel: {input: '/channel'}, limit: {const: limit}}, expect}],
  output: {ok: {step: 'history', pointer: '/ok'}}});
export const slackFile = actions => ({schemaVersion: 1, appId: 'slack', specVersion: 'fabric/0.2', reviewStatus: 'reviewed', pinnedParameters: {}, actions});

/**
 * Options: `actions` (test actions, loaded as a catalog), `identity` (the Slack sign-in the catalog's validator reads; the shipped one by
 * default), `scopes` (the token's), `accountScopes` (the record's; the token's by default), `slackDistribution` (the runtime's) and
 * `accounts` (more Slack accounts, each {id, team}). Returns the store, simulator, runtime and helpers: proxy(request, account) and
 * run(key, args, account) settle a job, approving each stop as the owner; record(account) reads an account; advance(ms) moves the clock.
 */
export function slackRig(t, {actions = [], identity = definitionFor('slack'), scopes = SCOPES, accountScopes = scopes, slackDistribution, accounts = [], start = '2026-10-26T15:00:00.000Z'} = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-slack-rig-'));
  let now = Date.parse(start);
  const clock = () => now;
  const store = new LocalRepository({store: new Store({dataDir: path.join(root, 'data'), clock, localAuthority: 'new'}), scope: OWNER.scope});
  t.after(() => { store.close(); rmSync(root, {recursive: true, force: true}); });
  const simulator = new SlackSimulator({clock, token: SLACK_TOKEN, scopes});
  let catalog = null;
  if (actions.length) {
    const deps = {groups: PERMISSION_GROUPS, configs: PROXY_CONFIGS, transforms: TRANSFORMS, pins: PINS.transforms, choices: new Map(), identities: new Map([['slack', identity]])};
    const file = withIds(slackFile(actions), {...deps, maps: new Map()}), directory = path.join(root, 'catalog', 'actions'), live = path.join(root, 'docs', 'live-evidence', 'slack');
    for (const dir of [directory, live]) mkdirSync(dir, {recursive: true});
    writeFileSync(path.join(directory, 'slack.json'), JSON.stringify(file));
    const entries = validateActionFile(file, {...deps, maps: new Map()}).actions;
    writeFileSync(path.join(live, 'actions.json'), JSON.stringify(Object.fromEntries(entries.map(entry => [entry.id, {passed: true,
      transforms: Object.fromEntries(entry.transforms.map(id => [id, PINS.transforms[id]])), definitionHash: entry.definitionHash}]))));
    catalog = loadActionCatalog({directory, evidenceRoot: root, deps, codeHashes: ids => Object.fromEntries(ids.map(id => [id, PINS.transforms[id]]))});
    if (catalog.refused.size) throw new Error(`The test file did not load: ${[...catalog.refused.values()].join(' ')}`);
  }
  const account = (id, team) => store.put('connections', {id, appId: 'slack', providerId: 'slack', driver: 'http', authMethod: 'oauth', authRevision: `r-${id}`, status: 'ready', label: 'Slack',
    identity: {id: `${team}:${IDS.owner}`, displayName: 'owner', workspaceId: team, workspaceName: 'Fabric Test', userId: IDS.owner}, allowedOrigins: [ORIGIN],
    scopes: [...accountScopes], createdAt: new Date(now).toISOString()});
  account('slack-account', IDS.team);
  for (const extra of accounts) account(extra.id, extra.team);
  const permissions = new PermissionManager({store}), proxyPolicy = new ProxyPolicy({store, permissions});
  const connections = {credentials: async () => ({headers: {Authorization: `Bearer ${SLACK_TOKEN}`}, allowedOrigins: [ORIGIN]})};
  const runtime = new Runtime({store, permissions, proxyPolicy, connections, request: simulator.request, clock, actions: catalog, ownerPrincipal: OWNER,
    ...(slackDistribution === undefined ? {} : {slackDistribution})});
  if (catalog) seedActions(store, catalog);
  const idOf = key => [...(catalog?.entries.values() ?? [])].find(item => item.entry.key === key)?.entry.id;
  const settle = async job => job.status === 'awaiting_approval' ? settle(await runtime.approve(job.id, job.approvalDigest, OWNER)) : job;
  return {root, store, simulator, runtime, permissions, proxyPolicy, catalog, account: 'slack-account', idOf, advance(ms) { now += ms; }, get now() { return now; },
    proxy: async (request, connectionId = 'slack-account') => settle(await runtime.createProxyJob({connectionId, request}, OWNER)),
    run: async (key, args, connectionId = 'slack-account') => settle(await runtime.createJob({connectionId, capabilityId: idOf(key), args}, OWNER)),
    record: (connectionId = 'slack-account') => store.get('connections', connectionId)};
}

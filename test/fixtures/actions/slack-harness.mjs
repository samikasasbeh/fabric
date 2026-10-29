// F10.21 part 2 (docs/F10.21-BUILD-MAP.md part 2): the run harness of Slack's action tests, modeled on calendarHarness()
// (calendar-harness.mjs) and built on part 1's rig (slack-rig.mjs). One call builds a temp root holding Slack's shipped action file,
// reviewed and certified there and loaded through withIds() (so a seeded fault inside the file reaches behaviour instead of tripping the id
// check), with temp passing evidence for every action written only under that root; a designated temp store with the shipped rows (or rows
// a test edits) and proxy settings; one ready Slack account (identity with workspaceId and userId) with the 11 required scopes and the
// optional ones the actions use by default; credentials through the network seam; and the Slack simulator
// (test/fixtures/provider-simulators/slack.mjs) behind it. Slack needs no map: its rows are request templates. Test data only: nothing in
// lib/ imports it, and nothing here reaches Slack.
import {mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {Store} from '../../../lib/store.mjs';
import {LocalRepository} from '../../../lib/repositories/local.mts';
import {PermissionManager} from '../../../lib/permissions.mjs';
import {ProxyPolicy} from '../../../lib/proxy-policy.mjs';
import {Runtime} from '../../../lib/runtime.mjs';
import {validateActionFile} from '../../../lib/actions.mjs';
import {loadActionCatalog, seedActions} from '../../../lib/action-catalog.mjs';
import {PREPARED} from '../../../lib/actions-runtime.mjs';
import {PERMISSION_GROUPS, validatePermissionGroups} from '../../../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../../../lib/proxy-config.mjs';
import {PINS} from '../../../lib/transform-pins.mjs';
import {definitionFor} from '../../../lib/providers/definitions.mjs';
import {approvalItem} from '../../../lib/ui-contracts.mjs';
import {SlackSimulator, ORIGIN, IDS} from '../provider-simulators/slack.mjs';
import {OWNER, SCOPES} from './slack-rig.mjs';
import {withIds} from './fixture-app.mjs';

const ROOT = new URL('../../../', import.meta.url);
/** The bearer token the harness account sends and the simulator accepts. */
export const TOKEN = 'xoxp-slack-harness-token-7e3b90';
export {OWNER, SCOPES, IDS};
export const EVIDENCE = 'docs/live-evidence/slack/actions.json';
const ACCOUNT = 'slack-account';

/** A fresh copy of Slack's shipped action file, as written. */
export const slackFile = () => JSON.parse(readFileSync(new URL('catalog/actions/slack.json', ROOT), 'utf8'));
/** A fresh copy of Slack's shipped rows file. */
export const slackRows = () => JSON.parse(readFileSync(new URL('catalog/permissions/slack.json', ROOT), 'utf8'));
/** The validator's dependencies for Slack: the shipped rows (or `groups`) and Slack's reviewed sign-in. Slack has no map. */
export function slackDeps({groups = PERMISSION_GROUPS} = {}) {
  return {groups, configs: PROXY_CONFIGS, identities: new Map([['slack', definitionFor('slack')]]), maps: new Map()};
}
/** The file reviewed, each action certified with live evidence (definition hashes as an author writes them), ids recomputed by withIds(). */
export function certified(file, deps) {
  const copy = structuredClone(file);
  copy.reviewStatus = 'reviewed';
  for (const action of copy.actions) action.certified = {evidence: EVIDENCE, definitionHash: '0'.repeat(64)};
  return withIds(copy, deps);
}

/**
 * Builds the harness. Options: `file` (Slack's action file as written; the shipped one by default), `scopes` (the account's and the
 * token's), `rows` (edits Slack's rows file before it is validated), `evidence` (false: every action stays a candidate), `start` (the
 * clock), `distribution` (the runtime's FABRIC_SLACK_DISTRIBUTION) and `rateLimit` (the simulator's distributed limit).
 * run(key, input) runs an action on the account; approve(job) approves it with its shown digest; card(job) is its approval item, and
 * fields(job) the card's field lines as {label: value}; setRow(groupId, mode) sets a row; proxy(request) runs a proxied request to its end.
 */
export function slackHarness(t, {file = slackFile(), scopes = SCOPES, rows = change => change, evidence = true, start = '2026-10-26T15:00:00.000Z', distribution, rateLimit = false} = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-slack-harness-'));
  let now = Date.parse(start);
  const clock = () => now;
  const groups = new Map([...PERMISSION_GROUPS, ['slack', validatePermissionGroups(rows(slackRows()))]]);
  const deps = slackDeps({groups});
  const written = certified(file, deps);
  const actions = path.join(root, 'catalog', 'actions'), live = path.join(root, 'docs', 'live-evidence', 'slack');
  for (const dir of [actions, live]) mkdirSync(dir, {recursive: true});
  writeFileSync(path.join(actions, 'slack.json'), JSON.stringify(written));
  let entries = [];
  try { entries = validateActionFile(written, deps).actions; } catch {}
  if (evidence) {
    writeFileSync(path.join(root, EVIDENCE), JSON.stringify(Object.fromEntries(entries.map(entry => [entry.id,
      {passed: true, transforms: Object.fromEntries(entry.transforms.map(id => [id, PINS.transforms[id]])), definitionHash: entry.definitionHash}]))));
  }
  const simulator = new SlackSimulator({clock, token: TOKEN, scopes: [...scopes], rateLimit});
  const store = new LocalRepository({store: new Store({dataDir: path.join(root, 'data'), clock, localAuthority: 'new'}), scope: OWNER.scope});
  t.after(() => { store.close(); rmSync(root, {recursive: true, force: true}); });
  const at = new Date(now).toISOString();
  store.put('connections', {id: ACCOUNT, appId: 'slack', providerId: 'slack', driver: 'http', authMethod: 'oauth', authRevision: 'r1', status: 'ready', label: 'Slack',
    identity: {id: `${IDS.team}:${IDS.owner}`, displayName: 'owner', workspaceId: IDS.team, workspaceName: 'Fabric Test', userId: IDS.owner}, allowedOrigins: [ORIGIN],
    scopes: [...scopes], createdAt: at, signedInAt: at});
  const permissions = new PermissionManager({store, groups, configs: PROXY_CONFIGS});
  const proxyPolicy = new ProxyPolicy({store, permissions, groups, configs: PROXY_CONFIGS});
  const catalog = loadActionCatalog({directory: actions, evidenceRoot: root, maps: deps.maps, deps: {groups, configs: PROXY_CONFIGS, identities: deps.identities},
    codeHashes: ids => Object.fromEntries(ids.map(id => [id, PINS.transforms[id]]))});
  const connections = {credentials: async () => ({headers: {Authorization: `Bearer ${TOKEN}`}, allowedOrigins: [ORIGIN]})};
  const runtime = new Runtime({store, permissions, proxyPolicy, connections, request: simulator.request, clock, actions: catalog, ownerPrincipal: OWNER,
    ...(distribution === undefined ? {} : {slackDistribution: distribution})});
  seedActions(store, catalog);
  const idOf = key => [...catalog.entries.values()].find(item => `${item.entry.key} v${item.entry.version}` === key)?.entry.id;
  const card = job => approvalItem(job, {prepared: id => store.get(PREPARED, id)});
  // The card's field lines as the prepared row holds them, which the Fields block of the card shows (lib/ui-contracts.mjs).
  const fields = job => Object.fromEntries((store.get(PREPARED, job.id)?.content?.fields ?? []).map(field => [field.label, field.value]));
  const settle = async job => job.status === 'awaiting_approval' ? settle(await runtime.approve(job.id, job.approvalDigest, OWNER)) : job;
  return {root, store, simulator, runtime, permissions, proxyPolicy, catalog, groups, file: written, entries, account: ACCOUNT, connections, idOf, card, fields,
    entry: key => catalog.entries.get(idOf(key)),
    run: (key, input) => runtime.createJob({connectionId: ACCOUNT, capabilityId: idOf(key), args: input}, OWNER),
    approve: job => runtime.approve(job.id, job.approvalDigest, OWNER),
    prepared: job => store.get(PREPARED, job.id),
    proxy: async request => settle(await runtime.createProxyJob({connectionId: ACCOUNT, request}, OWNER)),
    record: () => store.get('connections', ACCOUNT),
    setRow: (groupId, mode) => proxyPolicy.set({connectionId: ACCOUNT, row: `group:${groupId}`, mode, confirmAllow: true}),
    advance(ms) { now += ms; }, get now() { return now; }};
}

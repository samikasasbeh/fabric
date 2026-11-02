// F10.15 part 2 (docs/F10.15-BUILD-MAP.md part 2): the run harness of Gmail's action tests, a copy of calendarHarness()'s pattern
// (calendar-harness.mjs), which stays as it is. One call builds a temp root holding Gmail's shipped action file, reviewed and certified
// there and loaded through withIds() (so a seeded fault inside the file reaches behaviour instead of tripping the id check), with temp
// passing evidence for every action written only under that root; a temp store with the shipped rows (or rows a test edits) and proxy
// settings; Google's recorded Gmail map stored as Discovery would store it; one ready Gmail account with gmail.modify and
// gmail.settings.basic by default; credentials through the network seam; and the Gmail simulator (test/fixtures/provider-simulators/gmail.mjs)
// behind it, or behind a wrapper a test gives (the live guard). Test data only: nothing in lib/ imports it, and nothing here reaches Google.
import {mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {Store} from '../../../lib/store.mjs';
import {LocalRepository} from '../../../lib/repositories/local.mts';
import {OWNER as DESIGNATED_OWNER} from './slack-rig.mjs';
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
import {GmailSimulator, ORIGIN} from '../provider-simulators/gmail.mjs';
import {googleMap} from '../access/google-maps.mjs';
import {withIds} from './fixture-app.mjs';

const ROOT = new URL('../../../', import.meta.url);
/** The bearer token the harness account sends and the simulator accepts. */
export const TOKEN = 'ya29.gmail-harness-token-7c41a9';
/** The account's own address. */
export const OWNER_EMAIL = 'owner@example.com';
/** The two scopes of Fabric's Gmail sign-in (spec section 5.1), as Google names them: gmail.modify required, gmail.settings.basic optional. */
export const MODIFY = 'https://www.googleapis.com/auth/gmail.modify', SETTINGS = 'https://www.googleapis.com/auth/gmail.settings.basic';
export const BOTH = Object.freeze([MODIFY, SETTINGS]);
export const EVIDENCE = 'docs/live-evidence/gmail/actions.json';
const ACCOUNT = 'gmail-account';

/** A fresh copy of Gmail's shipped action file, as written. */
export const gmailFile = () => JSON.parse(readFileSync(new URL('catalog/actions/gmail.json', ROOT), 'utf8'));
/** A fresh copy of Gmail's shipped rows file. */
export const gmailRows = () => JSON.parse(readFileSync(new URL('catalog/permissions/gmail.json', ROOT), 'utf8'));
/** The validator's dependencies for Gmail: the shipped rows (or `groups`), Google's reviewed sign-in and, unless `map` is null, Google's recorded map. */
export function gmailDeps({groups = PERMISSION_GROUPS, map = googleMap('gmail')} = {}) {
  return {groups, configs: PROXY_CONFIGS, identities: new Map([['gmail', definitionFor('google')]]), maps: new Map(map ? [['gmail', map]] : [])};
}
/** The file reviewed, each action certified with live evidence (definition hashes as an author writes them), ids recomputed by withIds(). */
export function certified(file, deps) {
  const copy = structuredClone(file);
  copy.reviewStatus = 'reviewed';
  for (const action of copy.actions) action.certified = {evidence: EVIDENCE, definitionHash: '0'.repeat(64)};
  return withIds(copy, deps);
}

/**
 * Builds the harness. Options: `file` (Gmail's action file as written; the shipped one by default), `scopes` (the account's granted scopes;
 * both by default), `rows` (edits Gmail's rows file before it is validated), `evidence` (false: a reviewed file with no evidence, so every
 * action stays a candidate), `start` (the clock), `email` (the account's address), `wrap` (a function given the simulator's request,
 * whose result the runtime sends through: the live guard's wrap()) and `historyId` (where the simulator's history starts).
 * run(key, input) runs an action on the account; approve(job) approves it with its shown digest; card(job) is its approval item, and
 * fields(job) the card's field lines as {label: value}; setRow(groupId, mode) sets a row; allow(key) sets an action's own record to Allow.
 */
export function gmailHarness(t, {file = gmailFile(), scopes = BOTH, rows = change => change, evidence = true, start = '2026-10-26T13:00:00.000Z', email = OWNER_EMAIL, wrap = null, historyId, designated = false} = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-gmail-harness-'));
  let now = Date.parse(start);
  const clock = () => now;
  const groups = new Map([...PERMISSION_GROUPS, ['gmail', validatePermissionGroups(rows(gmailRows()))]]);
  const map = googleMap('gmail'), deps = gmailDeps({groups, map});
  const written = certified(file, deps);
  const actions = path.join(root, 'catalog', 'actions'), live = path.join(root, 'docs', 'live-evidence', 'gmail');
  for (const dir of [actions, live]) mkdirSync(dir, {recursive: true});
  writeFileSync(path.join(actions, 'gmail.json'), JSON.stringify(written));
  let entries = [];
  try { entries = validateActionFile(written, deps).actions; } catch {}
  if (evidence) {
    writeFileSync(path.join(root, EVIDENCE), JSON.stringify(Object.fromEntries(entries.map(entry => [entry.id,
      {passed: true, transforms: Object.fromEntries(entry.transforms.map(id => [id, PINS.transforms[id]])), definitionHash: entry.definitionHash}]))));
  }
  const simulator = new GmailSimulator({clock, token: TOKEN, owner: {email}, scopes: [...scopes], historyId});
  // A certification Fabric is designated, and only a designated store takes the proxy entry a live run's grant holds.
  const plain = new Store({dataDir: path.join(root, 'data'), clock, ...(designated ? {localAuthority: 'new'} : {})}), store = designated ? new LocalRepository({store: plain, scope: DESIGNATED_OWNER.scope}) : plain;
  t.after(() => { store.close(); rmSync(root, {recursive: true, force: true}); });
  store.put('applicationMaps', {id: 'gmail', ...structuredClone(map)});
  const at = new Date(now).toISOString();
  store.put('connections', {id: ACCOUNT, appId: 'gmail', providerId: 'google', driver: 'http', authMethod: 'oauth', authRevision: 'r1', status: 'ready', label: 'Gmail',
    identity: {id: 'google-sub-gmail-1', displayName: email, email}, scopes: [...scopes], grantCeiling: [...scopes], allowedOrigins: [ORIGIN], createdAt: at, signedInAt: at});
  const permissions = new PermissionManager({store, groups, configs: PROXY_CONFIGS});
  const proxyPolicy = new ProxyPolicy({store, permissions, groups, configs: PROXY_CONFIGS});
  const catalog = loadActionCatalog({directory: actions, evidenceRoot: root, maps: deps.maps, deps: {groups, configs: PROXY_CONFIGS, identities: deps.identities},
    codeHashes: ids => Object.fromEntries(ids.map(id => [id, PINS.transforms[id]]))});
  const connections = {credentials: async () => ({headers: {Authorization: `Bearer ${TOKEN}`}, allowedOrigins: [ORIGIN]})};
  const runtime = new Runtime({store, permissions, proxyPolicy, connections, request: wrap ? wrap(simulator.request) : simulator.request, clock, actions: catalog, ...(designated ? {ownerPrincipal: DESIGNATED_OWNER} : {})});
  seedActions(store, catalog);
  const idOf = key => [...catalog.entries.values()].find(item => `${item.entry.key} v${item.entry.version}` === key)?.entry.id;
  const card = job => approvalItem(job, {prepared: id => store.get(PREPARED, id)});
  // The card's field lines as the prepared row holds them, which the Fields block of the card shows (lib/ui-contracts.mjs).
  const fields = job => Object.fromEntries((store.get(PREPARED, job.id)?.content?.fields ?? []).map(field => [field.label, field.value]));
  return {root, store, simulator, runtime, permissions, proxyPolicy, catalog, groups, file: written, entries, account: ACCOUNT, connections, idOf, card, fields,
    entry: key => catalog.entries.get(idOf(key)),
    run: (key, input) => runtime.createJob({connectionId: ACCOUNT, capabilityId: idOf(key), args: input}, null),
    approve: job => runtime.approve(job.id, job.approvalDigest, null),
    prepared: job => store.get(PREPARED, job.id),
    setRow: (groupId, mode) => proxyPolicy.set({connectionId: ACCOUNT, row: `group:${groupId}`, mode, confirmAllow: true}),
    allow: key => permissions.set({connectionId: ACCOUNT, capabilityId: idOf(key), mode: 'allow'}),
    advance(ms) { now += ms; }, get now() { return now; }};
}

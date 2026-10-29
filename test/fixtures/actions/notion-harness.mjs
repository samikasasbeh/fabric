// F10.19 (docs/F10.19-BUILD-MAP.md parts 1 and 2): the run harness of Notion's action tests, modeled on calendarHarness() (calendar-harness.mjs).
// One call builds a temp root holding a Notion action file (Notion's shipped file by default, once part 2 ships it; part 1's runtime tests
// pass a small inline file), reviewed and certified there and loaded through withIds() (so a seeded fault inside the file reaches behaviour
// instead of tripping the id check), with temp passing evidence for every action written only under that root; a temp store with the shipped
// rows (or rows a test edits) and proxy settings; one ready Notion account; a real ConnectionManager over a temp vault, so Fabric adds
// Notion-Version from the shipped sign-in on every step as it does in a running Fabric; and the Notion simulator
// (test/fixtures/provider-simulators/notion.mjs) behind the network seam, which refuses any other version. Test data only: nothing in lib/
// imports it, and nothing here reaches Notion.
import {mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {Store} from '../../../lib/store.mjs';
import {Vault} from '../../../lib/vault.mjs';
import {ConnectionManager} from '../../../lib/connections.mjs';
import {OAuth2Provider} from '../../../lib/providers/oauth2.mjs';
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
import {NotionApiSimulator, ORIGIN, CAPABILITIES} from '../provider-simulators/notion.mjs';
import {withIds} from './fixture-app.mjs';

const ROOT = new URL('../../../', import.meta.url);
/** The bearer token the harness account holds and the simulator accepts. */
export const TOKEN = 'ntn_notion-harness-token-3f8a21c07b';
/** The person who installed the integration. */
export const OWNER = Object.freeze({name: 'Avery Owner', email: 'avery@example.com'});
export const EVIDENCE = 'docs/live-evidence/notion/actions.json';
const ACCOUNT = 'notion-account';

/** A fresh copy of Notion's shipped action file, as written (part 2). */
export const notionFile = () => JSON.parse(readFileSync(new URL('catalog/actions/notion.json', ROOT), 'utf8'));
/** A fresh copy of Notion's shipped rows file. */
export const notionRows = () => JSON.parse(readFileSync(new URL('catalog/permissions/notion.json', ROOT), 'utf8'));
/** The validator's dependencies for Notion: the shipped rows (or `groups`), Notion's reviewed sign-in, and no map: Notion places by method and path. */
export function notionDeps({groups = PERMISSION_GROUPS} = {}) {
  return {groups, configs: PROXY_CONFIGS, identities: new Map([['notion', definitionFor('notion')]]), maps: new Map()};
}
/** The file reviewed, each action certified with live evidence (definition hashes as an author writes them), ids recomputed by withIds(). */
export function certified(file, deps) {
  const copy = structuredClone(file);
  copy.reviewStatus = 'reviewed';
  for (const action of copy.actions) action.certified = {evidence: EVIDENCE, definitionHash: '0'.repeat(64)};
  return withIds(copy, deps);
}

/**
 * Builds the harness. Options: `file` (a Notion action file as written; the shipped one by default), `capabilities` (the integration's),
 * `rows` (edits Notion's rows file before it is validated), `evidence` (false: a reviewed file with no evidence, so every action stays a
 * candidate), `start` (the clock), `email` (the owner's address) and `wrap` (wraps the simulator's requester, as the live guard's wrap() does:
 * part 2's plan test). run(key, input) runs an action on the account; approve(job) approves it
 * with its shown digest; card(job) is its approval item, fields(job) the card's field lines as {label: value} and prepared(job) its prepared
 * row; setRow(groupId, mode) sets a row; allow(key) sets an action's own record to Allow.
 */
export function notionHarness(t, {file = notionFile(), capabilities = CAPABILITIES, rows = change => change, evidence = true, start = '2026-10-26T12:00:00.000Z', email = OWNER.email, wrap = inner => inner} = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-notion-harness-'));
  let now = Date.parse(start);
  const clock = () => now;
  const groups = new Map([...PERMISSION_GROUPS, ['notion', validatePermissionGroups(rows(notionRows()))]]);
  const deps = notionDeps({groups}), written = certified(file, deps);
  const actions = path.join(root, 'catalog', 'actions'), live = path.join(root, 'docs', 'live-evidence', 'notion'), data = path.join(root, 'data');
  for (const dir of [actions, live, data]) mkdirSync(dir, {recursive: true});
  writeFileSync(path.join(actions, 'notion.json'), JSON.stringify(written));
  let entries = [];
  try { entries = validateActionFile(written, deps).actions; } catch {}
  if (evidence) {
    writeFileSync(path.join(root, EVIDENCE), JSON.stringify(Object.fromEntries(entries.map(entry => [entry.id,
      {passed: true, transforms: Object.fromEntries(entry.transforms.map(id => [id, PINS.transforms[id]])), definitionHash: entry.definitionHash}]))));
  }
  const simulator = new NotionApiSimulator({clock, token: TOKEN, owner: {name: OWNER.name, email}, capabilities: [...capabilities]}), request = wrap(simulator.request);
  const store = new Store({dataDir: data, clock}), vault = new Vault(data);
  t.after(() => { store.close(); rmSync(root, {recursive: true, force: true}); });
  const at = new Date(now).toISOString();
  store.put('connections', {id: ACCOUNT, appId: 'notion', providerId: 'notion', driver: 'http', authMethod: 'oauth', authRevision: 'r1', status: 'ready', label: 'Notion',
    identity: {id: `ws-1:${simulator.owner.id}`, displayName: OWNER.name, email}, scopes: [], allowedOrigins: [ORIGIN], createdAt: at, signedInAt: at});
  vault.set(ACCOUNT, {accessToken: TOKEN, refreshToken: 'nrt_notion-harness-refresh-91d2', expiresAt: null, scopes: []});
  const connections = new ConnectionManager({store, vault, request, clock});
  // Notion's sign-in, configured with test client values, as server.mjs binds it: an account's credential is delivered with the shipped
  // definition's API headers. A Notion token has no expiry, so delivering it sends nothing.
  connections.setOAuthProvider(new OAuth2Provider(definitionFor('notion'), {store, vault, connections, request, clock, clientId: 'notion-harness-client',
    clientSecret: 'notion-harness-secret', publishing: 'testing', redirectUri: 'https://connect.example.com/oauth/notion/4320', allowHostedRedirect: true}));
  const permissions = new PermissionManager({store, groups, configs: PROXY_CONFIGS});
  const proxyPolicy = new ProxyPolicy({store, permissions, groups, configs: PROXY_CONFIGS});
  const catalog = loadActionCatalog({directory: actions, evidenceRoot: root, maps: deps.maps, deps: {groups, configs: PROXY_CONFIGS, identities: deps.identities},
    codeHashes: ids => Object.fromEntries(ids.map(id => [id, PINS.transforms[id]]))});
  const runtime = new Runtime({store, permissions, proxyPolicy, connections, request, clock, actions: catalog});
  seedActions(store, catalog);
  const idOf = key => [...catalog.entries.values()].find(item => `${item.entry.key} v${item.entry.version}` === key)?.entry.id;
  const card = job => approvalItem(job, {prepared: id => store.get(PREPARED, id)});
  const fields = job => Object.fromEntries((store.get(PREPARED, job.id)?.content?.fields ?? []).map(field => [field.label, field.value]));
  return {root, store, vault, simulator, runtime, permissions, proxyPolicy, catalog, groups, file: written, entries, account: ACCOUNT, connections, idOf, card, fields,
    entry: key => catalog.entries.get(idOf(key)),
    run: (key, input) => runtime.createJob({connectionId: ACCOUNT, capabilityId: idOf(key), args: input}, null),
    approve: job => runtime.approve(job.id, job.approvalDigest, null),
    prepared: job => store.get(PREPARED, job.id),
    setRow: (groupId, mode) => proxyPolicy.set({connectionId: ACCOUNT, row: `group:${groupId}`, mode, confirmAllow: true}),
    allow: key => permissions.set({connectionId: ACCOUNT, capabilityId: idOf(key), mode: 'allow'}),
    advance(ms) { now += ms; }, get now() { return now; }};
}

// F10.13 part 2 (docs/F10.13-BUILD-MAP.md part 2): the run harness of Calendar's action tests, modeled on actionHarness()
// (runtime-fixture.mjs). One call builds a temp root holding Calendar's shipped action file, reviewed and certified there and loaded through
// withIds() (so a seeded fault inside the file reaches behaviour instead of tripping the id check), with temp passing evidence for every
// action written only under that root; a temp store with the shipped rows (or rows a test edits) and proxy settings; Google's recorded
// Calendar map stored as Discovery would store it; one ready Calendar account with the six scopes by default; credentials through the
// network seam; and the Calendar simulator (test/fixtures/provider-simulators/google-calendar.mjs) behind it. Test data only: nothing in
// lib/ imports it, and nothing here reaches Google.
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
import {CalendarSimulator, ORIGIN} from '../provider-simulators/google-calendar.mjs';
import {googleMap} from '../access/google-maps.mjs';
import {withIds} from './fixture-app.mjs';

const ROOT = new URL('../../../', import.meta.url);
/** The bearer token the harness account sends and the simulator accepts. */
export const TOKEN = 'ya29.calendar-harness-token-5d2e81';
/** The account's own address and its calendar's zone. */
export const OWNER_EMAIL = 'owner@example.com';
export const ZONE = 'America/Toronto';
/** The six scopes of Fabric's Calendar sign-in (decision 2), as Google names them. */
export const SIX = Object.freeze(['calendar.events', 'calendar.calendarlist', 'calendar.calendars', 'calendar.acls', 'calendar.settings.readonly', 'calendar.freebusy']
  .map(name => `https://www.googleapis.com/auth/${name}`));
export const EVIDENCE = 'docs/live-evidence/google-calendar/actions.json';
const ACCOUNT = 'calendar-account';

/** A fresh copy of Calendar's shipped action file, as written. */
export const calendarFile = () => JSON.parse(readFileSync(new URL('catalog/actions/google-calendar.json', ROOT), 'utf8'));
/** A fresh copy of Calendar's shipped rows file. */
export const calendarRows = () => JSON.parse(readFileSync(new URL('catalog/permissions/google-calendar.json', ROOT), 'utf8'));
/** The validator's dependencies for Calendar: the shipped rows (or `groups`), Google's reviewed sign-in and, unless `map` is null, Google's recorded map. */
export function calendarDeps({groups = PERMISSION_GROUPS, map = googleMap('google-calendar')} = {}) {
  return {groups, configs: PROXY_CONFIGS, identities: new Map([['google-calendar', definitionFor('google')]]), maps: new Map(map ? [['google-calendar', map]] : [])};
}
/** The file reviewed, each action certified with live evidence (definition hashes as an author writes them), ids recomputed by withIds(). */
export function certified(file, deps) {
  const copy = structuredClone(file);
  copy.reviewStatus = 'reviewed';
  for (const action of copy.actions) action.certified = {evidence: EVIDENCE, definitionHash: '0'.repeat(64)};
  return withIds(copy, deps);
}

/**
 * Builds the harness. Options: `file` (Calendar's action file as written; the shipped one by default), `scopes` (the account's granted
 * scopes; the six by default), `zone` (the owner's zone), `rows` (edits Calendar's rows file before it is validated), `evidence` (false: a
 * reviewed file with no evidence, so every action stays a candidate), `start` (the clock) and `email` (the account's address).
 * run(key, input) runs an action on the account; approve(job) approves it with its shown digest; card(job) is its approval item, and
 * fields(job) the card's field lines as {label: value}; setRow(groupId, mode) sets a row; allow(key) sets an action's own record to Allow.
 */
export function calendarHarness(t, {file = calendarFile(), scopes = SIX, zone = ZONE, rows = change => change, evidence = true, start = '2026-10-23T13:00:00.000Z', email = OWNER_EMAIL, designated = false} = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-calendar-harness-'));
  let now = Date.parse(start);
  const clock = () => now;
  const groups = new Map([...PERMISSION_GROUPS, ['google-calendar', validatePermissionGroups(rows(calendarRows()))]]);
  const map = googleMap('google-calendar'), deps = calendarDeps({groups, map});
  const written = certified(file, deps);
  const actions = path.join(root, 'catalog', 'actions'), live = path.join(root, 'docs', 'live-evidence', 'google-calendar');
  for (const dir of [actions, live]) mkdirSync(dir, {recursive: true});
  writeFileSync(path.join(actions, 'google-calendar.json'), JSON.stringify(written));
  let entries = [];
  try { entries = validateActionFile(written, deps).actions; } catch {}
  if (evidence) {
    writeFileSync(path.join(root, EVIDENCE), JSON.stringify(Object.fromEntries(entries.map(entry => [entry.id,
      {passed: true, transforms: Object.fromEntries(entry.transforms.map(id => [id, PINS.transforms[id]])), definitionHash: entry.definitionHash}]))));
  }
  const simulator = new CalendarSimulator({clock, token: TOKEN, owner: {email, zone}, scopes: [...SIX]});
  // A certification Fabric is designated, and only a designated store takes the proxy entry a live run's grant holds.
  const plain = new Store({dataDir: path.join(root, 'data'), clock, ...(designated ? {localAuthority: 'new'} : {})}), store = designated ? new LocalRepository({store: plain, scope: DESIGNATED_OWNER.scope}) : plain;
  t.after(() => { store.close(); rmSync(root, {recursive: true, force: true}); });
  store.put('applicationMaps', {id: 'google-calendar', ...structuredClone(map)});
  const at = new Date(now).toISOString();
  store.put('connections', {id: ACCOUNT, appId: 'google-calendar', providerId: 'google', driver: 'http', authMethod: 'oauth', authRevision: 'r1', status: 'ready', label: 'Calendar',
    identity: {id: 'google-sub-calendar-1', displayName: email, email}, scopes: [...scopes], grantCeiling: [...scopes], allowedOrigins: [ORIGIN], createdAt: at, signedInAt: at});
  const permissions = new PermissionManager({store, groups, configs: PROXY_CONFIGS});
  const proxyPolicy = new ProxyPolicy({store, permissions, groups, configs: PROXY_CONFIGS});
  const catalog = loadActionCatalog({directory: actions, evidenceRoot: root, maps: deps.maps, deps: {groups, configs: PROXY_CONFIGS, identities: deps.identities},
    codeHashes: ids => Object.fromEntries(ids.map(id => [id, PINS.transforms[id]]))});
  const connections = {credentials: async () => ({headers: {Authorization: `Bearer ${TOKEN}`}, allowedOrigins: [ORIGIN]})};
  const runtime = new Runtime({store, permissions, proxyPolicy, connections, request: simulator.request, clock, actions: catalog, ...(designated ? {ownerPrincipal: DESIGNATED_OWNER} : {})});
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

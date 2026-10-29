import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {PermissionManager} from '../lib/permissions.mjs';
import {templatesFor} from '../lib/proxy-match.mjs';
import {proxyBase} from '../lib/proxy-request.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {Store} from '../lib/store.mjs';

// F10.7 listed churn (docs/F10.7-BUILD-MAP.md sections 4 and 6). test/fixtures/access/f10-7-bindings.before.json was recorded before
// any F10.7 data change (data as at 95f5aff), for one synthetic ready account per app: each app's proxy settings hash, every proxy-row
// binding, the policy hash of a proxied request to every reviewed member (filled in as test/f10-6-churn.test.mjs fills its template) and,
// over synthetic Gmail and Calendar maps, every typed policy hash. Policy hashes are grouped by the row the request or operation
// landed in. A part that moves any of them lists it in CHURN with its reason; nothing else moves. A row the owner may set to Allow
// for the proxy keeps its binding, and no proxy settings hash moves at all (reviewedMultiSegment is not hashed, open question 16).
const BEFORE = JSON.parse(readFileSync(new URL('./fixtures/access/f10-7-bindings.before.json', import.meta.url), 'utf8'));
const SERVERS = {gmail: 'https://gmail.googleapis.com', 'google-calendar': 'https://www.googleapis.com/calendar/v3'};
const HASH = /^[a-f0-9]{64}$/;
// Per app: the proxy rows whose binding changes, appears or disappears (every proxied request landing in one of them, before or now,
// moves with it), and the proxied and typed members whose policy hash moves for another reason. Parts d and e add their moves here.
// Part e's other moves are rules over what each member now reads, never a re-recorded snapshot: before part e no row carried scope
// data, so the synthetic account (it holds no scope) read every member as 'unknown', or 'unavailable' where F10.6 had marked it. A
// member now reading 'missing' gained scope data; one now 'unavailable' for a reason part e introduced in that app was marked by it.
// `proxied` names those reasons (true: every reason, as F10.6 shipped no marker for the app). `typed` (the two maps carry no
// Discovery scopes, so the rows speak): an operation moves when its row now carries scope sets, or part e marked it unavailable.
const NONE = Object.freeze({changed: [], added: [], removed: [], proxied: [], typed: []});
const OTHER = ['other-reads', 'other-changes', 'other-deletes', 'graphql'];
const CHURN = {'google-calendar': NONE,
  // Part e: the delete split moves drafts, labels and filters deletes into gmail.items.delete; the three message deletes are not-requested.
  gmail: {...NONE, changed: ['group:gmail.permanent.delete', ...OTHER], added: ['group:gmail.items.delete'], proxied: ['not-requested'], typed: ['not-requested']},
  // Parts d and e: the four git ref templates read {+ref}, so their rows and the Other and GraphQL rows (which bind every reviewed
  // template) move; every row gains scope data, and the repository and key deletes and the locked row's members are marked.
  github: {...NONE, changed: ['group:github.repos.read', 'group:github.code.write', ...OTHER], proxied: ['not-requested']},
  // Part e: the view-query delete joins notion.permanent.delete. Every row reads [[]] (Notion decides), which keeps 'unknown'.
  notion: {...NONE, changed: ['group:notion.permanent.delete', ...OTHER]},
  // Part e: files.remote.share and conversations.declineSharedInvite move into slack.admin, whose members are all classified. Slack's
  // only Other row is other-changes.
  slack: {...NONE, changed: ['group:slack.files.write', 'group:slack.channels.manage', 'group:slack.admin', 'other-changes'], proxied: true}};
/** Whether part e's data moved one member's policy hash, read from what it reads now (see CHURN). */
const movedByData = (churn, {providerAccess, unavailable}) => providerAccess === 'missing' || (providerAccess === 'unavailable' && (churn.proxied === true || churn.proxied.includes(unavailable)));
const sample = template => template.segments.flatMap(part => part.kind === 'literal' ? [part.value] : part.kind === 'param' ? ['p1'] : part.kind === 'verb' ? [`p1${part.suffix}`] : ['a', 'b']);
// {row: {member: hash}} read as {member: {row, hash}}; a member recorded twice would hide a move, so it is refused.
function flat(grouped, where) {
  const out = {};
  for (const [row, members] of Object.entries(grouped)) for (const [member, hash] of Object.entries(members)) {
    assert.ok(!Object.hasOwn(out, member), `${where}: ${member} is recorded in ${out[member]?.row} and ${row}`);
    out[member] = {row, hash};
  }
  return out;
}
const moved = (before, now, where) => {
  const was = flat(before, `${where} before`), is = flat(now, `${where} now`);
  return [...new Set([...Object.keys(was), ...Object.keys(is)])].filter(member => was[member]?.row !== is[member]?.row || was[member]?.hash !== is[member]?.hash).sort();
};

async function store(t, appId) {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-f10-7-churn-')), value = new Store({dataDir: dir});
  t.after(async () => {value.close(); await rm(dir, {recursive: true, force: true});});
  value.put('connections', structuredClone(BEFORE.connections[appId]));
  if (BEFORE.maps[appId]) value.put('applicationMaps', {id: appId, appId, operations: structuredClone(BEFORE.maps[appId].operations)});
  return value;
}

function bindingsNow(appId) {
  const config = PROXY_CONFIGS.get(appId), definition = PERMISSION_GROUPS.get(appId), policy = new ProxyPolicy({store: null});
  const templates = templatesFor(definition, config, BEFORE.maps[appId] ?? null);
  assert.ok(templates, `${appId}: the recorded map still covers every reviewed operation`);
  const context = {connection: BEFORE.connections[appId], config, templates};
  return Object.fromEntries(policy.rows({config, definition}).map(({row}) => [row, policy.binding(context, row)]));
}

/** The policy hash of one proxied request per reviewed member, on the member's own template (its alias forms come after it), by row and
 *  member; `reads` keeps what each member reads now (its provider access and unavailable reason). */
async function proxiedNow(t, appId, reads = {}) {
  const value = await store(t, appId), connectionId = BEFORE.connections[appId].id, config = PROXY_CONFIGS.get(appId), out = {}, seen = new Set();
  const policy = new ProxyPolicy({store: value, permissions: new PermissionManager({store: value})});
  for (const template of templatesFor(PERMISSION_GROUPS.get(appId), config, value.get('applicationMaps', appId)).filter(item => !item.unreviewed)) {
    if (seen.has(template.member)) continue;
    seen.add(template.member);
    const decision = policy.decide(connectionId, {method: template.method, path: `/${sample(template).join('/')}`, ...(['GET', 'HEAD', 'DELETE'].includes(template.method) ? {} : {body: {}})});
    (out[decision.row] ??= {})[template.member] = decision.policyHash;
    reads[template.member] = {providerAccess: decision.providerAccess, unavailable: decision.unavailable ?? null};
  }
  return out;
}

/** Every typed operation of the recorded map, compiled as test/f10-6-churn.test.mjs compiles it, by row and operation id. */
async function typedNow(t, appId) {
  const value = await store(t, appId), connection = value.get('connections', BEFORE.connections[appId].id), operations = BEFORE.maps[appId].operations, paths = {};
  for (const operation of operations) paths[operation.path] = {...paths[operation.path], [operation.method.toLowerCase()]: {operationId: operation.id,
    parameters: [...operation.path.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})), responses: {200: {description: 'ok'}}}};
  const caps = compileOpenApi({appId, document: {openapi: '3.0.3', info: {title: appId, version: '1'}, servers: [{url: SERVERS[appId]}], paths}}).capabilities.map(cap => ({...cap, status: 'active'}));
  for (const cap of caps) value.put('capabilities', cap);
  value.put('applicationMaps', {id: appId, appId, operations: operations.map(operation => ({...operation, capabilityId: caps.find(cap => cap.name === operation.id).id}))});
  const permissions = new PermissionManager({store: value}), out = {};
  for (const cap of caps) {const decision = permissions.decision(connection, cap); (out[`group:${decision.groupId}`] ??= {})[cap.name] = decision.policyHash;}
  return out;
}
/** The typed operations part e's data moved (see CHURN): those whose row now carries scope sets, and those it marked unavailable. */
function typedMoves(appId) {
  const churn = CHURN[appId];
  return PERMISSION_GROUPS.get(appId).groups.flatMap(group => group.operations.filter(id => group.scopeSets || group.memberScopeSets?.[id] || churn.typed.includes(group.unavailable?.[id])));
}

test('the recorded snapshot covers every proxy row, reviewed member and typed operation of the five apps', () => {
  const apps = [...PROXY_CONFIGS.keys()].sort();
  assert.deepEqual(Object.keys(BEFORE.connections).sort(), apps);
  for (const key of ['configHashes', 'bindings', 'proxied']) assert.deepEqual(Object.keys(BEFORE[key]).sort(), apps, key);
  assert.deepEqual(Object.keys(BEFORE.typed).sort(), Object.keys(BEFORE.maps).sort());
  assert.deepEqual(Object.keys(BEFORE.maps).sort(), ['gmail', 'google-calendar']);
  for (const appId of apps) {
    assert.match(BEFORE.configHashes[appId], HASH, appId);
    for (const [row, hash] of Object.entries(BEFORE.bindings[appId])) assert.match(hash, HASH, `${appId} ${row}`);
    for (const kind of ['proxied', 'typed']) for (const {row, hash} of Object.values(BEFORE[kind][appId] ? flat(BEFORE[kind][appId], `${appId} ${kind}`) : {})) assert.match(hash, HASH, `${appId} ${kind} ${row}`);
  }
  // Every typed operation of the five apps sits in the recorded maps, and every typed and reviewed proxy member was decided.
  for (const appId of Object.keys(BEFORE.maps)) assert.deepEqual(BEFORE.maps[appId].operations.map(operation => operation.id).sort(), PERMISSION_GROUPS.get(appId).groups.flatMap(group => group.operations).sort(), appId);
  const members = appId => Object.keys(flat(BEFORE.proxied[appId], appId)).length;
  assert.deepEqual(Object.fromEntries(apps.map(appId => [appId, members(appId)])), {github: 424, gmail: 79, 'google-calendar': 38, notion: 63, slack: 282});
  assert.deepEqual(Object.fromEntries(Object.keys(BEFORE.typed).map(appId => [appId, Object.keys(flat(BEFORE.typed[appId], appId)).length])), {gmail: 79, 'google-calendar': 38});
  assert.deepEqual(Object.keys(CHURN).sort(), apps);
  // One synthetic ready account per app, holding no scope, for the app's reviewed API address.
  for (const appId of apps) assert.deepEqual(BEFORE.connections[appId], {id: `f10-7-${appId}`, appId, authRevision: 'f10-7-before', identity: {id: 'f10-7'}, createdAt: '2026-10-18T00:00:00.000Z',
    driver: 'http', status: 'ready', authMethod: 'oauth', scopes: [], allowedOrigins: [proxyBase(PROXY_CONFIGS.get(appId).apiBase).origin]}, appId);
});

test('no proxy settings hash moves', () => {
  for (const appId of Object.keys(BEFORE.configHashes)) assert.equal(PROXY_CONFIGS.get(appId).configHash, BEFORE.configHashes[appId], appId);
});

test('proxy-row bindings move only as listed, and never for a row the owner may set to Allow', () => {
  for (const appId of Object.keys(BEFORE.bindings)) {
    const before = BEFORE.bindings[appId], now = bindingsNow(appId), churn = CHURN[appId];
    for (const id of PROXY_CONFIGS.get(appId).proxyAllowable) assert.equal(now[`group:${id}`], before[`group:${id}`], `${id} is proxyAllowable`);
    const kept = Object.keys(before).filter(row => !churn.removed.includes(row));
    assert.deepEqual(Object.keys(now).sort(), [...kept, ...churn.added].sort(), `${appId}: rows added and removed`);
    assert.deepEqual(kept.filter(row => now[row] !== before[row]).sort(), [...churn.changed].sort(), `${appId}: rows whose binding changed`);
  }
});

test('proxied policy hashes move only in rows whose binding moved, and for the members listed', async t => {
  for (const appId of Object.keys(BEFORE.proxied)) {
    const churn = CHURN[appId], rows = new Set([...churn.changed, ...churn.added, ...churn.removed]), before = BEFORE.proxied[appId], reads = {}, now = await proxiedNow(t, appId, reads);
    const inMovedRows = [...Object.entries(before), ...Object.entries(now)].filter(([row]) => rows.has(row)).flatMap(([, members]) => Object.keys(members));
    const byData = Object.keys(reads).filter(member => movedByData(churn, reads[member]));
    assert.deepEqual(moved(before, now, appId), [...new Set([...inMovedRows, ...byData])].sort(), `${appId}: proxied members whose policy hash moved`);
  }
});

test('typed policy hashes move only as listed', async t => {
  for (const appId of Object.keys(BEFORE.typed)) assert.deepEqual(moved(BEFORE.typed[appId], await typedNow(t, appId), appId), [...new Set(typedMoves(appId))].sort(), `${appId}: typed operations whose policy hash moved`);
});

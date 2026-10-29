import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {PERMISSION_GROUPS, validatePermissionGroups} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {PermissionManager} from '../lib/permissions.mjs';
import {templatesFor} from '../lib/proxy-match.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {Store} from '../lib/store.mjs';
import {stripped} from './fixtures/access/f10-6-fixtures.mjs';

// F10.6 listed churn (docs/F10.6-BUILD-MAP.md section 6): the shipped rows' unavailable markers change the policy hash of exactly
// the members they mark, typed and proxied, and never a binding. Each shipped definition is compared with the same rows stripped
// of the F10.6 keys, over every reviewed template filled in as test/proxy-request.test.mjs fills them, and (typed) over the Gmail
// and Calendar maps recorded for F10.3. test/f10-3-binding-churn.test.mjs keeps every proxy-row binding as it was. F10.7 (build map
// section 4): the rows compared are F10.6's as shipped, recorded in test/fixtures/access/f10-6-rows.snapshot.json, so the scope data
// F10.7 adds is measured by test/f10-7-churn.test.mjs, not here.
const BEFORE = JSON.parse(readFileSync(new URL('./fixtures/access/f10-3-bindings.before.json', import.meta.url), 'utf8'));
const F10_6 = JSON.parse(readFileSync(new URL('./fixtures/access/f10-6-rows.snapshot.json', import.meta.url), 'utf8')).apps;
const SERVERS = {gmail: 'https://gmail.googleapis.com', 'google-calendar': 'https://www.googleapis.com/calendar/v3'};
const ORIGINS = {gmail: 'https://gmail.googleapis.com', 'google-calendar': 'https://www.googleapis.com', github: 'https://api.github.com', notion: 'https://api.notion.com', slack: 'https://slack.com'};
const MARKED = {gmail: 21, 'google-calendar': 0, github: 2, notion: 3, slack: 0};
const sample = template => template.segments.flatMap(part => part.kind === 'literal' ? [part.value] : part.kind === 'param' ? ['p1'] : part.kind === 'verb' ? [`p1${part.suffix}`] : ['a', 'b']);

async function store(t, appId) {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-f10-6-churn-')), value = new Store({dataDir: dir});
  t.after(async () => {value.close(); await rm(dir, {recursive: true, force: true});});
  value.put('connections', {...(BEFORE.connections[appId] ?? {id: `f10-6-${appId}`, appId, authRevision: 'f10-6', identity: {id: 'f10-6'}, createdAt: '2026-10-18T00:00:00.000Z'}),
    driver: 'http', status: 'ready', authMethod: 'oauth', scopes: [], allowedOrigins: [ORIGINS[appId]]});
  if (BEFORE.maps[appId]) value.put('applicationMaps', {id: appId, appId, operations: BEFORE.maps[appId].operations});
  return value;
}
const changed = (before, after) => [...new Set(Object.keys(after).filter(member => after[member].policyHash !== before[member].policyHash))].sort();

test('proxied: exactly the marked members change their policy hash, and no binding moves', async t => {
  let total = 0;
  for (const appId of Object.keys(MARKED)) {
    const value = await store(t, appId), connectionId = value.list('connections')[0].id, config = PROXY_CONFIGS.get(appId), map = value.get('applicationMaps', appId);
    const decide = definition => {
      const groups = new Map([[appId, definition]]), policy = new ProxyPolicy({store: value, permissions: new PermissionManager({store: value, groups}), groups}), out = {};
      for (const template of templatesFor(definition, config, map).filter(item => !item.unreviewed && !item.request.includes('/repositories/{repository_id}'))) {
        const decision = policy.decide(connectionId, {method: template.method, path: `/${sample(template).join('/')}`, ...(['GET', 'HEAD', 'DELETE'].includes(template.method) ? {} : {body: {}})});
        if (decision.match.member) out[decision.match.member] = {policyHash: decision.policyHash, bindingHash: decision.bindingHash};
      }
      return out;
    };
    const shipped = validatePermissionGroups(F10_6[appId]), before = decide(validatePermissionGroups(stripped(shipped))), after = decide(shipped);
    const moved = changed(before, after), marked = shipped.groups.flatMap(group => Object.keys(group.unavailable ?? {}));
    assert.deepEqual(moved, [...marked].sort(), appId);
    assert.equal(moved.length, MARKED[appId], appId);
    assert.deepEqual(Object.keys(after).filter(member => after[member].bindingHash !== before[member].bindingHash), [], `${appId}: no binding moves`);
    total += moved.length;
  }
  assert.equal(total, 26);
});

test('typed: over the recorded Gmail and Calendar maps, exactly the 21 marked Gmail members change their policy hash, and no binding moves', async t => {
  for (const appId of ['gmail', 'google-calendar']) {
    const value = await store(t, appId), connection = value.list('connections')[0], operations = BEFORE.maps[appId].operations, paths = {};
    for (const operation of operations) paths[operation.path] = {...paths[operation.path], [operation.method.toLowerCase()]: {operationId: operation.id,
      parameters: [...operation.path.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})), responses: {200: {description: 'ok'}}}};
    const caps = compileOpenApi({appId, document: {openapi: '3.0.3', info: {title: appId, version: '1'}, servers: [{url: SERVERS[appId]}], paths}}).capabilities.map(cap => ({...cap, status: 'active'}));
    for (const cap of caps) value.put('capabilities', cap);
    value.put('applicationMaps', {id: appId, appId, operations: operations.map(operation => ({...operation, capabilityId: caps.find(cap => cap.name === operation.id).id}))});
    const decide = definition => {
      const permissions = new PermissionManager({store: value, groups: new Map([[appId, definition]])});
      return Object.fromEntries(caps.map(cap => {const decision = permissions.decision(connection, cap); return [cap.name, {policyHash: decision.policyHash, bindingHash: decision.bindingHash}];}));
    };
    const shipped = validatePermissionGroups(F10_6[appId]), before = decide(validatePermissionGroups(stripped(shipped))), after = decide(shipped);
    assert.deepEqual(changed(before, after), shipped.groups.flatMap(group => Object.keys(group.unavailable ?? {})).sort(), appId);
    assert.equal(changed(before, after).length, MARKED[appId], appId);
    assert.deepEqual(Object.keys(after).filter(name => after[name].bindingHash !== before[name].bindingHash), [], `${appId}: no binding moves`);
  }
});

test('the shipped rows still carry every marker F10.6 shipped, on the same member and for the same reason', () => {
  // F10.7 moved rows and added markers of its own; none of F10.6's may go missing or change its reason.
  const markers = groups => Object.fromEntries(groups.flatMap(group => Object.entries(group.unavailable ?? {})));
  let total = 0;
  for (const appId of Object.keys(MARKED)) {
    const before = markers(validatePermissionGroups(F10_6[appId]).groups), now = markers(PERMISSION_GROUPS.get(appId).groups);
    assert.equal(Object.keys(before).length, MARKED[appId], appId);
    for (const [member, reason] of Object.entries(before)) assert.equal(now[member], reason, `${appId} ${member}`);
    total += Object.keys(before).length;
  }
  assert.equal(total, 26);
});

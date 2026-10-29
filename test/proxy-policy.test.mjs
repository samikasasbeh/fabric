import test from 'node:test';
import assert from 'node:assert/strict';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {PROXY_CONFIGS, validateProxyConfig, loadProxyConfigs} from '../lib/proxy-config.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {fixture} from './fixtures/continuation-fixture.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';

// F08.0b (docs/F08.0-GOVERNED-PROXY.md section 5): reviewed proxy settings and the per-row decision.
// Fixture store, synthetic accounts that exist only inside the test, no network.
async function setup(t) {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const policy = new ProxyPolicy({store: f.store, permissions: f.runtime.permissions});
  const decide = (method, path, extra = {}, options) => policy.decide('acct-a', {method, path, ...extra}, options);
  return {f, policy, decide};
}
const other = (f, id, appId, origin, extra = {}) => f.store.put('connections', {id, appId, driver: 'http', authMethod: 'oauth', authRevision: `consent-${id}`, status: 'ready', label: id, identity: {id}, allowedOrigins: [origin], scopes: [], createdAt: '2026-10-11T10:00:00.000Z', ...extra});

test('reviewed proxy settings load for five apps and are refused when they would widen anything', () => {
  assert.deepEqual([...PROXY_CONFIGS.keys()].sort(), ['github', 'gmail', 'google-calendar', 'notion', 'slack']);
  const github = JSON.parse(JSON.stringify({...PROXY_CONFIGS.get('github')}));
  delete github.documented; delete github.configHash;
  const ok = {allowedOrigins: ['https://api.github.com'], routes: {routes: ['GET /user']}};
  assert.ok(validateProxyConfig(github, ok));
  const refuse = (change, options = ok) => assert.throws(() => validateProxyConfig({...github, ...change}, options), /Proxy settings/, JSON.stringify(change));
  assert.throws(() => validateProxyConfig(github, {...ok, allowedOrigins: ['https://other.example']}), /approved origins/);
  refuse({apiBase: 'http://api.github.com'});
  refuse({proxyAllowable: ['github.permanent.delete']}); refuse({proxyAllowable: ['github.repos.read']}); refuse({proxyAllowable: ['github.nope']});
  refuse({typedOnly: ['POST /not/reviewed']}); refuse({inheritFamilies: ['admin']}); refuse({pathPrefixes: ['/v1']});
  assert.throws(() => validateProxyConfig({...github, extra: 1}, ok), /exactly the documented fields/);
  assert.equal(loadProxyConfigs(new URL('../catalog/proxy/', import.meta.url)).get('github').documented.length, 1232);
});

test('defaults: reads follow the row, changes ask, Never rows and Other deletes stay Never', async t => {
  const {decide} = await setup(t);
  const cases = [
    ['GET', '/repos/o/r/issues', 'group:github.issues.read', 'allow'],
    ['POST', '/repos/o/r/issues', 'group:github.issues.write', 'ask'],
    ['PUT', '/notifications', 'group:github.notifications.manage', 'ask'],
    ['DELETE', '/repos/o/r', 'group:github.permanent.delete', 'deny'],
    ['GET', '/user/emails', 'other-reads', 'ask'],
    ['POST', '/some/new/endpoint', 'other-changes', 'ask'],
    ['DELETE', '/repos/o/r/x/y', 'other-deletes', 'deny'],
    ['POST', '/graphql', 'graphql', 'deny'],
  ];
  for (const [method, path, row, mode] of cases) {
    const decision = decide(method, path, method === 'GET' || method === 'DELETE' ? {} : {body: {}});
    assert.deepEqual([decision.row, decision.mode], [row, mode], `${method} ${path}`);
    assert.equal(decision.requiresApproval, mode === 'ask');
  }
  assert.equal(decide('GET', '/repos/o/r/issues').request.url, 'https://api.github.com/repos/o/r/issues');
});

test('Allow for a change is offered only on reviewed rows and needs its own confirmation; deletes and Other changes never Allow', async t => {
  const {policy, decide} = await setup(t);
  const set = (row, mode, confirmAllow) => policy.set({connectionId: 'acct-a', row, mode, confirmAllow});
  assert.throws(() => set('group:github.issues.write', 'allow', true), error => error.code === 'invalid_request', 'not a reviewed in-account row');
  assert.throws(() => set('group:github.permanent.delete', 'allow', true), error => error.code === 'invalid_request');
  assert.throws(() => set('other-changes', 'allow', true), error => error.code === 'invalid_request');
  assert.throws(() => set('group:github.notifications.manage', 'allow'), error => error.code === 'confirm_required');
  assert.equal(set('group:github.notifications.manage', 'allow', true).mode, 'allow');
  assert.equal(decide('PUT', '/notifications', {body: {}}).mode, 'allow', 'the proxy Allow on a reviewed row');
  set('group:github.permanent.delete', 'ask');
  // F10.7: deleting a whole repository is unavailable (delete_repo is never requested), so a release delete stands in.
  assert.equal(decide('DELETE', '/repos/o/r/releases/1').mode, 'ask', 'a delete can at most Ask');
  // The typed-operation setting never becomes the proxy's: Allow on a typed write leaves the proxy at Ask.
  assert.equal(decide('POST', '/repos/o/r/issues', {body: {}}).mode, 'ask');
});

test('c3: Other reads are never looser than the strictest read row', async t => {
  const {policy, decide} = await setup(t);
  policy.set({connectionId: 'acct-a', row: 'other-reads', mode: 'allow'});
  assert.equal(decide('GET', '/user/emails').mode, 'allow');
  policy.set({connectionId: 'acct-a', row: 'group:github.repos.read', mode: 'ask'});
  const clamped = decide('GET', '/user/emails');
  assert.equal(clamped.mode, 'ask'); assert.ok(clamped.clamps.includes('c3_read_rows'));
  policy.set({connectionId: 'acct-a', row: 'group:github.repos.read', mode: 'deny'});
  assert.equal(decide('GET', '/user/emails').mode, 'deny');
});

test('c3 and c4: a typed setting for the same endpoint, or any typed read, limits the proxy', async t => {
  const {f, policy, decide} = await setup(t);
  f.store.put('applicationMaps', {id: 'github', operations: [{id: 'listRepos', capabilityId: f.read.id, method: 'GET', path: '/user/repos'}, {id: 'createIssue', capabilityId: f.write.id, method: 'POST', path: '/repos/{owner}/{repo}/issues'}]});
  assert.equal(decide('GET', '/user/repos').mode, 'allow');
  f.runtime.permissions.set({connectionId: 'acct-a', capabilityId: f.read.id, mode: 'deny'});
  const denied = decide('GET', '/user/repos');
  assert.equal(denied.mode, 'deny'); assert.ok(denied.clamps.includes('c4_typed_operation'));
  policy.set({connectionId: 'acct-a', row: 'other-reads', mode: 'allow'});
  assert.equal(decide('GET', '/user/emails').mode, 'deny', 'a typed read set to Never also limits Other reads');
});

test('c5: an unreviewed sub-path inherits Never from the reviewed row above it', async t => {
  const {policy, decide} = await setup(t);
  policy.set({connectionId: 'acct-a', row: 'other-deletes', mode: 'ask'});
  const inherited = decide('DELETE', '/repos/o/r/x/y');
  assert.equal(inherited.mode, 'deny'); assert.ok(inherited.clamps.includes('c5_inherited_never')); assert.match(inherited.reason, /Permanently delete/);
  policy.set({connectionId: 'acct-a', row: 'group:github.permanent.delete', mode: 'ask'});
  assert.equal(decide('DELETE', '/repos/o/r/x/y').mode, 'ask');
});

test('c6 and c7: a write in a read row asks, and an unresolved uncertain write forces Ask', async t => {
  const {f, policy, decide} = await setup(t);
  policy.set({connectionId: 'acct-a', row: 'group:github.notifications.manage', mode: 'allow', confirmAllow: true});
  assert.equal(decide('PUT', '/notifications', {body: {}}, {unresolvedUncertain: true}).mode, 'ask');
  other(f, 'notion-a', 'notion', 'https://api.notion.com');
  const notion = policy.decide('notion-a', {method: 'POST', path: '/v1/views/v1/queries', body: {}});
  assert.deepEqual([notion.row, notion.effect, notion.mode], ['group:notion.content.read', 'write', 'ask'], 'a writing method not reviewed as a read is a change');
  assert.ok(notion.clamps.includes('c6_change_needs_reviewed_allow'));
  assert.equal(policy.decide('notion-a', {method: 'POST', path: '/v1/search', body: {}}).mode, 'allow', 'a reviewed read runs');
});

test('Gmail send stays typed-only, Slack is matched by method name, and missing maps or origins make the proxy unavailable', async t => {
  const {f, policy} = await setup(t);
  other(f, 'gmail-a', 'gmail', 'https://gmail.googleapis.com');
  assert.throws(() => policy.decide('gmail-a', {method: 'GET', path: '/gmail/v1/users/me/messages'}), error => error.code === 'proxy_unavailable', 'no stored map');
  const ids = PERMISSION_GROUPS.get('gmail').groups.flatMap(group => group.operations);
  const operations = ids.map(id => ({id, method: id.endsWith('.list') || id.endsWith('.get') ? 'GET' : 'POST', path: `/gmail/v1/users/{userId}/${id.split('.').slice(2).join('/')}`}));
  operations[operations.findIndex(op => op.id === 'gmail.users.messages.send')] = {id: 'gmail.users.messages.send', method: 'POST', path: '/gmail/v1/users/{userId}/messages/send', scopeSets: [['https://www.googleapis.com/auth/gmail.send']]};
  f.store.put('applicationMaps', {id: 'gmail', operations});
  const send = policy.decide('gmail-a', {method: 'POST', path: '/gmail/v1/users/me/messages/send', body: {raw: 'x'}});
  assert.equal(send.mode, 'deny'); assert.ok(send.clamps.includes('typed_only')); assert.equal(send.executable, false);
  assert.equal(send.providerAccess, 'missing', 'scopes come from the reviewed map');
  // On a row that Allows, a missing provider scope still blocks: local Allow cannot stand in for provider consent.
  const listIndex = operations.findIndex(op => op.id === 'gmail.users.messages.list');
  operations[listIndex] = {...operations[listIndex], method: 'GET', path: '/gmail/v1/users/{userId}/messages', scopeSets: [['https://www.googleapis.com/auth/gmail.readonly']]};
  f.store.put('applicationMaps', {id: 'gmail', operations});
  const list = policy.decide('gmail-a', {method: 'GET', path: '/gmail/v1/users/me/messages'});
  assert.deepEqual([list.mode, list.providerAccess, list.executable], ['allow', 'missing', false]); assert.match(list.reason, /provider scope/);
  f.store.put('connections', {...f.store.get('connections', 'gmail-a'), scopes: ['https://www.googleapis.com/auth/gmail.readonly']});
  assert.deepEqual([policy.decide('gmail-a', {method: 'GET', path: '/gmail/v1/users/me/messages'}).providerAccess, policy.decide('gmail-a', {method: 'GET', path: '/gmail/v1/users/me/messages'}).executable], ['granted', true]);
  other(f, 'slack-a', 'slack', 'https://slack.com');
  const viaGet = policy.decide('slack-a', {method: 'GET', path: '/chat.postMessage', query: {channel: 'C1', text: 'hi'}});
  assert.deepEqual([viaGet.row, viaGet.effect, viaGet.mode], ['group:slack.messages.send', 'write', 'ask']);
  assert.equal(policy.decide('slack-a', {method: 'POST', path: '/admin.users.brandNew', body: {}}).mode, 'deny', 'the admin family is Never');
  other(f, 'gh-elsewhere', 'github', 'https://github.example.com');
  assert.throws(() => policy.decide('gh-elsewhere', {method: 'GET', path: '/user'}), error => error.code === 'proxy_unavailable');
  f.store.put('connections', {...f.store.get('connections', 'acct-a'), status: 'revoked'});
  assert.throws(() => policy.decide('acct-a', {method: 'GET', path: '/user'}), error => error.code === 'proxy_unavailable');
});

test('settings drift: Never stays Never, Allow falls back to Ask, and every change has a fresh revision (no ABA)', async t => {
  const {f, policy, decide} = await setup(t);
  policy.set({connectionId: 'acct-a', row: 'group:github.issues.read', mode: 'deny'});
  policy.set({connectionId: 'acct-a', row: 'group:github.notifications.manage', mode: 'allow', confirmAllow: true});
  const before = decide('GET', '/user/emails').policyHash;
  policy.set({connectionId: 'acct-a', row: 'group:github.repos.read', mode: 'deny'});
  policy.set({connectionId: 'acct-a', row: 'group:github.repos.read', mode: 'allow'});
  assert.notEqual(decide('GET', '/user/emails').policyHash, before, 'flipping a related row and back changes the hash');
  f.store.put('connections', {...f.store.get('connections', 'acct-a'), authRevision: 'consent-new'});
  const stale = decide('GET', '/repos/o/r/issues');
  assert.deepEqual([stale.mode, stale.stale], ['deny', true], 'a Never survives reauthorization');
  const allow = decide('PUT', '/notifications', {body: {}});
  assert.deepEqual([allow.mode, allow.stale], ['ask', true], 'an Allow does not survive it');
  assert.equal(policy.reset({connectionId: 'acct-a'}), 2, 'the row set back to its default already follows it');
  assert.equal(decide('GET', '/repos/o/r/issues').mode, 'allow');
  const records = f.store.list('permissions').filter(record => record.kind === 'proxy-row');
  assert.ok(records.length === 3 && records.every(record => record.followsDefault === true), 'reset writes records, never deletes them');
  assert.ok(f.store.list('activity').some(event => event.type === 'proxy.policy.reset'));
});

test('the owner view lists every proxy row with what can be chosen', async t => {
  const {policy} = await setup(t);
  const rows = policy.view('acct-a');
  assert.equal(rows.length, PERMISSION_GROUPS.get('github').groups.length + 4);
  const byRow = Object.fromEntries(rows.map(row => [row.row, row]));
  assert.deepEqual(byRow['other-reads'].allowedModes, ['allow', 'ask', 'deny']);
  assert.deepEqual(byRow['other-changes'].allowedModes, ['ask', 'deny']);
  assert.deepEqual(byRow['group:github.notifications.manage'].allowedModes, ['allow', 'ask', 'deny']);
  assert.deepEqual(byRow['group:github.issues.write'].allowedModes, ['ask', 'deny']);
  assert.deepEqual([byRow.graphql.mode, byRow['other-deletes'].mode], ['deny', 'deny']);
});

// ---- review fixes ----------------------------------------------------------------------------
const compiled = (appId, server, path, method) => {
  const cap = compileOpenApi({appId, document: {openapi: '3.0.3', info: {title: 'x', version: '1'}, servers: [{url: server}], paths: {[path]: {[method]: {operationId: `${method}-${path}`, responses: {200: {description: 'ok'}}}}}}}).capabilities[0];
  return {...cap, status: 'active'};
};

test('c4 holds without any stored map, through aliases, for RPC method spelling and in the Other rows', async t => {
  const {f, policy, decide} = await setup(t);
  assert.equal(f.store.get('applicationMaps', 'github'), null, 'GitHub, Slack and Notion never have a stored map');
  f.runtime.permissions.set({connectionId: 'acct-a', capabilityId: f.read.id, mode: 'deny'});
  f.runtime.permissions.set({connectionId: 'acct-a', capabilityId: f.write.id, mode: 'deny'});
  assert.equal(decide('GET', '/user/repos').mode, 'deny');
  assert.equal(decide('POST', '/repos/o/r/issues', {body: {}}).mode, 'deny');
  assert.equal(decide('POST', '/repositories/1/issues', {body: {}}).mode, 'deny', 'the alias route reaches the same typed operation');
  const emails = compiled('github', 'https://api.github.com', '/user/emails', 'post');
  f.store.put('capabilities', emails);
  f.runtime.permissions.set({connectionId: 'acct-a', capabilityId: emails.id, mode: 'deny'});
  const otherChange = decide('POST', '/user/emails', {body: {}});
  assert.deepEqual([otherChange.row, otherChange.mode], ['other-changes', 'deny'], 'c4 applies in the Other rows too');
  other(f, 'slack-a', 'slack', 'https://slack.com');
  const history = compiled('slack', 'https://slack.com/api', '/conversations.history', 'post');
  f.store.put('capabilities', history);
  f.runtime.permissions.set({connectionId: 'slack-a', capabilityId: history.id, mode: 'deny'});
  for (const method of ['GET', 'POST']) assert.equal(policy.decide('slack-a', {method, path: '/conversations.history', ...(method === 'POST' ? {body: {}} : {})}).mode, 'deny', `RPC ${method}`);
});

test('no ABA: a related row that drifts and returns never restores an old hash, and c7 stays out of the hash', async t => {
  const {policy, decide} = await setup(t);
  const v1 = PROXY_CONFIGS, raw = {...PROXY_CONFIGS.get('github')};
  delete raw.documented; delete raw.configHash;
  const routes = {routes: [...PROXY_CONFIGS.get('github').documented]};
  const v2 = new Map([...v1, ['github', validateProxyConfig({...raw, typedOnly: [...raw.typedOnly], acceptTypes: ['application/json', 'application/vnd.github+json']}, {allowedOrigins: ['https://api.github.com'], routes})]]);
  const before = decide('GET', '/user/emails').policyHash;
  policy.set({connectionId: 'acct-a', row: 'group:github.repos.read', mode: 'deny'});
  policy.configs = v2; policy.set({connectionId: 'acct-a', row: 'group:github.repos.read', mode: 'ask'});
  policy.configs = v1;
  assert.notEqual(decide('GET', '/user/emails').policyHash, before);
  policy.set({connectionId: 'acct-a', row: 'group:github.notifications.manage', mode: 'allow', confirmAllow: true});
  const plain = decide('PUT', '/notifications', {body: {}}), uncertain = decide('PUT', '/notifications', {body: {}}, {unresolvedUncertain: true});
  assert.deepEqual([plain.mode, uncertain.mode], ['allow', 'ask']); assert.equal(uncertain.policyHash, plain.policyHash);
});

test('settings data: only in-account reversible rows may Allow, aliases only map root resources, typed-only matches any spelling', async t => {
  assert.deepEqual(PROXY_CONFIGS.get('gmail').proxyAllowable, ['gmail.labels.manage'], 'marking can trash or spam mail in bulk, so it is not Allow-able');
  const github = {...PROXY_CONFIGS.get('github')}; delete github.documented; delete github.configHash;
  const ok = {allowedOrigins: ['https://api.github.com'], routes: {routes: ['GET /user']}};
  for (const id of ['github.actions.run', 'github.code.write', 'github.issues.write']) assert.throws(() => validateProxyConfig({...github, typedOnly: [], proxyAllowable: [id]}, ok), /staying inside the account/, id);
  const gmail = {...PROXY_CONFIGS.get('gmail')}; delete gmail.documented; delete gmail.configHash;
  for (const id of ['gmail.messages.mark', 'gmail.settings.write', 'gmail.access.grant', 'gmail.messages.send']) assert.throws(() => validateProxyConfig({...gmail, typedOnly: [], proxyAllowable: [id]}, {allowedOrigins: ['https://gmail.googleapis.com']}), /staying inside the account/, id);
  assert.throws(() => validateProxyConfig({...github, typedOnly: [], aliases: [{from: '/repos/{owner}/{repo}/notifications', to: '/repos/{owner}/{repo}/collaborators/{username}'}]}, ok), /root resource/);
  const narrowed = validateProxyConfig({...github, typedOnly: ['PUT /repos/{owner}/{repo}/contents/{+path}']}, {...ok, routes: {routes: [...PROXY_CONFIGS.get('github').documented]}});
  const {f} = await setup(t);
  const policy = new ProxyPolicy({store: f.store, permissions: f.runtime.permissions, configs: new Map([...PROXY_CONFIGS, ['github', narrowed]])});
  const contents = policy.decide('acct-a', {method: 'PUT', path: '/repos/o/r/contents/.github/workflows/x.yml', body: {}});
  assert.equal(contents.mode, 'deny'); assert.ok(contents.clamps.includes('typed_only'));
});

test('robustness: Slack /graphql, malformed maps and the typed reset', async t => {
  const {f, policy, decide} = await setup(t);
  other(f, 'slack-a', 'slack', 'https://slack.com');
  for (const path of ['/graphql', '/GraphQL']) assert.equal(policy.decide('slack-a', {method: 'POST', path, body: {}}).row, 'other-changes', path);
  f.store.put('applicationMaps', {id: 'github', operations: [null, 7]});
  assert.equal(decide('GET', '/user/repos').mode, 'deny', 'a typed decision that cannot be computed fails closed, without crashing the proxy');
  f.store.put('applicationMaps', {id: 'github', operations: [{id: 'x'}]});
  assert.equal(decide('GET', '/user/repos').mode, 'allow');
  policy.set({connectionId: 'acct-a', row: 'group:github.issues.read', mode: 'deny'});
  assert.equal(f.runtime.permissions.reset({connectionId: 'acct-a'}), 0, 'the typed reset leaves proxy rows alone');
  assert.equal(decide('GET', '/repos/o/r/issues').mode, 'deny');
});

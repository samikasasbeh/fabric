import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {hostedSetup} from './fixtures/hosted-fixture.mjs';
import {owner, fixture} from './fixtures/continuation-fixture.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {PERMISSION_GROUPS, validatePermissionGroups} from '../lib/permission-groups.mjs';
import {describePage} from '../public/hosted-approve.js';

// F03.11 security review, group d (governance and the proxy): GOV-2 to GOV-6 and ISO-4. Each test fails on the code
// before its fix; test/faults/review-d.mjs seeds each fix back out.
const rowOf = (view, groupId) => view.sections.flatMap(section => section.rows).find(row => row.groupId === groupId);

/** The hosted setup plus one GitHub account (read:user and repo) for u1, and a proxy call on it. */
async function githubWorld(t) {
  const setup = await hostedSetup(t);
  const {app, keys, call, repo, userOf, scope} = setup;
  await call(keys.standard, 'POST', '/v1/connect-sessions', {externalUserId: 'u1'});
  const user = userOf('u1'), gh = randomUUID(), stamp = app.registry.now();
  repo().put('connections', stampOwner({id: gh, appId: 'github', providerId: 'github', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: '4242', displayName: 'octo'}, label: 'octo',
    allowedOrigins: ['https://api.github.com'], scopes: ['read:user', 'repo'], createdAt: stamp, updatedAt: stamp, authRevision: randomUUID(), providerApp: {kind: 'shared'}}, {subjectId: 'u1', userRecordId: user.id}));
  app.stores.open(scope).vault.set(gh, {accessToken: 'gho_review_d_token', refreshToken: '1//r', expiresAt: Date.parse(stamp) + 3600_000});
  const proxy = (request, key = keys.full) => call(key, 'POST', '/v1/proxy/requests', {externalUserId: 'u1', accountRef: gh, request}, {'Idempotency-Key': randomUUID()});
  const github = () => setup.sim.calls.filter(line => line.includes('api.github.com'));
  return {...setup, gh, proxy, github};
}

// ---- GOV-2 ---------------------------------------------------------------------------------------------------------
test('GOV-2: GitHub grants reachable with the repo scope are Never in a developer environment, in both path forms', async t => {
  const {proxy, github} = await githubWorld(t);
  const grants = [
    {method: 'PUT', path: '/orgs/acme/teams/t/memberships/eve', body: {role: 'maintainer'}},
    {method: 'PUT', path: '/teams/7/memberships/eve'},
    {method: 'PUT', path: '/orgs/acme/teams/t/repos/o/r', body: {permission: 'admin'}},
    {method: 'PUT', path: '/teams/7/repos/o/r', body: {permission: 'admin'}},
    {method: 'PUT', path: '/user/installations/1/repositories/2'},
    {method: 'POST', path: '/repos/o/r/actions/runners/registration-token'},
    {method: 'POST', path: '/repos/o/r/actions/runners/generate-jitconfig', body: {name: 'x', runner_group_id: 1, labels: ['self-hosted']}},
    {method: 'POST', path: '/orgs/acme/actions/runners/registration-token'},
    {method: 'POST', path: '/orgs/acme/actions/runners/generate-jitconfig', body: {name: 'x', runner_group_id: 1, labels: ['self-hosted']}},
    {method: 'PATCH', path: '/repos/o/r', body: {visibility: 'public'}},
    {method: 'PATCH', path: '/repositories/1', body: {private: false}},
    {method: 'POST', path: '/repos/o/r/forks', body: {organization: 'elsewhere'}},
    {method: 'POST', path: '/repositories/1/forks', body: {organization: 'elsewhere'}},
    {method: 'POST', path: '/repositories/1/actions/runners/registration-token'},
  ];
  for (const request of grants) {
    const answer = await proxy(request);
    assert.equal(answer.status, 403, `${request.method} ${request.path}: ${JSON.stringify(answer.body)}`); assert.equal(answer.body.error.code, 'permission_denied');
  }
  assert.deepEqual(github(), [], 'nothing reached GitHub');
  // Changes that give nothing away still wait for the person.
  for (const request of [{method: 'POST', path: '/repos/o/r/issues', body: {title: 'x'}}, {method: 'PATCH', path: '/repos/o/r/issues/1', body: {title: 'y'}}]) {
    const answer = await proxy(request);
    assert.equal(answer.body.status, 'awaiting_approval', `${request.method} ${request.path}`);
  }
});

// ---- GOV-6 ---------------------------------------------------------------------------------------------------------
test('GOV-6: locked org endpoints are Never through GitHub\'s id form /organizations/{organization_id} too', async t => {
  const {proxy, github} = await githubWorld(t);
  const viaId = [
    {method: 'POST', path: '/organizations/9919/hooks', body: {name: 'web', config: {url: 'https://evil.example'}}},
    {method: 'PATCH', path: '/organizations/9919/hooks/5/config', body: {url: 'https://evil.example'}},
    {method: 'POST', path: '/organizations/9919/invitations', body: {invitee_id: 1}},
    {method: 'PUT', path: '/organizations/9919/memberships/eve', body: {role: 'admin'}},
    {method: 'PUT', path: '/organizations/9919/actions/secrets/X', body: {encrypted_value: 'x', key_id: '1', visibility: 'all'}},
    {method: 'PUT', path: '/organizations/9919/dependabot/secrets/X', body: {encrypted_value: 'x', key_id: '1', visibility: 'all'}},
    {method: 'PUT', path: '/organizations/9919/teams/t/memberships/eve'},
    {method: 'PUT', path: '/organizations/9919/team/7/repos/o/r', body: {permission: 'admin'}},
    {method: 'POST', path: '/organizations/9919/actions/runners/registration-token'},
  ];
  for (const request of viaId) {
    const answer = await proxy(request);
    assert.equal(answer.status, 403, `${request.method} ${request.path}: ${JSON.stringify(answer.body)}`); assert.equal(answer.body.error.code, 'permission_denied');
  }
  assert.deepEqual(github(), [], 'nothing reached GitHub');
  assert.equal((await proxy({method: 'POST', path: '/organizations/9919/projects', body: {name: 'x'}})).body.status, 'awaiting_approval', 'an org change that grants nothing still waits');
});

// ---- GOV-3 ---------------------------------------------------------------------------------------------------------
const MUTATION = {query: 'mutation { updateTeamsRepository(input: {repositoryId: "R_1", teamIds: ["T_1"], permission: ADMIN}) { clientMutationId } }'};
test('GOV-3: every GraphQL request to an app with locked entries is t4_locked, and its proxy row offers Never only', async t => {
  const {app, scope, keys, call, repo, userOf, gh, proxy, github} = await githubWorld(t);
  // F10.3: GitHub has a row Fabric locks, so its GraphQL row offers Never only; Notion has none.
  const user = userOf('u1'), notion = randomUUID(), stamp = app.registry.now();
  repo().put('connections', stampOwner({id: notion, appId: 'notion', providerId: 'notion', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: 'n-1', displayName: 'Notion'}, label: 'Notion',
    allowedOrigins: ['https://api.notion.com'], scopes: [], createdAt: stamp, updatedAt: stamp, authRevision: randomUUID(), providerApp: {kind: 'shared'}}, {subjectId: 'u1', userRecordId: user.id}));
  const policy = app.runtimes.bundle(scope).runtime.proxyPolicy, graphqlRow = account => policy.rows(policy.route(account)).find(entry => entry.row === 'graphql');
  assert.deepEqual([graphqlRow(gh).allowedModes, graphqlRow(notion).allowedModes], [['deny'], ['ask', 'deny']]);
  // An Ask saved before the row offered Never only reads as Never, and a mutation is Never in Fabric's lock words.
  policy.store.put('permissions', {id: policy.policyId(gh, 'graphql'), kind: 'proxy-row', connectionId: gh, row: 'graphql', mode: 'ask', bindingHash: policy.binding(policy.route(gh), 'graphql'), revision: randomUUID(), updatedAt: stamp});
  const decided = policy.decide(gh, {method: 'POST', path: '/graphql', body: MUTATION});
  assert.deepEqual([decided.mode, decided.policySource, decided.locked, decided.reason], ['deny', 'saved', true, 'Fabric keeps this off: it gives access to other people or services. No setting can turn it on.']);
  // The row: Never only, and a key cannot open it to Ask.
  const view = (await call(keys.full, 'GET', `/v1/users/u1/apps/github?account=${gh}`)).body;
  const row = view.proxyRows.find(item => item.groupId === 'graphql');
  assert.deepEqual([row.mode, row.allowedModes], ['deny', ['deny']]);
  const opened = await call(keys.full, 'POST', `/v1/users/u1/accounts/${gh}/permissions`, {groupId: 'graphql', mode: 'ask', etag: row.etag, proxy: true});
  assert.equal(opened.status, 409); assert.equal(opened.body.error.code, 'mode_not_allowed');
  const refused = await proxy({method: 'POST', path: '/graphql', body: MUTATION});
  assert.equal(refused.status, 403); assert.equal(refused.body.error.code, 'permission_denied');
  // An agent cannot be given the row either.
  const token = await call(keys.full, 'POST', '/v1/users/u1/agent-tokens', {name: 'coder', proxy: [{accountRef: gh, rows: ['graphql']}]});
  assert.equal(token.status, 403); assert.equal(token.body.error.code, 'permission_denied');
  assert.deepEqual(github(), [], 'nothing reached GitHub');
});

// F10.3 (map correction 2): GOV-3 held by a row Fabric locks, in every deployment. The GraphQL row of such an app offers Never
// only, so its saved mode already reads Never; a policy whose GraphQL row still offers Ask isolates the clamp itself.
test('GOV-3 (F10.3): an app with a locked row keeps every GraphQL request Never, the clamp holds on its own, and Notion still offers Ask', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  f.store.put('connections', {id: 'notion-a', appId: 'notion', driver: 'http', authMethod: 'token', authRevision: 'consent-notion', status: 'ready', label: 'Notion', identity: {id: 'n1'}, allowedOrigins: ['https://api.notion.com'], createdAt: new Date(f.now).toISOString()});
  // The shipped GitHub rows have a row Fabric locks; the control is GitHub without it (and without the routes into it).
  const raw = JSON.parse(JSON.stringify(PERMISSION_GROUPS.get('github')));
  const unlocked = new Map([...PERMISSION_GROUPS, ['github', validatePermissionGroups({...raw, groups: raw.groups.filter(group => group.locked !== 'fabric').map(({bodyRoutes, ...group}) => group)})]]);
  class AskGraphql extends ProxyPolicy { allowedModes(entry, config, definition) { return entry.row === 'graphql' ? ['ask', 'deny'] : super.allowedModes(entry, config, definition); } }
  const policy = new ProxyPolicy({store: f.store, permissions: f.runtime.permissions}), graphqlRow = (on, account) => on.rows(on.route(account)).find(entry => entry.row === 'graphql');
  assert.deepEqual([graphqlRow(policy, 'acct-a').allowedModes, graphqlRow(policy, 'notion-a').allowedModes], [['deny'], ['ask', 'deny']]);
  const decided = policy.decide('acct-a', {method: 'POST', path: '/graphql', body: MUTATION});
  assert.deepEqual([decided.mode, decided.locked], ['deny', true]); assert.match(decided.reason, /No setting can turn it on/); assert.doesNotMatch(decided.reason, /developer environments/);
  for (const path of ['/repos/o/r/collaborators/octo', '/repositories/1/collaborators/octo']) assert.equal(policy.decide('acct-a', {method: 'PUT', path, body: {}}).row, 'group:github.access.grant', path);
  const isolated = new AskGraphql({store: f.store, permissions: f.runtime.permissions}), control = new AskGraphql({store: f.store, permissions: f.runtime.permissions, groups: unlocked});
  isolated.set({connectionId: 'acct-a', row: 'graphql', mode: 'ask'});
  const clamped = isolated.decide('acct-a', {method: 'POST', path: '/graphql', body: MUTATION}), open = control.decide('acct-a', {method: 'POST', path: '/graphql', body: MUTATION});
  assert.deepEqual([clamped.mode, clamped.clamps], ['deny', ['t4_locked']]);
  assert.deepEqual([open.mode, open.clamps], ['ask', []], 'the control: without a locked row the saved Ask stands');
  assert.equal(f.calls.length, 0);
});

// ---- GOV-4 ---------------------------------------------------------------------------------------------------------
test('GOV-4: a Reset under a developer ceiling keeps the write-Allow clamp, so lifting the ceiling never brings an Allow back', async t => {
  const {keys, call, sim, caps, account} = await hostedSetup(t);
  const ref = await account('u1', 'g-1');
  // F10.15 listed churn: the write row whose default is Allow is "Manage labels"; "Draft emails" is Never only in a developer environment.
  const labels = async () => rowOf((await call(keys.standard, 'GET', `/v1/users/u1/apps/gmail?account=${ref}`)).body, 'gmail.labels.manage');
  // The person's Never, relayed by a key without decisions:write (permissions:write and project:write only).
  assert.equal((await call(keys.standard, 'POST', `/v1/users/u1/accounts/${ref}/permissions`, {groupId: 'gmail.labels.manage', mode: 'deny', etag: (await labels()).etag})).status, 200);
  assert.equal((await call(keys.standard, 'PUT', '/v1/environment/apps/gmail', {ceilings: {'gmail.labels.manage': 'ask'}})).status, 200);
  const reset = await call(keys.standard, 'POST', `/v1/users/u1/accounts/${ref}/permissions/reset`, {groupIds: ['gmail.labels.manage']});
  assert.equal(reset.status, 200); assert.equal(reset.body.clampedToAsk, 1, 'the default Allow is clamped although the ceiling hides it');
  assert.equal((await call(keys.standard, 'PUT', '/v1/environment/apps/gmail', {ceilings: {'gmail.labels.manage': null}})).status, 200);
  assert.equal((await labels()).mode, 'ask', 'lifting the ceiling brings back Ask, not Allow');
  const create = (await caps()).find(item => item.id.includes('labels-create'));
  sim.calls.length = 0;
  const ran = await call(keys.standard, 'POST', '/v1/executions', {externalUserId: 'u1', accountRef: ref, capabilityId: create.id, definitionHash: create.definitionHash, args: {userId: 'me', body: {name: 'Receipts'}}}, {'Idempotency-Key': randomUUID()});
  assert.equal(ran.body.status, 'awaiting_approval', JSON.stringify(ran.body));
  assert.deepEqual(sim.calls, [], 'nothing was sent unattended');
});

test('GOV-4: the person\'s Reset on Fabric\'s page under a ceiling brings a write Allow back as Ask (Q6)', async t => {
  const {keys, call, open, account} = await hostedSetup(t);
  const ref = await account('u1', 'g-1');
  const link = await open(keys.full, {externalUserId: 'u1', purpose: 'manage', appId: 'gmail'});
  const page = {get: route => link.person.call('GET', `/connect/${link.id}/v1/${route}`), post: (route, body) => link.person.call('POST', `/connect/${link.id}/v1/${route}`, body)};
  const drafts = async () => rowOf((await page.get(`apps/gmail?account=${ref}`)).body, 'gmail.drafts.write');
  assert.equal((await page.post(`apps/gmail/accounts/${ref}/permissions`, {groupId: 'gmail.drafts.write', mode: 'deny', etag: (await drafts()).etag})).status, 200);
  await call(keys.standard, 'PUT', '/v1/environment/apps/gmail', {ceilings: {'gmail.drafts.write': 'deny'}});
  const reset = await page.post(`apps/gmail/accounts/${ref}/reset`, {groupIds: ['gmail.drafts.write']});
  assert.equal(reset.status, 200); assert.equal(reset.body.clampedToAsk, 1);
  await call(keys.standard, 'PUT', '/v1/environment/apps/gmail', {ceilings: {'gmail.drafts.write': null}});
  assert.equal((await drafts()).mode, 'ask');
});

// ---- GOV-5 ---------------------------------------------------------------------------------------------------------
test('GOV-5: Fabric\'s approve page names the person\'s own account the call acts on, by its display name only', async t => {
  const {keys, call, caps, account, open} = await hostedSetup(t);
  await account('u1', 'g-personal', {displayName: 'me.personal@example.com'});
  const work = await account('u1', 'g-work', {displayName: 'me@employer.example'});
  const send = (await caps()).find(item => item.id.includes('messages-send'));
  const waiting = (await call(keys.standard, 'POST', '/v1/executions', {externalUserId: 'u1', accountRef: work, capabilityId: send.id, definitionHash: send.definitionHash, args: {userId: 'me', body: {raw: 'eA'}}}, {'Idempotency-Key': randomUUID()})).body;
  assert.equal(waiting.status, 'awaiting_approval');
  const link = await open(keys.approve, {externalUserId: 'u1', purpose: 'approve', callRef: waiting.callRef});
  const shown = (await link.person.call('GET', `/connect/${link.id}/v1/approval`)).body;
  assert.equal(shown.state, 'pending');
  assert.equal(shown.approval.account, 'me@employer.example');
  assert.equal(JSON.stringify(shown).includes('me.personal'), false, 'the other account is not named');
  assert.ok(describePage(shown, {tenant: true}).notes.includes('On your account me@employer.example'), JSON.stringify(describePage(shown, {tenant: true}).notes));
  // The developer's relay still carries the opaque accountRef only (D7).
  const relayed = (await call(keys.full, 'GET', '/v1/users/u1/approvals')).body.approvals.find(item => item.callRef === waiting.callRef);
  assert.equal(relayed.accountRef, work); assert.equal('account' in relayed, false);
});

// ---- ISO-4 ---------------------------------------------------------------------------------------------------------
const json = (status, body) => ({status, headers: {'content-type': 'application/json'}, data: Buffer.from(JSON.stringify(body))});
/** The local runtime with one GitHub account, every list of the response collection counted. */
async function bodies(t) {
  const f = await fixture(t);
  f.account('acct-a', '101');
  f.hooks.request = async () => json(200, {big: 'x'.repeat(200)});
  const store = f.runtime.store, list = store.list.bind(store), lists = [];
  store.list = collection => { lists.push(collection); return list(collection); };
  const read = () => f.runtime.createProxyJob({connectionId: 'acct-a', request: {method: 'GET', path: '/repos/o/r/issues'}}, owner);
  return {f, store, lists, read, scans: () => lists.filter(name => name === 'proxyResponses').length};
}

test('ISO-4: a proxied call finds its holder\'s kept bodies by key, never by reading every stored body', async t => {
  const {f, store, read, scans} = await bodies(t);
  const first = await read();
  assert.equal(first.result.response.payload, 'stored');
  // Other holders keep many bodies; the next calls must not read them.
  for (let i = 0; i < 40; i++) store.put('proxyResponses', {id: randomUUID(), holder: `user:other-${i}`, body: {big: 'y'.repeat(2000)}, bytes: 2012, createdAt: new Date(f.now).toISOString(), expiresAt: new Date(f.now + 1000).toISOString()});
  const before = scans();
  const second = await read();
  assert.equal(second.result.response.payload, 'stored');
  // The quota still holds: the third body would pass it.
  f.runtime.proxyResponseQuota = 2 * Buffer.byteLength(JSON.stringify({body: {big: 'x'.repeat(200)}})) + 10;
  const third = await read();
  assert.equal(third.result.response.payload, 'over_quota'); assert.equal(third.status, 'succeeded');
  // A week later this holder's bodies are gone, by key, and the quota is free again.
  f.advance(7 * 24 * 60 * 60 * 1000 + 1);
  const later = await read();
  assert.equal(later.result.response.payload, 'stored');
  assert.equal(store.get('proxyResponses', first.id), null); assert.equal(store.get('proxyResponses', second.id), null);
  assert.equal(scans(), before, 'no call listed the response collection');
});

test('ISO-4: bodies kept before holders had an index still count toward the quota and still expire', async t => {
  const {f, store, read} = await bodies(t);
  const old = randomUUID(), size = Buffer.byteLength(JSON.stringify({body: {big: 'x'.repeat(200)}}));
  store.put('proxyResponses', {id: old, holder: 'owner', connectionId: 'acct-a', body: {big: 'x'.repeat(200)}, bytes: size, createdAt: new Date(f.now).toISOString(), expiresAt: new Date(f.now + 60_000).toISOString()});
  f.runtime.proxyResponseQuota = size + 10;
  assert.equal((await read()).result.response.payload, 'over_quota', 'the old body counts');
  f.advance(60_001);
  const after = await read();
  assert.equal(after.result.response.payload, 'stored'); assert.equal(store.get('proxyResponses', old), null, 'the old body expired by key');
});

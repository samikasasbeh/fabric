import test from 'node:test';
import {randomUUID} from 'node:crypto';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, readdirSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {Store} from '../lib/store.mjs';
import {Vault} from '../lib/vault.mjs';
import {ConnectionManager, catalog} from '../lib/connections.mjs';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {AppDetailService} from '../lib/app-detail.mjs';
import {offeredLevels, heldLevel, levelLabel} from '../lib/access-levels.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {END_USER_COLLECTIONS} from '../lib/tenant/users.mjs';
import {capabilityPermissionHash} from '../lib/permissions.mjs';
import {NOTES, NOTE_SOURCES, notePages, pagesNote, pagesLevel} from '../lib/connection-notes.mjs';
import {notionHarness, notionFile} from './fixtures/actions/notion-harness.mjs';
import {developerHarness} from './fixtures/actions/developer-fixture.mjs';
import {fixture as ownerServer} from './fixtures/signin-fixture.mjs';
import {SIMULATORS} from './fixtures/oauth-simulators.mjs';

// F10.19 part 2 (docs/F10.19-BUILD-MAP.md section 2, the account note; spec lines 1176-1177): a Notion account reads "Pages you shared (N)"
// once an agent's Search with no words, no kind and no cursor succeeds, in the owner's Fabric and in a developer environment. The note sits in
// its own collection (lib/connection-notes.mjs), so the connection record, its generation and health fields and every row etag stay as they
// were; a disconnect and an end user's erasure remove it; "Share more pages" signs in again on the same account, a renewal that keeps every
// saved setting. Nothing here reaches Notion: the action runs on the Notion simulator, the sign-in on the OAuth simulator.

const ROOT = new URL('../', import.meta.url);
/** Seeds `count` shared top pages. */
const sharePages = (h, count, from = 0) => { for (let index = from; index < from + count; index++) h.simulator.seedPage({title: `[SYNTHETIC] Shared ${index}`, shared: true}); };
const ended = (job, status) => { assert.equal(job.status, status, `${job.error ?? ''} ${JSON.stringify(job.details ?? '')}`); return job; };
const search = async (h, args = {}) => ended(await h.run('search v1', args), 'succeeded');
/** The owner's label for the harness account, as the owner's server builds it (server.mjs accessLevelOf). */
const ownerLabel = h => levelLabel(pagesLevel(h.store, h.store.get('connections', h.account), 'pages'));
/** What a note must never move: the connection record but its last use, and every row's mode and etag. */
const untouched = h => {
  const {lastUsedAt: _used, updatedAt: _updated, ...connection} = h.store.get('connections', h.account);
  return {connection, rows: h.proxyPolicy.view(h.account).map(row => [row.row, row.mode, row.etag])};
};

test('the label: "Pages you shared (N)" with a note, "(100+)" when Notion had more, and the plain words with none; the level stays pages', () => {
  assert.equal(levelLabel('pages'), 'Pages you shared');
  assert.equal(levelLabel({level: 'pages', pages: 12, more: false}), 'Pages you shared (12)');
  assert.equal(levelLabel({level: 'pages', pages: 0, more: false}), 'Pages you shared (0)');
  assert.equal(levelLabel({level: 'pages', pages: 100, more: true}), 'Pages you shared (100+)');
  assert.equal(levelLabel({level: 'pages', pages: 37, more: true}), 'Pages you shared (37+)', 'Notion may answer a short page that still has more');
  for (const broken of [{level: 'pages'}, {level: 'pages', pages: -1, more: false}, {level: 'pages', pages: 1.5, more: false}, {level: 'pages', pages: 3}]) assert.equal(levelLabel(broken), 'Pages you shared');
  // A note never changes another level, and never turns one into pages.
  const store = {get: () => ({id: 'c1', connectionId: 'c1', appId: 'notion', pages: 4, more: false})};
  assert.deepEqual([pagesLevel(store, {id: 'c1', appId: 'notion'}, 'pages'), pagesLevel(store, {id: 'c1', appId: 'notion'}, 'full'), pagesLevel(store, {id: 'c1', appId: 'gmail'}, 'pages')],
    [{level: 'pages', pages: 4, more: false}, 'full', 'pages']);
  assert.deepEqual(NOTE_SOURCES, {notion: {action: 'search'}});
});

test('owner runtime: a Search with no query sets N; a query, a kind or a cursor leaves it; 100 with more reads (100+); the connection, its generation and every row etag stay', async t => {
  const h = notionHarness(t);
  sharePages(h, 12);
  await search(h, {query: 'shared'});
  assert.equal(pagesNote(h.store, h.store.get('connections', h.account)), null, 'a search with words counts nothing');
  assert.equal(ownerLabel(h), 'Pages you shared');
  const before = untouched(h);
  const full = await search(h);
  assert.deepEqual([full.result.data.results.length, pagesNote(h.store, h.store.get('connections', h.account)), ownerLabel(h)], [12, {pages: 12, more: false}, 'Pages you shared (12)']);
  assert.deepEqual(untouched(h), before, 'the note is never on the connection record, and no row moves');
  const note = h.store.get(NOTES, h.account);
  assert.deepEqual(Object.keys(note).sort(), ['appId', 'at', 'connectionId', 'id', 'more', 'pages']);
  assert.equal(note.at, new Date(h.now).toISOString());
  // Narrowed searches leave N as it was, even when they see more.
  sharePages(h, 3, 12);
  const first = await search(h, {kind: 'page'});
  assert.equal(first.result.data.results.length, 15);
  await search(h, {query: 'shared', kind: 'data_source'});
  assert.equal(ownerLabel(h), 'Pages you shared (12)');
  // 130 pages: the first full page is 100 with more; its cursor's page never sets N.
  sharePages(h, 115, 15);
  const hundred = await search(h);
  assert.deepEqual([hundred.result.data.results.length, hundred.result.data.hasMore, ownerLabel(h)], [100, true, 'Pages you shared (100+)']);
  await search(h, {cursor: hundred.result.data.nextCursor});
  assert.deepEqual(pagesNote(h.store, h.store.get('connections', h.account)), {pages: 100, more: true});
  // A failed Search writes nothing.
  h.simulator.fail('POST /search', {status: 400, data: {object: 'error', status: 400, code: 'validation_error', message: 'Simulated.', request_id: '00000000-0000-4000-8000-0000000000aa'}});
  ended(await h.run('search v1', {}), 'failed');
  assert.deepEqual(pagesNote(h.store, h.store.get('connections', h.account)), {pages: 100, more: true});
  // A disconnect removes the note.
  h.connections.revoke(h.account, null);
  assert.equal(h.store.get(NOTES, h.account), null);
});

test('the owner\'s app page shows the note on the Notion account: accessLevel pages, accessLabel "Pages you shared (N)"', async t => {
  const f = await ownerServer(t), at = new Date(f.now).toISOString();
  f.app.store.put('connections', {id: 'notion-a', appId: 'notion', providerId: 'notion', driver: 'http', authMethod: 'oauth', authRevision: 'r1', status: 'ready', label: 'Notion',
    identity: {id: 'ws-a:user-a', displayName: 'Avery'}, scopes: [], allowedOrigins: ['https://api.notion.com'], createdAt: at, updatedAt: at});
  const account = async () => (await f.json('GET', '/api/ui/apps/notion?account=notion-a')).body.accounts.find(item => item.accountRef === 'notion-a');
  assert.deepEqual([(await account()).accessLevel, (await account()).accessLabel], ['pages', 'Pages you shared']);
  const job = {status: 'succeeded', connectionId: 'notion-a', args: {}}, entry = {appId: 'notion', key: 'search'};
  notePages(f.app.store, job, entry, {results: Array(12).fill({}), hasMore: false}, at);
  assert.deepEqual([(await account()).accessLevel, (await account()).accessLabel], ['pages', 'Pages you shared (12)']);
  notePages(f.app.store, job, entry, {results: Array(100).fill({}), hasMore: true}, at);
  assert.equal((await account()).accessLabel, 'Pages you shared (100+)');
});

/** Notion's shipped Search alone, reviewed and certified, for the developer harness. */
const searchFile = () => {
  const file = notionFile();
  return {...file, reviewStatus: 'reviewed', actions: file.actions.filter(action => action.key === 'search').map(action => ({...action, certified: {evidence: 'docs/live-evidence/notion/actions.json', definitionHash: '0'.repeat(64)}}))};
};
/** Notion's search answer of `count` pages. */
const answer = (count, more = false) => ({status: 200, headers: {'content-type': 'application/json'}, data: {object: 'list', type: 'page_or_data_source', page_or_data_source: {}, has_more: more, next_cursor: more ? 'cursor-2' : null,
  results: Array.from({length: count}, (_, index) => ({object: 'page', id: `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`, url: `https://www.notion.so/page-${index}`, last_edited_time: '2026-10-20T10:00:00.000Z',
    in_trash: false, parent: {type: 'workspace', workspace: true}, properties: {title: {id: 'title', type: 'title', title: [{type: 'text', plain_text: `Page ${index}`, text: {content: `Page ${index}`}}]}}}))}});

test('developer environment: a Search with no query sets N on that person\'s account row, owner-stamped; a query leaves it; the person\'s erasure and a disconnect remove it', async t => {
  const d = await developerHarness(t, {notion: searchFile(), users: ['u1', 'u2']}), capability = d.capability('search v1');
  const run = async (user, args) => (await d.call(d.keys.standard, 'POST', '/v1/executions', {externalUserId: user, capabilityId: capability.id, definitionHash: capabilityPermissionHash(capability), args, waitMs: 5000},
    {'Idempotency-Key': randomUUID()})).body;
  const label = async user => (await d.call(d.keys.standard, 'GET', `/v1/users/${user}/accounts`)).body.accounts.find(row => row.appId === 'notion');
  assert.equal((await label('u1')).accessLabel, 'Pages you shared');
  d.fail('POST /v1/search', answer(7));
  assert.equal((await run('u1', {})).status, 'succeeded');
  assert.deepEqual([(await label('u1')).accessLevel, (await label('u1')).accessLabel, (await label('u2')).accessLabel], ['pages', 'Pages you shared (7)', 'Pages you shared']);
  const note = d.repo().get(NOTES, d.accounts.u1.notion), user = d.repo().list('endUsers').find(item => item.subjectId === 'u1' && item.status === 'active');
  assert.deepEqual([note.ownership, note.userRecordId], [{owner: {kind: 'product_user', id: 'u1'}}, user.id], 'stamped with its owner');
  // The person's own page on Fabric (a manage link) reads the same.
  const link = await d.open(d.keys.full, {externalUserId: 'u1', purpose: 'manage'}), hosted = (await link.get(`apps/notion?account=${d.accounts.u1.notion}`)).body;
  assert.deepEqual(hosted.accounts.map(row => row.accessLabel), ['Pages you shared (7)']);
  d.fail('POST /v1/search', answer(100, true));
  assert.equal((await run('u1', {query: 'page'})).status, 'succeeded');
  assert.equal((await label('u1')).accessLabel, 'Pages you shared (7)');
  d.fail('POST /v1/search', answer(100, true));
  await run('u2', {});
  assert.equal((await label('u2')).accessLabel, 'Pages you shared (100+)');
  // u2 disconnects the account: its note goes. u1 is erased: its note goes with the person.
  assert.equal((await d.call(d.keys.full, 'POST', `/v1/accounts/${d.accounts.u2.notion}/disconnect`, {})).status, 200);
  assert.equal(d.repo().get(NOTES, d.accounts.u2.notion), null);
  assert.ok((await d.call(d.keys.full, 'DELETE', '/v1/users/u1')).status < 300);
  assert.deepEqual(d.repo().list(NOTES), []);
});

test('"Share more pages": a pages account offers a sign-in on the same account, with no rows to confirm; that sign-in is a renewal that keeps every saved setting and the note', async t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'fabric-notion-note-'));
  let now = Date.UTC(2026, 9, 26, 12);
  const clock = () => now, client = {clientId: 'note-client', clientSecret: 'note-secret'}, sim = new SIMULATORS.notion({...client, clock});
  const store = new Store({dataDir: directory, clock, localAuthority: 'new'}), vault = new Vault(directory), request = req => sim.request(req);
  t.after(() => { store.close(); rmSync(directory, {recursive: true, force: true}); });
  const connections = new ConnectionManager({store, vault, request, clock});
  const provider = new OAuth2Provider(definitionFor('notion'), {store, vault, connections, request, clock, ...client, publishing: 'testing', redirectUri: 'https://connect.example.com/oauth/notion/4320', allowHostedRedirect: true});
  connections.setOAuthProvider(provider);
  const runtime = new Runtime({store, connections, clock, ownerPrincipal: {schemaVersion: 1, id: 'note-owner', kind: 'local_owner', scope: {schemaVersion: 1, kind: 'local', localOwnerId: 'note-owner'}}});
  const access = appId => provider.access(provider.app(appId));
  const service = new AppDetailService({store, runtime, catalog: () => catalog, oauthProviderFor: () => provider, accessLevels: appId => offeredLevels(access(appId)),
    accessLevelOf: connection => pagesLevel(store, connection, heldLevel(access(connection.appId), connection.scopes))});
  connections.setUpgradeGuard((previous, next, confirmed) => service.pinUnconfirmed(previous, next, confirmed));
  const signIn = async input => { const started = provider.start(input), grant = sim.consent(started.authorizationUrl, {}); return provider.callback({state: grant.state, code: grant.code, error: grant.error, flowId: started.flowId}); };
  const account = await signIn({appId: 'notion'});
  runtime.proxyPolicy.set({connectionId: account.id, row: 'group:notion.content.edit', mode: 'deny'});
  notePages(store, {status: 'succeeded', connectionId: account.id, args: {}}, {appId: 'notion', key: 'search'}, {results: Array(3).fill({}), hasMore: false}, new Date(now).toISOString());
  const view = service.view('notion', account.id);
  assert.deepEqual(view.upgrade, {label: 'Share more pages', providerId: 'notion', body: {connectionId: account.id}, rows: [], etag: null});
  assert.equal(view.accounts[0].accessLabel, 'Pages you shared (3)');
  const before = store.get('connections', account.id);
  now += 60_000;
  const again = await signIn(view.upgrade.body);
  const after = store.get('connections', account.id);
  assert.deepEqual([again.id, after.status, store.list('connections').length], [account.id, 'ready', 1], 'the same account, signed in again');
  assert.deepEqual(store.list('activity').filter(event => event.connectionId === account.id && /^connection\.(connected|reconsented|upgraded)$/.test(event.type)).map(event => event.type),
    ['connection.connected', 'connection.reconsented'], 'a renewal, never an upgrade');
  assert.deepEqual([after.authRevision, after.createdAt], [before.authRevision, before.createdAt], 'the authorization is kept');
  assert.equal(runtime.proxyPolicy.view(account.id).find(row => row.row === 'group:notion.content.edit').mode, 'deny', 'saved settings are kept');
  assert.deepEqual(pagesNote(store, after), {pages: 3, more: false}, 'N stays as of the last full search');
  // Another app's partial or read account still gets the full upgrade, never "Share more pages" (test/f10-7-full-access.test.mjs).
});

test('the collection: only lib/connection-notes.mjs reads or writes it; an end user\'s erasure lists it; no agent path imports the note', () => {
  assert.ok(END_USER_COLLECTIONS.includes(NOTES));
  const files = folder => readdirSync(new URL(folder, ROOT), {withFileTypes: true}).flatMap(entry => entry.isDirectory() ? files(`${folder}${entry.name}/`) : /\.(mjs|mts|js)$/.test(entry.name) ? [`${folder}${entry.name}`] : []);
  const source = [...files('lib/'), ...files('scripts/'), ...files('public/'), 'server.mjs', 'developer-server.mjs', 'mcp.mts', 'cli.mjs'].map(file => [file, readFileSync(new URL(file, ROOT), 'utf8')]);
  const naming = source.filter(([, text]) => text.includes("'connectionNotes'")).map(([file]) => file).sort();
  assert.deepEqual(naming, ['lib/connection-notes.mjs', 'lib/tenant/users.mjs']);
  const importing = source.filter(([, text]) => /from '\.{1,2}\/(?:lib\/)?(?:\.\.\/)?connection-notes\.mjs'/.test(text)).map(([file]) => file).sort();
  assert.deepEqual(importing, ['lib/actions-runtime.mjs', 'lib/connections.mjs', 'lib/tenant/accounts.mjs', 'lib/tenant/app-pages.mjs', 'lib/tenant/views.mjs', 'server.mjs']);
  for (const [file, text] of source.filter(([name]) => /fabric-protocol|mcp|agent/.test(name))) assert.ok(!/connection-notes|pagesNote|Pages you shared/.test(text), file);
});

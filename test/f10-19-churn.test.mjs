import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {templatesFor} from '../lib/proxy-match.mjs';
import {Store} from '../lib/store.mjs';
import {Vault} from '../lib/vault.mjs';
import {ConnectionManager} from '../lib/connections.mjs';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {addedHeaders, providerHeaders} from '../lib/proxy-runtime.mjs';
import {appEntry, checkSigned, readGolden, ROOT} from '../scripts/defaults-golden.mjs';
import {validatePrincipal} from '../contracts/identity.mts';
import {actionIds, validateActionFile} from '../lib/actions.mjs';
import {v1Definition} from './fixtures/auth-v1/urls.mjs';
import {SIMULATORS} from './fixtures/oauth-simulators.mjs';

// F10.19 (docs/F10.19-BUILD-MAP.md sections 3 and 6, test/f10-19-churn.test.mjs): what step 19 must not move. Part 1 changes one value,
// Notion's Notion-Version, from 2025-09-03 to 2026-03-11 (owner decision 7). Fabric adds the header itself on every request it sends to
// Notion: sign-in, identity, refresh and revocation (lib/providers/oauth2.mjs) and every proxied or action request (providerHeaders() in
// lib/proxy-runtime.mjs, which lib/actions-runtime.mjs calls too). The defaults table never reads apiHeaders, so Notion's data hash and
// Sami's 2026-10-20 sign-off stay; only Notion's files hash moves, for information. A pending Notion proxy job approved before the bump
// shows the old header, so it is refused as changed, never sent with a header the owner did not see.
const json = file => JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8'));
const LOADERS = json('./fixtures/access/f10-9-loaders.before.json');
const BEFORE = json('./fixtures/access/f10-9-bindings.before.json');
const VERSION = '2026-03-11', OLD_VERSION = '2025-09-03';
/** catalog/auth/notion.json at 7af1bde (test/f10-12-churn.test.mjs), text read with LF line ends, and its two digests in the golden then. */
const AUTH_BEFORE = '23db59a52b90f4f8b60fcd57ed15cad47952af4c666adf68a6c0444dca867041';
const FILES_BEFORE = Object.freeze({file: 'b88bf95f5a27ca5e063268e1b0ac3f33fe2928ac69d83a265496d30eb979b96d', hash: 'b13b2725703c946732e924a7b9117434a8947bb8e59330c00c6dfa00ece8c686'});
/** Sami's sign-off of Notion's defaults, 2026-10-20. */
const SIGNED = Object.freeze({by: 'Sami', date: '2026-10-20', dataHash: '33fee7708e0dda65c2ea5a6f1ea3a9832d5bfd7794cad67d609e0bd6f65c5e81'});
const OWNER = validatePrincipal({schemaVersion: 1, kind: 'local_owner', id: 'f1019-owner', scope: {schemaVersion: 1, kind: 'local', localOwnerId: 'f1019-owner'}});
const CLIENT = {clientId: 'f1019-client', clientSecret: 'f1019-secret'};
const REDIRECT = 'https://connect.example.com/oauth/notion/4320';
const NOTION = 'https://api.notion.com';
const plain = value => JSON.parse(JSON.stringify(value));
const versionOf = request => Object.entries(request.headers ?? {}).find(([name]) => name.toLowerCase() === 'notion-version')?.[1];

function temporary(t) {
  const directory = mkdtempSync(path.join(tmpdir(), 'fabric-f10-19-churn-'));
  t.after(() => rmSync(directory, {recursive: true, force: true}));
  return directory;
}

test('Notion\'s sign-in file differs from its recorded digest only by the version line; the version 1 fixture keeps 2025-09-03 (T6)', () => {
  const text = readFileSync(path.join(ROOT, 'catalog', 'auth', 'notion.json'), 'utf8').replace(/\r\n/g, '\n');
  const now = `"Notion-Version": "${VERSION}"`;
  assert.equal(text.split(now).length, 2, 'the new version line, once');
  assert.equal(createHash('sha256').update(text.replace(now, `"Notion-Version": "${OLD_VERSION}"`)).digest('hex'), AUTH_BEFORE, 'with the version put back, the file Sami signed');
  assert.deepEqual(definitionFor('notion').apiHeaders, {'Notion-Version': VERSION});
  assert.deepEqual(v1Definition('notion').apiHeaders, {'Notion-Version': OLD_VERSION}, 'version 1 definitions never change');
});

test('Notion\'s rows and proxy settings load unchanged; every app\'s data hash is the one Sami signed; only Notion\'s files hash moved in the golden', () => {
  assert.deepStrictEqual(plain(PERMISSION_GROUPS.get('notion')), LOADERS.permissionGroups.notion, 'Notion\'s rows');
  const config = PROXY_CONFIGS.get('notion');
  assert.deepStrictEqual({...plain(config), documented: {count: config.documented.length, hash: LOADERS.proxyConfigs.notion.documented.hash}}, LOADERS.proxyConfigs.notion, 'Notion\'s proxy settings');
  // F10.15's and F10.17's listed churn move Gmail's and GitHub's data hashes, and their sign-offs wait for Sami (S15.1, S17.1);
  // test/f10-15-churn.test.mjs and test/f10-17-churn.test.mjs pin both.
  assert.deepEqual(checkSigned().filter(problem => !problem.startsWith('gmail: ') && !problem.startsWith('github: ')), [], 'every app but Gmail and GitHub is signed for the data it gives now');
  const golden = readGolden(), notion = appEntry(ROOT, 'notion');
  assert.equal(notion.dataHash, SIGNED.dataHash, 'apiHeaders is not in the defaults table, so the data hash stays');
  assert.deepEqual(golden.apps.notion.signedOff, SIGNED, 'Sami\'s 2026-10-20 sign-off stays');
  assert.equal(golden.apps.notion.previousSignedOff, undefined);
  for (const appId of ['slack']) assert.equal(appEntry(ROOT, appId).dataHash, BEFORE.dataHashes[appId], `${appId} data hash`);
  assert.notEqual(golden.apps.notion.files['catalog/auth/notion.json'], FILES_BEFORE.file, 'the sign-in file\'s own hash moved');
  assert.notEqual(golden.apps.notion.filesHash, FILES_BEFORE.hash, 'so the files hash moved, for information');
  assert.deepEqual(golden.apps.notion.files, notion.files, 'the golden records what the files give now');
});

test('identity, token, refresh and revocation requests to Notion carry 2026-03-11', async t => {
  const directory = temporary(t);
  let now = Date.UTC(2026, 9, 26, 12);
  const clock = () => now, sim = new SIMULATORS.notion({...CLIENT, clock});
  const store = new Store({dataDir: directory, clock, localAuthority: 'new'}), vault = new Vault(directory);
  t.after(() => store.close());
  const request = req => sim.request(req), connections = new ConnectionManager({store, vault, request, clock});
  const provider = new OAuth2Provider(definitionFor('notion'), {store, vault, connections, request, clock, ...CLIENT, publishing: 'testing', redirectUri: REDIRECT, allowHostedRedirect: true});
  connections.setOAuthProvider(provider);
  const started = provider.start({appId: 'notion'}), consent = sim.consent(started.authorizationUrl, {});
  const connection = await provider.callback({state: consent.state, code: consent.code, flowId: started.flowId});
  vault.set(connection.id, {...vault.get(connection.id), expiresAt: now - 1000});
  await provider.refresh(connection.id);
  await provider.revoke(connection.id);
  const sent = url => sim.calls.filter(req => req.url === url);
  const token = sent('https://api.notion.com/v1/oauth/token'), identity = sent('https://api.notion.com/v1/users/me'), revoke = sent('https://api.notion.com/v1/oauth/revoke');
  assert.deepEqual([token.length, identity.length, revoke.length], [2, 2, 1], 'the code exchange and the refresh, an identity check after each, and one revocation');
  for (const req of [...token, ...identity, ...revoke]) assert.equal(versionOf(req), VERSION, req.url);
});

/** A designated owner's store with a ready Notion account (a token, as F10.9's snapshot connected one), a real ConnectionManager and a Runtime;
 *  `definition` replaces Notion's sign-in in the provider registry, as the file stood before the bump; `mode` opens the store new or again. */
function ownerRuntime(t, directory, {definition = null, calls = [], mode = 'new'} = {}) {
  let now = Date.parse('2026-10-26T12:00:00.000Z');
  const clock = () => now, store = new Store({dataDir: directory, clock, localAuthority: mode}), vault = new Vault(directory);
  let open = true;
  const close = () => { if (open) store.close(); open = false; };
  t.after(close);
  const request = async req => { calls.push(req); return {status: 200, headers: {'content-type': 'application/json'}, data: Buffer.from(JSON.stringify({object: 'page', id: 'p1'}))}; };
  const connections = new ConnectionManager({store, vault, request, clock});
  if (definition) connections.setOAuthProvider(new OAuth2Provider(definition, {store, vault, connections, request, clock, ...CLIENT, publishing: 'testing', redirectUri: REDIRECT, allowHostedRedirect: true}));
  if (!store.get('connections', 'notion-a')) {
    store.put('connections', {id: 'notion-a', appId: 'notion', providerId: 'notion', driver: 'http', authMethod: 'token', authRevision: 'r1', status: 'ready', label: 'Notion',
      identity: {id: 'ws-a:notion-user-a', displayName: 'Avery A'}, allowedOrigins: [NOTION], createdAt: new Date(now).toISOString()});
    vault.set('notion-a', {accessToken: 'ntn_f1019churntoken0000000000000000', expiresAt: null});
  }
  const runtime = new Runtime({store, connections, clock, ownerPrincipal: OWNER, request});
  return {store, runtime, connections, calls, close};
}

test('a proxied Notion request and an action request carry 2026-03-11 in Fabric\'s added headers; a pending proxy job approved with the old header is refused authority_changed and nothing is sent', async t => {
  const directory = temporary(t);
  // providerHeaders() is the one source of Fabric's added provider headers, for the proxy (lib/proxy-runtime.mjs) and for every action step
  // (lib/actions-runtime.mjs build()), shown on the card and compared again before a send.
  const now = ownerRuntime(t, directory);
  assert.deepEqual(providerHeaders(now.runtime, 'notion'), {'Notion-Version': VERSION});
  const read = await now.runtime.createProxyJob({connectionId: 'notion-a', request: {method: 'GET', path: '/v1/pages/p1'}}, OWNER);
  assert.equal(read.status, 'succeeded');
  assert.deepEqual(read.proxy.added.filter(header => header.name === 'Notion-Version'), [{name: 'Notion-Version', value: VERSION}]);
  assert.equal(now.calls.length, 1);
  assert.equal(versionOf(now.calls[0]), VERSION, 'and it is the header sent');
  assert.deepEqual(addedHeaders({headers: {}, body: '{}'}, providerHeaders(now.runtime, 'notion')).map(header => header.name), ['Authorization', 'Notion-Version', 'Accept', 'Content-Type']);
  now.close();
  // Before the bump: the same account's Fabric, with the sign-in file as it stood, accepts an edit that waits for approval.
  const old = structuredClone(definitionFor('notion'));
  old.apiHeaders = {'Notion-Version': OLD_VERSION};
  const then = ownerRuntime(t, directory, {definition: old, mode: 'require'});
  const pending = await then.runtime.createProxyJob({connectionId: 'notion-a', request: {method: 'PATCH', path: '/v1/pages/p1', body: {properties: {title: {title: [{text: {content: 'Renamed'}}]}}}}}, OWNER);
  assert.equal(pending.status, 'awaiting_approval');
  assert.deepEqual(pending.proxy.added.filter(header => header.name === 'Notion-Version'), [{name: 'Notion-Version', value: OLD_VERSION}]);
  then.close();
  // After the bump the owner approves the card that showed 2025-09-03: refused as changed, and nothing goes to Notion.
  const after = ownerRuntime(t, directory, {mode: 'require'});
  await assert.rejects(after.runtime.approve(pending.id, pending.approvalDigest, OWNER), error => error.code === 'authority_changed');
  assert.equal(after.calls.length, 0, 'nothing was sent');
});

test('no proxy-row binding moves: every Notion row binds what F10.9 recorded', () => {
  const connection = BEFORE.connections.notion, config = PROXY_CONFIGS.get('notion'), definition = PERMISSION_GROUPS.get('notion'), policy = new ProxyPolicy({store: null});
  const templates = templatesFor(definition, config, null);
  const rows = Object.fromEntries(policy.rows({config, definition}).map(({row}) => [row, policy.binding({connection, config, templates, definition}, row)]));
  assert.deepEqual(rows, BEFORE.proxyRows.notion);
  assert.deepEqual(BEFORE.typed.notion ?? {}, {}, 'Notion has no typed operations, so no typed binding can move');
});

// Part 2: the shipped ids are checked here, not in test/actions-notion.test.mjs, which recomputes them (withIds()) so a seeded fault inside the
// file reaches behaviour instead of tripping the id check.
test('Notion\'s shipped action file holds current ids: each stored id is the one its content hashes to, and the file validates with them, with no map', () => {
  const file = JSON.parse(readFileSync(path.join(ROOT, 'catalog', 'actions', 'notion.json'), 'utf8'));
  const deps = {identities: new Map([['notion', definitionFor('notion')]]), maps: new Map()};
  const ids = actionIds(file, deps);
  assert.deepEqual(file.actions.map(action => action.id), file.actions.map(action => ids.get(`${action.key} v${action.version}`).id));
  assert.equal(validateActionFile(file, deps).actions.length, 16);
});

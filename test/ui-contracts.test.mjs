import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {CATEGORIES, appCard, catalogPage, connectionState, primaryAction, permissionRow, approvalItem, watchApprovalItem, watchRow} from '../lib/ui-contracts.mjs';
import {describeApproval} from '../public/hosted-approval.js';

// UI-1: catalog view models (docs/UI-0-SCREEN-CONTRACTS.md sections 2-3). Pure projections only.
const catalog = JSON.parse(readFileSync(new URL('../catalog/apps.json', import.meta.url), 'utf8'));
const available = {enabled: true, availability: 'available'};
const apps = catalog.map(app => ({...app, connectionOptions: [app.id === 'slack' ? {enabled: false, availability: 'setup_required'} : available]}));
const account = (id, appId, status = 'ready', extra = {}) => ({id, appId, driver: 'http', status, label: `acct ${id}`, identity: {id: '1', displayName: 'Octo', email: 'octo@example.test'}, scopes: ['secret.scope'], authMethod: 'oauth', allowedOrigins: ['https://api.example.test'], ...extra});

test('every catalog app declares a known category, a short consumer tagline and a unique featured rank', () => {
  const ids = new Set(CATEGORIES.map(category => category.id));
  const ranks = catalog.filter(app => app.featured).map(app => app.featuredRank);
  for (const app of catalog) {
    assert.ok(ids.has(app.categoryId), `${app.id} category`);
    assert.ok(typeof app.tagline === 'string' && app.tagline.length > 0 && app.tagline.length <= 80, `${app.id} tagline`);
    assert.equal(typeof app.featured, 'boolean', `${app.id} featured`);
    if (app.featured) assert.ok(Number.isSafeInteger(app.featuredRank), `${app.id} rank`);
  }
  assert.equal(new Set(ranks).size, ranks.length, 'featured ranks are unique');
  assert.ok(ranks.length >= 3, 'the Featured row has at least three apps');
  assert.deepEqual(CATEGORIES.map(category => category.order), [...CATEGORIES.map(category => category.order)].sort((a, b) => a - b));
});

test('connected means present and usable; revoked and quarantined accounts do not count', () => {
  assert.deepEqual(connectionState('gmail', []), {state: 'available', accounts: 0, browserSessions: 0, needsAttention: 0});
  assert.equal(connectionState('gmail', [account('a', 'gmail', 'revoked'), account('b', 'gmail', 'pending_confirmation')]).state, 'available');
  assert.deepEqual(connectionState('gmail', [account('a', 'gmail'), account('b', 'gmail', 'reconnect_required')]), {state: 'connected', accounts: 2, browserSessions: 0, needsAttention: 1});
  assert.equal(connectionState('gmail', [account('b', 'gmail', 'reconnect_required')]).state, 'attention');
  assert.equal(connectionState('instagram', [account('s', 'instagram', 'paired', {driver: 'browser'})]).state, 'connected');
  assert.deepEqual(connectionState('instagram', [account('s', 'instagram', 'expired', {driver: 'browser'})]), {state: 'attention', accounts: 0, browserSessions: 1, needsAttention: 1});
  assert.equal(connectionState('gmail', [account('a', 'github')]).state, 'available', 'other apps never count');
});

test('the row action comes from real state and runtime options', () => {
  const app = {connectionOptions: [available]};
  assert.equal(primaryAction(app, {state: 'connected'}), 'view');
  assert.equal(primaryAction(app, {state: 'attention'}), 'view');
  assert.equal(primaryAction(app, {state: 'available'}), 'connect');
  assert.equal(primaryAction({connectionOptions: [{enabled: false, availability: 'setup_required'}]}, null), 'setup_required');
  assert.equal(primaryAction({connectionOptions: [{enabled: false, availability: 'available'}]}, null), 'unavailable', 'a disabled option is not connectable');
  assert.equal(primaryAction({}, null), 'unavailable');
});

test('owner cards carry connection counts but never identities, scopes, origins or tokens', () => {
  const card = appCard(apps.find(app => app.id === 'gmail'), {connections: [account('a', 'gmail')], accessLevels: () => ['read', 'read_write']});
  assert.deepEqual(Object.keys(card).sort(), ['accessLevels', 'authKinds', 'categoryId', 'connectionState', 'displayName', 'driver', 'featured', 'featuredRank', 'iconUrl', 'id', 'name', 'primaryAction', 'tagline']);
  assert.equal(card.primaryAction, 'view'); assert.equal(card.tagline, 'Messages, drafts, and labels');
  assert.deepEqual(card.authKinds, ['oauth', 'browser']); assert.equal(card.driver, 'api'); assert.deepEqual(card.accessLevels, ['read', 'read_write']);
  const wire = JSON.stringify(card);
  for (const secret of ['octo@example.test', 'secret.scope', 'api.example.test', 'Octo', 'acct a']) assert.ok(!wire.includes(secret), `leaked ${secret}`);
});

test('the developer view has no connection state, no device apps and no connection filters', () => {
  const connections = [account('a', 'gmail')];
  const card = appCard(apps.find(app => app.id === 'gmail'), {party: 'developer', connections});
  assert.equal(card.connectionState, undefined); assert.equal(card.primaryAction, 'connect');
  const page = catalogPage({apps, connections, party: 'developer'});
  const all = [...page.featured, ...page.categories.flatMap(group => group.preview)];
  assert.ok(all.every(item => item.connectionState === undefined));
  assert.ok(!page.categories.some(group => group.category.id === 'device'));
  assert.ok(!JSON.stringify(page).includes('local-device'));
  for (const status of ['available', 'connected']) assert.throws(() => catalogPage({apps, party: 'developer', status}), error => error.code === 'invalid_request');
  assert.throws(() => catalogPage({apps, party: 'developer', categoryId: 'device'}), error => error.code === 'invalid_request');
  assert.throws(() => catalogPage({apps, party: 'agent'}), error => error.code === 'invalid_request', 'agents get no catalog view at all');
  assert.equal(catalogPage({apps, party: 'end_user'}).categories.some(group => group.category.id === 'device'), false, 'device apps are owner-only');
});

test('the catalog page shows Featured in rank order and categories in order with five-row previews', () => {
  const many = [...apps, ...Array.from({length: 7}, (_, i) => ({id: `extra-${i}`, name: `Extra ${i}`, categoryId: 'productivity', tagline: 'Extra', featured: false, authMethods: ['token'], connectionOptions: [available]}))];
  const page = catalogPage({apps: many});
  assert.deepEqual(page.featured.map(card => card.id), ['gmail', 'google-calendar', 'notion']);
  const orders = page.categories.map(group => group.category.order);
  assert.deepEqual(orders, [...orders].sort((a, b) => a - b));
  const productivity = page.categories.find(group => group.category.id === 'productivity');
  assert.equal(productivity.preview.length, 5); assert.equal(productivity.more, true); assert.equal(productivity.category.count, 9);
  assert.deepEqual(productivity.preview.slice(0, 2).map(card => card.id), ['google-calendar', 'notion'], 'featured apps lead their category');
  assert.equal(page.results, undefined);
});

test('Available and Connected split the catalog by real state', () => {
  const connections = [account('a', 'gmail'), account('b', 'github', 'revoked'), account('c', 'slack', 'reconnect_required')];
  const ids = page => [...page.featured, ...page.categories.flatMap(group => group.preview)].map(card => card.id);
  const connected = catalogPage({apps, connections, status: 'connected'}), open = catalogPage({apps, connections, status: 'available'});
  assert.deepEqual(new Set(ids(connected)), new Set(['gmail', 'slack']));
  assert.ok(!ids(open).includes('gmail') && !ids(open).includes('slack') && ids(open).includes('github'));
  assert.throws(() => catalogPage({apps, status: 'enabled'}), error => error.code === 'invalid_request');
});

test('search and See all return flat pages with an opaque cursor', () => {
  const found = catalogPage({apps, q: '  DRAFTS '});
  assert.deepEqual(found.results.map(card => card.id), ['gmail']); assert.equal(found.q, 'drafts');
  assert.deepEqual(catalogPage({apps, q: 'developer tools'}).results.map(card => card.id), ['github'], 'category labels are searchable');
  assert.deepEqual(catalogPage({apps, q: 'nothing-like-this'}).results, []);
  const many = Array.from({length: 7}, (_, i) => ({id: `p-${i}`, name: `P ${i}`, categoryId: 'business', tagline: 'p', featured: false, authMethods: ['token'], connectionOptions: [available]}));
  const first = catalogPage({apps: many, categoryId: 'business', limit: 3});
  assert.deepEqual(first.results.map(card => card.id), ['p-0', 'p-1', 'p-2']); assert.ok(first.nextCursor);
  const second = catalogPage({apps: many, categoryId: 'business', limit: 3, cursor: first.nextCursor});
  assert.deepEqual(second.results.map(card => card.id), ['p-3', 'p-4', 'p-5']);
  const last = catalogPage({apps: many, categoryId: 'business', limit: 3, cursor: second.nextCursor});
  assert.deepEqual(last.results.map(card => card.id), ['p-6']); assert.equal(last.nextCursor, undefined);
  for (const cursor of ['not-a-cursor', Buffer.from('o:-1').toString('base64url'), Buffer.from('x:3').toString('base64url')]) assert.throws(() => catalogPage({apps: many, categoryId: 'business', cursor}), error => error.code === 'invalid_request');
  assert.throws(() => catalogPage({apps, categoryId: 'nope'}), error => error.code === 'invalid_request');
  assert.equal(catalogPage({apps: many, categoryId: 'business', limit: 1000}).results.length, 7, 'the page size is capped, not refused');
});

test('untrusted catalog text is bounded and stripped of control characters', () => {
  const card = appCard({id: 'custom', name: `Evil\u0000App${'x'.repeat(200)}`, tagline: 'Line\nbreak', authMethods: ['token'], connectionOptions: []});
  assert.ok(card.name.length <= 80 && !card.name.includes('\u0000'));
  assert.equal(card.tagline, 'Line break'); assert.equal(card.categoryId, 'other'); assert.equal(card.primaryAction, 'unavailable');
  assert.equal(card.iconUrl, '/api/icons/custom');
  assert.equal(appCard({id: 'a/b?c', name: 'x', authMethods: []}).iconUrl, '/api/icons/a%2Fb%3Fc');
});

test('Featured follows the declared rank, not the alphabet', () => {
  const ranked = [['zeta', 1], ['alpha', 3], ['mid', 2]].map(([id, featuredRank]) => ({id, name: id, categoryId: 'business', tagline: id, featured: true, featuredRank, authMethods: ['token'], connectionOptions: [available]}));
  assert.deepEqual(catalogPage({apps: ranked}).featured.map(card => card.id), ['zeta', 'mid', 'alpha']);
  assert.deepEqual(catalogPage({apps: ranked}).categories[0].preview.map(card => card.id), ['zeta', 'mid', 'alpha']);
});

// F10.3 (T4): rows Fabric locks and rows that reach other people; everything else keeps its shape and its etag.
const decided = (capabilityId, policyHash, extra = {}) => ({capabilityId, policyHash, mode: 'ask', defaultMode: 'ask', policySource: 'default', providerAccess: 'missing', status: 'active', ...extra});
const etagOf = decisions => createHash('sha256').update(decisions.map(decision => `${decision.capabilityId}:${decision.policyHash}`).sort().join('|')).digest('hex').slice(0, 32);

test('F10.3: a plain permission row has no locked or audience key and the same etag as before', () => {
  const decisions = [decided('b', 'h2'), decided('a', 'h1', {providerAccess: 'granted'})], addAccess = {providerId: 'p', body: {scopes: ['s']}};
  const plain = permissionRow({id: 'g', label: 'Do things', effect: 'write', decisions, addAccess});
  assert.deepEqual(plain, {groupId: 'g', label: 'Do things', effect: 'write', mode: 'ask', defaultMode: 'ask', allowedModes: ['allow', 'ask', 'deny'], access: 'missing', addAccess,
    policySource: 'default', reviewRequired: false, operations: 2, etag: etagOf(decisions)});
  assert.equal(JSON.stringify(permissionRow({id: 'g', label: 'Do things', effect: 'write', decisions, addAccess, locked: false, audience: false})), JSON.stringify(plain), 'false flags change nothing, key order included');
  const audience = permissionRow({id: 'g', label: 'Do things', effect: 'write', decisions, addAccess, audience: true});
  assert.equal(audience.audience, true); assert.deepEqual(audience.allowedModes, ['allow', 'ask', 'deny']); assert.equal(audience.etag, plain.etag);
});

test('F10.3: a locked row offers Never only, with Fabric\'s words, and never an Add access action', () => {
  const decisions = [decided('a', 'h1', {mode: 'deny', defaultMode: 'deny', allowBlocked: true}), decided('b', 'h2', {mode: 'deny', defaultMode: 'deny'})];
  const row = permissionRow({id: 'x.access.grant', label: 'Give access to other people or services', effect: 'write', decisions, addAccess: {providerId: 'p', body: {}}, addBlocked: 'Sign in again', locked: true, audience: true});
  assert.deepEqual({locked: row.locked, audience: row.audience, mode: row.mode, allowedModes: row.allowedModes, blockedReason: row.blockedReason, access: row.access, etag: row.etag},
    {locked: true, audience: true, mode: 'deny', allowedModes: ['deny'], blockedReason: 'Fabric keeps this off: it gives access to other people or services.', access: 'missing', etag: etagOf(decisions)});
  assert.ok(!('addAccess' in row) && !('addBlocked' in row));
});

test('F10.3: approval warnings keep reaches_people and body_routed, still drop unknown codes, and read as fixed sentences', () => {
  const job = {id: 'j1', kind: 'proxy', proxy: {rowLabel: 'Send messages', method: 'POST'}, effect: 'write', approvalDigest: 'd', approvalExpiresAt: '2026-10-17T00:10:00.000Z',
    preview: {application: 'slack', warnings: ['reaches_people', 'made_up', 'body_routed', 'delete', 'not_reviewed', 'duplicate_of_uncertain']}};
  const item = approvalItem(job);
  assert.deepEqual(item.warnings, ['reaches_people', 'body_routed', 'delete', 'not_reviewed', 'duplicate_of_uncertain']);
  const shown = describeApproval(item).warnings;
  assert.deepEqual(shown.slice(0, 2), ['Reaches other people.', 'Fabric placed this request in a stricter permission because of what its body does.']);
  assert.equal(shown.length, 5);
});

test('Iteration 9: a watch\'s card and row are pure projections, in the shape of an approval and a fixed list of fields', () => {
  const subscription = {id: 'w1', appId: 'gmail', connectionId: 'a', clientId: 'c', status: 'awaiting_approval', args: {}, approvalExpiresAt: '2026-10-17T00:10:00.000Z', authority: {bindingHash: 'never shown'}};
  assert.deepEqual(Object.keys(watchApprovalItem(subscription)), Object.keys(approvalItem({id: 'j1', status: 'awaiting_approval', approvalDigest: 'd', approvalExpiresAt: 'then', preview: {}})));
  assert.deepEqual(watchApprovalItem(subscription).exact, {complete: false, blocks: []}, 'with no facts there is nothing to show, so nothing to approve');
  assert.equal(watchApprovalItem(subscription).approve, null);
  assert.deepEqual(describeApproval(watchApprovalItem(subscription)).warnings, ['Fabric reads this in the background and tells the agent what it finds, until you pause or remove it.']);
  assert.deepEqual(Object.keys(watchRow({...subscription, status: 'active'})), ['ref', 'status', 'state', 'line', 'name', 'appId', 'appName', 'account', 'agent', 'details', 'pause', 'remove']);
  assert.equal(watchRow({...subscription, status: 'active'}).line, 'Fabric cannot describe this watch right now.');
});

// F10.6 (docs/F10.6-BUILD-MAP.md part g): a row's proxy setting, its notes and its "N of M work" count appear only when there is something to
// say, so every other row keeps its keys and its etag. Written before part g, which turned it on.
test('F10.6: a plain row keeps its keys and etag; a proxy entry changes the etag; notes and counts appear only when needed', () => {
  const decisions = [decided('a', 'h1', {mode: 'allow', defaultMode: 'allow', providerAccess: 'granted'}), decided('b', 'h2', {mode: 'allow', defaultMode: 'allow', providerAccess: 'granted'})];
  const plain = permissionRow({id: 'g', label: 'Read things', effect: 'read', decisions});
  assert.deepEqual(Object.keys(plain), ['groupId', 'label', 'effect', 'mode', 'defaultMode', 'allowedModes', 'access', 'policySource', 'reviewRequired', 'operations', 'etag']);
  assert.equal(plain.etag, etagOf(decisions));
  const proxy = {mode: 'allow', defaultMode: 'allow', allowedModes: ['allow', 'ask', 'deny'], source: 'default', revision: 'default', bindingHash: 'b'.repeat(64)};
  const both = permissionRow({id: 'g', label: 'Read things', effect: 'read', decisions, proxy});
  assert.notEqual(both.etag, plain.etag, 'the proxy record\'s revision and binding are part of what was shown');
  assert.ok(!JSON.stringify(both).includes('b'.repeat(64)), 'the binding itself is never shown');
  assert.notEqual(permissionRow({id: 'g', label: 'Read things', effect: 'read', decisions, proxy: {...proxy, revision: 'r2'}}).etag, both.etag);
  assert.ok(!('notes' in both) && !('working' in both) && !('total' in both));
  const asks = permissionRow({id: 'g', label: 'Read things', effect: 'read', decisions, proxy: {...proxy, mode: 'ask', defaultMode: 'ask'}});
  assert.deepEqual(asks.notes, ['raw_requests_ask'], 'the proxy is stricter than the row');
  const some = permissionRow({id: 'g', label: 'Read things', effect: 'read', decisions: [...decisions, decided('c', 'h3', {mode: 'allow', defaultMode: 'allow', providerAccess: 'unavailable', unavailable: 'not-requested'})]});
  assert.deepEqual([some.working, some.total, some.notes], [2, 3, ['not-requested']]);
});

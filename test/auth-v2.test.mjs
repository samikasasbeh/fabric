import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import {validateAuthDefinition, normalizeAuthApp, fullLevelScopes} from '../contracts/auth-definition.mts';
import {OAuth2Provider, MAX_REQUESTED_SCOPES} from '../lib/providers/oauth2.mjs';
import {offeredLevels, heldLevel, levelLabel} from '../lib/access-levels.mjs';
import {accountRow} from '../lib/ui-contracts.mjs';
import {Store} from '../lib/store.mjs';
import {Vault} from '../lib/vault.mjs';
import {authorizationUrls, v1Definition, PROVIDERS} from './fixtures/auth-v1/urls.mjs';
import {googleV2, githubV2, notionV2, slackV2} from './fixtures/auth-v2/definitions.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {AppDetailService, accessSummary} from '../lib/app-detail.mjs';
import {createApp} from '../server.mjs';
import {existsSync} from 'node:fs';

// F10.2 auth definitions, version 2 (docs/F10-FIVE-APPS-DEEP.md). Version 2 says full access directly, marks scopes
// required, optional or in context, and lists the scopes Fabric never asks for (T1). Version 1 definitions keep
// byte-identical authorization URLs (T6). The checked-in catalog stays version 1 until F10.7; the fixtures in
// test/fixtures/auth-v2 are version 2 shapes of the planned Gmail, Calendar, GitHub, Notion and Slack definitions.
const G = 'https://www.googleapis.com/auth/';
const ajv = new Ajv2020({strict: true, allErrors: true});
addFormats(ajv);
const schema = ajv.compile(JSON.parse(readFileSync(new URL('../contracts/auth-definition.schema.json', import.meta.url))));
const refused = (mutate, pattern, make = googleV2) => { const value = make(); mutate(value); assert.throws(() => validateAuthDefinition(value), error => error.code === 'invalid_definition' && pattern.test(error.message), pattern.source); return value; };

function harness(t, definition, options = {}) {
  const directory = mkdtempSync(path.join(tmpdir(), 'fabric-auth-v2-'));
  t.after(() => rmSync(directory, {recursive: true, force: true}));
  const store = new Store({dataDir: directory}), vault = new Vault(directory);
  const hosted = ['notion', 'slack'].includes(definition.providerId) ? {redirectUri: `https://connect.example.com/oauth/${definition.providerId}/4320`, allowHostedRedirect: true} : {};
  const provider = new OAuth2Provider(definition, {store, vault, connections: {}, clientId: 'fixture-client', clientSecret: 'fixture-secret', ...hosted, ...options});
  const asked = flow => { const url = new URL(flow.authorizationUrl); return {scope: (url.searchParams.get('scope') || '').split(/[ ,]/).filter(Boolean), user: (url.searchParams.get('user_scope') || '').split(',').filter(Boolean)}; };
  return {store, provider, asked};
}
const code = expected => error => error.code === expected;

test('version 2 definitions validate, structurally and semantically; version 1 is still accepted; unknown fields are refused', () => {
  for (const make of [googleV2, githubV2, notionV2, slackV2]) {
    const raw = make(), checked = validateAuthDefinition(raw);
    assert.deepEqual(checked, raw);
    assert.ok(schema(raw), `${raw.providerId}: ${JSON.stringify(schema.errors)}`);
  }
  for (const providerId of PROVIDERS) { assert.ok(validateAuthDefinition(v1Definition(providerId))); assert.ok(schema(v1Definition(providerId)), providerId); }
  assert.equal(schema(refused(value => { value.apps[1].unexpected = true; }, /unexpected is not allowed/)), false);
  assert.equal(schema(refused(value => { value.apps[1].access.levels.full.extra = []; }, /extra is not allowed/)), false);
  assert.equal(schema(refused(value => { value.schemaVersion = 3; }, /schemaVersion must be 1 or 2/)), false);
  assert.equal(schema(refused(value => { delete value.consentPolicy; }, /consentPolicy is required/)), false);
  assert.equal(schema(refused(value => { value.consentPolicy.testing = 'everything'; }, /consentPolicy.testing must be one of/)), false);
  // A version 1 definition cannot carry version 2 fields, and a version 2 one cannot carry a version 1 app entry.
  assert.throws(() => validateAuthDefinition({...v1Definition('google'), consentPolicy: {testing: 'full', production: 'full'}}), /consentPolicy is not allowed/);
  refused(value => { value.apps[0] = v1Definition('google').apps[0]; }, /scopes is not allowed|access is required/);
});

test('T1 at the source: a level can never contain a never-request scope, directly or through an implication', () => {
  refused(value => { value.apps[1].access.levels.full.optional.push('https://mail.google.com/'); }, /asks for https:\/\/mail.google.com\/ in the full level and also lists it in neverRequest/);
  refused(value => { value.apps[1].access.levels.read.required.push(`${G}gmail.metadata`); }, /in the read level and also lists it in neverRequest/);
  refused(value => { value.apps[1].access.levels.full.inContext.push({scope: `${G}gmail.modify`, rows: ['gmail.messages.mark']}); }, /inContext repeats/);
  refused(value => { value.apps[1].access.levels.full.inContext.push({scope: 'https://mail.google.com/', rows: ['gmail.permanent.delete']}); }, /in the full level and also lists it in neverRequest/);
  refused(value => { value.apps[1].access.levels.full.inContext.push({scope: `${G}gmail.labels`, rows: ['google-calendar.events.read']}); }, /must name one of gmail's permission rows/);
  refused(value => { value.apps[1].access.levels.full.inContext.push({scope: `${G}gmail.labels`, rows: []}); }, /rows must be a list of 1-16 entries/);
  refused(value => { value.apps[1].access.levels.full.inContext.push({scope: `${G}gmail.labels`, rows: ['gmail.labels.manage']}, {scope: `${G}gmail.labels`, rows: ['gmail.labels.read']}); }, /names a scope twice/);
  refused(value => { value.apps[1].access.levels.full.inContext.push(`${G}gmail.labels`); }, /must be an object/);
  refused(value => { value.apps[1].attestedCapabilities = ['read_content']; }, /attestedCapabilities belong to a pages grant only/);
  refused(value => { value.apps[1].access.levels.full.optional.push(`${G}gmail.modify`); }, /both required and optional/);
  refused(value => { value.apps[1].neverRequest.push('email'); }, /neverRequest lists the identity scope email/);
  refused(value => { value.apps[1].access.levels.full.optional.push('openid'); }, /repeats the identity scope openid/);
  // GitHub: `user` already grants `read:user`; asking for both is a contradiction, and asking for a parent of a never-request scope grants it anyway.
  refused(value => { value.apps[0].neverRequest = value.apps[0].neverRequest.filter(scope => scope !== 'user'); value.apps[0].access.levels.full.optional.push('user'); }, /asks for user and read:user, which user already grants/, githubV2);
  refused(value => { value.apps[0].access.levels.full.optional.push('admin:org'); value.apps[0].neverRequest.push('write:org'); value.apps[0].access.levels.full.optional = value.apps[0].access.levels.full.optional.filter(scope => scope !== 'read:org'); }, /asks for admin:org, which grants the never-requested write:org/, githubV2);
  refused(value => { value.scopeImplications.repo = ['repo']; }, /repo cannot grant itself/, githubV2);
  refused(value => { value.apps[0].access.levels.full.required.push('read:user'); }, /pages carries no scopes/, notionV2);
  const attested = notionV2(); attested.apps[0].attestedCapabilities = ['read_content', 'insert_content'];
  assert.ok(validateAuthDefinition(attested)); assert.ok(schema(attested));
  refused(value => { value.apps[0].attestedCapabilities = ['Read Content']; }, /malformed/, notionV2);
  refused(value => { value.authorization.userScopeParameter = null; }, /user_scope requires authorization.userScopeParameter/, slackV2);
  refused(value => { value.apps[1].access.levels.full.optional = Array.from({length: 65}, (_, index) => `${G}scope${index}`); }, /list of 0-64 entries/);
});

test('T6: version 1 definitions read through version 2 code produce byte-identical authorization URLs', t => {
  const golden = JSON.parse(readFileSync(new URL('./fixtures/auth-v1/urls.golden.json', import.meta.url), 'utf8'));
  assert.equal(Object.keys(golden).length, 20);
  assert.deepEqual(authorizationUrls(), golden);
  // The level input that Add account and the connect route now send gives the same URLs as writeAccess did.
  const levels = authorizationUrls(providerId => v1Definition(providerId));
  for (const providerId of PROVIDERS) for (const app of v1Definition(providerId).apps) {
    const {provider} = harness(t, v1Definition(providerId));
    const strip = href => { const url = new URL(href); url.searchParams.set('state', 'STATE'); if (url.searchParams.has('code_challenge')) url.searchParams.set('code_challenge', 'CODE_CHALLENGE'); return url.href; };
    assert.equal(strip(provider.start({appId: app.appId, level: 'full'}).authorizationUrl), levels[`${providerId}/${app.appId}/write`], `${app.appId} full`);
    assert.equal(strip(provider.start({appId: app.appId, level: 'read'}).authorizationUrl), levels[`${providerId}/${app.appId}/read`], `${app.appId} read`);
  }
  // The normalized reading of a version 1 entry is its write set as the full level and its read set as the read level.
  const google = validateAuthDefinition(v1Definition('google')), gmail = normalizeAuthApp(google, google.apps[1]);
  assert.deepEqual(gmail.levels.full, {required: google.apps[1].scopes.write, optional: [], inContext: []});
  assert.deepEqual(gmail.levels.read, {required: google.apps[1].scopes.read, optional: []});
  assert.equal(gmail.upgradeScopes, google.apps[1].upgradeScopes);
  const slack = validateAuthDefinition(v1Definition('slack'));
  assert.equal(normalizeAuthApp(slack, slack.apps[0]).grant, 'user_scope');
});

test('sign-in asks for the full level under the consent policy: testing asks for everything, production only what is required', t => {
  const testing = harness(t, googleV2(), {publishing: 'testing'});
  assert.deepEqual(testing.asked(testing.provider.start({appId: 'gmail', level: 'full'})).scope, ['openid', 'email', `${G}gmail.modify`, `${G}gmail.settings.basic`]);
  assert.deepEqual(testing.asked(testing.provider.start({appId: 'gmail', writeAccess: true})).scope, ['openid', 'email', `${G}gmail.modify`, `${G}gmail.settings.basic`], 'writeAccess still means full');
  assert.deepEqual(testing.asked(testing.provider.start({appId: 'gmail', level: 'read'})).scope, ['openid', 'email', `${G}gmail.readonly`]);
  assert.deepEqual(testing.provider.defaultScopes(testing.provider.app('gmail')), [`${G}gmail.modify`, `${G}gmail.settings.basic`]);
  const production = harness(t, googleV2(), {publishing: 'production'});
  assert.deepEqual(production.asked(production.provider.start({appId: 'gmail', level: 'full'})).scope, ['openid', 'email', `${G}gmail.modify`]);
  assert.deepEqual(production.provider.defaultScopes(production.provider.app('gmail')), [`${G}gmail.modify`]);
  // The settings scope stays reachable in context, through Add access.
  assert.deepEqual(production.asked(production.provider.start({appId: 'gmail', level: 'full', scopes: [`${G}gmail.settings.basic`]})).scope, ['openid', 'email', `${G}gmail.modify`, `${G}gmail.settings.basic`]);
  assert.throws(() => production.provider.start({appId: 'google-calendar', level: 'read'}), /offers only full access/);
  assert.throws(() => production.provider.start({appId: 'gmail', level: 'everything'}), code('invalid_input'));
  assert.throws(() => production.provider.start({appId: 'gmail', level: 'read', writeAccess: true}), /Write access needs the full access level/);
  assert.throws(() => harness(t, googleV2(), {publishing: 'live'}), /FABRIC_GOOGLE_PUBLISHING must be testing or production/);
  // A user-credential app asks for its levels as user scopes; in-context scopes only through Add access.
  const slack = harness(t, slackV2());
  assert.deepEqual(slack.asked(slack.provider.start({appId: 'slack', level: 'full'})), {scope: [], user: ['channels:read', 'users:read', 'chat:write']});
  assert.deepEqual(slack.asked(slack.provider.start({appId: 'slack', level: 'full', scopes: ['channels:history']})).user, ['channels:read', 'users:read', 'chat:write', 'channels:history']);
  assert.deepEqual(slack.provider.defaultScopes(slack.provider.app('slack')), ['channels:read', 'users:read', 'chat:write'], 'in-context scopes are never asked for at sign-in');
  // A page grant asks for no scopes at all.
  const notion = harness(t, notionV2());
  assert.deepEqual(notion.asked(notion.provider.start({appId: 'notion', level: 'full'})), {scope: [], user: []});
});

test('adversarial T1: Add access never asks for a never-request scope, anything outside the full level, or too many scopes', t => {
  const {provider, store} = harness(t, googleV2());
  assert.throws(() => provider.start({appId: 'gmail', level: 'full', scopes: ['https://mail.google.com/']}), code('never_requested'));
  assert.throws(() => provider.start({appId: 'gmail', level: 'full', scopes: [`${G}gmail.labels`, `${G}gmail.settings.sharing`]}), code('never_requested'));
  assert.throws(() => provider.start({appId: 'gmail', level: 'full', scopes: [`${G}drive`]}), code('invalid_scope'), 'not in the full level');
  assert.throws(() => provider.start({appId: 'gmail', level: 'full', scopes: [`${G}calendar`]}), code('invalid_scope'), 'another app of the same provider');
  assert.throws(() => provider.start({appId: 'gmail', level: 'full', scopes: [`${G}gmail.readonly`]}), code('invalid_scope'), 'a read-level scope is not an extra full-level scope');
  assert.throws(() => provider.start({appId: 'gmail', level: 'full', scopes: Array(MAX_REQUESTED_SCOPES + 1).fill(`${G}gmail.settings.basic`)}), code('invalid_scope'));
  assert.throws(() => provider.start({appId: 'gmail', level: 'full', scopes: [42]}), code('invalid_scope'));
  assert.equal(MAX_REQUESTED_SCOPES, 64);
  // A refused start leaves no flow behind.
  assert.equal(store.list('oauthFlows').length, 0);
  assert.equal(provider.belongsToApp(provider.app('gmail'), 'https://mail.google.com/'), false);
  assert.equal(provider.belongsToApp(provider.app('gmail'), `${G}gmail.readonly`), true);
  assert.equal(provider.belongsToApp(provider.app('gmail'), `${G}calendar`), false);
});

test('adversarial T1: a never-request scope an older connection holds is dropped from the reconnect URL and audited', t => {
  const {provider, store, asked} = harness(t, googleV2());
  store.put('connections', {id: 'old-gmail', appId: 'gmail', authMethod: 'oauth', status: 'ready', authRevision: 1,
    scopes: ['openid', 'email', `${G}gmail.modify`, 'https://mail.google.com/', `${G}gmail.settings.sharing`, `${G}calendar`]});
  const url = asked(provider.start({connectionId: 'old-gmail', appId: 'gmail', level: 'full'}));
  assert.deepEqual(url.scope, ['openid', 'email', `${G}gmail.modify`, `${G}gmail.settings.basic`]);
  const dropped = store.list('activity').filter(event => event.type === 'connection.scope_dropped');
  assert.equal(dropped.length, 1);
  assert.deepEqual({connectionId: dropped[0].connectionId, appId: dropped[0].appId, scopes: dropped[0].scopes}, {connectionId: 'old-gmail', appId: 'gmail', scopes: ['https://mail.google.com/', `${G}gmail.settings.sharing`]});
  // A full-level reconnect carries only full-level scopes: never a read-level scope such as gmail.readonly.
  store.put('connections', {id: 'read-then-full', appId: 'gmail', authMethod: 'oauth', status: 'ready', authRevision: 1, scopes: [`${G}gmail.readonly`, `${G}gmail.settings.basic`]});
  assert.deepEqual(asked(provider.start({connectionId: 'read-then-full', appId: 'gmail', level: 'full'})).scope, ['openid', 'email', `${G}gmail.modify`, `${G}gmail.settings.basic`]);
  assert.deepEqual(asked(provider.start({connectionId: 'read-then-full', appId: 'gmail', level: 'read'})).scope, ['openid', 'email', `${G}gmail.readonly`]);
  // Nothing to drop, nothing audited.
  store.put('connections', {id: 'clean', appId: 'gmail', authMethod: 'oauth', status: 'ready', authRevision: 1, scopes: [`${G}gmail.modify`]});
  provider.start({connectionId: 'clean', appId: 'gmail', level: 'full'});
  assert.equal(store.list('activity').filter(event => event.type === 'connection.scope_dropped').length, 1);
});

test('access levels: version 1 keeps read and read_write; version 2 says full, partial, read or pages; a page grant is never full access', () => {
  const google1 = validateAuthDefinition(v1Definition('google')), gmail1 = normalizeAuthApp(google1, google1.apps[1]);
  assert.deepEqual(offeredLevels(gmail1), ['read', 'read_write']);
  assert.equal(heldLevel(gmail1, gmail1.levels.full.required), 'read_write');
  const google2 = validateAuthDefinition(googleV2()), gmail2 = normalizeAuthApp(google2, google2.apps[1]), calendar2 = normalizeAuthApp(google2, google2.apps[0]);
  assert.deepEqual(offeredLevels(gmail2), ['full', 'read']);
  assert.deepEqual(offeredLevels(calendar2), ['full']);
  assert.equal(heldLevel(gmail2, ['openid', `${G}gmail.modify`, `${G}gmail.settings.basic`]), 'full');
  assert.deepEqual(heldLevel(gmail2, [`${G}gmail.modify`]), {level: 'partial', notGranted: 1});
  assert.equal(heldLevel(gmail2, [`${G}gmail.readonly`]), 'read');
  assert.equal(heldLevel(gmail2, [`${G}gmail.labels`]), 'custom');
  assert.equal(levelLabel(heldLevel(gmail2, [`${G}gmail.modify`])), 'Partial access (1 permission not granted)');
  assert.equal(levelLabel({level: 'partial', notGranted: 3}), 'Partial access (3 permissions not granted)');
  // Critique test 19: Notion is never labelled full access, whatever its grant or version.
  const notion2 = validateAuthDefinition(notionV2()), notion1 = validateAuthDefinition(v1Definition('notion'));
  assert.deepEqual(offeredLevels(normalizeAuthApp(notion2, notion2.apps[0])), ['pages']);
  for (const scopes of [[], undefined, ['anything']]) {
    assert.equal(heldLevel(normalizeAuthApp(notion2, notion2.apps[0]), scopes), 'pages');
    assert.notEqual(heldLevel(normalizeAuthApp(notion1, notion1.apps[0]), scopes), 'full');
  }
  const row = accountRow({id: 'n1', appId: 'notion', status: 'ready', identity: {displayName: 'Ada'}}, {accessLevel: () => heldLevel(normalizeAuthApp(notion2, notion2.apps[0]), [])});
  assert.deepEqual({level: row.accessLevel, label: row.accessLabel}, {level: 'pages', label: 'Pages you shared'});
  const partial = accountRow({id: 'g1', appId: 'gmail', status: 'ready'}, {accessLevel: () => ({level: 'partial', notGranted: 2})});
  assert.deepEqual({level: partial.accessLevel, label: partial.accessLabel}, {level: 'partial', label: 'Partial access (2 permissions not granted)'});
  assert.deepEqual(fullLevelScopes(gmail2), [`${G}gmail.modify`, `${G}gmail.settings.basic`]);
});

test('every in-context scope names permission rows that exist in catalog/permissions', () => {
  // The checked-in definitions are version 1 until F10.7; the version 2 fixtures stand in for them here, and the same
  // check covers the catalog files the moment they move to version 2.
  const definitions = [googleV2(), githubV2(), notionV2(), slackV2(), ...PROVIDERS.map(providerId => JSON.parse(readFileSync(new URL(`../catalog/auth/${providerId}.json`, import.meta.url), 'utf8')))];
  let named = 0;
  for (const definition of definitions.filter(item => item.schemaVersion === 2)) for (const app of definition.apps) for (const entry of app.access.levels.full.inContext) for (const row of entry.rows) {
    named++;
    assert.ok(PERMISSION_GROUPS.get(app.appId)?.groups.some(group => group.id === row), `${definition.providerId}/${app.appId}: ${entry.scope} names ${row}, which is not a permission row`);
  }
  assert.ok(named > 0);
});

test('review fix: Add access sends the level the account holds, so a version 2 account is never narrowed or refused', t => {
  // The exact body AppDetailService.addAccess builds goes to start() unchanged, as the hosted page and start route do.
  const run = (definition, appId, connection, scopeSets, options = {}) => {
    const h = harness(t, definition, options);
    h.store.put('connections', connection);
    h.store.put('applicationMaps', {id: appId, operations: [{requiredScopes: scopeSets.flat()}]});
    const service = new AppDetailService({store: h.store, oauthProviderFor: () => ({...h.provider, availability: () => ({available: true}), providerId: h.provider.providerId, app: id => h.provider.app(id), access: app => h.provider.access(app), belongsToApp: (app, scope) => h.provider.belongsToApp(app, scope)})});
    const result = service.addAccess({id: appId}, connection, [{decision: {providerAccess: 'missing', scopeSets}}]);
    return {result, flow: () => h.asked(h.provider.start(result.addAccess.body))};
  };
  // Gmail, production consent: a partial account (gmail.modify only) adds the settings scope and keeps gmail.modify.
  const gmail = run(googleV2(), 'gmail', {id: 'gm', appId: 'gmail', authMethod: 'oauth', status: 'ready', authRevision: 1, scopes: ['openid', 'email', `${G}gmail.modify`]}, [[`${G}gmail.settings.basic`]], {publishing: 'production'});
  assert.equal(gmail.result.addAccess.body.level, 'full');
  assert.deepEqual(gmail.flow().scope, ['openid', 'email', `${G}gmail.modify`, `${G}gmail.settings.basic`]);
  // GitHub has no read level: Add access works instead of failing with "offers only full access".
  const github = run(githubV2(), 'github', {id: 'gh', appId: 'github', authMethod: 'oauth', status: 'ready', authRevision: 1, scopes: ['read:user', 'repo']}, [['read:org']]);
  assert.deepEqual(github.flow().scope, ['read:user', 'repo', 'read:org', 'gist', 'workflow']);
  // A read-only Gmail account stays read when it adds a scope.
  const read = run(googleV2(), 'gmail', {id: 'gr', appId: 'gmail', authMethod: 'oauth', status: 'ready', authRevision: 1, scopes: ['openid', 'email', `${G}gmail.readonly`]}, [[`${G}gmail.settings.basic`]]);
  assert.equal(read.result.addAccess.body.level, 'read');
  assert.deepEqual(read.flow().scope, ['openid', 'email', `${G}gmail.readonly`, `${G}gmail.settings.basic`]);
  // start() itself: a version 2 reconnect with no level keeps the held level; a new sign-in starts at full.
  const h = harness(t, googleV2());
  h.store.put('connections', {id: 'full-gm', appId: 'gmail', authMethod: 'oauth', status: 'ready', authRevision: 1, scopes: [`${G}gmail.modify`, `${G}gmail.settings.basic`]});
  assert.deepEqual(h.asked(h.provider.start({connectionId: 'full-gm'})).scope, ['openid', 'email', `${G}gmail.modify`, `${G}gmail.settings.basic`]);
  assert.deepEqual(h.asked(h.provider.start({appId: 'google-calendar'})).scope, ['openid', 'email', `${G}calendar`]);
  // writeAccess must be a boolean: a string no longer silently picks a level.
  assert.throws(() => h.provider.start({appId: 'gmail', writeAccess: 'true'}), /Write access must be true or false/);
});

test('review fix: implication chains, cycles and identity scopes cannot smuggle a never-request scope or a parent with its child', () => {
  // A chain: admin:org grants write:org, which grants read:org; read:org is never requested.
  refused(value => { value.scopeImplications = {'admin:org': ['write:org'], 'write:org': ['read:org']}; value.apps[0].access.levels.full.optional = ['gist', 'workflow', 'admin:org']; value.apps[0].neverRequest.push('read:org'); }, /asks for admin:org, which grants the never-requested read:org/, githubV2);
  refused(value => { value.scopeImplications = {a: ['b'], b: ['a']}; }, /grants itself through b/, githubV2);
  // Identity scopes are on every sign-in, so the rules see them too.
  refused(value => { value.authorization.identityScopes = ['user']; value.apps[0].neverRequest = ['delete_repo', 'user:email']; value.apps[0].access.levels.full.required = ['repo']; }, /asks for user, which grants the never-requested user:email/, githubV2);
  refused(value => { value.authorization.identityScopes = ['read:user']; value.apps[0].neverRequest = ['delete_repo']; value.apps[0].access.levels.full.required = ['repo', 'user']; }, /asks for user and read:user, which user already grants/, githubV2);
  // An in-context scope may not sit in the read level, and levels must ask for something.
  refused(value => { value.apps[1].access.levels.read.optional.push(`${G}gmail.labels`); value.apps[1].access.levels.full.inContext.push({scope: `${G}gmail.labels`, rows: ['gmail.labels.manage']}); }, /inContext repeats .*gmail.labels, which a sign-in asks for/);
  refused(value => { value.apps[0].access.levels.full.required = []; }, /full asks for no scope at sign-in/);
  refused(value => { value.apps[1].access.levels.read.required = []; }, /read needs at least one required scope/);
  // The normalized reading is frozen: one caller cannot change every later sign-in.
  const checked = validateAuthDefinition(googleV2()), reading = normalizeAuthApp(checked, checked.apps[1]);
  assert.throws(() => { reading.levels.full.required.push('x'); }, TypeError);
  assert.throws(() => { reading.grant = 'pages'; }, TypeError);
  assert.throws(() => { reading.neverRequest = []; }, TypeError);
  const v1 = validateAuthDefinition(v1Definition('google')), v1Reading = normalizeAuthApp(v1, v1.apps[1]);
  assert.throws(() => { v1Reading.levels.full = {required: ['https://mail.google.com/'], optional: [], inContext: []}; }, TypeError);
  assert.deepEqual(reading.identityScopes, ['openid', 'email']);
});

test('review fix: Read-only means only read scopes, and the page promises full access only when sign-in asks for it', () => {
  const checked = validateAuthDefinition(googleV2()), gmail = normalizeAuthApp(checked, checked.apps[1]);
  assert.equal(heldLevel(gmail, ['openid', 'email', `${G}gmail.readonly`]), 'read');
  assert.equal(heldLevel(gmail, [`${G}gmail.readonly`, `${G}gmail.settings.basic`]), 'custom', 'a write scope beside the read scope is not Read-only');
  assert.equal(heldLevel(gmail, [`${G}gmail.readonly`, `${G}gmail.compose`]), 'custom');
  assert.equal(accessSummary({oauth: true, levels: ['full', 'read'], consentMode: 'full'}), 'Full access at sign-in. You control each permission below.');
  assert.equal(accessSummary({oauth: true, levels: ['full'], consentMode: 'required'}), 'Sign-in asks for what this app needs to work. Add the rest from the permission that needs it, below.');
  assert.equal(accessSummary({oauth: true, levels: ['pages'], providerName: 'Notion'}), 'Notion shares only the pages you pick. You control each permission below.');
  assert.equal(accessSummary({oauth: true, levels: ['read', 'read_write']}), 'You can give read-only or read and write access');
  assert.equal(accessSummary({oauth: false, levels: [], connectable: false}), null);
});

test('review fix: a bad publishing setting names itself before any local state opens', async t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'fabric-publishing-'));
  t.after(() => { delete process.env.FABRIC_SLACK_PUBLISHING; rmSync(directory, {recursive: true, force: true}); });
  process.env.FABRIC_SLACK_PUBLISHING = 'Production';
  await assert.rejects(createApp({dataDir: path.join(directory, 'data'), port: 0}), /FABRIC_SLACK_PUBLISHING must be testing or production/);
  assert.equal(existsSync(path.join(directory, 'data', 'fabric.sqlite')), false);
});

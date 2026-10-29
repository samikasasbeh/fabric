import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import {validateAuthDefinition} from '../contracts/auth-definition.mts';
import {PERMISSION_GROUPS, memberKey} from '../lib/permission-groups.mjs';
import {appCard} from '../lib/ui-contracts.mjs';
import {catalog} from '../lib/connections.mjs';
import {v1Definition} from './fixtures/auth-v1/urls.mjs';
import {versionTwoUrls, catalogDefinition, PROVIDERS} from './fixtures/auth-v2/urls.mjs';
import {definitions, rows, FIXTURE_APPS} from './fixtures/access/f10-6-fixtures.mjs';

// F10.7 part f (docs/F10.7-BUILD-MAP.md section 4, "New test/f10-7-catalog.test.mjs"): the four sign-in definitions are version 2 with
// section 5's scope sets, the F10.6 fixtures read them, T6 cannot go vacuous, and the version 2 URLs are pinned byte for byte. Part e:
// every member of GitHub's locked row and of Slack's admin row is classified by one family, each read from the provider's reference.
const G = 'https://www.googleapis.com/auth/', g = list => list.map(scope => G + scope);
const ajv = new Ajv2020({strict: true, allErrors: true});
addFormats(ajv);
const schema = ajv.compile(JSON.parse(readFileSync(new URL('../contracts/auth-definition.schema.json', import.meta.url), 'utf8')));
const level = (required, optional = [], inContext = []) => ({required, optional, inContext});

test('each catalog/auth file is a valid version 2 definition: the levels, never lists, implications and consent policies of section 5', () => {
  const shipped = Object.fromEntries(PROVIDERS.map(providerId => [providerId, catalogDefinition(providerId)]));
  for (const [providerId, definition] of Object.entries(shipped)) {
    assert.equal(definition.schemaVersion, 2, providerId);
    assert.deepEqual(validateAuthDefinition(definition), definition, providerId);
    assert.ok(schema(definition), `${providerId}: ${JSON.stringify(schema.errors)}`);
  }
  const {google, github, slack, notion} = shipped;
  assert.deepEqual(google.apps.map(app => [app.appId, app.access, app.neverRequest]), [
    ['google-calendar', {default: 'full', grant: 'scope', levels: {full: level(g(['calendar.events', 'calendar.calendarlist']), g(['calendar.calendars', 'calendar.acls', 'calendar.settings.readonly', 'calendar.freebusy'])), read: null}}, g(['calendar'])],
    ['gmail', {default: 'full', grant: 'scope', levels: {full: level(g(['gmail.modify']), g(['gmail.settings.basic'])), read: {required: g(['gmail.readonly']), optional: []}}},
      ['https://mail.google.com/', ...g(['gmail.settings.sharing', 'gmail.metadata', 'gmail.insert'])]]]);
  // Both Google apps keep their access probes (open question 11); Google names no settings address (open question 10).
  assert.deepEqual(google.apps.map(app => app.accessProbe.url), ['https://www.googleapis.com/calendar/v3/users/me/calendarList?maxResults=1&fields=kind', 'https://gmail.googleapis.com/gmail/v1/users/me/profile?fields=emailAddress']);
  assert.deepEqual([google.scopeImplications, google.consentPolicy], [{}, {testing: 'full', production: 'required'}]);
  assert.deepEqual(github.apps[0].access, {default: 'full', grant: 'scope', levels: {full: level(['read:user', 'repo'], ['read:org', 'gist', 'workflow']), read: null}});
  assert.deepEqual(github.apps[0].neverRequest, ['delete_repo', 'user', 'admin:public_key', 'admin:gpg_key', 'admin:ssh_signing_key']);
  // Section 5.3, plus write:org granting read:org (F10.5 correction 9); no admin:public_key rule (open question 9).
  assert.deepEqual(github.scopeImplications, {repo: ['public_repo', 'repo:status', 'repo_deployment', 'repo:invite', 'security_events'], user: ['read:user', 'user:email', 'user:follow'],
    'admin:org': ['write:org', 'read:org'], 'write:org': ['read:org'], 'admin:repo_hook': ['write:repo_hook', 'read:repo_hook']});
  assert.deepEqual(github.consentPolicy, {testing: 'full', production: 'full'});
  assert.deepEqual(Object.fromEntries(PROVIDERS.map(providerId => [providerId, shipped[providerId].revocation.settingsUrl ?? null])), {google: null, github: 'https://github.com/settings/applications', notion: null, slack: null});
  const {full} = slack.apps[0].access.levels;
  assert.deepEqual([slack.apps[0].access.grant, full.required.length, full.optional.length, full.inContext], ['user_scope', 11, 22, [{scope: 'channels:write', rows: ['slack.channels.manage']}, {scope: 'groups:write', rows: ['slack.channels.manage']}]]);
  assert.ok(full.required.includes('im:write') && !full.optional.includes('channels:write'));
  assert.deepEqual(slack.apps[0].neverRequest, ['admin', 'remote_files:share', 'conversations.connect:manage', 'search:read.public', 'search:read.private', 'search:read.im', 'search:read.mpim', 'search:read.files', 'search:read.users']);
  assert.deepEqual(notion.apps[0], {appId: 'notion', accessProbe: null, access: {default: 'full', grant: 'pages', levels: {full: level([]), read: null}}, neverRequest: [],
    attestedCapabilities: ['read_content', 'update_content', 'insert_content', 'read_comments', 'insert_comments', 'user_email']});
  assert.deepEqual([notion.apiHeaders, notion.authorization.extraParameters], [{'Notion-Version': '2026-03-11'}, {owner: 'user'}], 'F10.19 (owner decision 7): Notion moves to 2026-03-11');
  // Only the named fields moved: everything else is the version 1 file byte for byte. F10.17 (listed churn, docs/F10.17-BUILD-MAP.md part 1)
  // names one more: GitHub's grant header, which no other definition has.
  for (const providerId of PROVIDERS) {
    // F10.21 (listed churn): Slack's definition gains apiSuccessRequire, /ok true; no other definition has one.
    assert.deepEqual(JSON.parse(JSON.stringify(shipped[providerId])).apiSuccessRequire, providerId === 'slack' ? [{pointer: '/ok', equals: true}] : undefined, `${providerId} apiSuccessRequire`);
    const before = v1Definition(providerId), after = shipped[providerId], same = ({schemaVersion, apps, scopeImplications, consentPolicy, revocation, apiSuccessRequire, grantHeader, ...rest}) => rest;
    assert.equal(after.grantHeader, providerId === 'github' ? 'x-oauth-scopes' : undefined, `${providerId} grantHeader`);
    // F10.9 (R5, listed churn): Slack's identity gains userId, the provider's own user id; no other definition has one.
    const now = same(after), {userId, ...attributes} = now.identity.attributes;
    assert.equal(userId, providerId === 'slack' ? '/user_id' : undefined, `${providerId} userId`);
    // F10.19 (owner decision 7, listed churn): Notion's Notion-Version moves to 2026-03-11; every other apiHeaders is the version 1 one.
    const then = same(before);
    if (providerId === 'notion') {
      assert.deepEqual([now.apiHeaders, then.apiHeaders], [{'Notion-Version': '2026-03-11'}, {'Notion-Version': '2025-09-03'}]);
      then.apiHeaders = now.apiHeaders;
    }
    assert.deepEqual({...now, identity: {...now.identity, attributes}}, then, providerId);
    const {settingsUrl, ...revocation} = after.revocation;
    assert.deepEqual(revocation, before.revocation, `${providerId} revocation`);
  }
  // Google's app order still matches the typed contract (lib/providers/google.mjs).
  assert.deepEqual(google.apps.map(app => app.appId), ['google-calendar', 'gmail']);
});

test('the F10.6 fixtures read the catalog, and T6 cannot go vacuous: the version 1 fixtures differ from the shipped definitions', () => {
  for (const providerId of PROVIDERS) assert.deepEqual(definitions[providerId], catalogDefinition(providerId), providerId);
  for (const appId of FIXTURE_APPS) assert.deepEqual(rows(appId), JSON.parse(readFileSync(new URL(`../catalog/permissions/${appId}.json`, import.meta.url), 'utf8')), appId);
  for (const providerId of PROVIDERS) assert.notDeepEqual(v1Definition(providerId), catalogDefinition(providerId), providerId);
});

test('the version 2 authorization URLs, per app and level under testing and production, are pinned byte for byte', () => {
  const golden = JSON.parse(readFileSync(new URL('./fixtures/auth-v2/urls.golden.json', import.meta.url), 'utf8')), urls = versionTwoUrls();
  assert.deepEqual(urls, golden);
  assert.deepEqual(Object.keys(golden).sort(), ['github/github/full/production', 'github/github/full/testing', 'google/gmail/full/production', 'google/gmail/full/testing', 'google/gmail/read/production',
    'google/gmail/read/testing', 'google/google-calendar/full/production', 'google/google-calendar/full/testing', 'notion/notion/full/production', 'notion/notion/full/testing', 'slack/slack/full/production', 'slack/slack/full/testing']);
  const v1 = JSON.parse(readFileSync(new URL('./fixtures/auth-v1/urls.golden.json', import.meta.url), 'utf8'));
  // Gmail's advanced read-only sign-in asks for exactly what version 1's read level did, and Notion's URL never moved.
  for (const publishing of ['testing', 'production']) assert.equal(golden[`google/gmail/read/${publishing}`], v1['google/gmail/read'], publishing);
  for (const key of ['read', 'write', 'reconnect', 'reconnect-write']) for (const publishing of ['testing', 'production']) assert.equal(golden[`notion/notion/full/${publishing}`], v1[`notion/notion/${key}`], `${key} ${publishing}`);
  // Production asks Google only for what each app needs; testing asks for the whole level. GitHub and Slack ask for everything in both.
  const scope = key => new URL(golden[key]).searchParams.get('scope');
  assert.equal(scope('google/gmail/full/production'), `openid email ${G}gmail.modify`);
  assert.equal(scope('google/gmail/full/testing'), `openid email ${G}gmail.modify ${G}gmail.settings.basic`);
  assert.equal(scope('github/github/full/production'), 'read:user repo read:org gist workflow');
  assert.equal(golden['slack/slack/full/production'], golden['slack/slack/full/testing']);
  assert.equal(new URL(golden['slack/slack/full/testing']).searchParams.get('user_scope').split(',').length, 33, 'required and optional, never the in-context scopes');
});

test('critique 17: the GitHub, Notion and Slack cards list sign-in among their ways to connect; the token tab stays first', () => {
  const card = id => appCard(catalog.find(app => app.id === id));
  for (const id of ['github', 'notion', 'slack']) {
    assert.deepEqual(catalog.find(app => app.id === id).authMethods, ['token', 'oauth', 'browser'], id);
    assert.deepEqual(card(id).authKinds, ['api_key', 'oauth', 'browser'], id);
  }
  assert.deepEqual(card('gmail').authKinds, ['oauth', 'browser']);
  // The stale words went: no token promise on GitHub, and Calendar no longer says read-only is the default.
  const text = id => JSON.stringify(catalog.find(app => app.id === id));
  assert.doesNotMatch(text('github'), /Permissions remain limited by the token|scoped personal access token/);
  assert.doesNotMatch(text('google-calendar'), /Read-only access is the default/);
  assert.match(catalog.find(app => app.id === 'github').tokenHelp, /fine-grained personal access token/, 'the token tab keeps its help');
});

// ---- part e: the families of GitHub's locked row and Slack's admin row (decision 11, open questions 13, 14 and 17) --------------
// Each family: the members it holds, and either the scope sets a member needs or the reason it can never work. The sources are the
// provider's REST reference as read on 2026-10-18; "scopes" is GitHub's "Scopes for OAuth apps" page.
const SCOPES_PAGE = 'https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps';
const GITHUB_LOCKED = [
  {family: 'repository webhooks', match: /^(POST|PATCH|DELETE) \/repos\/\{owner\}\/\{repo\}\/hooks/, count: 7, sets: [['admin:repo_hook'], ['repo']], source: ['https://docs.github.com/en/rest/repos/webhooks', SCOPES_PAGE]},
  {family: 'organization webhooks', match: /^(POST|PATCH|DELETE) \/(orgs\/\{org\}|organizations\/\{organization_id\})\/hooks/, count: 12, reason: 'not-requested', source: ['https://docs.github.com/en/rest/orgs/webhooks (admin:org_hook)']},
  {family: 'repository collaborators and invitations', match: /^(PUT \/repos\/\{owner\}\/\{repo\}\/collaborators\/|PATCH \/repos\/\{owner\}\/\{repo\}\/invitations\/)/, count: 2, sets: [['repo']], source: ['https://docs.github.com/en/rest/collaborators/invitations', SCOPES_PAGE]},
  {family: 'organization invitations', match: /^POST \/(orgs\/\{org\}|organizations\/\{organization_id\})\/invitations$/, count: 2, sets: [['admin:org'], ['repo']], source: [`${SCOPES_PAGE} (repo also manages organization invitations)`]},
  {family: 'organization memberships', match: /^PUT \/(orgs\/\{org\}|organizations\/\{organization_id\})\/memberships\//, count: 2, reason: 'not-requested', source: [`${SCOPES_PAGE} (admin:org or write:org)`, 'https://docs.github.com/en/rest/orgs/members']},
  {family: 'deploy keys', match: /^(POST|DELETE) \/repos\/\{owner\}\/\{repo\}\/keys/, count: 2, sets: [['repo']], source: ['https://docs.github.com/en/rest/deploy-keys/deploy-keys', SCOPES_PAGE]},
  {family: 'a user\'s SSH key', match: /^POST \/user\/keys$/, count: 1, reason: 'not-requested', source: ['https://docs.github.com/en/rest/users/keys (write:public_key)']},
  {family: 'repository and environment secrets', match: /^PUT \/repos\/\{owner\}\/\{repo\}\/(actions|dependabot|codespaces|agents|environments\/\{environment_name\})\/secrets\//, count: 5, sets: [['repo']],
    source: ['https://docs.github.com/en/rest/actions/secrets', 'https://docs.github.com/en/rest/dependabot/secrets', 'https://docs.github.com/en/rest/codespaces/repository-secrets', 'https://docs.github.com/en/rest/agents/secrets']},
  {family: 'organization secrets', match: /^PUT \/(orgs\/\{org\}|organizations\/\{organization_id\})\/(actions|dependabot|codespaces|agents)\/secrets\//, count: 24, reason: 'not-requested',
    source: ['https://docs.github.com/en/rest/actions/secrets (admin:org)', 'https://docs.github.com/en/rest/codespaces/organization-secrets']},
  {family: 'a user\'s Codespaces secrets', match: /^PUT \/user\/codespaces\/secrets\//, count: 3, reason: 'not-requested', source: ['https://docs.github.com/en/rest/codespaces/secrets (codespace or codespace:secrets)']},
  {family: 'environments', match: /^PUT \/repos\/\{owner\}\/\{repo\}\/environments\/\{environment_name\}$/, count: 1, sets: [['repo']], source: ['https://docs.github.com/en/rest/deployments/environments']},
  {family: 'repository transfer', match: /^POST \/repos\/\{owner\}\/\{repo\}\/transfer$/, count: 1, sets: [['repo']], source: ['https://docs.github.com/en/rest/repos/repos', SCOPES_PAGE]},
  {family: 'team repositories and memberships', match: /^PUT \/(orgs\/\{org\}\/teams\/\{team_slug\}|teams\/\{team_id\}|organizations\/\{organization_id\}\/(teams\/\{team_slug\}|team\/\{team_id\}))\/(repos|memberships|members)\//, count: 9, sets: [['read:org']],
    source: ['https://docs.github.com/en/rest/teams/teams', 'https://docs.github.com/en/rest/teams/members (OAuth access tokens require read:org)']},
  {family: 'app installation repositories', match: /^PUT \/user\/installations\//, count: 1, sets: [['repo']], source: ['https://docs.github.com/en/rest/apps/installations']},
  {family: 'repository runner registration', match: /^POST \/repos\/\{owner\}\/\{repo\}\/actions\/runners\//, count: 2, sets: [['repo']], source: ['https://docs.github.com/en/rest/actions/self-hosted-runners']},
  {family: 'organization runner registration', match: /^POST \/(orgs\/\{org\}|organizations\/\{organization_id\})\/actions\/runners\//, count: 4, reason: 'not-requested', source: ['https://docs.github.com/en/rest/actions/self-hosted-runners (admin:org)']},
  {family: 'organization roles and security managers', match: /\/(organization-roles|security-managers)\//, count: 6, reason: 'not-requested', source: ['https://docs.github.com/en/rest/orgs/organization-roles (admin:org)', 'https://docs.github.com/en/rest/orgs/security-managers']},
  {family: 'Copilot Spaces collaborators', match: /\/copilot-spaces\//, count: 6, reason: 'not-requested', source: ['https://docs.github.com/en/rest/copilot (no published scope; no level asks for one)']},
  {family: 'workflow access level', match: /^PUT \/repos\/\{owner\}\/\{repo\}\/actions\/permissions\/access$/, count: 1, sets: [['repo']], source: ['https://docs.github.com/en/rest/actions/permissions']},
  {family: 'private registries', match: /\/private-registries/, count: 4, reason: 'not-requested', source: ['https://docs.github.com/en/rest/private-registries/organization-configurations (admin:org)']},
];
const SLACK_DOCS = method => `https://docs.slack.dev/reference/methods/${method}`;
const SLACK_ADMIN = [
  {family: 'admin.* methods (admin.* user scopes of an organization install)', test: method => method.startsWith('admin.'), count: 121, reason: 'not-requested', source: [SLACK_DOCS('admin.conversations.archive')]},
  {family: 'app configuration, app-level and client-secret methods', test: method => /^(apps\.manifest\.|functions\.distributions\.permissions\.|oauth\.)/.test(method) ||
    ['apps.managed.permissions.set', 'tooling.tokens.rotate', 'apps.connections.open', 'apps.event.authorizations.list', 'apps.uninstall', 'openid.connect.token'].includes(method), count: 22, reason: 'client-credentials-only',
    source: [SLACK_DOCS('apps.manifest.create'), SLACK_DOCS('apps.connections.open'), SLACK_DOCS('oauth.v2.exchange'), SLACK_DOCS('apps.uninstall')]},
  {family: 'bot-only methods', test: method => /^(apps\.datastore\.|workflows\.triggers\.permissions\.)/.test(method) || ['files.remote.remove', 'users.discoverableContacts.lookup', 'conversations.declineSharedInvite'].includes(method),
    count: 16, reason: 'bot-token-only', source: [SLACK_DOCS('apps.datastore.get'), SLACK_DOCS('workflows.triggers.permissions.add'), SLACK_DOCS('files.remote.remove'), SLACK_DOCS('conversations.declineSharedInvite')]},
  {family: 'user scopes no level asks for', test: method => ['apps.activities.list', 'apps.icon.set', 'migration.exchange', 'openid.connect.userInfo', 'reminders.delete', 'slackLists.items.delete', 'slackLists.items.deleteMultiple',
    'team.billing.info', 'files.remote.share'].includes(method), count: 9, reason: 'not-requested', source: [SLACK_DOCS('team.billing.info'), SLACK_DOCS('reminders.delete'), SLACK_DOCS('files.remote.share')]},
  {family: 'featured workflows (bookmarks)', test: method => method.startsWith('workflows.featured.'), count: 4, sets: method => method === 'workflows.featured.list' ? [['bookmarks:read']] : [['bookmarks:write']],
    source: [SLACK_DOCS('workflows.featured.add'), SLACK_DOCS('workflows.featured.list')]},
  {family: 'a user\'s app connection', test: method => method === 'apps.user.connection.update', count: 1, sets: () => [['users:write']], source: [SLACK_DOCS('apps.user.connection.update')]},
  {family: 'methods that need no scope (Slack decides)', test: method => /^(views\.|functions\.complete|functions\.workflows\.steps\.|apps\.auth\.external\.)/.test(method) || ['auth.revoke', 'dialog.open'].includes(method), count: 12, sets: () => [[]],
    source: [SLACK_DOCS('auth.revoke'), SLACK_DOCS('views.open'), SLACK_DOCS('functions.completeSuccess')]},
  {family: 'retired methods', test: method => /^(apps\.permissions\.|rtm\.|workflows\.(stepCompleted|stepFailed|updateStep)$)/.test(method) || method === 'files.upload', count: 12, reason: 'no-oauth-scope',
    source: [SLACK_DOCS('rtm.connect'), SLACK_DOCS('files.upload')]},
];

test('part e: every member of GitHub\'s locked row is classified by exactly one family, each read from GitHub\'s REST reference', () => {
  const locked = PERMISSION_GROUPS.get('github').groups.find(group => group.id === 'github.access.grant');
  assert.equal(locked.requests.length, 95);
  const counts = Object.fromEntries(GITHUB_LOCKED.map(entry => [entry.family, 0]));
  for (const request of locked.requests) {
    const families = GITHUB_LOCKED.filter(entry => entry.match.test(request)), key = memberKey(request);
    assert.equal(families.length, 1, `${request}: ${families.map(entry => entry.family).join(', ')}`);
    const [family] = families;
    counts[family.family]++;
    if (family.reason) assert.deepEqual([locked.unavailable?.[key], locked.memberScopeSets?.[key]], [family.reason, undefined], request);
    else assert.deepEqual([locked.memberScopeSets?.[key], locked.unavailable?.[key]], [family.sets, undefined], request);
  }
  assert.deepEqual(counts, Object.fromEntries(GITHUB_LOCKED.map(entry => [entry.family, entry.count])));
  for (const entry of GITHUB_LOCKED) assert.ok(entry.source.length && entry.source.every(item => item.startsWith('https://docs.github.com/')), entry.family);
  // The row is still Fabric's: locked, Never, and nothing on it justifies a scope.
  assert.deepEqual([locked.locked, locked.defaultMode, 'scopeSets' in locked, 'conditionalScopes' in locked], ['fabric', 'deny', false, false]);
});

test('part e: every member of Slack\'s admin row is classified by exactly one family, each read from Slack\'s method reference', () => {
  const admin = PERMISSION_GROUPS.get('slack').groups.find(group => group.id === 'slack.admin');
  assert.equal(admin.requests.length, 197, 'the 195 methods it held, and the two that moved in');
  const counts = Object.fromEntries(SLACK_ADMIN.map(entry => [entry.family, 0]));
  for (const request of admin.requests) {
    const method = request.slice(request.indexOf('/') + 1), families = SLACK_ADMIN.filter(entry => entry.test(method)), key = memberKey(request);
    assert.equal(families.length, 1, `${request}: ${families.map(entry => entry.family).join(', ')}`);
    const [family] = families;
    counts[family.family]++;
    if (family.reason) assert.deepEqual([admin.unavailable?.[key], admin.memberScopeSets?.[key]], [family.reason, undefined], request);
    else assert.deepEqual([admin.memberScopeSets?.[key], admin.unavailable?.[key]], [family.sets(method), undefined], request);
  }
  assert.deepEqual(counts, Object.fromEntries(SLACK_ADMIN.map(entry => [entry.family, entry.count])));
  for (const entry of SLACK_ADMIN) assert.ok(entry.source.length && entry.source.every(item => item.startsWith('https://docs.slack.dev/reference/methods/')), entry.family);
  // The two members part e moved: Never in this row now, each with its reason; their old rows no longer hold them.
  assert.deepEqual([admin.unavailable['GET /files.remote.share'], admin.unavailable['GET /conversations.declineSharedInvite']], ['not-requested', 'bot-token-only']);
  const rowOf = request => PERMISSION_GROUPS.get('slack').groups.filter(group => group.requests.includes(request)).map(group => group.id);
  assert.deepEqual([rowOf('GET /files.remote.share'), rowOf('GET /conversations.declineSharedInvite')], [['slack.admin'], ['slack.admin']]);
  assert.deepEqual([admin.defaultMode, 'locked' in admin], ['deny', false]);
});

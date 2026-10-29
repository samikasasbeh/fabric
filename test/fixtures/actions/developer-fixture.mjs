// F10.11 part m (docs/F10.11-BUILD-MAP.md parts b and m): the developer-environment harness of the action tests. A developer server on a
// temp tenant data root whose platform catalog holds Slack and Notion actions seeded from a temp action catalog (reviewed and certified
// with passing live evidence, on the shipped rows), one environment with its keys, end users with ready Slack and Notion accounts (stored
// as a confirmed sign-in stores them: the sign-in itself is the OAuth simulators' tests' job), and a scripted provider behind the network
// seam: Slack's methods (SlackScript, test/fixtures/actions/runtime-fixture.mjs) and Notion's pages, each call recorded without its
// Authorization header. The server loads the same catalog at start (part p) and gates its platform catalog with it. Test data only: nothing
// in lib/ imports it.
import {mkdirSync, mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {createDeveloperApp} from '../../../developer-server.mjs';
import {PlatformStore} from '../../../lib/tenant/platform.mjs';
import {stampOwner} from '../../../lib/tenant/deployment.mjs';
import {loadActionCatalog, seedActions} from '../../../lib/action-catalog.mjs';
import {validateActionFile} from '../../../lib/actions.mjs';
import {validateChoiceSources} from '../../../lib/choice-sources.mjs';
import {PERMISSION_GROUPS} from '../../../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../../../lib/proxy-config.mjs';
import {definitionFor} from '../../../lib/providers/definitions.mjs';
import {directMessageFile, SlackScript, SLACK_TOKEN} from './runtime-fixture.mjs';
import {withIds} from './fixture-app.mjs';
import {compileOpenApi} from '../../../lib/compiler.mjs';
import {TRANSFORMS, PINS} from './registry.mjs';

const SLACK_OK = {status: [200], require: [{equals: {pointer: '/ok', value: {const: true}}}]}, OK = {status: [200], require: []};
const closed = properties => ({type: 'object', properties, required: Object.keys(properties), additionalProperties: false});
const words = (max = 200) => ({type: 'string', minLength: 1, maxLength: max});
const certified = appId => ({evidence: `docs/live-evidence/${appId}/actions.json`, definitionHash: '0'.repeat(64)});
/** Slack Find a person: one reviewed read (GET /users.lookupByEmail), so it runs at its row's default Allow. */
export const findPerson = () => ({id: `slack.action.find-person.v1.${'0'.repeat(24)}`, key: 'find-person', version: 1, name: 'Find a person', description: 'Finds one person by email.',
  effect: 'read', row: 'slack.workspace.read', hints: {readOnly: true, destructive: false, idempotent: true, openWorld: true},
  inputSchema: closed({email: {type: 'string', minLength: 3, maxLength: 254}}), outputSchema: closed({id: {type: 'string', maxLength: 64}, name: {type: 'string', maxLength: 200}}), guards: [], prepare: [],
  perform: [{id: 'person', method: 'GET', path: '/users.lookupByEmail', query: {email: {input: '/email'}}, expect: SLACK_OK}],
  output: {id: {step: 'person', pointer: '/user/id'}, name: {step: 'person', pointer: '/user/real_name'}}, preview: [{label: 'Email', expr: {input: '/email'}}], definitive: [400], certified: certified('slack')});
/** Slack Post fields: a channel's own fields decide what it posts (a resource-dependent input, F10.9 section 9). */
export const postFields = () => ({id: `slack.action.post-fields.v1.${'0'.repeat(24)}`, key: 'post-fields', version: 1, name: 'Post fields', description: 'Posts values in a channel\'s own fields.',
  effect: 'write', row: 'slack.messages.send', hints: {readOnly: false, destructive: false, idempotent: false, openWorld: true},
  inputSchema: closed({channel: words(64), values: {type: 'object', properties: {}, additionalProperties: false}}), outputSchema: closed({ts: {type: 'string', maxLength: 64}}), guards: [], prepare: [],
  // F10.21 listed churn: every Slack step requires /ok true (apiSuccessRequire), the schema step included.
  resolvedInputs: [{input: 'values', dependsOn: ['channel'], schema: {steps: [{id: 'info', method: 'GET', path: '/conversations.info', query: {channel: {input: '/channel'}}, expect: SLACK_OK}],
    derive: {transform: 'notion.schema@1', args: {dataSource: {step: 'info', pointer: ''}}}}, maxProperties: 10}],
  perform: [{id: 'post', method: 'POST', path: '/chat.postMessage', body: {object: {channel: {input: '/channel'}, metadata: {transform: 'notion.propertyValues@1', args: {schema: {resolved: 'values'}, values: {input: '/values'}}}}}, expect: SLACK_OK}],
  verify: {requests: [{id: 'link', method: 'GET', path: '/chat.getPermalink', query: {channel: {step: 'post', pointer: '/channel'}, message_ts: {step: 'post', pointer: '/ts'}}, expect: SLACK_OK}],
    identity: [{kind: 'readback', step: 'link', pointer: '/channel', equals: {step: 'post', pointer: '/channel'}}], assert: []},
  output: {ts: {step: 'post', pointer: '/ts'}}, preview: [{label: 'Channel', expr: {input: '/channel'}}], definitive: [400], certified: certified('slack')});
/** Slack Find a channel: a read no live evidence certifies, so it stays a candidate. */
export const findChannel = () => {
  const {certified: _none, ...action} = {...findPerson(), id: `slack.action.find-channel.v1.${'0'.repeat(24)}`, key: 'find-channel', name: 'Find a channel', description: 'Finds one channel by its id.', row: 'slack.channels.read',
    inputSchema: closed({channel: words(64)}), perform: [{id: 'person', method: 'GET', path: '/conversations.info', query: {channel: {input: '/channel'}}, expect: SLACK_OK}],
    outputSchema: closed({id: {type: 'string', maxLength: 64}, name: {type: 'string', maxLength: 200}}), output: {id: {step: 'person', pointer: '/channel/id'}, name: {step: 'person', pointer: '/channel/name'}},
    preview: [{label: 'Channel', expr: {input: '/channel'}}]};
  return action;
};
/** F10.11 part o: Slack's channel list as a choice source: conversations.list in its read row, the types it lists configured by the choice,
 *  paged by Slack's cursor at most two pages, searched locally, and never offering the archive channel C0. */
export const slackChoices = () => ({schemaVersion: 2, appId: 'slack', reviewed: 'F10.11 part o test', sources: [{id: 'channels', kind: 'directory', read: {request: 'GET /conversations.list'},
  row: 'slack.channels.read', args: {types: {configured: 'types'}, exclude_archived: {const: true}}, items: '/channels', value: '/id', valueType: 'string', label: ['/name'],
  page: {next: {pointer: '/response_metadata/next_cursor'}, into: {query: 'cursor'}, max: 2}, search: {mode: 'local'}, exclude: ['C0'], maxItems: 50}]});
/** F10.11 part o: Slack Read a channel, its channel picked from the channel list of the kind its own `kind` input names (a choice that
 *  depends on another input). */
export const channelInfo = () => ({id: `slack.action.channel-info.v1.${'0'.repeat(24)}`, key: 'channel-info', version: 1, name: 'Read a channel', description: 'Reads one channel picked from a list.',
  effect: 'read', row: 'slack.channels.read', hints: {readOnly: true, destructive: false, idempotent: true, openWorld: true},
  inputSchema: closed({kind: {type: 'string', enum: ['public_channel', 'private_channel']}, channel: words(64)}), outputSchema: closed({name: {type: 'string', maxLength: 200}}), guards: [], prepare: [],
  choices: [{input: 'channel', source: 'channels', dependsOn: ['kind'], args: {types: {input: '/kind'}}}],
  perform: [{id: 'info', method: 'GET', path: '/conversations.info', query: {channel: {input: '/channel'}, types: {input: '/kind'}}, expect: SLACK_OK}],
  output: {name: {step: 'info', pointer: '/channel/name'}}, preview: [{label: 'Channel', expr: {input: '/channel'}}], definitive: [400], certified: certified('slack')});
/** F10.11 part o: a GitHub choice source on one account's page, GET /user/{account_id}, whose account id a choice takes from another input:
 *  a value of 'repos' would land the request on GET /user/repos, a literal sibling in another row. */
export const githubChoices = () => ({schemaVersion: 2, appId: 'github', reviewed: 'F10.11 part o test', sources: [{id: 'account', kind: 'directory', read: {request: 'GET /user/{account_id}'},
  row: 'github.profile.read', args: {account_id: {configured: 'who'}}, items: '/items', value: '/id', valueType: 'string', label: ['/name'], page: null, search: null, maxItems: 10}]});
/** F10.11 part o: GitHub Read an account, its account picked from the list GET /user/{account_id} gives for the person its `who` input names. */
export const pickAccount = () => ({id: `github.action.pick-account.v1.${'0'.repeat(24)}`, key: 'pick-account', version: 1, name: 'Read an account', description: 'Reads one account picked from a list.',
  effect: 'read', row: 'github.profile.read', hints: {readOnly: true, destructive: false, idempotent: true, openWorld: true},
  inputSchema: closed({who: words(39), account: words(39)}), outputSchema: closed({login: {type: 'string', maxLength: 64}}), guards: [], prepare: [],
  choices: [{input: 'account', source: 'account', dependsOn: ['who'], args: {account_id: {input: '/who'}}}],
  perform: [{id: 'read', method: 'GET', path: '/users/{username}', params: {username: {input: '/account'}}, query: {who: {input: '/who'}}, expect: {status: [200], require: []}}],
  output: {login: {step: 'read', pointer: '/login'}}, preview: [{label: 'Account', expr: {input: '/account'}}], definitive: [404], certified: certified('github')});
/** The Slack file: Send a direct message (the two-phase write), Find a person, Post fields and Find a channel. */
export const slackFile = () => {
  const file = directMessageFile();
  file.actions.push(findPerson(), postFields(), findChannel());
  return file;
};
const GITHUB_OK = {status: [200], require: []};
/** GitHub List my gists (a read whose row needs gist, a scope the sign-in asks for only as an optional one) and File an issue with fields
 *  (a repository's own fields decide what it files: a resource-dependent input). Held calls use them: Fabric's shared GitHub app runs in
 *  development, its shared Slack app does not. */
export const githubFile = () => ({schemaVersion: 1, appId: 'github', specVersion: 'fabric/0.2', reviewStatus: 'reviewed', pinnedParameters: {}, actions: [
  {id: `github.action.list-gists.v1.${'0'.repeat(24)}`, key: 'list-gists', version: 1, name: 'List my gists', description: 'Lists your gists.', effect: 'read', row: 'github.gists.read',
    hints: {readOnly: true, destructive: false, idempotent: true, openWorld: true}, inputSchema: closed({}), outputSchema: closed({first: {type: 'string', maxLength: 64}}), guards: [], prepare: [],
    perform: [{id: 'list', method: 'GET', path: '/gists', expect: GITHUB_OK}], output: {first: {step: 'list', pointer: '/0/id'}}, preview: [], definitive: [404], certified: certified('github')},
  {id: `github.action.issue-fields.v1.${'0'.repeat(24)}`, key: 'issue-fields', version: 1, name: 'File an issue with fields', description: 'Files an issue with a repository\'s own fields.',
    effect: 'write', row: 'github.issues.write', hints: {readOnly: false, destructive: false, idempotent: false, openWorld: true},
    inputSchema: closed({owner: words(100), repo: words(100), values: {type: 'object', properties: {}, additionalProperties: false}}), outputSchema: closed({number: {type: 'integer'}}), guards: [], prepare: [],
    resolvedInputs: [{input: 'values', dependsOn: ['owner', 'repo'], schema: {steps: [{id: 'info', method: 'GET', path: '/repos/{owner}/{repo}', params: {owner: {input: '/owner'}, repo: {input: '/repo'}}, expect: GITHUB_OK}],
      derive: {transform: 'notion.schema@1', args: {dataSource: {step: 'info', pointer: ''}}}}, maxProperties: 10}],
    perform: [{id: 'file', method: 'POST', path: '/repos/{owner}/{repo}/issues', params: {owner: {input: '/owner'}, repo: {input: '/repo'}},
      body: {object: {title: {const: 'Fields'}, labels: {transform: 'notion.propertyValues@1', args: {schema: {resolved: 'values'}, values: {input: '/values'}}}}}, expect: {status: [201], require: []}}],
    verify: {requests: [{id: 'check', method: 'GET', path: '/repos/{owner}/{repo}/issues/{issue_number}', params: {owner: {input: '/owner'}, repo: {input: '/repo'}, issue_number: {step: 'file', pointer: '/number'}}, expect: GITHUB_OK}],
      identity: [{kind: 'readback', step: 'check', pointer: '/number', equals: {step: 'file', pointer: '/number'}}], assert: []},
    output: {number: {step: 'file', pointer: '/number'}}, preview: [{label: 'Repository', expr: {input: '/repo'}}], definitive: [404, 410, 422], certified: certified('github')},
]});
/** Notion Create a page (Fabric records the page it made) and Rename a page (askUnless: a page Fabric did not make asks first). */
export const notionFile = () => ({schemaVersion: 1, appId: 'notion', specVersion: 'fabric/0.2', reviewStatus: 'reviewed', pinnedParameters: {}, actions: [
  {id: `notion.action.create-page.v1.${'0'.repeat(24)}`, key: 'create-page', version: 1, name: 'Create a page', description: 'Creates one page under a parent page.',
    effect: 'write', row: 'notion.content.create', hints: {readOnly: false, destructive: false, idempotent: false, openWorld: true},
    inputSchema: closed({parentId: words(64), emoji: words(8)}), outputSchema: closed({id: {type: 'string', maxLength: 64}}), guards: [], prepare: [],
    perform: [{id: 'create', method: 'POST', path: '/v1/pages', body: {object: {parent: {object: {page_id: {input: '/parentId'}}}, icon: {object: {emoji: {input: '/emoji'}}}}}, expect: OK}],
    verify: {requests: [{id: 'check', method: 'GET', path: '/v1/pages/{page_id}', params: {page_id: {step: 'create', pointer: '/id'}}, expect: OK}],
      identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {step: 'create', pointer: '/id'}}], assert: []},
    records: {kind: 'page', pointer: '/id'}, output: {id: {step: 'create', pointer: '/id'}}, preview: [{label: 'Parent', expr: {input: '/parentId'}}], definitive: [400], certified: certified('notion')},
  {id: `notion.action.rename-page.v1.${'0'.repeat(24)}`, key: 'rename-page', version: 1, name: 'Change a page icon', description: 'Changes one page\'s icon.',
    effect: 'write', row: 'notion.content.edit', hints: {readOnly: false, destructive: false, idempotent: false, openWorld: true},
    inputSchema: closed({pageId: words(64), emoji: words(8)}), outputSchema: closed({id: {type: 'string', maxLength: 64}}), guards: [], prepare: [],
    perform: [{id: 'change', method: 'PATCH', path: '/v1/pages/{page_id}', params: {page_id: {input: '/pageId'}}, body: {object: {icon: {object: {emoji: {input: '/emoji'}}}}}, expect: OK}],
    verify: {requests: [{id: 'check', method: 'GET', path: '/v1/pages/{page_id}', params: {page_id: {input: '/pageId'}}, expect: OK}],
      identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {input: '/pageId'}}], assert: []},
    askUnless: {createdByFabric: {kind: 'page', input: 'pageId'}}, output: {id: {step: 'change', pointer: '/id'}}, preview: [{label: 'Page', expr: {input: '/pageId'}}], definitive: [400], certified: certified('notion')},
]});

/** A typed Slack operation, users.info, compiled from a small description (a typed http member of slack.workspace.read). Its operation id
 *  makes its capability id sort before every action id, so a listing that puts actions first shows it. */
export const typedSlack = () => compileOpenApi({appId: 'slack', document: {openapi: '3.1.0', info: {title: 'Slack', version: '1'}, servers: [{url: 'https://slack.com/api'}],
  paths: {'/users.info': {get: {operationId: 'aaUsersInfo', parameters: [{name: 'user', in: 'query', required: true, schema: {type: 'string'}}], responses: {200: {description: 'The user'}}}}}}}).capabilities[0];
/** Notion's pages as the scripted provider keeps them, and the calls made to it. */
class NotionScript {
  constructor() { this.pages = new Map([['shared-page', {object: 'page', id: 'shared-page', icon: null}]]); this.calls = []; this.made = 0; }
  answer({method, path: route, body}) {
    if (method === 'POST' && route === '/v1/pages') { const page = {object: 'page', id: `page-${++this.made}`, icon: body?.icon ?? null}; this.pages.set(page.id, page); return {status: 200, data: page}; }
    const id = route.match(/^\/v1\/pages\/([^/]+)$/)?.[1], page = id ? this.pages.get(decodeURIComponent(id)) : null;
    if (!page) return {status: 404, data: {object: 'error', code: 'object_not_found'}};
    if (method === 'PATCH') Object.assign(page, {icon: body?.icon ?? null});
    return {status: 200, data: structuredClone(page)};
  }
}

/**
 * Builds the harness. Options: `slack`, `notion` and `github` (the action files, ids recomputed; the files above by default), `choices` (choice
 * source files, validated into the catalog's choices; none by default), `load` (replaces the server's guarded import of the action catalog,
 * for a load that fails), `users` (the
 * external user ids to make, each with a ready Slack, Notion and GitHub account; ['u1'] by default), `bare` (more users made with no account) and `typed`
 * (a typed Slack operation, users.info, active in the platform catalog). Returns {app, scope, catalog, slack, notion, calls, callsOf(name),
 * call(key, method, route, body, headers), agent(token, method, params), keys, accounts, repo(), idOf(key), capability(key), open(key, body),
 * hold(name), fail(name, answer, times), advance(ms)}.
 */
export async function developerHarness(t, {slack = slackFile(), notion = notionFile(), github = githubFile(), choices = [], users = ['u1'], bare = [], typed = false, load} = {}) {
  const data = mkdtempSync(path.join(tmpdir(), 'fabric-action-developer-')), folder = mkdtempSync(path.join(tmpdir(), 'fabric-action-developer-catalog-'));
  const deps = {groups: PERMISSION_GROUPS, configs: PROXY_CONFIGS, transforms: TRANSFORMS, pins: PINS, choices: new Map(), identities: new Map(['slack', 'notion', 'github'].map(appId => [appId, definitionFor(appId)])), maps: new Map()};
  for (const file of choices) deps.choices.set(file.appId, validateChoiceSources(file, deps));
  const directory = path.join(folder, 'catalog', 'actions');
  mkdirSync(directory, {recursive: true});
  for (const file of [slack, notion, github]) {
    const written = withIds(file, deps), live = path.join(folder, 'docs', 'live-evidence', file.appId);
    mkdirSync(live, {recursive: true});
    writeFileSync(path.join(directory, `${file.appId}.json`), JSON.stringify(written));
    const valid = validateActionFile(written, deps).actions;
    writeFileSync(path.join(live, 'actions.json'), JSON.stringify(Object.fromEntries(valid.map(entry => [entry.id, {passed: true, transforms: Object.fromEntries(entry.transforms.map(id => [id, PINS[id]])), definitionHash: entry.definitionHash}]))));
  }
  const codeHashes = ids => Object.fromEntries(ids.map(id => [id, PINS[id]]));
  const seeding = loadActionCatalog({directory, evidenceRoot: folder, deps, codeHashes});
  // The operator's catalog command (part p) writes the platform's action records; here seedActions() does, before the server opens it.
  const platform = new PlatformStore({root: data});
  // The typed operation is stored first, so a listing in store order would show it before the actions.
  if (typed) platform.put('capabilities', {...typedSlack(), status: 'active'});
  seedActions(platform, seeding, {audit: () => {}});
  platform.close();
  let now = Date.UTC(2026, 9, 23, 9);
  const slackScript = new SlackScript(), notionScript = new NotionScript(), calls = [], gates = new Map(), faults = new Map();
  // A call's name: a Slack method ('users.lookupByEmail') or a Notion request ('POST /v1/pages').
  const nameOf = (method, target) => target.origin === 'https://slack.com' ? target.pathname.replace(/^\/api\//, '') : `${method} ${target.pathname}`;
  const request = async options => {
    const target = new URL(options.url), {Authorization: _credential, ...headers} = options.headers ?? {}, method = options.method ?? 'GET', name = nameOf(method, target);
    calls.push({method, name, url: options.url, headers, body: options.body === undefined ? null : JSON.parse(options.body)});
    const gate = gates.get(name);
    if (gate) { gates.delete(name); gate.reach(); await gate.released; }
    const fault = faults.get(name);
    if (fault) { if (--fault.times <= 0) faults.delete(name); return structuredClone(fault.answer); }
    if (target.origin === 'https://slack.com') return slackScript.request(options);
    if (target.origin === 'https://api.notion.com') {
      if (!Array.isArray(options.allowedOrigins) || !options.allowedOrigins.includes(target.origin)) throw Object.assign(new Error('Request origin is outside the connection grant.'), {sent: false});
      const answer = notionScript.answer({method: options.method ?? 'GET', path: target.pathname, body: options.body === undefined ? null : JSON.parse(options.body)});
      return {status: answer.status, headers: {'content-type': 'application/json'}, data: answer.data};
    }
    throw Object.assign(new Error(`unexpected ${options.url}`), {sent: false});
  };
  // The server loads the same catalog at start (part p), from the same folder and registry; `load` replaces its guarded import.
  const app = await createDeveloperApp({dataRoot: data, port: 0, clock: () => now, request, actions: {directory, evidenceRoot: folder, deps, codeHashes, ...(load ? {importer: load} : {})},
    providerSettings: {slack: {clientId: 's-client', clientSecret: 's-secret'}, notion: {clientId: 'n-client', clientSecret: 'n-secret'}, github: {clientId: 'gh-client', clientSecret: 'gh-secret'}}});
  const catalog = app.runtimes.actions;
  t.after(async () => { await app.close(); rmSync(data, {recursive: true, force: true}); rmSync(folder, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent', appName: 'Acme Assistant'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  const mint = options => app.keys.mint({environmentId: dev.id, ...options});
  const keys = {standard: mint({preset: 'standard'}), full: mint({preset: 'full'}), catalog: mint({scopes: ['catalog:read']})};
  const call = async (key, method, route, body, headers = {}) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key.token ?? key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, body: response.status === 204 ? null : await response.json()};
  };
  const agent = async (token, method, params = {}) => {
    const response = await fetch(`${app.origin}/fabric/v1`, {method: 'POST', headers: {Authorization: `Bearer ${token}`, 'Content-Type': 'application/json'}, body: JSON.stringify({protocol: 'fabric/0.1', id: randomUUID(), method, params})});
    return {status: response.status, body: await response.json()};
  };
  const repo = () => app.stores.open(scope).repository;
  const accounts = {};
  for (const externalUserId of bare) await call(keys.standard, 'POST', '/v1/connect-sessions', {externalUserId});
  for (const externalUserId of users) {
    await call(keys.standard, 'POST', '/v1/connect-sessions', {externalUserId});
    const user = repo().list('endUsers').find(item => item.subjectId === externalUserId && item.status === 'active'), stamp = app.registry.now(), owner = {subjectId: externalUserId, userRecordId: user.id};
    const put = (appId, providerId, origin, identity, scopes, token) => {
      const id = randomUUID();
      repo().put('connections', stampOwner({id, appId, providerId, driver: 'http', status: 'ready', authMethod: 'oauth', identity, label: identity.displayName, allowedOrigins: [origin], scopes, createdAt: stamp, updatedAt: stamp,
        authRevision: randomUUID(), providerApp: {kind: 'shared'}}, owner));
      app.stores.open(scope).vault.set(id, {accessToken: token, refreshToken: '1//r', expiresAt: Date.parse(stamp) + 3600_000});
      return id;
    };
    accounts[externalUserId] = {
      slack: put('slack', 'slack', 'https://slack.com', {id: `T1:${externalUserId.toUpperCase()}`, displayName: `${externalUserId} in Slack`}, ['users:read', 'users:read.email', 'im:write', 'chat:write', 'channels:read'], SLACK_TOKEN),
      notion: put('notion', 'notion', 'https://api.notion.com', {id: `ws-1:${externalUserId}`, displayName: `${externalUserId} in Notion`}, [], `notion-token-${externalUserId}`),
      github: put('github', 'github', 'https://api.github.com', {id: `gh-${externalUserId}`, displayName: `${externalUserId} on GitHub`}, ['read:user', 'repo', 'gist'], `github-token-${externalUserId}`),
    };
  }
  const idOf = key => [...seeding.entries.values()].find(item => `${item.entry.key} v${item.entry.version}` === key)?.entry.id;
  // F10.11 part n: a browser on Fabric's hosted pages, as test/fixtures/hosted-fixture.mjs has one: its own cookies, and what Fabric's page
  // sends (Sec-Fetch-Site, Origin and the CSRF value from claim or view).
  const browser = () => {
    const jar = new Map();
    let csrf = null;
    return {jar, async call(method, route, body) {
      const cookie = [...jar].filter(([, value]) => value).map(([name, value]) => `${name}=${value}`).join('; ');
      const response = await fetch(`${app.origin}${route}`, {method, redirect: 'manual', headers: {'Sec-Fetch-Site': 'same-origin', ...(cookie ? {Cookie: cookie} : {}), ...(body !== undefined ? {'Content-Type': 'application/json', Origin: app.origin, ...(csrf ? {'X-Fabric-CSRF': csrf} : {})} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
      const cookies = response.headers.getSetCookie();
      for (const line of cookies) { const [pair] = line.split(';'), at = pair.indexOf('='); jar.set(pair.slice(0, at), pair.slice(at + 1)); }
      const parsed = (response.headers.get('content-type') || '').includes('json') ? await response.json() : await response.text();
      if (typeof parsed?.csrf === 'string') csrf = parsed.csrf;
      return {status: response.status, cookies, body: parsed};
    }};
  };
  /** Mints a manage or approve link and opens it in a fresh browser: {id, person, get(path), post(path, body)} under the link's own API. */
  const open = async (key, body) => {
    const created = await call(key, 'POST', '/v1/connect-sessions', body);
    if (created.status !== 201) throw new Error(`link refused: ${JSON.stringify(created.body)}`);
    const person = browser(), id = created.body.id;
    const claimed = await person.call('POST', `/connect/${id}/v1/claim`, {secret: new URL(created.body.connectUrl).hash.slice(3)});
    if (claimed.status !== 200) throw new Error(`claim refused: ${JSON.stringify(claimed.body)}`);
    return {id, person, created: created.body, get: route => person.call('GET', `/connect/${id}/v1/${route}`), post: (route, payload = {}) => person.call('POST', `/connect/${id}/v1/${route}`, payload)};
  };
  return {app, scope, catalog, slack: slackScript, notion: notionScript, calls, call, agent, keys, accounts, repo, idOf, open, capability: key => repo().get('capabilities', idOf(key)),
    bundle: () => app.runtimes.bundle(scope), advance(ms) { now += ms; }, get now() { return now; },
    /** Holds the next call of `name` until released: {reached, release}. */
    hold(name) { let reach, release; const reached = new Promise(resolve => { reach = resolve; }), released = new Promise(resolve => { release = resolve; }); gates.set(name, {reach, released}); return {reached, release}; },
    /** Answers the next `times` calls of `name` with `answer` ({status, headers, data}) instead of the script. */
    fail(name, answer, times = 1) { faults.set(name, {answer, times}); },
    /** Every call of `name`. */
    callsOf: name => calls.filter(item => item.name === name)};
}

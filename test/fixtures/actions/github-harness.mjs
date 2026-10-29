// F10.17 (docs/F10.17-BUILD-MAP.md parts 1 and 2): the run harness of GitHub's action tests, modeled on calendarHarness()
// (calendar-harness.mjs). One call builds a temp root holding a GitHub action file, reviewed and certified there and loaded through
// withIds() (so a seeded fault inside the file reaches behaviour instead of tripping the id check), with temp passing evidence for every
// action written only under that root; a designated temp store with the shipped rows (or rows a test edits) and proxy settings, so raw
// proxied requests run on the same account; one ready GitHub account (providerId github, identity {id: '101', displayName: <login>}) with
// the five scopes by default; credentials through the network seam with a token of GitHub's gho_ shape; the GitHub simulator
// (test/fixtures/provider-simulators/github.mjs) behind it; and a fake clock whose wait(ms) seam moves the clock, so write spacing takes no
// real time. GitHub places with no application map, so none is stored. The shipped file (catalog/actions/github.json, part 2) is the
// default; part 1's tests pass their own small action files. Test data only: nothing in lib/ imports it, and nothing here reaches GitHub.
import {mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {Store} from '../../../lib/store.mjs';
import {LocalRepository} from '../../../lib/repositories/local.mts';
import {PermissionManager} from '../../../lib/permissions.mjs';
import {ProxyPolicy} from '../../../lib/proxy-policy.mjs';
import {Runtime} from '../../../lib/runtime.mjs';
import {validateActionFile} from '../../../lib/actions.mjs';
import {loadActionCatalog, seedActions} from '../../../lib/action-catalog.mjs';
import {PREPARED} from '../../../lib/actions-runtime.mjs';
import {PERMISSION_GROUPS, validatePermissionGroups} from '../../../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../../../lib/proxy-config.mjs';
import {PINS} from '../../../lib/transform-pins.mjs';
import {definitionFor} from '../../../lib/providers/definitions.mjs';
import {approvalItem} from '../../../lib/ui-contracts.mjs';
import {validatePrincipal} from '../../../contracts/identity.mts';
import {GitHubSimulator, ORIGIN, FIVE} from '../provider-simulators/github.mjs';
import {withIds} from './fixture-app.mjs';

const ROOT = new URL('../../../', import.meta.url);
/** The bearer token the harness account sends and the simulator accepts, in the shape of a GitHub OAuth token. */
export const TOKEN = 'gho_16C7e42F292c6912E7710c838347Ae178B4a';
export const LOGIN = 'octo-a';
export const SANDBOX = `${LOGIN}/fabric-sandbox`;
export const OWNER = validatePrincipal({schemaVersion: 1, kind: 'local_owner', id: 'github-owner', scope: {schemaVersion: 1, kind: 'local', localOwnerId: 'github-owner'}});
export const EVIDENCE = 'docs/live-evidence/github/actions.json';
export {FIVE};
const ACCOUNT = 'github-account';

/** A fresh copy of GitHub's shipped action file, as written. */
export const githubFile = () => JSON.parse(readFileSync(new URL('catalog/actions/github.json', ROOT), 'utf8'));
/** A fresh copy of GitHub's shipped rows file. */
export const githubRows = () => JSON.parse(readFileSync(new URL('catalog/permissions/github.json', ROOT), 'utf8'));
/** The validator's dependencies for GitHub: the shipped rows (or `groups`) and GitHub's reviewed sign-in; GitHub needs no map. */
export function githubDeps({groups = PERMISSION_GROUPS} = {}) {
  return {groups, configs: PROXY_CONFIGS, identities: new Map([['github', definitionFor('github')]]), maps: new Map()};
}
/** The file reviewed, each action certified with live evidence (definition hashes as an author writes them), ids recomputed by withIds(). */
export function certified(file, deps) {
  const copy = structuredClone(file);
  copy.reviewStatus = 'reviewed';
  for (const action of copy.actions) action.certified = {evidence: EVIDENCE, definitionHash: '0'.repeat(64)};
  return withIds(copy, deps);
}

/**
 * Builds the harness. Options: `file` (a GitHub action file as written; the shipped one by default), `scopes` (the account's recorded
 * scopes; the five by default), `rows` (edits GitHub's rows file before it is validated), `evidence` (false: a reviewed file with no
 * evidence, so every action stays a candidate), `start` (the clock) and `login` (the account's login). run(key, input) runs an action on the
 * account; approve(job) approves it with its shown digest; card(job) is its approval item, fields(job) the card's field lines as
 * {label: value} and prepared(job) its prepared row; proxy(method, path, extra) sends a raw proxied request on the account; setRow(groupId,
 * mode) sets a row. `waits` lists each wait(ms) the runtime asked for, with how many writes the simulator had seen when it began.
 */
export function githubHarness(t, {file = githubFile(), scopes = FIVE, rows = change => change, evidence = true, start = '2026-10-23T13:00:00.000Z', login = LOGIN} = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-github-harness-'));
  let now = Date.parse(start);
  const clock = () => now;
  const groups = new Map([...PERMISSION_GROUPS, ['github', validatePermissionGroups(rows(githubRows()))]]), deps = githubDeps({groups});
  const written = certified(file, deps);
  const actions = path.join(root, 'catalog', 'actions'), live = path.join(root, 'docs', 'live-evidence', 'github');
  for (const dir of [actions, live]) mkdirSync(dir, {recursive: true});
  writeFileSync(path.join(actions, 'github.json'), JSON.stringify(written));
  let entries = [];
  try { entries = validateActionFile(written, deps).actions; } catch {}
  if (evidence) {
    writeFileSync(path.join(root, EVIDENCE), JSON.stringify(Object.fromEntries(entries.map(entry => [entry.id,
      {passed: true, transforms: Object.fromEntries(entry.transforms.map(id => [id, PINS.transforms[id]])), definitionHash: entry.definitionHash}]))));
  }
  const simulator = new GitHubSimulator({clock, token: TOKEN, owner: {login, id: 101}, scopes: [...FIVE]});
  const plain = new Store({dataDir: path.join(root, 'data'), clock, localAuthority: 'new'}), store = new LocalRepository({store: plain, scope: OWNER.scope});
  t.after(() => { store.close(); rmSync(root, {recursive: true, force: true}); });
  const at = new Date(now).toISOString();
  store.put('connections', {id: ACCOUNT, appId: 'github', providerId: 'github', driver: 'http', authMethod: 'oauth', authRevision: 'r1', signInRevision: 's1', status: 'ready', label: 'GitHub',
    identity: {id: '101', displayName: login}, scopes: [...scopes], grantCeiling: [...scopes], allowedOrigins: [ORIGIN], createdAt: at, signedInAt: at});
  const permissions = new PermissionManager({store, groups, configs: PROXY_CONFIGS});
  const proxyPolicy = new ProxyPolicy({store, permissions, groups, configs: PROXY_CONFIGS});
  const catalog = loadActionCatalog({directory: actions, evidenceRoot: root, maps: deps.maps, deps: {groups, configs: PROXY_CONFIGS, identities: deps.identities},
    codeHashes: ids => Object.fromEntries(ids.map(id => [id, PINS.transforms[id]]))});
  const connections = {credentials: async () => ({headers: {Authorization: `Bearer ${TOKEN}`}, allowedOrigins: [ORIGIN]})};
  const waits = [];
  const wait = async ms => { waits.push({ms, writesBefore: simulator.writes().length}); now += ms; };
  const runtime = new Runtime({store, permissions, proxyPolicy, connections, request: simulator.request, clock, wait, actions: catalog, ownerPrincipal: OWNER});
  seedActions(store, catalog);
  const idOf = key => [...catalog.entries.values()].find(item => `${item.entry.key} v${item.entry.version}` === key)?.entry.id;
  const card = job => approvalItem(job, {prepared: id => store.get(PREPARED, id)});
  const fields = job => Object.fromEntries((store.get(PREPARED, job.id)?.content?.fields ?? []).map(field => [field.label, field.value]));
  return {root, store, simulator, runtime, permissions, proxyPolicy, catalog, groups, file: written, entries, account: ACCOUNT, connections, idOf, card, fields, waits,
    entry: key => catalog.entries.get(idOf(key)),
    connection: () => store.get('connections', ACCOUNT),
    run: (key, input) => runtime.createJob({connectionId: ACCOUNT, capabilityId: idOf(key), args: input}, OWNER),
    approve: job => runtime.approve(job.id, job.approvalDigest, OWNER),
    proxy: (method, requestPath, extra = {}) => runtime.createProxyJob({connectionId: ACCOUNT, request: {method, path: requestPath, ...extra}}, OWNER),
    prepared: job => store.get(PREPARED, job.id),
    setRow: (groupId, mode) => proxyPolicy.set({connectionId: ACCOUNT, row: `group:${groupId}`, mode, confirmAllow: true}),
    advance(ms) { now += ms; }, get now() { return now; }};
}

// ---- part 1's probe actions -----------------------------------------------------------------------------------------------------------
const OK = status => ({status: [status], require: []});
const closed = (properties, required = Object.keys(properties)) => ({type: 'object', properties, required, additionalProperties: false});
const words = (max = 100) => ({type: 'string', minLength: 1, maxLength: max});
const NUMBER = {type: 'integer', minimum: 1, maximum: 2_147_483_647};
const REPO = {owner: {input: '/owner'}, repo: {input: '/repo'}};
const READ_HINTS = {readOnly: true, destructive: false, idempotent: true, openWorld: true}, WRITE_HINTS = {readOnly: false, destructive: false, idempotent: false, openWorld: true};
const stub = key => `github.action.${key}.v1.${'0'.repeat(24)}`;
/**
 * Six small GitHub actions with no transforms, for part 1's write spacing and grant drift tests before part 2 ships GitHub's file: Read an
 * issue, List my gists and Read an issue then my gists (reads at Allow; the last reads in two rows in one job), Create an issue, Comment and
 * Rename an issue (writes at Ask, each read back; Rename reads the issue first, so its answer is kept in the prepared row).
 */
export const probeFile = () => ({schemaVersion: 1, appId: 'github', specVersion: 'fabric/0.2', reviewStatus: 'candidate', pinnedParameters: {}, actions: [
  {id: stub('read-issue'), key: 'read-issue', version: 1, name: 'Read an issue', description: 'Reads one issue.', effect: 'read', row: 'github.issues.read', hints: READ_HINTS,
    inputSchema: closed({owner: words(39), repo: words(100), number: NUMBER}), outputSchema: closed({title: {type: 'string', maxLength: 256}}), guards: [], prepare: [],
    perform: [{id: 'issue', method: 'GET', path: '/repos/{owner}/{repo}/issues/{issue_number}', params: {...REPO, issue_number: {input: '/number'}}, expect: OK(200)}],
    output: {title: {step: 'issue', pointer: '/title'}}, preview: [{label: 'Issue', expr: {input: '/number'}}], definitive: [403, 404, 410]},
  {id: stub('list-gists'), key: 'list-gists', version: 1, name: 'List my gists', description: 'Lists your gists.', effect: 'read', row: 'github.gists.read', hints: READ_HINTS,
    inputSchema: closed({}), outputSchema: closed({first: {type: 'string', maxLength: 64}}), guards: [], prepare: [],
    perform: [{id: 'list', method: 'GET', path: '/gists', expect: OK(200)}], output: {first: {step: 'list', pointer: '/0/id'}}, preview: [], definitive: [403, 404]},
  {id: stub('create-issue'), key: 'create-issue', version: 1, name: 'Create an issue', description: 'Creates one issue.', effect: 'write', row: 'github.issues.write', hints: WRITE_HINTS,
    inputSchema: closed({owner: words(39), repo: words(100), title: words(256)}), outputSchema: closed({number: NUMBER}), guards: [], prepare: [],
    perform: [{id: 'create', method: 'POST', path: '/repos/{owner}/{repo}/issues', params: REPO, body: {object: {title: {input: '/title'}}}, expect: OK(201)}],
    verify: {requests: [{id: 'check', method: 'GET', path: '/repos/{owner}/{repo}/issues/{issue_number}', params: {...REPO, issue_number: {step: 'create', pointer: '/number'}}, expect: OK(200)}],
      identity: [{kind: 'readback', step: 'check', pointer: '/number', equals: {step: 'create', pointer: '/number'}}], assert: []},
    output: {number: {step: 'create', pointer: '/number'}}, preview: [{label: 'Title', expr: {input: '/title'}}], definitive: [403, 404, 410, 422]},
  {id: stub('comment'), key: 'comment', version: 1, name: 'Comment', description: 'Comments on one issue.', effect: 'write', row: 'github.comments.write', hints: WRITE_HINTS,
    inputSchema: closed({owner: words(39), repo: words(100), number: NUMBER, body: words(1000)}), outputSchema: closed({id: {type: 'integer', minimum: 1}}), guards: [], prepare: [],
    perform: [{id: 'post', method: 'POST', path: '/repos/{owner}/{repo}/issues/{issue_number}/comments', params: {...REPO, issue_number: {input: '/number'}}, body: {object: {body: {input: '/body'}}}, expect: OK(201)}],
    verify: {requests: [{id: 'check', method: 'GET', path: '/repos/{owner}/{repo}/issues/comments/{comment_id}', params: {...REPO, comment_id: {step: 'post', pointer: '/id'}}, expect: OK(200)}],
      identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {step: 'post', pointer: '/id'}}], assert: []},
    output: {id: {step: 'post', pointer: '/id'}}, preview: [{label: 'Comment', expr: {input: '/body'}}], definitive: [403, 404, 410, 422]},
  {id: stub('rename-issue'), key: 'rename-issue', version: 1, name: 'Rename an issue', description: 'Gives one issue a new title.', effect: 'write', row: 'github.issues.write', hints: WRITE_HINTS,
    inputSchema: closed({owner: words(39), repo: words(100), number: NUMBER, title: words(256)}), outputSchema: closed({title: {type: 'string', maxLength: 256}}), guards: [],
    prepare: [{id: 'issue', method: 'GET', path: '/repos/{owner}/{repo}/issues/{issue_number}', params: {...REPO, issue_number: {input: '/number'}}, expect: OK(200)}],
    perform: [{id: 'rename', method: 'PATCH', path: '/repos/{owner}/{repo}/issues/{issue_number}', params: {...REPO, issue_number: {input: '/number'}}, body: {object: {title: {input: '/title'}}}, expect: OK(200)}],
    verify: {requests: [{id: 'check', method: 'GET', path: '/repos/{owner}/{repo}/issues/{issue_number}', params: {...REPO, issue_number: {input: '/number'}}, expect: OK(200)}],
      identity: [{kind: 'readback', step: 'check', pointer: '/number', equals: {input: '/number'}}], assert: []},
    output: {title: {step: 'rename', pointer: '/title'}}, preview: [{label: 'Title now', expr: {step: 'issue', pointer: '/title'}}, {label: 'New title', expr: {input: '/title'}}], definitive: [403, 404, 410, 422]},
  {id: stub('issue-then-gists'), key: 'issue-then-gists', version: 1, name: 'Read an issue, then my gists', description: 'Reads one issue, then lists your gists.', effect: 'read', row: 'github.gists.read', hints: READ_HINTS,
    inputSchema: closed({owner: words(39), repo: words(100), number: NUMBER}), outputSchema: closed({title: {type: 'string', maxLength: 256}, first: {type: 'string', maxLength: 64}}), guards: [], prepare: [],
    perform: [{id: 'issue', method: 'GET', path: '/repos/{owner}/{repo}/issues/{issue_number}', params: {...REPO, issue_number: {input: '/number'}}, expect: OK(200)},
      {id: 'list', method: 'GET', path: '/gists', expect: OK(200)}],
    output: {title: {step: 'issue', pointer: '/title'}, first: {step: 'list', pointer: '/0/id'}}, preview: [], definitive: [403, 404, 410]},
]});

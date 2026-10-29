// F10.11 part p (docs/F10.11-BUILD-MAP.md part p): the owner's own Fabric with actions loaded at start, for the startup and HTTP tests. A
// temp folder of actions on the shipped rows and transforms (Slack Send a direct message and Find a person, GitHub List my gists, and
// Calendar List my calendars, which places only on a stored Calendar map) with
// their live evidence, and the owner's server over a temp data folder, its actions read from that folder through the server's own
// guarded import, Slack scripted behind the network seam. Test data only: nothing in lib/ imports it.
import {mkdirSync, mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createApp} from '../../../server.mjs';
import {validateActionFile} from '../../../lib/actions.mjs';
import {PINS as SHIPPED_PINS} from '../../../lib/transform-pins.mjs';
import {PERMISSION_GROUPS} from '../../../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../../../lib/proxy-config.mjs';
import {definitionFor} from '../../../lib/providers/definitions.mjs';
import {directMessageFile, SlackScript, OWNER} from './runtime-fixture.mjs';
import {findPerson, githubFile} from './developer-fixture.mjs';
import {withIds} from './fixture-app.mjs';
import {googleMap} from '../access/google-maps.mjs';
import {freePort} from '../signin-fixture.mjs';

/** The code each shipped transform has now: its shipped pin. */
export const shippedHashes = ids => Object.fromEntries(ids.map(id => [id, SHIPPED_PINS.transforms[id]]));
/**
 * A repository-like folder of actions for the servers, on the shipped rows and transforms: Slack Send a direct message and Find a person,
 * GitHub List my gists and Calendar List my calendars (unplaced until a Calendar map is stored), reviewed and certified. `pass(false)`
 * rewrites their live evidence to fail, so each loads as a candidate.
 */
const calendarFile = () => ({schemaVersion: 1, appId: 'google-calendar', specVersion: 'fabric/0.2', reviewStatus: 'reviewed', pinnedParameters: {}, actions: [
  {id: `google-calendar.action.list-calendars.v1.${'0'.repeat(24)}`, key: 'list-calendars', version: 1, name: 'List my calendars', description: 'Lists the calendars on your list.', effect: 'read',
    row: 'google-calendar.calendars.read', hints: {readOnly: true, destructive: false, idempotent: true, openWorld: true},
    inputSchema: {type: 'object', properties: {}, required: [], additionalProperties: false}, outputSchema: {type: 'object', properties: {first: {type: 'string', maxLength: 200}}, required: ['first'], additionalProperties: false},
    guards: [], prepare: [], perform: [{id: 'list', method: 'GET', path: '/users/me/calendarList', expect: {status: [200], require: []}}], output: {first: {step: 'list', pointer: '/items/0/id'}},
    preview: [], definitive: [404], certified: {evidence: 'docs/live-evidence/google-calendar/actions.json', definitionHash: '0'.repeat(64)}}]});
export function shippedFolder(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-action-shipped-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const deps = {groups: PERMISSION_GROUPS, configs: PROXY_CONFIGS, identities: new Map([...['slack', 'github'].map(appId => [appId, definitionFor(appId)]), ['google-calendar', definitionFor('google')]]),
    maps: new Map([['google-calendar', googleMap('google-calendar')]])};
  const directory = path.join(root, 'catalog', 'actions'), slack = directMessageFile(), github = githubFile();
  slack.actions.push(findPerson());
  github.actions = github.actions.filter(action => action.key === 'list-gists');
  mkdirSync(directory, {recursive: true});
  const valid = new Map();
  for (const file of [slack, github, calendarFile()]) {
    const written = withIds(file, deps);
    writeFileSync(path.join(directory, `${file.appId}.json`), JSON.stringify(written));
    for (const entry of validateActionFile(written, deps).actions) valid.set(`${entry.key} v${entry.version}`, {...entry, appId: file.appId});
  }
  const pass = passed => {
    for (const appId of ['slack', 'github', 'google-calendar']) {
      const live = path.join(root, 'docs', 'live-evidence', appId);
      mkdirSync(live, {recursive: true});
      writeFileSync(path.join(live, 'actions.json'), JSON.stringify(Object.fromEntries([...valid.values()].filter(entry => entry.appId === appId)
        .map(entry => [entry.id, {passed, transforms: Object.fromEntries(entry.transforms.map(id => [id, SHIPPED_PINS.transforms[id]])), definitionHash: entry.definitionHash}]))));
    }
  };
  pass(true);
  return {root, directory, pass, idOf: key => valid.get(key).id, options: {directory, evidenceRoot: root, codeHashes: shippedHashes}};
}
/** The owner's Fabric on a free loopback port over `dir`, its actions from `where`: a designated store, Slack scripted behind the network.
 *  Returns {app, call(method, route, data), protocol(token, method, params), close(), slack}. */
export async function ownerApp(t, where, {dir, mode = 'new', slack = new SlackScript(), importer, start = true} = {}) {
  const app = await createApp({dataDir: dir, port: await freePort(), request: async options => { if (new URL(options.url).origin === 'https://slack.com') return slack.request(options); throw Object.assign(new Error(`unexpected ${options.url}`), {sent: false}); },
    localAuthority: {mode, ownerPrincipal: OWNER}, actions: {...where.options, ...(importer ? {importer} : {})}});
  let closed = false;
  const close = async () => { if (!closed) { closed = true; await app.close(); } };
  t.after(close);
  // `start: false` gives the app exactly as createApp() left it, before any request can read or change a record.
  if (!start) return {app, close, slack};
  await app.start();
  const boot = await fetch(`${app.origin}/api/state`), cookie = boot.headers.get('set-cookie').split(';')[0], {csrfToken} = await boot.json();
  const call = async (method, route, data) => { const response = await fetch(`${app.origin}${route}`, {method, headers: {'Content-Type': 'application/json', Cookie: cookie, 'X-Fabric-CSRF': csrfToken}, ...(data !== undefined ? {body: JSON.stringify(data)} : {})}); return {status: response.status, body: await response.json()}; };
  const protocol = async (token, method, params) => (await (await fetch(`${app.origin}/fabric/v1`, {method: 'POST', headers: {'Content-Type': 'application/json', Authorization: `Bearer ${token}`}, body: JSON.stringify({protocol: 'fabric/0.1', id: `req-${Math.random().toString(36).slice(2, 9)}`, method, params})})).json());
  return {app, call, protocol, close, slack};
}
/** A Slack and a GitHub token account, stored as the owner's own. */
export function accounts(app) {
  const at = new Date().toISOString();
  app.store.put('connections', {id: 'slack-account', appId: 'slack', driver: 'http', authMethod: 'token', authRevision: 'r1', status: 'ready', label: 'Slack', identity: {id: 'T1:U1'}, allowedOrigins: ['https://slack.com'], createdAt: at});
  app.store.put('connections', {id: 'github-account', appId: 'github', driver: 'http', authMethod: 'token', authRevision: 'r1', status: 'ready', label: 'GitHub', identity: {id: 'gh-1'}, allowedOrigins: ['https://api.github.com'], createdAt: at});
  app.vault.set('slack-account', {accessToken: 'xoxb-slack-harness-token-7c41'});
  app.vault.set('github-account', {accessToken: 'github-owner-token-9d2a'});
}

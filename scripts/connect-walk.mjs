// A throwaway walk-through of the hosted Connect page (F03.6c's browser walk). Everything is simulated and temporary:
// a developer server on 127.0.0.1:4342 with a fresh data folder, simulated GitHub and Google (no network), and a small
// "developer app" on 127.0.0.1:4343 that mints Connect links, plays the provider's sign-in screen, and shows what the
// developer gets back. Never 4188, 4320 or 4340; never the real .fabric folder or .env. Stop it with Ctrl+C.
import http from 'node:http';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {deflateSync, crc32} from 'node:zlib';
import {createDeveloperApp} from '../developer-server.mjs';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';

const FABRIC_PORT = 4342, APP_PORT = 4343, APP = `http://127.0.0.1:${APP_PORT}`;
const escape = value => String(value).replace(/[&<>"']/g, char => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'})[char]);

// The provider's sign-in screen is played by the walk app: the real authorization URL keeps its parameters, on another host.
const start = OAuth2Provider.prototype.start;
OAuth2Provider.prototype.start = function walkStart(...args) {
  const flow = start.apply(this, args), real = new URL(flow.authorizationUrl);
  return {...flow, authorizationUrl: `${APP}/provider/${this.providerId}?${real.searchParams}`};
};

const identities = new Map();
let issued = 0;
const request = async req => {
  const token = String(req.headers?.Authorization || '').slice(7);
  if (req.url === 'https://github.com/login/oauth/access_token') { const access = `gho_walk${++issued}`; identities.set(access, {id: 9001, login: 'walk-tester', name: 'Walk Tester'}); return {status: 200, headers: {}, data: {access_token: access, token_type: 'bearer', scope: 'read:user,repo'}}; }
  if (req.url === 'https://api.github.com/user') return {status: 200, headers: {}, data: identities.get(token)};
  if (req.url === 'https://oauth2.googleapis.com/token') { const access = `ya29.walk${++issued}`; identities.set(access, {sub: 'walk-google-1', email: 'walk.tester@example.com', name: 'Walk Tester'}); return {status: 200, headers: {}, data: {access_token: access, refresh_token: `1//walk${issued}`, token_type: 'Bearer', expires_in: 3600, scope: walkScopes.get('google') || ''}}; }
  if (req.url === 'https://openidconnect.googleapis.com/v1/userinfo') return {status: 200, headers: {}, data: identities.get(token)};
  if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/me/profile')) return {status: 200, headers: {}, data: {emailAddress: identities.get(token)?.email}};
  if (req.url.startsWith('https://www.googleapis.com/calendar/v3/users/me/calendarList')) return {status: 200, headers: {}, data: {kind: 'calendar#calendarList'}};
  if (req.url.startsWith('https://api.github.com/applications/')) return {status: 204, headers: {}, data: null};
  throw new Error(`The walk has no simulation for ${req.url}`);
};
const walkScopes = new Map();

const root = mkdtempSync(path.join(tmpdir(), 'fabric-connect-walk-'));
const fabric = await createDeveloperApp({dataRoot: root, port: FABRIC_PORT, request, providerSettings: {github: {clientId: 'walk-github', clientSecret: 'walk-github-secret'}, google: {clientId: 'walk-google', clientSecret: 'walk-google-secret'}}});
const org = fabric.registry.createOrganization({name: 'Walk Org'}), project = fabric.registry.createProject({organizationId: org.id, name: 'Walk', appName: 'Walkthrough App', supportEmail: 'help@walk.example'});
const dev = fabric.registry.createEnvironment({projectId: project.id, kind: 'development'}, fabric.stores);
fabric.registry.put('environments', {...fabric.registry.get('environments', dev.id), redirectOrigins: [APP]});
const key = fabric.keys.mint({environmentId: dev.id, preset: 'standard'}).token;
const v1 = async (method, route, body, type = 'application/json') => {
  const response = await fetch(`${fabric.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body ? {'Content-Type': type} : {})}, ...(body ? {body: type === 'application/json' ? JSON.stringify(body) : body} : {})});
  return response.json();
};
// A small generated logo for the walk's developer (a violet square), so the sheet shows the developer's branding.
const chunk = (type, data) => { const length = Buffer.alloc(4); length.writeUInt32BE(data.length); const body = Buffer.concat([Buffer.from(type, 'latin1'), data]); const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body)); return Buffer.concat([length, body, crc]); };
const header = Buffer.alloc(13); header.writeUInt32BE(64, 0); header.writeUInt32BE(64, 4); header[8] = 8; header[9] = 2;
const row = Buffer.concat([Buffer.from([0]), Buffer.alloc(64 * 3).map((_, index) => [91, 75, 219][index % 3])]);
await v1('PUT', '/v1/project/logo', Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', header), chunk('IDAT', deflateSync(Buffer.concat(Array(64).fill(row)))), chunk('IEND', Buffer.alloc(0))]), 'image/png');

const SCENARIOS = {
  github: {label: 'GitHub (one app)', body: {appId: 'github'}},
  gmail: {label: 'Gmail, sent by message for "Sam at Walkthrough" (level choice, Testing-mode notice)', body: {appId: 'gmail', delivery: 'message', userHint: 'Sam at Walkthrough'}},
  any: {label: 'Any app (the person picks)', body: {}},
};
const page = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(title)}</title>
<style>body{font:15px -apple-system,system-ui,sans-serif;max-width:640px;margin:32px auto;padding:0 16px;color:#172e2d}a,button{color:#126f61}li{margin:8px 0}code{background:#eef1ed;padding:2px 5px;border-radius:5px}.sim{border:1px dashed #9aa8a3;padding:16px;border-radius:12px}</style></head><body>${body}</body></html>`;
let user = 0;

const app = http.createServer(async (req, res) => {
  const url = new URL(req.url, APP), send = (status, html, headers = {}) => { res.writeHead(status, {'Content-Type': 'text/html; charset=utf-8', ...headers}); res.end(html); };
  try {
    if (url.pathname === '/') return send(200, page('Connect walk', `<h1>Connect walk (simulated)</h1><p>Temporary data, simulated providers. Each link is fresh.</p><ul>${Object.entries(SCENARIOS).map(([name, scenario]) => `<li><a href="/new?kind=${name}">${escape(scenario.label)}</a></li>`).join('')}</ul>
<p><button id="popup" type="button">Open the GitHub link in a popup</button></p><p id="popup-result"></p>
<script>document.getElementById('popup').addEventListener('click', () => { const opened = window.open('/new?kind=github', 'fabric-connect', 'popup,width=480,height=720'); document.getElementById('popup-result').textContent = opened ? 'Popup opened.' : 'The popup was blocked: open the link in this tab instead.'; });</script>`));
    if (url.pathname === '/new' && SCENARIOS[url.searchParams.get('kind')]) {
      const created = await v1('POST', '/v1/connect-sessions', {externalUserId: `walk-user-${++user}`, ...SCENARIOS[url.searchParams.get('kind')].body, successRedirectUri: `${APP}/back?app=walk&ok=1`, errorRedirectUri: `${APP}/back?app=walk&ok=0`});
      if (!created.connectUrl) return send(500, page('Walk', `<p>Could not create a link: ${escape(JSON.stringify(created))}</p>`));
      return send(302, '', {Location: created.connectUrl});
    }
    const provider = url.pathname.match(/^\/provider\/(github|google)$/);
    if (provider) {
      if (provider[1] === 'google') walkScopes.set('google', url.searchParams.get('scope') || '');
      const back = `${fabric.origin}/api/oauth/${provider[1]}/callback?state=${encodeURIComponent(url.searchParams.get('state'))}`;
      return send(200, page('Simulated sign-in', `<div class="sim"><h1>Simulated ${provider[1] === 'github' ? 'GitHub' : 'Google'} sign-in</h1><p>This stands in for the provider's own screen. It asks for: <code>${escape(url.searchParams.get('scope') || '(none)')}</code></p>
<p><a id="approve" href="${escape(`${back}&code=walk-code`)}">Approve as Walk Tester</a></p><p><a id="deny" href="${escape(`${back}&error=access_denied`)}">Deny</a></p></div>`));
    }
    if (url.pathname === '/back') return send(200, page('Back in the developer app', `<h1>Back in the developer's app</h1><p>What Fabric appended to the return address:</p><ul>${[...url.searchParams].map(([name, value]) => `<li><code>${escape(name)}</code> = ${escape(value)}</li>`).join('')}</ul><p><a href="/">Another walk</a></p>`));
    return send(404, page('Not found', '<p>Not found.</p>'));
  } catch (error) { return send(500, page('Walk error', `<p>${escape(error.message)}</p>`)); }
});
await new Promise(resolve => app.listen(APP_PORT, '127.0.0.1', resolve));
console.log(`Connect walk ready: ${APP}/ (Fabric on ${fabric.origin}; data in a temporary folder, removed on exit)`);
const stop = async () => { app.close(); await fabric.close(); rmSync(root, {recursive: true, force: true}); process.exit(0); };
process.on('SIGINT', stop); process.on('SIGTERM', stop);

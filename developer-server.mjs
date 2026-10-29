// F03.1b: the developer layer's own server (docs/F03-DEVELOPER-LAYER.md). Separate from the single-owner runtime
// (server.mjs): it serves developers' servers on /v1, icons on /assets, and (from F03.4) the Connect page. It answers
// only on 127.0.0.1 at its own port (4340 by default), and opens nothing outside the tenant data root.
import http from 'node:http';
import {readFileSync} from 'node:fs';
import {randomBytes, createHash, timingSafeEqual} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {existsSync} from 'node:fs';
import path from 'node:path';
import {TenantRegistry} from './lib/tenant/registry.mjs';
import {ServiceKeys} from './lib/tenant/keys.mjs';
import {EnvironmentStores, EnvironmentError} from './lib/tenant/environments.mjs';
import {PlatformCatalog, PLATFORM_DESIGNATION} from './lib/tenant/platform.mjs';
import {loadActionsSafely, gateCatalog} from './lib/action-gate.mjs';
import {TenantApi, appSetting} from './lib/tenant/api.mjs';
import {ConnectSessions, SessionError} from './lib/tenant/connect-sessions.mjs';
import {TenantError} from './lib/tenant/errors.mjs';
import {tenantApps} from './lib/tenant/views.mjs';
import {relayOrigin} from './lib/oauth-relay.mjs';
import {ProviderApps} from './lib/tenant/provider-apps.mjs';
import {TenantAccounts} from './lib/tenant/accounts.mjs';
import {ExternalUsers} from './lib/tenant/users.mjs';
import {TenantAppPages} from './lib/tenant/app-pages.mjs';
import {appIcon} from './lib/tenant/icons.mjs';
import {EnvironmentRuntimes} from './lib/tenant/runtime-bundle.mjs';
import {TenantExecutions} from './lib/tenant/executions.mjs';
import {TenantApprovals} from './lib/tenant/approvals.mjs';
import {TenantActivity} from './lib/tenant/activity.mjs';
import {TenantHostedPages} from './lib/tenant/hosted-pages.mjs';
import {PAGE_API, pageActionOf} from './lib/tenant/page-routes.mjs';
import {TenantAgentTokens} from './lib/tenant/agent-tokens.mjs';
import {AGENT_PROTOCOL, agentStatus} from './lib/tenant/agent-protocol.mjs';
import {TOKEN} from './lib/tenant/agent-tokens.mjs';

import {UsageRecords} from './lib/tenant/usage.mjs';
import {TenantOptions} from './lib/tenant/options.mjs';
import {distributionOf} from './lib/slack-limits.mjs';

const PUBLIC = fileURLToPath(new URL('./public/', import.meta.url));
const SECURITY_HEADERS = {'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer'};
const INVALID_STATE = 'This sign-in has expired, was already used, or belongs to another browser. Start again from the app.';

export {monogram} from './lib/tenant/icons.mjs';

/**
 * @param {{dataRoot: string, port?: number, clock?: () => number, forbiddenRoots?: string[]}} options
 * port 0 picks a free port (tests); the Host check uses the port actually bound.
 */
/**
 * Cookies parsed strictly: a nameless or repeated cookie makes the whole header unusable (no last-one-wins). Given
 * `names`, only those are read and checked; any other cookie on 127.0.0.1 (another local app's) is ignored.
 */
export function strictCookies(header, names = null) {
  const cookies = new Map();
  if (header === undefined) return cookies;
  for (const part of String(header).split(';')) {
    const at = part.indexOf('='), name = (at < 0 ? '' : part.slice(0, at)).trim();
    if (names && !names.includes(name)) continue;
    if (!name) throw new Error('A nameless cookie was sent.');
    if (cookies.has(name)) throw new Error('A cookie was sent twice.');
    cookies.set(name, part.slice(at + 1).trim());
  }
  return cookies;
}

/**
 * BRW-2: a page on another 127.0.0.1 port can plant Fabric's cookie names on a wider path (cookies ignore the port).
 * These expire every copy this request could have carried except on Fabric's own path, so the browser drops a planted
 * copy and the link keeps working instead of answering 'Malformed cookies' for good.
 */
export function plantedCookieResets(requestPath, names, ownPath) {
  const parts = String(requestPath).split('/').filter(Boolean), paths = ['/'];
  parts.forEach((part, at) => { const prefix = `/${parts.slice(0, at + 1).join('/')}`; paths.push(prefix); if (at < parts.length - 1) paths.push(`${prefix}/`); });
  return names.flatMap(name => paths.filter(item => item !== ownPath).map(item => `${name}=; Path=${item}; Max-Age=0`));
}
const PAGE_COOKIES = ['fabric_t_session', 'fabric_t_finish'], FLOW_COOKIES = ['fabric_t_oauth'];

/**
 * `fabricClientIds` names Fabric's own local client ids ([{providerId, clientId}]) so no developer can register them (H10).
 * `relay` is {base, appsReady} for developers' own Slack and Notion apps (D2); nothing is read from the environment.
 */
export async function createDeveloperApp({dataRoot, port = 4340, clock = Date.now, forbiddenRoots, providerSettings = {}, request, fabricClientIds = [], relay = null, actions: actionOptions = {}} = {}) {
  if (typeof dataRoot !== 'string' || !path.isAbsolute(dataRoot)) throw new Error('createDeveloperApp needs an absolute tenant data root.');
  // F10.21: how Fabric's Slack app is installed (lib/slack-limits.mjs), read once, before anything opens; every environment's runtime gets it.
  const slackDistribution = distributionOf(process.env);
  const registry = new TenantRegistry({root: dataRoot, clock, forbiddenRoots});
  const reader = existsSync(path.join(dataRoot, 'platform', PLATFORM_DESIGNATION)) && existsSync(path.join(dataRoot, 'platform', 'fabric.sqlite')) ? new PlatformCatalog({root: dataRoot, forbiddenRoots}) : null;
  // F10.11 part p: the action catalog loads once, from the platform's maps, through the one guarded import (lib/action-gate.mjs). The
  // operator's catalog command writes the platform's action records; the start gate serves none more active than this catalog computes, and
  // with no catalog serves every action as a candidate. `actions` is a test seam ({directory, evidenceRoot, codeHashes, deps, importer}).
  const actions = await loadActionsSafely({...actionOptions, maps: new Map((reader ? reader.list('applicationMaps') : []).map(map => [map.appId ?? map.id, map]))}, actionOptions.importer ? {importer: actionOptions.importer} : {});
  const catalog = gateCatalog(reader, actions);
  const stores = new EnvironmentStores({root: dataRoot, clock, forbiddenRoots, catalog});
  const keys = new ServiceKeys(registry);
  let api, bound, closed = false;
  const send = (res, status, body, headers = {}) => {
    // A 204 carries no body and no content type.
    if (status === 204) { res.writeHead(204, {...SECURITY_HEADERS, ...headers}); return res.end(); }
    const payload = typeof body === 'string' ? body : JSON.stringify(body);
    res.writeHead(status, {...SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8', ...headers});
    res.end(payload);
  };
  const server = http.createServer(async (req, res) => {
    try {
      // Only this exact origin: a request for any other Host is refused before anything else.
      if (req.headers.host !== `127.0.0.1:${bound}`) return send(res, 421, {error: {code: 'misdirected', message: 'Use the address this server listens on.'}});
      // A '.' or '..' path segment, in any spelling, would be resolved away by the URL parser and could turn one route into
      // another (a user named '..' listing every account); such paths are refused before parsing.
      if (/(^|\/)(\.|%2e){1,2}(\/|\?|#|$)/i.test(String(req.url))) return send(res, 404, {error: {code: 'not_found', message: 'Not found.'}});
      const url = new URL(req.url, `http://127.0.0.1:${bound}`);
      if (req.method === 'GET' && url.pathname === '/health') return send(res, 200, {ok: true});
      if (url.pathname === '/v1' || url.pathname.startsWith('/v1/')) { const {status, body, headers} = await api.handle(req, url); return send(res, status, body, headers); }
      // F03.9c: agents, with their own tokens, on fabric/0.1. Never a browser, never a developer key.
      if (url.pathname === '/fabric/v1') return await agentApi(req, res);
      // The provider's redirect back after sign-in. Only Fabric's flow cookie is read; the owner comes from the flow.
      // A developer's own provider app comes back on its own address (D2): /api/oauth/<provider>/apps/<pa_id>/callback.
      const callback = url.pathname.match(/^\/api\/oauth\/([a-z][a-z0-9-]{1,39})(?:\/apps\/(pa_[a-z2-7]{26}))?\/callback$/);
      if (req.method === 'GET' && callback) {
        const callbackPath = url.pathname, providerAppId = callback[2] ?? null;
        let flowId;
        try { flowId = strictCookies(req.headers.cookie, FLOW_COOKIES).get('fabric_t_oauth'); } catch { return send(res, 400, {error: {code: 'invalid_request', message: 'Malformed cookies.'}}, {'Set-Cookie': plantedCookieResets(callbackPath, FLOW_COOKIES, callbackPath)}); }
        try {
          const {sessionId, finish} = await sessions.callback(callback[1], {state: url.searchParams.get('state'), code: url.searchParams.get('code'), error: url.searchParams.get('error'), flowId}, providerAppId);
          // Only this browser, which came back from the provider, can confirm the account (N4). A failed sign-in lands
          // on the same page, which shows how it ended.
          res.writeHead(303, {...SECURITY_HEADERS, Location: `/connect/${sessionId}/finish`, 'Set-Cookie': [`fabric_t_oauth=; HttpOnly; SameSite=Lax; Path=${callbackPath}; Max-Age=0`,
            ...(finish ? [`fabric_t_finish=${finish}; HttpOnly; SameSite=Strict; Path=/connect/${sessionId}; Max-Age=600`] : [])]});
          return res.end();
        } catch (error) {
          // Every invalid_state reads the same (N2): a live state from another browser or environment, a used one and one that
          // never existed cannot be told apart by their words. Any other failure reads the same too: an internal code
          // (a closed environment, a missing sign-in app) never reaches the browser.
          if (error?.code === 'consent_denied') return send(res, 400, {error: {code: 'consent_denied', message: error.message}});
          return send(res, 400, {error: {code: 'invalid_state', message: INVALID_STATE}});
        }
      }
      // F03.4c: the hosted Connect page and its own small API. Every write must come from this page (exact Origin).
      const asset = url.pathname.match(/^\/connect\/assets\/(connect\.js|connect\.css|hosted\.css)$/);
      if (req.method === 'GET' && asset) return sendFile(res, asset[1]);
      const page = url.pathname.match(/^\/connect\/(cs_[a-z2-7]{26})(\/finish)?$/);
      if (req.method === 'GET' && page) return sendFile(res, 'connect.html');
      // F03.10: Fabric's hosted manage and approval pages under the link's own address; their data comes from its API.
      const hostedPage = url.pathname.match(/^\/connect\/cs_[a-z2-7]{26}\/(apps|apps\/[a-z][a-z0-9-]{0,63}|activity|approve)$/);
      if (req.method === 'GET' && hostedPage) return sendFile(res, hostedPage[1] === 'apps' ? 'hosted-catalog.html' : hostedPage[1].startsWith('apps/') ? 'hosted-app.html' : hostedPage[1] === 'activity' ? 'hosted-activity.html' : 'hosted-approve.html');
      // The hosted pages' own files, at the root paths their HTML names (the owner's Fabric serves the same files).
      const hostedAsset = url.pathname.match(/^\/(hosted\.css|hosted-(?:catalog|app|activity|approve|approval|text|base)\.js|sign-in-target\.js)$/);
      if (req.method === 'GET' && hostedAsset) return sendFile(res, hostedAsset[1]);
      // F03.10: the hosted manage and approval pages read and write through the same session-bound API.
      const pageApi = url.pathname.match(PAGE_API);
      if (pageApi) return connectApi(req, res, url, pageApi[1], pageApi[2]);
      // F03.6b: a project's approved logo only (never a pending one), with a fixed type and nothing the browser may run.
      const logo = url.pathname.match(/^\/assets\/logos\/(prj_[a-z2-7]{26})\/([0-9a-f]{32})$/);
      if (req.method === 'GET' && logo) {
        const project = registry.get('projects', logo[1]), stored = project?.logo?.hash === logo[2] ? registry.get('projectLogos', `${logo[1]}.${logo[2]}`) : null;
        if (!stored) return send(res, 404, {error: {code: 'not_found', message: 'No such logo.'}});
        res.writeHead(200, {...SECURITY_HEADERS, 'Content-Type': stored.contentType, 'Cache-Control': 'public, max-age=31536000, immutable', 'Content-Security-Policy': "default-src 'none'; sandbox", 'Content-Disposition': 'inline; filename="logo"'});
        return res.end(Buffer.from(stored.data, 'base64'));
      }
      const icon = url.pathname.match(/^\/assets\/icons\/([a-z][a-z0-9-]{0,63})$/);
      if (req.method === 'GET' && icon) {
        const app = tenantApps().find(item => item.id === icon[1]);
        if (!app) return send(res, 404, {error: {code: 'not_found', message: 'No such app.'}});
        return send(res, 200, appIcon(app.id, app.name), {'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400, immutable', 'Content-Security-Policy': "default-src 'none'"});
      }
      return send(res, 404, {error: {code: 'not_found', message: 'Not found.'}});
    } catch {
      if (!res.headersSent) send(res, 500, {error: {code: 'internal_error', message: 'Something went wrong. Nothing was changed.'}});
    }
  });
  const PAGE_HEADERS = {...SECURITY_HEADERS, 'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", 'X-Frame-Options': 'DENY'};
  const TYPES = {'connect.html': 'text/html; charset=utf-8', 'connect.js': 'text/javascript; charset=utf-8', 'connect.css': 'text/css; charset=utf-8', 'hosted.css': 'text/css; charset=utf-8'};
  const typeOf = name => TYPES[name] ?? (name.endsWith('.html') ? 'text/html; charset=utf-8' : name.endsWith('.js') ? 'text/javascript; charset=utf-8' : 'text/css; charset=utf-8');
  const sendFile = (res, name) => { res.writeHead(200, {...PAGE_HEADERS, 'Content-Type': typeOf(name)}); res.end(readFileSync(path.join(PUBLIC, name))); };
  const readJson = req => new Promise((resolve, reject) => { let size = 0; const chunks = []; req.on('data', chunk => { size += chunk.length; if (size > 16 * 1024) { reject(new Error('too large')); req.destroy(); } else chunks.push(chunk); }); req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch (error) { reject(error); } }); req.on('error', reject); });
  const AGENT_BODY_MAX = 256 * 1024, AGENT_DUMMY = createHash('sha256').update('fab_client.no-such-route').digest();
  /** Reads an agent request up to 256 KiB; anything larger is read and thrown away, then answered 413 (cut off only far over). */
  const readAgentBody = req => new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', chunk => { size += chunk.length; if (size <= AGENT_BODY_MAX) chunks.push(chunk); else if (size > 8 * AGENT_BODY_MAX) req.destroy(); });
    req.on('end', () => resolve(size > AGENT_BODY_MAX ? null : Buffer.concat(chunks))); req.on('error', reject);
  });
  /** A token's environment, if its route is live: not revoked, not expired, and the environment and organization active. */
  const agentScope = token => {
    const match = TOKEN.exec(typeof token === 'string' ? token : ''), route = match ? registry.get('agentTokenRoutes', match[1]) : null;
    const environment = route && registry.get('environments', route.environmentId), organization = environment && registry.get('organizations', environment.organizationId);
    const live = route && !route.revokedAt && Date.parse(route.expiresAt) > Date.parse(registry.now()) && environment?.status === 'active' && organization?.status === 'active' && (environment.kind !== 'production' || environment.productionEnabled);
    return live ? {organizationId: route.organizationId, projectId: route.projectId, environmentId: route.environmentId} : null;
  };
  async function agentApi(req, res) {
    const answer = (status, body) => send(res, status, body);
    const refusal = (status, code, message, id = null) => answer(status, {protocol: AGENT_PROTOCOL, id, error: {code, message}});
    if (req.headers.origin !== undefined || req.headers.cookie !== undefined) return refusal(403, 'browser_not_allowed', 'Agents call Fabric from a server, never from a browser.');
    if (req.method !== 'POST') return refusal(405, 'invalid_request', 'Use POST.');
    if (!/^application\/json(;|$)/.test(String(req.headers['content-type'] || ''))) return refusal(400, 'invalid_request', 'Send JSON with Content-Type application/json.');
    const raw = await readAgentBody(req);
    if (raw === null) return refusal(413, 'request_too_large', 'The request is larger than 256 KiB.');
    let envelope;
    try { envelope = JSON.parse(raw.toString('utf8')); } catch { return refusal(400, 'invalid_request', 'The body is not valid JSON.'); }
    const token = /^Bearer (\S{1,200})$/.exec(String(req.headers.authorization || ''))?.[1], scope = agentScope(token);
    // Every unusable token gets the same answer, after the same work.
    if (!scope) { timingSafeEqual(AGENT_DUMMY, createHash('sha256').update(String(token || '')).digest()); return refusal(401, 'unauthorized', 'This agent token is not valid.'); }
    // Opened before it is pinned: after a restart or an eviction nothing else has opened it yet.
    let bundle;
    try { bundle = runtimes.bundle(scope); stores.pin(scope); }
    catch (error) {
      if (!(error instanceof EnvironmentError && error.code === 'too_many_open')) throw error;
      return send(res, 503, {protocol: AGENT_PROTOCOL, id: null, error: {code: 'unavailable', message: 'Fabric is busy; try again shortly.'}}, {'Retry-After': '1'});
    }
    try { const result = await bundle.agents.handle(token, envelope); return answer(agentStatus(result), result); }
    finally { try { stores.unpin(scope); } catch { /* closed */ } }
  }
  /** A hosted page's read: the person comes from the session, never from the query (F03.10). */
  const hostedRead = (id, binding, action, url) => {
    const query = name => url.searchParams.get(name) ?? undefined;
    if (action === 'catalog') return hosted.catalog(id, binding, {q: query('q'), categoryId: query('category'), cursor: query('cursor'), limit: query('limit')});
    if (action === 'activity') return hosted.activity(id, binding, {appId: query('appId'), accountRef: query('accountRef'), cursor: query('cursor'), limit: query('limit')});
    if (action === 'approval') return hosted.approval(id, binding);
    return hosted.app(id, binding, action.slice('apps/'.length), query('account'));
  };
  /** F10.4: what an error tells Fabric's own page beyond its words: the upgrade card, or the accounts a disconnect affects. Fixed
   *  fields from Fabric's own errors only; none carries a token. */
  const pageDetails = error => {
    if (!(error instanceof SessionError || error instanceof TenantError) || !error.details) return null;
    const {upgrade, siblings, affected} = error.details, out = {...(upgrade ? {upgrade: {rows: upgrade.rows.map(row => ({groupId: row.groupId, label: row.label, typed: row.typed, proxy: row.proxy})), etag: upgrade.etag}} : {}),
      ...(Array.isArray(siblings) ? {siblings} : {}), ...(Array.isArray(affected) ? {affected} : {})};
    return Object.keys(out).length ? out : null;
  };
  /** F10.11 part n: a continuing approve link lives as long as its call's current stop, and its page cookie lives exactly as long as the link. */
  const continuingCookie = (id, binding) => {
    const seconds = sessions.continuingSeconds(id, binding);
    return seconds === null ? {} : {'Set-Cookie': `fabric_t_session=${binding}; HttpOnly; SameSite=Strict; Path=/connect/${id}; Max-Age=${seconds}`};
  };
  /** The page's CSRF value for a browser binding: derived one way, so it never reveals the cookie. */
  const csrfFor = binding => createHash('sha256').update(`csrf:${binding}`).digest('hex');
  const sameCsrf = (presented, binding) => typeof presented === 'string' && /^[0-9a-f]{64}$/.test(presented) && typeof binding === 'string' && timingSafeEqual(Buffer.from(presented, 'hex'), Buffer.from(csrfFor(binding), 'hex'));
  async function connectApi(req, res, url, id, action) {
    const reply = (status, body, headers = {}) => { res.writeHead(status, {...PAGE_HEADERS, 'Content-Type': 'application/json; charset=utf-8', ...headers}); res.end(JSON.stringify(body)); };
    try {
      let cookies;
      try { cookies = strictCookies(req.headers.cookie, PAGE_COOKIES); } catch { return reply(400, {error: {code: 'invalid_request', message: 'Malformed cookies.'}}, {'Set-Cookie': plantedCookieResets(url.pathname, PAGE_COOKIES, `/connect/${id}`)}); }
      const binding = cookies.get('fabric_t_session');
      // N10: every request, reads included, comes from Fabric's own page; another site's page is refused before anything is read.
      if (req.headers['sec-fetch-site'] !== 'same-origin') return reply(403, {error: {code: 'origin_not_allowed', message: 'This action must come from Fabric\'s Connect page.'}});
      if (pageActionOf(action)?.method === 'GET') {
        if (req.method !== 'GET') return reply(405, {error: {code: 'invalid_request', message: 'Use GET.'}});
        if (action === 'view') return reply(200, {...sessions.view(id, binding, url.searchParams.get('appId') ?? undefined, cookies.get('fabric_t_finish')), ...(binding ? {csrf: csrfFor(binding)} : {})});
        return reply(200, hostedRead(id, binding, action, url), action === 'approval' ? continuingCookie(id, binding) : {});
      }
      if (req.method !== 'POST' || req.headers.origin !== origin || !/^application\/json(;|$)/.test(req.headers['content-type'] || '')) return reply(403, {error: {code: 'origin_not_allowed', message: 'This action must come from Fabric\'s Connect page.'}});
      // Every action but the claim also carries the page's CSRF value from claim or view, held in page memory only (section
      // 6.1 step 6). A browser with no session cookie gets the session's own not_found below, the same as before.
      if (action !== 'claim' && binding !== undefined && !sameCsrf(req.headers['x-fabric-csrf'], binding)) return reply(403, {error: {code: 'csrf_mismatch', message: 'Reload Fabric\'s page and try again.'}});
      const body = await readJson(req);
      if (action === 'claim') {
        // The browser binding is always Fabric's own fresh random value on a first claim, in an HttpOnly cookie scoped to
        // this one session's path; a cookie the browser already carried only recognises the same browser coming back.
        const {binding: value, session} = sessions.claim(id, body.secret, randomBytes(32).toString('base64url'), binding);
        // The cookie lives as long as the link (a message link lasts up to 4 hours), never longer.
        const seconds = Math.max(1, Math.min(4 * 3600, Math.floor((Date.parse(session.expiresAt) - Date.parse(registry.now())) / 1000)));
        // A cookie carried to a claim may be a copy planted on a wider path (BRW-2): those go first, Fabric's own last.
        const resets = PAGE_COOKIES.some(name => cookies.has(name)) ? plantedCookieResets(url.pathname, PAGE_COOKIES, `/connect/${id}`) : [];
        return reply(200, {ok: true, csrf: csrfFor(value)}, {'Set-Cookie': [...resets, `fabric_t_session=${value}; HttpOnly; SameSite=Strict; Path=/connect/${id}; Max-Age=${seconds}`]});
      }
      if (action === 'start') {
        const started = sessions.start(id, binding, typeof body.appId === 'string' ? body.appId : undefined, typeof body.level === 'string' ? body.level : undefined, typeof body.confirmRows === 'string' ? body.confirmRows : undefined);
        return reply(200, {authorizationUrl: started.authorizationUrl}, {'Set-Cookie': `fabric_t_oauth=${started.flowId}; HttpOnly; SameSite=Lax; Path=${started.callbackPath}; Max-Age=600`});
      }
      if (action === 'close') return reply(200, await sessions.close(id, binding));
      if (action === 'reject') return reply(200, await sessions.reject(id, binding));
      if (action === 'select') return reply(200, sessions.select(id, binding, typeof body.choice === 'string' ? body.choice : ''));
      if (action === 'decline') return reply(200, await sessions.decline(id, binding));
      const write = action.match(/^apps\/([a-z][a-z0-9-]{0,63})\/accounts\/([0-9a-f-]{36})\/(permissions|reset|background|disconnect)$/);
      if (write) {
        const [, appId, accountRef, kind] = write;
        return reply(200, kind === 'disconnect' ? await hosted.disconnect(id, binding, appId, accountRef, body) : hosted[kind === 'permissions' ? 'setRow' : kind](id, binding, appId, accountRef, body));
      }
      const decision = action.match(/^approvals\/([0-9a-f-]{36})\/decision$/);
      if (decision) return reply(200, hosted.decide(id, binding, decision[1], body), continuingCookie(id, binding));
      const confirmed = sessions.confirm(id, binding, cookies.get('fabric_t_finish'), body);
      return reply(200, confirmed, {'Set-Cookie': `fabric_t_finish=; HttpOnly; SameSite=Strict; Path=/connect/${id}; Max-Age=0`});
    } catch (error) {
      const status = Number.isInteger(error.status) ? error.status : 400, details = pageDetails(error);
      return reply(status, {error: {code: error.code || 'invalid_request', message: error.status ? error.message : 'This link cannot be used.', ...(details ? {details} : {})}});
    }
  }
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  bound = server.address().port;
  const origin = `http://127.0.0.1:${bound}`;
  const providerApps = new ProviderApps({settings: providerSettings, registry, stores, origin, fabricClientIds, relay: relay ? {base: relayOrigin(relay.base), appsReady: relay.appsReady === true} : null});
  providerApps.seedFabricClientIds();
  const runtimes = new EnvironmentRuntimes({stores, registry, providerApps, origin, request, actions});
  runtimes.slackDistribution = slackDistribution;
  const usage = new UsageRecords({registry});
  const sessions = new ConnectSessions({registry, stores, providerApps, origin, appSetting, tenantApps, request, runtimes, usage});
  const accounts = new TenantAccounts({stores, registry, providerApps, adapterFor: (scope, providerId, providerApp) => sessions.adapterFor(scope, providerId, providerApp)});
  const users = new ExternalUsers({stores, registry, accounts});
  const pages = new TenantAppPages({stores, registry, providerApps, accounts, origin, appSetting, runtimes});
  const executions = new TenantExecutions({stores, registry, accounts, runtimes, usage, sessions});
  // A held execution resumes when its person confirms an account on Fabric's page (F03.9d).
  sessions.resumeHold = (scope, session, accountRef) => executions.resumeHold(scope, session, accountRef);
  // Agents' calls are projected and counted exactly like the developer's own.
  runtimes.executions = executions; runtimes.usage = usage;
  const options = new TenantOptions({stores, registry, accounts, runtimes, providerApps, appSetting});
  const approvals = new TenantApprovals({runtimes, accounts, registry, executions});
  const activity = new TenantActivity({runtimes, accounts, registry, approvals});
  const agentTokens = new TenantAgentTokens({runtimes, accounts, registry, executions});
  const hosted = new TenantHostedPages({sessions, pages, accounts, approvals, activity, stores, registry});
  api = new TenantApi({registry, keys, catalog, origin, providerApps, sessions, users, accounts, pages, executions, options, approvals, activity, agentTokens, runtimes});
  // Every minute: erase accounts left on a confirm screen that ended (section 6.2 step 8). Never keeps the process alive.
  // F10.21: and every open environment's Slack data past its 24 hours (lib/retention.mjs).
  const sweeper = setInterval(() => { sessions.sweep().catch(() => {}); try { runtimes.sweepOpen(); } catch {} }, 60_000); sweeper.unref();
  return {server, port: bound, origin, registry, keys, stores, providerApps, sessions, users, accounts, pages, runtimes, executions, approvals, agentTokens, usage, hosted,
    async close() { if (closed) return; closed = true; clearInterval(sweeper); await new Promise(resolve => server.close(resolve)); await runtimes.drain(); await sessions.settled(); stores.closeAll(); catalog?.close(); registry.close(); }};
}

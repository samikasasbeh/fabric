// Shared by the hosted pages (F03.10): which Fabric a page talks to. On the owner's own computer the pages read
// /api/ui with the workspace session and its CSRF token. Opened from a developer's Connect link
// (/connect/<session>/...), the same pages read that link's own API under /connect/<session>/v1, with the CSRF value
// from its view, and show the developer's name and colours. Pure: nothing here runs on import.

const enc = encodeURIComponent;
const SESSION = /^\/connect\/(cs_[a-z2-7]{26})(?:\/|$)/;

const OWNER = Object.freeze({
  tenant: false, catalog: '/connectors', app: id => `/connectors/${enc(id)}`, activity: '/activity',
  catalogApi: '/api/ui/catalog', appApi: id => `/api/ui/apps/${enc(id)}`, activityApi: '/api/ui/activity', approvalApi: id => `/api/ui/approvals/${enc(id)}`,
  accountPath: (appId, ref) => `/api/ui/apps/${enc(appId)}/accounts/${enc(ref)}`, icon: /^\/api\/icons\/[A-Za-z0-9%._~-]+$/,
});

/** The base for a page path: a Connect link's own pages and API, or the owner's (also for anything malformed, which then fails closed). */
export function baseFor(pathname) {
  const match = SESSION.exec(String(pathname ?? ''));
  if (!match) return OWNER;
  const root = `/connect/${match[1]}`, api = `${root}/v1`;
  return Object.freeze({
    tenant: true, sessionId: match[1], catalog: `${root}/apps`, app: id => `${root}/apps/${enc(id)}`, activity: `${root}/activity`,
    catalogApi: `${api}/catalog`, appApi: id => `${api}/apps/${enc(id)}`, activityApi: `${api}/activity`, approvalApi: () => `${api}/approval`,
    accountPath: (appId, ref) => `${api}/apps/${enc(appId)}/accounts/${enc(ref)}`, view: `${api}/view`, close: `${api}/close`,
    icon: /^\/assets\/icons\/[a-z][a-z0-9-]{0,63}$/,
  });
}

/**
 * An error body from either Fabric: {error: {code, message, details?}} from a Connect link, {error, code, ...} from the owner's.
 * F10.4: a confirm keeps what it is about, the upgrade card or the other accounts a disconnect signs out (and what it affected),
 * only in the fixed shapes Fabric sends.
 */
export function errorOf(data, status) {
  const error = data?.error;
  const message = typeof error === 'string' ? error : typeof error?.message === 'string' ? error.message : `Request failed (${status})`;
  const code = typeof error?.code === 'string' ? error.code : typeof data?.code === 'string' ? data.code : null;
  const details = error?.details && typeof error.details === 'object' ? error.details : data ?? {}, upgrade = details.upgrade;
  return Object.assign(new Error(message), {code, view: data?.view, ...(Array.isArray(upgrade?.rows) && typeof upgrade.etag === 'string' ? {upgrade: {rows: upgrade.rows, etag: upgrade.etag}} : {}),
    ...(Array.isArray(details.siblings) ? {siblings: details.siblings} : {}), ...(Array.isArray(details.affected) ? {affected: details.affected} : {})});
}

/** T7 (F10.4): what confirming an upgrade card means, in the words every owner page uses. */
export function cardText(card) {
  return `After this sign-in the agent can do these without asking you first: ${card.rows.map(row => row.label).join(', ')}. Anything you set to Allow before asks you again, and anything set to Never stays off.`;
}

/**
 * The page's request function for a base. Owner: the workspace session and CSRF token, refreshed once on a 403. A
 * Connect link: the CSRF value its view returned, held in page memory only; there is no workspace session to refresh.
 */
export function makeApi(base, fetcher) {
  let session = null, csrf = null;
  const send = async (path, body) => {
    const headers = body === undefined ? {} : {'Content-Type': 'application/json', 'X-Fabric-CSRF': (base.tenant ? csrf : session?.csrfToken) || ''};
    const response = await fetcher(path, {method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', headers, body: body === undefined ? undefined : JSON.stringify(body)});
    let data = {};
    try { data = await response.json(); } catch {}
    return {response, data};
  };
  const api = async (path, body) => {
    let {response, data} = await send(path, body);
    if (!base.tenant && response.status === 403 && body !== undefined) { session = await api('/api/state'); ({response, data} = await send(path, body)); }
    if (!response.ok) throw errorOf(data, response.status);
    if (base.tenant && typeof data?.csrf === 'string') csrf = data.csrf;
    return data;
  };
  /** Owner: the workspace session (with settings). Connect link: the link's view (developer, purpose, state, CSRF). */
  api.start = async () => base.tenant ? api(base.view) : (session = await api('/api/state'));
  api.session = () => session;
  return api;
}

/**
 * A developer's colours on a Connect link's pages: only Fabric's named custom properties, only #rrggbb values, set
 * through the CSS object model (never markup); the dark set applies while the system is dark.
 */
export const BRAND_PROPERTIES = new Set(['--surface', '--surface-raised', '--ink', '--muted', '--line', '--accent', '--on-accent', '--danger', '--attention']);
export function applyBrand(brand, {root, media} = {}) {
  if (!brand || typeof brand !== 'object' || !root) return;
  const paint = () => {
    for (const name of BRAND_PROPERTIES) root.style.removeProperty(name);
    const set = media?.matches ? brand.dark : brand.light;
    for (const [name, value] of Object.entries(set && typeof set === 'object' ? set : {})) if (BRAND_PROPERTIES.has(name) && /^#[0-9a-f]{6}$/.test(value)) root.style.setProperty(name, value);
  };
  paint(); media?.addEventListener?.('change', paint);
}

/**
 * Section 6.6: tells the developer's popup that opened this link how it ended, at the session's own opener origin only
 * (never '*'), with the message Fabric built. Returns true when it was told, so the page closes instead of navigating.
 */
export function tellOpener(result, opener) {
  if (!result?.opener || typeof result.opener.origin !== 'string' || !opener || opener.closed) return false;
  try { opener.postMessage(result.opener.message, result.opener.origin); return true; } catch { return false; }
}

/** Done on a Connect link: the link ends; a popup tells its opener and closes, a full page goes back to the developer's app. */
export async function finish(api, base, {assign, opener = null, close = () => {}}) {
  const result = await api(base.close, {});
  if (tellOpener(result, opener)) close();
  else if (result?.redirect) assign(result.redirect);
  return result;
}

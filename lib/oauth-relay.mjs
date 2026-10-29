// Callback relay (docs/AUTH-ENGINE.md). Providers that refuse loopback callbacks (Notion, Slack) send the browser to
// <base>/oauth/<provider>/<port>/callback; the static page in relay/index.html sends it straight back to
// http://127.0.0.1:<port>/api/oauth/<provider>/callback, where the flow cookie and state are checked as usual.
// The page forwards only the ports below, so Fabric offers relayed sign-in only on them.

export const RELAY_PORTS = Object.freeze([4188, 4320]);
export const RELAY_VARIABLE = 'FABRIC_PUBLIC_CALLBACK_BASE';

/** A provider is relayed only when its reviewed definition says it refuses plain-HTTP loopback callbacks. */
export function relayed(definition) { return definition?.authorization?.loopbackRedirect === 'https-required'; }

/**
 * The relay base must be a public HTTPS origin without a path. Returns its origin, or null when unset.
 * @param {unknown} value
 * @returns {string | null}
 */
export function relayOrigin(value) {
  if (value === undefined || value === null || value === '') return null;
  const refuse = rule => { throw new Error(`${RELAY_VARIABLE} must be ${rule}.`); };
  if (typeof value !== 'string' || value !== value.trim() || !value) refuse('a public HTTPS origin such as https://connect.example.com, without spaces');
  let url;
  try { url = new URL(value); } catch { refuse('a valid URL such as https://connect.example.com'); }
  if (url.protocol !== 'https:') refuse('an HTTPS origin');
  if (url.username || url.password || url.pathname !== '/' || url.search || url.hash || value.endsWith('?') || value.endsWith('#')) refuse('an origin without credentials, a path, a query or a fragment');
  if (url.port === '0') refuse('an origin on a usable port');
  const host = url.hostname;
  if (host.endsWith('.') || host === 'localhost' || host.endsWith('.localhost') || /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(':')) refuse('a public hostname, not an IP address, localhost or a name ending in a dot');
  return url.origin;
}

/** @param {string} base @param {string} providerId @param {number} port */
export function relayRedirect(base, providerId, port) { return `${base}/oauth/${providerId}/${port}/callback`; }

/** The developer runtime's port, where the page sends a developer's own app's sign-ins (F03.8, D2). */
export const RELAY_APPS_PORT = 4340;
/** @param {string} base @param {string} providerId @param {string} providerAppId */
export function relayAppRedirect(base, providerId, providerAppId) { return `${base}/oauth/${providerId}/apps/${providerAppId}/callback`; }

/** Shown when a relay is set but this Fabric listens on a port the relay page does not forward. */
export function relayPortHelp(port, ports = RELAY_PORTS) {
  return `The callback relay forwards only Fabric ports ${ports.join(' and ')}, and this Fabric runs on port ${port}. Set FABRIC_PORT to one of them.`;
}

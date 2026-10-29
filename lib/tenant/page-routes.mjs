// The Connect page's own API (docs/F03-DEVELOPER-LAYER.md section 5.13) and the other browser-facing routes, as data:
// the developer server routes from these lists, and the tests pin them and walk every entry (the isolation matrix, the
// credential checks), so a new route cannot appear without a row.

/** Every action under /connect/<sessionId>/v1/. Reads are GET; every other action is a POST from Fabric's own page. */
export const PAGE_ACTIONS = Object.freeze([
  ['POST', 'claim'], ['GET', 'view'], ['POST', 'start'], ['POST', 'confirm'], ['POST', 'close'], ['POST', 'reject'], ['POST', 'select'], ['POST', 'decline'],
  ['GET', 'catalog'], ['GET', 'activity'], ['GET', 'approval'], ['GET', 'apps/:appId'],
  ['POST', 'apps/:appId/accounts/:accountRef/permissions'], ['POST', 'apps/:appId/accounts/:accountRef/reset'],
  ['POST', 'apps/:appId/accounts/:accountRef/background'], ['POST', 'apps/:appId/accounts/:accountRef/disconnect'],
  ['POST', 'approvals/:callRef/decision'],
].map(([method, action]) => Object.freeze({method, action})));

const PARAMS = {':appId': '[a-z][a-z0-9-]{0,63}', ':accountRef': '[0-9a-f-]{36}', ':callRef': '[0-9a-f-]{36}'};
const pattern = action => action.replace(/:[A-Za-z]+/g, name => PARAMS[name]);
const EXACT = PAGE_ACTIONS.map(entry => ({entry, test: new RegExp(`^${pattern(entry.action)}$`)}));

/** /connect/<sessionId>/v1/<action> for a listed action: [, sessionId, action]. */
export const PAGE_API = new RegExp(`^/connect/(cs_[a-z2-7]{26})/v1/(${PAGE_ACTIONS.map(({action}) => `(?:${pattern(action)})`).join('|')})$`);

/** The listed action a matched action path is, or null. */
export function pageActionOf(action) { return EXACT.find(({test}) => test.test(action))?.entry ?? null; }

/** The provider's way back after sign-in: Fabric's shared apps, and a developer's own app (F03.8). */
export const CALLBACK_ROUTES = Object.freeze(['GET /api/oauth/:providerId/callback', 'GET /api/oauth/:providerId/apps/:providerAppId/callback']);

/** The one agent endpoint (fabric/0.1); its methods are tenantAgentManifest.methods. */
export const AGENT_ROUTE = 'POST /fabric/v1';

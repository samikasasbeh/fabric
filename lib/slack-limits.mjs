// F10.21 part 1 d (docs/F10.21-BUILD-MAP.md part 1 d; spec lines 1213-1218 and section 5.5): how Fabric's Slack app is installed, from the
// operator flag FABRIC_SLACK_DISTRIBUTION, read once at start by server.mjs and developer-server.mjs and passed to every runtime:
//   internal      the default: installed only in its own workspace (owner decision 10); Slack's normal limits
//   distributed   installed in other workspaces outside the Slack Marketplace: Slack allows conversations.history and conversations.replies
//                 one request a minute in each workspace, 15 messages each, so Fabric holds itself to that before sending and says so
//   marketplace   approved for the Marketplace: Slack's normal limits
// A refusal is Fabric's own limit: code rate_limited (as F10.11 keeps it), a reason, retryAfterSeconds when a minute is running, fixed
// words, and nothing sent. The minute is kept in memory on the runtime, keyed <workspaceId>:<method>, as the write locks are.
export const DISTRIBUTIONS = Object.freeze(['internal', 'distributed', 'marketplace']);
/** The Slack methods Slack paces for a distributed app. */
export const PACED = Object.freeze(['conversations.history', 'conversations.replies']);
export const PACE_MS = 60_000;
export const PAGE_LIMIT = 15;
export const DISTRIBUTION_WORDS = 'FABRIC_SLACK_DISTRIBUTION must be internal, distributed or marketplace.';
/** The one line Slack's app page adds under distributed (lib/app-detail.mjs). */
export const DISTRIBUTED_LINE = 'Slack limits this app to one history or thread read a minute in each workspace, 15 messages each, because it is distributed outside the Slack Marketplace.';
export const PACE_WORDS = Object.freeze({
  slack_pace: 'Slack allows this app one history or thread read a minute in each workspace. Nothing was sent: ask again in a minute.',
  slack_page_limit: 'Slack allows this app at most 15 messages in each history or thread read. Nothing was sent: ask for 15 or fewer.',
});

/** A checked distribution, or the fixed words as an Error. */
export function checkDistribution(value) {
  if (!DISTRIBUTIONS.includes(value)) throw new Error(DISTRIBUTION_WORDS);
  return value;
}
/** The operator's setting, internal when it is not set. Any other value, an empty one included, stops the server before any state opens. */
export const distributionOf = (env = process.env) => env.FABRIC_SLACK_DISTRIBUTION === undefined ? 'internal' : checkDistribution(env.FABRIC_SLACK_DISTRIBUTION);
/** The lines a distribution adds to an app page's limitations. */
export const limitationsFor = (appId, distribution) => appId === 'slack' && distribution === 'distributed' ? [DISTRIBUTED_LINE] : [];

/** The `limit` one request asks for: from the query of a GET, from the JSON body of a POST; null when it names none. */
function limitOf(url, body) {
  if (url.searchParams.has('limit')) return url.searchParams.get('limit');
  try { const parsed = typeof body === 'string' ? JSON.parse(body) : null; return parsed !== null && typeof parsed === 'object' && Object.hasOwn(parsed, 'limit') ? parsed.limit : null; }
  catch { return null; }
}

/**
 * Right before a request is sent: null when it may go, else the refusal {code: 'rate_limited', reason, retryAfterSeconds?, words}. Only a
 * Slack account of a runtime whose distribution is `distributed` is ever paced, and only conversations.history and conversations.replies:
 * a limit above 15, or none, is refused (slack_page_limit) before the minute is looked at; then a second request of the same method in
 * the same workspace within 60 seconds is refused (slack_pace). A request that may go takes the minute.
 */
export function paceCheck(runtime, connection, request) {
  if (runtime?.slackDistribution !== 'distributed' || connection?.appId !== 'slack') return null;
  let url;
  try { url = new URL(request.url); } catch { return null; }
  const method = url.pathname.split('/').pop();
  if (!PACED.includes(method)) return null;
  const limit = limitOf(url, request.body), size = typeof limit === 'number' ? limit : typeof limit === 'string' && /^[0-9]{1,6}$/.test(limit) ? Number(limit) : NaN;
  if (!(Number.isSafeInteger(size) && size >= 1 && size <= PAGE_LIMIT)) return {code: 'rate_limited', reason: 'slack_page_limit', words: PACE_WORDS.slack_page_limit};
  const workspace = typeof connection.identity?.workspaceId === 'string' && connection.identity.workspaceId ? connection.identity.workspaceId : String(connection.identity?.id ?? connection.id).split(':')[0];
  const key = `${workspace}:${method}`, now = runtime.clock(), last = runtime.slackPace.get(key);
  if (last !== undefined && now - last < PACE_MS) return {code: 'rate_limited', reason: 'slack_pace', retryAfterSeconds: Math.ceil((last + PACE_MS - now) / 1000), words: PACE_WORDS.slack_pace};
  runtime.slackPace.set(key, now);
  return null;
}

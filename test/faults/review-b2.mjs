// Seeded faults for the security review fixes of group b2 (Connect sessions and sign-in), Iteration 8 step 11. Same
// shape as test/faults/registry.mjs: `from` is copied exactly from the current file and occurs there once; `to` is the
// faulty replacement that test/review-b2.test.mjs must catch. Data only: nothing here reads or changes a file.

const TESTS = ['test/review-b2.test.mjs'];
const SAME = "const same = env.repository.list('connections').find(other => other.id !== pending.id && other.appId === pending.appId && present(other) && other.identity?.id === pending.identity?.id && sameApp(appOf(other), appOf(pending)) && ownedBy(other, owner, deployment));";
const READY = SAME.replace('present(other)', "other.status === 'ready'");

export const FAULTS = Object.freeze([
  // b2-secrets-1-confirm-revoke and b2-signin-2-widens held the T7 refusal F10.4 lifts (F10.4 build map, correction 2): a wider
  // sign-in now waits at the upgrade card, and closing the link drops it through #drop, which b2-signin-1-drop holds.
  {id: 'b2-rob-3-reject-finished', step: 'F03.11', name: '"Not this account" writes the link back as opened after a cancel landed during its await (ROB-3).',
    file: 'lib/tenant/connect-sessions.mjs', from: "if (!fresh || fresh.state !== 'awaiting_confirmation' || fresh.pendingAccountRef !== session.pendingAccountRef) return {state: fresh ? this.#state(fresh) : 'expired'};",
    to: '/* seeded: reject reopens a finished link */', tests: TESTS},
  {id: 'b2-signin-1-drop', step: 'F03.11', name: 'Dropping a waiting account revokes a token a live account still holds (SIGNIN-1).',
    file: 'lib/tenant/connect-sessions.mjs', from: "adapter.revocationCovers() === 'grant' || this.providerApps.tokenHeldElsewhere(env, stored) ? {remote: false} : {}",
    to: "adapter.revocationCovers() === 'grant' ? {remote: false} : {}", note: 'F10.4: re-copied onto #drop, which also keeps every grant-wide revoke local (f104-auto-grant-revoke).',
    tests: [...TESTS, 'test/tenant-renewal-upgrade.test.mjs']},
  {id: 'b2-signin-1-replaced', step: 'F03.11', name: 'The revoke after a confirm sends a token a live account still holds (SIGNIN-1).',
    file: 'lib/tenant/connect-sessions.mjs', from: 'if (this.providerApps.tokenHeldElsewhere(env, account, tokens)) return;', to: '/* seeded: no shared-token check */', tests: TESTS},
  {id: 'b2-signin-1-disconnect', step: 'F03.11', name: 'Disconnecting an account revokes a token another account still holds (SIGNIN-1).',
    file: 'lib/tenant/accounts.mjs', from: '{remote: this.providerApps.tokenHeldElsewhere(env, connection) ? false : remote}', to: '{remote}', tests: TESTS},
  {id: 'b2-signin-1-self', step: 'F03.11', name: 'The shared-token check counts the account being dropped as another holder, so nothing is ever revoked (SIGNIN-1).',
    file: 'lib/tenant/provider-apps.mjs', from: "other.id !== record.id && other.status !== 'revoked'", to: "other.status !== 'revoked'", tests: TESTS},
  {id: 'b2-signin-2-merge', step: 'F03.11', name: 'The same-identity merge at confirm sees only ready accounts, so a reconnect makes a second row (SIGNIN-2).',
    file: 'lib/tenant/connect-sessions.mjs', from: `${SAME}\n    if (!same) return {same: null, kind: 'connected'};`, to: `${READY}\n    if (!same) return {same: null, kind: 'connected'};`,
    note: 'F10.4: the merge and the renewal or upgrade choice share one lookup (#classify).', tests: [...TESTS, 'test/tenant-renewal-upgrade.test.mjs']},
  {id: 'b2-signin-3-notion', step: 'F03.11', name: 'Fabric\'s shared Notion app reads ready although no runtime can sign anyone in through it (SIGNIN-3).',
    file: 'lib/tenant/provider-apps.mjs', from: 'if (relayed(this.definitions(providerId))) return', to: 'if (false) return', tests: TESTS},
  {id: 'b2-signin-4-cap', step: 'F03.11', name: 'A link starts sign-ins without limit (SIGNIN-4).',
    file: 'lib/tenant/connect-sessions.mjs', from: "if (starts >= START_LIMIT) throw new SessionError(429, 'rate_limited',", to: "if (false) throw new SessionError(429, 'rate_limited',", tests: TESTS},
  {id: 'b2-signin-4-one-flow', step: 'F03.11', name: 'A new sign-in leaves the link\'s earlier flow and its registry route alive (SIGNIN-4).',
    file: 'lib/tenant/connect-sessions.mjs', from: "if (typeof session.flowRouteId === 'string') {", to: 'if (false) {', tests: TESTS},
  {id: 'b2-iso-5-sweep-links', step: 'F03.11', name: 'The minute sweep leaves expired link routes in the registry (ISO-5, ROB-6).',
    file: 'lib/tenant/connect-sessions.mjs', from: "for (const route of routes) if (!route.pendingSince && ended(route)) this.registry.removeRoute('sessionRoutes', route.id);", to: '/* seeded: no link route pruning */', tests: TESTS},
  {id: 'b2-rob-6-sweep-flows', step: 'F03.11', name: 'The minute sweep leaves expired sign-in routes in the registry (SIGNIN-4, ROB-6).',
    file: 'lib/tenant/connect-sessions.mjs', from: "for (const route of this.registry.list('flowRoutes')) if (ended(route)) this.registry.removeRoute('flowRoutes', route.id);", to: '/* seeded: no flow route pruning */', tests: TESTS},
  {id: 'b2-iso-5-unclaimed', step: 'F03.11', name: 'A link that ends before anyone opened it keeps its registry route (ISO-5, agent-3).',
    file: 'lib/tenant/connect-sessions.mjs', from: "#unrouteUnclaimed(session) { if (!session.claimedAt) this.registry.removeRoute('sessionRoutes', session.id); }", to: '#unrouteUnclaimed(session) { void session; }', tests: TESTS},
  {id: 'b2-authz-4-link-oracle', step: 'F03.11', name: 'POST /link tells a key that may not read sessions which ids exist (authz-4).',
    file: 'lib/tenant/connect-sessions.mjs', from: "if (!caller.scopes.includes('connect:write')) throw notFound();", to: '/* seeded: 403 for a known id, 404 for an unknown one */', tests: TESTS},
  {id: 'b2-brw-2-claim-reset', step: 'F03.11', name: 'A claim keeps a session cookie planted on a wider path, so every later request is refused (BRW-2).',
    file: 'developer-server.mjs', from: 'const resets = PAGE_COOKIES.some(name => cookies.has(name)) ?', to: 'const resets = false ?', tests: TESTS},
  {id: 'b2-brw-2-page-reset', step: 'F03.11', name: 'A page request refused for a duplicated cookie never expires the planted copy (BRW-2).',
    file: 'developer-server.mjs', from: "{'Set-Cookie': plantedCookieResets(url.pathname, PAGE_COOKIES, ", to: "{'X-Seeded': plantedCookieResets(url.pathname, PAGE_COOKIES, ", tests: TESTS},
  {id: 'b2-brw-2-flow-reset', step: 'F03.11', name: 'A callback refused for a duplicated flow cookie never expires the planted copy (BRW-2).',
    file: 'developer-server.mjs', from: "{'Set-Cookie': plantedCookieResets(callbackPath, FLOW_COOKIES, callbackPath)}", to: '{}', tests: TESTS},
  {id: 'b2-brw-2-own-path', step: 'F03.11', name: 'The resets expire Fabric\'s own cookie too (BRW-2).',
    file: 'developer-server.mjs', from: 'paths.filter(item => item !== ownPath)', to: 'paths', tests: TESTS},
  {id: 'b2-brw-2-other-cookies', step: 'F03.11', name: 'Another local app\'s nameless or repeated cookie blocks every Connect request (BRW-2).',
    file: 'developer-server.mjs', from: 'if (names && !names.includes(name)) continue;', to: '/* seeded: every cookie checked */', tests: TESTS},
  {id: 'b2-callback-code', step: 'F03.11', name: 'The sign-in callback echoes an internal error code to the browser.',
    file: 'developer-server.mjs', from: "return send(res, 400, {error: {code: 'invalid_state', message: INVALID_STATE}});", to: "return send(res, 400, {error: {code: error?.code || 'invalid_state', message: INVALID_STATE}});", tests: TESTS},
]);

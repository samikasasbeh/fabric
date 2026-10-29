// The security review of the developer layer (docs/F03-SECURITY-REVIEW.md), group a: agents and executions. One
// seeded fault per fix, each caught by test/review-a.test.mjs. Same entry shape as test/faults/registry.mjs: `from` is
// copied exactly from the current file and occurs there once; `to` is the faulty replacement. Data only.

const TESTS = ['test/review-a.test.mjs'];

export const FAULTS = Object.freeze([
  // agent-1 and GOV-1: the developer's app switch holds for agents, and at dispatch for every job.
  {id: 'review-a-app-off-at-dispatch', step: 'F03.11', name: 'authorizeJob ignores the app switch, so a call accepted before the app was turned off still runs.',
    file: 'lib/tenant/agent-protocol.mjs', from: "if (typeof appId === 'string' && this.#appOff(appId)) fail('app_disabled', APP_OFF);", to: '/* seeded: app switch ignored at dispatch */', tests: TESTS},
  {id: 'review-a-app-off-listing', step: 'F03.11', name: 'capabilities.list shows a turned-off app\'s operations as available.',
    file: 'lib/tenant/agent-protocol.mjs', from: "if (this.#appOff(cap.appId)) return {...base, status: 'unavailable', reason: 'app_disabled'};",
    to: '/* seeded: app switch not listed */', tests: TESTS},
  {id: 'review-a-agent-status', step: 'F03.11', name: 'agentStatus answers app_disabled as 400.',
    file: 'lib/tenant/agent-protocol.mjs', from: 'not_available: 422, app_disabled: 422, rate_limited: 429', to: 'not_available: 422, rate_limited: 429', tests: TESTS},
  // agent-2 and ROB-4: an agent's proxied requests keep the developer's limits, per token.
  {id: 'review-a-agent-proxy-rate', step: 'F03.11', name: 'An agent\'s proxied requests are evaluated past 60 refusals a minute.',
    file: 'lib/tenant/agent-protocol.mjs', from: "if (limited) fail('rate_limited', 'Too many refused proxied requests. Wait a minute before trying again.');", to: '/* seeded: no refusal window for agents */', tests: TESTS},
  {id: 'review-a-agent-proxy-pending', step: 'F03.11', name: 'An agent may leave any number of proxied requests waiting for approval.',
    file: 'lib/tenant/agent-protocol.mjs', from: "if (this.executions.pendingFull(this.env, {proxy: true, owner, from: source => source?.kind === 'client' && source.clientId === grant.id}))",
    to: 'if (false)', tests: TESTS},
  {id: 'review-a-agent-proxy-uncounted', step: 'F03.11', name: 'An agent\'s refused proxied requests are not counted.',
    file: 'lib/tenant/agent-protocol.mjs', from: 'try { decision = this.runtime.proxyPolicy.decide(accountRef, params.request, options); } catch (error) { throw refused(this.#coded(error)); }',
    to: 'try { decision = this.runtime.proxyPolicy.decide(accountRef, params.request, options); } catch (error) { throw this.#coded(error); }', tests: TESTS},
  // ROB-5: waiting approvals capped per requester, and a person's records read through their index.
  {id: 'review-a-agent-typed-pending', step: 'F03.11', name: 'An agent may leave any number of typed calls waiting for approval.',
    file: 'lib/tenant/agent-protocol.mjs', from: "if (waits && this.executions.pendingFull(this.env, {proxy: false, owner, from: source => source?.kind === 'client' && source.clientId === grant.id}))",
    to: 'if (false)', tests: TESTS},
  {id: 'review-a-key-typed-pending', step: 'F03.11', name: 'A key may leave any number of typed calls waiting for one person\'s approval.',
    file: 'lib/tenant/executions.mjs', from: "if (waits && this.pendingFull(env, {proxy: false, owner, from: source => source?.kind === 'service' && source.serviceClientId === caller.serviceClientId}))",
    to: 'if (false)', tests: TESTS},
  {id: 'review-a-approvals-scan', step: 'F03.11', name: 'A person\'s approvals parse every job in the environment.',
    file: 'lib/tenant/approvals.mjs', from: "(jobs ?? env.repository.listWhere('jobs', 'userRecordId', owner.userRecordId))", to: "(jobs ?? env.repository.list('jobs'))", tests: TESTS},
  {id: 'review-a-activity-scan', step: 'F03.11', name: 'A person\'s activity parses every job in the environment.',
    file: 'lib/tenant/activity.mjs', from: "const theirs = env.repository.listWhere('jobs', 'userRecordId', owner.userRecordId)", to: "const theirs = env.repository.list('jobs')", tests: TESTS},
  {id: 'review-a-holds-scan', step: 'F03.11', name: 'Counting a requester\'s waiting holds parses every hold in the environment.',
    file: 'lib/tenant/executions.mjs', from: "env.repository.listWhere('continuations', 'status', 'waiting').filter(item => item?.kind === 'hold' &&",
    to: "env.repository.list('continuations').filter(item => item?.kind === 'hold' && item.status === 'waiting' &&", tests: TESTS},
  // agent-3: account requests limited per token per hour; a closed request leaves no route.
  {id: 'review-a-asks-an-hour', step: 'F03.11', name: 'An agent may make and withdraw account requests without limit.',
    file: 'lib/tenant/agent-protocol.mjs', from: "if (this.executions.asksFull(this.env, owner, mine)) fail('rate_limited', 'Too many account requests in the last hour. Wait before asking again.');",
    to: '/* seeded: no hourly limit */', tests: TESTS},
  {id: 'review-a-hold-route-kept', step: 'F03.11', name: 'A closed account request keeps its link route in the shared registry.',
    file: 'lib/tenant/executions.mjs', from: "if (!env.repository.get('connectSessions', sessionId)?.claimedAt) this.registry.removeRoute('sessionRoutes', sessionId);", to: '/* seeded: route kept */', tests: TESTS},
  // agent-4 and authz-3: a requester that lost its authority closes its waiting requests; no link, nothing runs.
  {id: 'review-a-token-status-route', step: 'F03.11', name: 'The token list ignores a route revoked with its key.',
    file: 'lib/tenant/agent-tokens.mjs', from: "if (this.registry.get('agentTokenRoutes', grant.id)?.revokedAt) return 'revoked';", to: '/* seeded: route not read */', tests: TESTS},
  {id: 'review-a-agent-hold-kept', step: 'F03.11', name: 'An account request whose agent token was revoked or expired keeps waiting.',
    file: 'lib/tenant/executions.mjs', from: "try { this.runtimes.bundle(scope).agents.activeGrant(source.clientId); return null; } catch { return 'agent_revoked'; }", to: 'return null;', tests: TESTS},
  {id: 'review-a-key-hold-kept', step: 'F03.11', name: 'A held call whose key was revoked keeps waiting and runs when the person connects.',
    file: 'lib/tenant/executions.mjs', from: "return active && client?.status === 'active' && client.id === source.serviceClientId ? null : 'key_revoked';", to: 'return null;', tests: TESTS},
  {id: 'review-a-resume-unchecked', step: 'F03.11', name: 'Resuming a held call does not check that its requester can still ask.',
    file: 'lib/tenant/executions.mjs', from: 'const gone = this.#requesterGone(scope, hold);\n      if (gone) return close(gone);', to: '/* seeded: requester not checked on resume */', tests: TESTS},
  {id: 'review-a-link-for-dead-hold', step: 'F03.11', name: '/link mints a link for a held call whose requester is gone.',
    file: 'lib/tenant/connect-sessions.mjs', from: "if (session.purpose === 'handoff' && this.runtimes.executions && !this.runtimes.executions.handoffWaiting(caller.scope, session)) throw new SessionError(409, 'already_finished', 'This session has already finished.');",
    to: '/* seeded: no hold check on link */', tests: TESTS},
  // agent-5: the MCP adapter accepts a resumed account request's replay and a hold that is resuming.
  {id: 'review-a-mcp-resumed-replay', step: 'F03.11', name: 'The MCP adapter rejects the replay of an account request that resumed.',
    file: 'lib/mcp-adapter.mts', from: 'const requested=handoff?handoff.appId===input.appId:value.appId===input.appId;', to: 'const requested=handoff?.appId===input.appId;', tests: TESTS},
  {id: 'review-a-mcp-queued-hold', step: 'F03.11', name: 'The MCP adapter rejects a held call while it resumes (queued, no account yet).',
    file: 'lib/mcp-adapter.mts', from: "['awaiting_connection','queued','cancelled','expired','failed']", to: "['awaiting_connection','cancelled','expired','failed']", tests: TESTS},
  // GOV-7: a replay of an accepted call answers the call.
  {id: 'review-a-replay-after-limit', step: 'F03.11', name: 'A replayed proxied request meets the pending limit before its replay.',
    file: 'lib/tenant/executions.mjs', from: '    // A replay of an accepted request answers that request, never a limit or the app switch, and is never counted.\n',
    to: "    if (this.pendingFull(env, {proxy: true, from: source => source?.kind === 'service' && source.serviceClientId === caller.serviceClientId})) throw new TenantError(429, 'pending_limit', 'Seeded.');\n", tests: TESTS},
  {id: 'review-a-replay-after-switch', step: 'F03.11', name: 'A replayed execution meets the app switch before its replay.',
    file: 'lib/tenant/executions.mjs', from: '    // Then the Idempotency-Key (after scope and ownership), keyed by environment, service client, route and key. A\n',
    to: '    this.#turnedOff(caller, cap.appId);\n', tests: TESTS},
  // authz-1: a refused rotation changes nothing.
  {id: 'review-a-rotate-stamps-first', step: 'F03.11', name: 'A refused rotation has already set the current key to expire.',
    file: 'lib/tenant/keys.mjs', from: '    this.#roomFor(client);\n    const expiresAt', to: '    const expiresAt', tests: TESTS},
]);

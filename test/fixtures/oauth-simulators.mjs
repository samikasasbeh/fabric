// Independent simulations of each provider's documented OAuth behavior, written from
// the official documentation verified on 2026-10-11 (docs/AUTH-DEFINITIONS-RESEARCH.md).
// They deliberately do not read catalog/auth definitions: the conformance suite proves
// that a definition plus the engine satisfies the provider's rules, not that the
// definition agrees with itself. Behaviors the docs leave open are marked ASSUMPTION.
//
// Fault switches shared by every simulator, for negative conformance cases:
//   failIdentity  number of upcoming identity calls that return 502
//   failToken     one-shot {status,data} response from the token endpoint
//   expiring      issue expiring access tokens with refresh credentials
//   omitRotatedRefresh  refresh responses leave out refresh_token (rotating providers)
//   revokeFails   the revocation endpoint fails
//
// Partial grants (F10.5), the `grant` option of consent():
//   'all'          every scope asked for
//   other string   every scope asked for but the last
//   {omit, add}    the scopes asked for minus `omit` (each one asked for) plus `add` (a provider granting more, or a parent).
//                  Google's granular consent offers a box for every scope but the identity ones; a GitHub user may edit
//                  scopes and GitHub drops any scope another granted one implies; Slack lets a person decline only the
//                  scopes the app's manifest marks user_optional.
// Slack switches:
//   userOptional    the user scopes the manifest marks user_optional (a Set)
//   reuseUserToken  the code exchange returns the account's last user token again, carrying the union of its scopes
import { createHash, randomBytes } from 'node:crypto';

const s256 = value => createHash('sha256').update(value).digest('base64url');
const header = (req, name) => { for (const [key, value] of Object.entries(req.headers || {})) if (key.toLowerCase() === name) return value; return undefined; };
const bearer = req => { const value = header(req, 'authorization'); return typeof value === 'string' && value.startsWith('Bearer ') ? value.slice(7) : null; };
// GitHub (curl -u), Slack and Notion document plain base64(client_id:client_secret).
function basic(req) {
  const value = header(req, 'authorization');
  if (typeof value !== 'string' || !value.startsWith('Basic ')) return null;
  const decoded = Buffer.from(value.slice(6), 'base64').toString('utf8'), at = decoded.indexOf(':');
  return at < 0 ? null : { id: decoded.slice(0, at), secret: decoded.slice(at + 1) };
}
function body(req) {
  if (!req.body) return {};
  if (String(header(req, 'content-type')).startsWith('application/json')) return JSON.parse(req.body);
  return Object.fromEntries(new URLSearchParams(req.body));
}
const json = (status, data) => ({ status, data });
/** The scopes a consent grants of those asked; `declinable` throws for a scope the consent page offers no box for. */
function granted(asked, grant, declinable = () => {}) {
  if (grant === 'all') return [...asked];
  if (typeof grant === 'string') return asked.slice(0, -1);
  if (!grant || typeof grant !== 'object' || Array.isArray(grant) || Object.keys(grant).some(key => !['omit', 'add'].includes(key))) throw new Error('Simulator: grant is all, a string, or {omit, add}.');
  const { omit = [], add = [] } = grant;
  for (const scope of omit) { if (!asked.includes(scope)) throw new Error(`Simulator: ${scope} was not asked for.`); declinable(scope); }
  return [...new Set([...asked.filter(scope => !omit.includes(scope)), ...add])];
}

class Simulator {
  constructor({ clientId, clientSecret, clock, accounts }) {
    Object.assign(this, { clientId, clientSecret, clock, accounts });
    this.codes = new Map(); this.access = new Map(); this.refresh = new Map(); this.calls = [];
    this.expiring = false; this.revokeFails = false; this.counter = 0;
    this.failIdentity = 0; this.failToken = null; this.omitRotatedRefresh = false;
  }
  next(prefix) { return `${prefix}${++this.counter}-${randomBytes(6).toString('hex')}`; }
  /** Simulates the account holder at the provider's consent page. */
  consent(authorizationUrl, { account = 'a', grant = 'all', deny = false } = {}) {
    const url = new URL(authorizationUrl), params = Object.fromEntries(url.searchParams);
    const problem = this.checkAuthorize(url, params);
    if (problem) return { state: params.state, error: problem };
    if (deny) return { state: params.state, error: 'access_denied' };
    const code = this.next('code-');
    this.codes.set(code, { account, params, ...this.grant(params, grant), expiresAt: this.clock() + 600_000 });
    return { state: params.state, code };
  }
  grant(params, grant) { return { granted: this.grantedScopes(params, grant) }; }
  takeCode(code, redirectUri, verifier) {
    const entry = this.codes.get(code);
    this.codes.delete(code);
    if (!entry || entry.expiresAt <= this.clock()) return null;
    if (entry.params.redirect_uri !== redirectUri) return null;
    if (entry.params.code_challenge && (typeof verifier !== 'string' || s256(verifier) !== entry.params.code_challenge)) return null;
    if (!entry.params.code_challenge && verifier !== undefined) return { ...entry, unexpectedVerifier: true };
    return entry;
  }
  issue(account, scopes, { refreshable, extra = {} }) {
    const accessToken = this.next('access-'), refreshToken = refreshable ? this.next('refresh-') : undefined;
    this.access.set(accessToken, { account, scopes, expiresAt: this.expiring ? this.clock() + this.lifetime * 1000 : null, ...extra });
    if (refreshToken) this.refresh.set(refreshToken, { account, scopes, accessToken, ...extra });
    return { accessToken, refreshToken };
  }
  activeAccess(req) {
    const token = bearer(req), entry = token && this.access.get(token);
    if (!entry || (entry.expiresAt !== null && entry.expiresAt <= this.clock())) return null;
    return { token, ...entry };
  }
  /** Provider-side revocation of everything an account granted (user removes the app). */
  revokeAccount(account) {
    for (const [token, entry] of this.access) if (entry.account === account) this.access.delete(token);
    for (const [token, entry] of this.refresh) if (entry.account === account) this.refresh.delete(token);
  }
  identityOutage() { if (this.failIdentity > 0) { this.failIdentity--; return json(502, { message: 'Bad Gateway' }); } return null; }
  tokenFault() { const fault = this.failToken; this.failToken = null; return fault ? json(fault.status, fault.data) : null; }
  async request(req) { this.calls.push(req); return this.handle(req); }
}

// Google: developers.google.com/identity/protocols/oauth2/web-server and openid-connect.
export class GoogleSimulator extends Simulator {
  constructor(options) { super({ accounts: { a: { sub: 'google-sub-a', email: 'a@example.com', name: 'A' }, b: { sub: 'google-sub-b', email: 'b@example.com', name: 'B' } }, ...options }); this.expiring = true; this.lifetime = 3599; this.consented = new Set(); }
  checkAuthorize(url, p) {
    if (url.origin + url.pathname !== 'https://accounts.google.com/o/oauth2/v2/auth') return 'invalid_request';
    if (p.client_id !== this.clientId || p.response_type !== 'code' || !p.redirect_uri || !p.scope || !p.state) return 'invalid_request';
    if (p.code_challenge && p.code_challenge_method !== 'S256') return 'invalid_request';
    return null;
  }
  grantedScopes(p, grant) {
    return granted(p.scope.split(' '), grant, scope => { if (['openid', 'email', 'profile'].includes(scope)) throw new Error(`Google simulator: granular consent offers no box for ${scope}.`); });
  }
  handle(req) {
    if (req.url === 'https://oauth2.googleapis.com/token') {
      const fault = this.tokenFault(); if (fault) return fault;
      const f = body(req);
      if (String(header(req, 'content-type')) !== 'application/x-www-form-urlencoded') return json(400, { error: 'invalid_request' });
      if ((f.client_id ?? basic(req)?.id) !== this.clientId || (f.client_secret ?? basic(req)?.secret) !== this.clientSecret) return json(401, { error: 'invalid_client' });
      if (f.grant_type === 'authorization_code') {
        const entry = this.takeCode(f.code, f.redirect_uri, f.code_verifier);
        if (!entry) return json(400, { error: 'invalid_grant', error_description: 'Bad Request' });
        // A refresh token comes with offline access on first consent, or again only with prompt=consent.
        const refreshable = entry.params.access_type === 'offline' && (!this.consented.has(entry.account) || entry.params.prompt === 'consent');
        this.consented.add(entry.account);
        const issued = this.issue(entry.account, entry.granted, { refreshable });
        return json(200, { access_token: issued.accessToken, expires_in: this.lifetime, token_type: 'Bearer', scope: entry.granted.join(' '), ...(issued.refreshToken ? { refresh_token: issued.refreshToken } : {}) });
      }
      if (f.grant_type === 'refresh_token') {
        const entry = this.refresh.get(f.refresh_token);
        if (!entry) return json(400, { error: 'invalid_grant', error_description: 'Token has been expired or revoked.' });
        // Google keeps the refresh token; the response omits it.
        const accessToken = this.next('access-');
        this.access.set(accessToken, { account: entry.account, scopes: entry.scopes, expiresAt: this.clock() + this.lifetime * 1000 });
        return json(200, { access_token: accessToken, expires_in: this.lifetime, token_type: 'Bearer', scope: entry.scopes.join(' ') });
      }
      return json(400, { error: 'unsupported_grant_type' });
    }
    if (req.url === 'https://oauth2.googleapis.com/revoke') {
      if (this.revokeFails) return json(503, null);
      const token = body(req).token, entry = this.refresh.get(token) ?? this.access.get(token);
      if (!entry) return json(400, { error: 'invalid_token' });
      this.revokeAccount(entry.account);
      return json(200, {});
    }
    if (req.url === 'https://openidconnect.googleapis.com/v1/userinfo') {
      const outage = this.identityOutage(); if (outage) return outage;
      const active = this.activeAccess(req);
      if (!active) return json(401, { error: 'invalid_token' });
      const account = this.accounts[active.account];
      return json(200, { sub: account.sub, email: account.email, name: account.name });
    }
    const active = this.activeAccess(req);
    if (req.url.startsWith('https://www.googleapis.com/calendar/v3/')) return active?.scopes.some(s => s.includes('/auth/calendar')) ? json(200, { kind: 'calendar#calendarList' }) : json(active ? 403 : 401, { error: { code: 403 } });
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/')) return active?.scopes.some(s => s.includes('/auth/gmail') || s === 'https://mail.google.com/') ? json(200, { emailAddress: 'a@example.com' }) : json(active ? 403 : 401, { error: { code: 403 } });
    throw new Error(`Google simulator: unexpected endpoint ${req.url}`);
  }
}

// GitHub OAuth Apps: docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
const GITHUB_IMPLIED = Object.freeze({ user: ['read:user', 'user:email', 'user:follow'], repo: ['public_repo', 'repo:status', 'repo_deployment', 'repo:invite', 'security_events'], 'admin:org': ['write:org', 'read:org'], 'write:org': ['read:org'],
  'admin:repo_hook': ['write:repo_hook', 'read:repo_hook'] });
export class GitHubSimulator extends Simulator {
  constructor(options) { super({ accounts: { a: { id: 101, login: 'octo-a', name: 'Octo A' }, b: { id: 202, login: 'octo-b', name: null } }, ...options }); this.lifetime = 28800; }
  checkAuthorize(url, p) {
    if (url.origin + url.pathname !== 'https://github.com/login/oauth/authorize') return 'invalid_request';
    if (p.client_id !== this.clientId || !p.redirect_uri || !p.state) return 'invalid_request';
    // PKCE is S256 only, with a 43-character challenge.
    if (p.code_challenge && (p.code_challenge_method !== 'S256' || p.code_challenge.length !== 43)) return 'invalid_request';
    return null;
  }
  grantedScopes(p, grant) {
    const asked = (p.scope || '').split(' ').filter(Boolean);
    // GitHub normalizes scopes: a scope implied by another granted scope is dropped.
    const normalized = list => list.filter(scope => !list.some(other => other !== scope && (GITHUB_IMPLIED[other] || []).includes(scope)));
    if (typeof grant === 'string') return grant === 'all' ? normalized(asked) : normalized(asked).slice(0, -1);
    // The person edits the scopes before authorizing: any may be removed, and an added parent hides what it implies.
    return normalized(granted(asked, grant));
  }
  token(req, data) {
    // Without Accept: application/json the response is form-encoded text.
    if (!String(header(req, 'accept')).includes('application/json')) return json(200, new URLSearchParams(Object.entries(data).map(([k, v]) => [k, String(v)])).toString());
    return json(200, data);
  }
  handle(req) {
    if (req.url === 'https://github.com/login/oauth/access_token') {
      const fault = this.tokenFault(); if (fault) return fault;
      const f = body(req);
      if (f.client_id !== this.clientId || f.client_secret !== this.clientSecret) return this.token(req, { error: 'incorrect_client_credentials', error_description: 'The client_id and/or client_secret passed are incorrect.' });
      if (f.grant_type === 'refresh_token') {
        const entry = this.refresh.get(f.refresh_token);
        if (!entry) return this.token(req, { error: 'bad_refresh_token', error_description: 'The refresh token passed is incorrect or expired.' });
        // Single-use rotation: the old refresh token and old access token stop working.
        this.refresh.delete(f.refresh_token); this.access.delete(entry.accessToken);
        const issued = this.issue(entry.account, entry.scopes, { refreshable: !this.omitRotatedRefresh });
        return this.token(req, { access_token: issued.accessToken, token_type: 'bearer', scope: entry.scopes.join(','), expires_in: this.lifetime, ...(issued.refreshToken ? { refresh_token: issued.refreshToken, refresh_token_expires_in: 15897600 } : {}) });
      }
      const entry = this.takeCode(f.code, f.redirect_uri, f.code_verifier);
      if (!entry) return this.token(req, { error: 'bad_verification_code', error_description: 'The code passed is incorrect or expired.' });
      const issued = this.issue(entry.account, entry.granted, { refreshable: this.expiring });
      return this.token(req, { access_token: issued.accessToken, token_type: 'bearer', scope: entry.granted.join(','), ...(this.expiring ? { expires_in: this.lifetime, refresh_token: issued.refreshToken, refresh_token_expires_in: 15897600 } : {}) });
    }
    const revoke = /^https:\/\/api\.github\.com\/applications\/([^/]+)\/token$/.exec(req.url);
    if (revoke && req.method === 'DELETE') {
      if (this.revokeFails) return json(503, null);
      const creds = basic(req);
      if (!creds || creds.id !== this.clientId || creds.secret !== this.clientSecret || decodeURIComponent(revoke[1]) !== this.clientId) return json(404, { message: 'Not Found' });
      const token = body(req).access_token;
      if (!this.access.has(token)) return json(422, { message: 'Validation Failed' });
      this.access.delete(token);
      // ASSUMPTION: the docs do not say whether the paired refresh token survives a token revoke;
      // it is modeled as surviving, which is why the engine never claims the grant was removed.
      return json(204, null);
    }
    if (req.url === 'https://api.github.com/user') {
      if (!header(req, 'user-agent')) return json(403, { message: 'Request forbidden by administrative rules. Please make sure your request has a User-Agent header.' });
      const outage = this.identityOutage(); if (outage) return outage;
      const active = this.activeAccess(req);
      if (!active) return json(401, { message: 'Bad credentials' });
      const account = this.accounts[active.account];
      return json(200, { id: account.id, login: account.login, name: account.name, type: 'User' });
    }
    throw new Error(`GitHub simulator: unexpected endpoint ${req.url}`);
  }
}

// Slack OAuth v2: docs.slack.dev/authentication/installing-with-oauth.
export class SlackSimulator extends Simulator {
  constructor(options) { super({ accounts: { a: { team_id: 'T0001', user_id: 'U000A', team: 'Fixture Team', user: 'alice' }, b: { team_id: 'T0001', user_id: 'U000B', team: 'Fixture Team', user: 'bob' } }, ...options }); this.lifetime = 43200; this.requireHttpsRedirect = true; this.botTokens = []; this.userOptional = new Set(); this.reuseUserToken = false; this.lastUserToken = new Map(); }
  checkAuthorize(url, p) {
    if (url.origin + url.pathname !== 'https://slack.com/oauth/v2/authorize') return 'invalid_request';
    if (p.client_id !== this.clientId || !p.state || (!p.scope && !p.user_scope)) return 'invalid_request';
    // Redirect URLs must use HTTPS (http://localhost is only for PKCE-enabled desktop apps).
    if (this.requireHttpsRedirect && !String(p.redirect_uri).startsWith('https://')) return 'bad_redirect_uri';
    // A non-PKCE app rejects PKCE parameters.
    if (p.code_challenge) return 'pkce_not_allowed';
    return null;
  }
  grant(p, grant) {
    const user = (p.user_scope || '').split(',').filter(Boolean), bot = (p.scope || '').split(',').filter(Boolean);
    return { granted: granted(user, grant, scope => { if (!this.userOptional.has(scope)) throw new Error(`Slack simulator: only user_optional scopes can be declined, not ${scope}.`); }), bot };
  }
  handle(req) {
    if (req.url === 'https://slack.com/api/oauth.v2.access') {
      const fault = this.tokenFault(); if (fault) return fault;
      const f = body(req), creds = basic(req) ?? { id: f.client_id, secret: f.client_secret };
      if (creds.id !== this.clientId) return json(200, { ok: false, error: 'invalid_client_id' });
      if (creds.secret !== this.clientSecret) return json(200, { ok: false, error: 'bad_client_secret' });
      if (f.grant_type === 'refresh_token') {
        const entry = this.refresh.get(f.refresh_token);
        if (!entry) return json(200, { ok: false, error: 'invalid_refresh_token' });
        this.refresh.delete(f.refresh_token);
        const issued = this.issue(entry.account, entry.scopes, { refreshable: !this.omitRotatedRefresh });
        // The documented user refresh example is flat and has no `ok` field.
        return json(200, { id: this.accounts[entry.account].user_id, scope: entry.scopes.join(','), access_token: issued.accessToken, expires_in: this.lifetime, ...(issued.refreshToken ? { refresh_token: issued.refreshToken } : {}), token_type: 'user' });
      }
      const entry = this.takeCode(f.code, f.redirect_uri, f.code_verifier);
      if (!entry) return json(200, { ok: false, error: 'invalid_code' });
      if (entry.unexpectedVerifier) return json(200, { ok: false, error: 'pkce_not_allowed' });
      // Slack adds scopes to one user token: with reuseUserToken the account's live token comes back, carrying the union.
      const account = this.accounts[entry.account], previous = this.reuseUserToken ? this.lastUserToken.get(entry.account) : undefined, reused = previous !== undefined && this.access.get(previous);
      const scopes = reused ? [...new Set([...reused.scopes, ...entry.granted])] : entry.granted;
      if (reused) this.access.set(previous, { ...reused, scopes });
      const user = reused ? { accessToken: previous } : this.issue(entry.account, scopes, { refreshable: this.expiring });
      this.lastUserToken.set(entry.account, user.accessToken);
      // Bot scopes install a separate workspace bot credential at the top level of the response.
      const bot = entry.bot.length ? this.issue(entry.account, entry.bot, { refreshable: false }) : null;
      if (bot) this.botTokens.push(bot.accessToken);
      return json(200, { ok: true, app_id: 'A0001', team: { id: account.team_id, name: account.team }, enterprise: null, is_enterprise_install: false,
        ...(bot ? { access_token: bot.accessToken, token_type: 'bot', scope: entry.bot.join(','), bot_user_id: 'B0001' } : {}),
        authed_user: { id: account.user_id, scope: scopes.join(','), access_token: user.accessToken, token_type: 'user', ...(this.expiring && !reused ? { expires_in: this.lifetime, refresh_token: user.refreshToken } : {}) } });
    }
    if (req.url === 'https://slack.com/api/auth.revoke') {
      if (this.revokeFails) return json(200, { ok: false, error: 'internal_error' });
      const token = body(req).token ?? bearer(req);
      if (!this.access.has(token)) return json(200, { ok: false, error: 'invalid_auth' });
      this.access.delete(token);
      return json(200, { ok: true, revoked: true });
    }
    if (req.url === 'https://slack.com/api/auth.test') {
      const outage = this.identityOutage(); if (outage) return outage;
      const active = this.activeAccess(req);
      if (!active) return json(200, { ok: false, error: 'invalid_auth' });
      const account = this.accounts[active.account];
      return json(200, { ok: true, url: 'https://fixture.slack.com/', team: account.team, user: account.user, team_id: account.team_id, user_id: account.user_id });
    }
    throw new Error(`Slack simulator: unexpected endpoint ${req.url}`);
  }
}

// Notion public connections: developers.notion.com/docs/authorization and /reference.
export class NotionSimulator extends Simulator {
  constructor(options) { super({ accounts: { a: { owner: 'notion-user-a', ownerName: 'Avery A', email: 'avery@a.example', workspaceId: 'ws-a', workspace: 'Workspace A' }, b: { owner: 'notion-user-b', ownerName: 'Blake B', email: 'blake@b.example', workspaceId: 'ws-b', workspace: 'Workspace B' } }, ...options }); this.nullRefresh = false; this.shareEmail = true;
    // F10.19: the scope introspection reports for an active token. ASSUMPTION: Notion documents scope as an optional string and not its
    // format; the simulator lists the integration's capabilities space-separated. Step 20's N0 records what Notion really answers.
    this.introspectScope = 'read_content update_content insert_content read_comments insert_comments user_email'; }
  // The owner as a Notion user object; person.email appears only with the user-email capability (developers.notion.com/reference/user).
  ownerUser(owner) { return { object: 'user', id: owner.owner, name: owner.ownerName, avatar_url: null, type: 'person', person: this.shareEmail ? { email: owner.email } : {} }; }
  checkAuthorize(url, p) {
    if (url.origin + url.pathname !== 'https://api.notion.com/v1/oauth/authorize') return 'invalid_request';
    if (p.client_id !== this.clientId || p.response_type !== 'code' || p.owner !== 'user' || !p.redirect_uri) return 'invalid_request';
    if (p.scope || p.code_challenge) return 'invalid_request';
    return null;
  }
  grantedScopes() { return []; }
  // Each authorization mints a new bot (bot_id is unique per token); the owner and workspace
  // stay the same for the same person and workspace.
  issueBot(account, { internal = false } = {}) { return { botId: this.next('bot-'), internal }; }
  checkCall(req) {
    if (!header(req, 'notion-version')) return json(400, { object: 'error', status: 400, code: 'missing_version', message: 'Notion-Version header failed validation.' });
    const creds = basic(req);
    if (!creds || creds.id !== this.clientId || creds.secret !== this.clientSecret) return json(401, { object: 'error', status: 401, code: 'invalid_client', message: 'Client authentication failed.' });
    if (!String(header(req, 'content-type')).startsWith('application/json')) return json(400, { object: 'error', status: 400, code: 'invalid_request', message: 'Body must be JSON.' });
    return null;
  }
  tokenBody(account, issued, bot, refreshToken) {
    const owner = this.accounts[account];
    return { access_token: issued.accessToken, token_type: 'bearer', refresh_token: refreshToken, bot_id: bot.botId, workspace_id: owner.workspaceId, workspace_name: owner.workspace, workspace_icon: null, owner: { type: 'user', user: this.ownerUser(owner) }, duplicated_template_id: null };
  }
  handle(req) {
    if (req.url === 'https://api.notion.com/v1/oauth/token') {
      const fault = this.tokenFault(); if (fault) return fault;
      const problem = this.checkCall(req); if (problem) return problem;
      const f = body(req);
      if (f.grant_type === 'refresh_token') {
        const entry = this.refresh.get(f.refresh_token);
        if (!entry) return json(400, { object: 'error', status: 400, code: 'invalid_grant', message: 'Invalid refresh token.' });
        // ASSUMPTION: a null refresh_token in the response means the previous one stays valid.
        if (!this.nullRefresh) this.refresh.delete(f.refresh_token);
        const issued = this.issue(entry.account, [], { refreshable: !this.nullRefresh, extra: { bot: entry.bot, issuedAt: this.clock() } });
        return json(200, this.tokenBody(entry.account, issued, entry.bot, this.nullRefresh ? null : issued.refreshToken));
      }
      const entry = this.takeCode(f.code, f.redirect_uri, f.code_verifier);
      if (!entry || entry.unexpectedVerifier) return json(400, { object: 'error', status: 400, code: 'invalid_grant', message: 'Invalid code.' });
      const bot = this.issueBot(entry.account), issued = this.issue(entry.account, [], { refreshable: true, extra: { bot, issuedAt: this.clock() } });
      return json(200, this.tokenBody(entry.account, issued, bot, issued.refreshToken));
    }
    if (req.url === 'https://api.notion.com/v1/oauth/revoke') {
      if (this.revokeFails) return json(500, { object: 'error', status: 500, code: 'internal_server_error' });
      const problem = this.checkCall(req); if (problem) return problem;
      const token = body(req).token;
      if (!this.access.has(token)) return json(400, { object: 'error', status: 400, code: 'invalid_grant', message: 'Invalid token.' });
      this.access.delete(token);
      return json(200, { request_id: 'req-1' });
    }
    // F10.19 (developers.notion.com/reference/introspect-token): client Basic authentication, {token}; {active, scope?, iat?, request_id?}.
    // An inactive token answers {active: false} only (ASSUMPTION: Notion does not document the inactive answer).
    if (req.url === 'https://api.notion.com/v1/oauth/introspect') {
      const problem = this.checkCall(req); if (problem) return problem;
      const entry = this.access.get(body(req).token);
      if (!entry) return json(200, { active: false });
      return json(200, { active: true, scope: this.introspectScope, iat: Math.floor((entry.issuedAt ?? this.clock()) / 1000), request_id: '00000000-0000-4000-8000-000000000001' });
    }
    if (req.url === 'https://api.notion.com/v1/users/me') {
      if (!header(req, 'notion-version')) return json(400, { object: 'error', status: 400, code: 'missing_version' });
      const outage = this.identityOutage(); if (outage) return outage;
      const active = this.activeAccess(req);
      if (!active) return json(401, { object: 'error', status: 401, code: 'unauthorized' });
      const owner = this.accounts[active.account], bot = active.bot;
      // Internal integrations are owned by the workspace, not a person.
      return json(200, { object: 'user', id: bot.botId, type: 'bot', name: 'Fabric Fixture',
        bot: { owner: bot.internal ? { type: 'workspace', workspace: true } : { type: 'user', user: this.ownerUser(owner) }, workspace_id: owner.workspaceId, workspace_name: owner.workspace } });
    }
    throw new Error(`Notion simulator: unexpected endpoint ${req.url}`);
  }
}

export const SIMULATORS = Object.freeze({ google: GoogleSimulator, github: GitHubSimulator, slack: SlackSimulator, notion: NotionSimulator });

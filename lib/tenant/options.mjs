// F03.7d (docs/F03-DEVELOPER-LAYER.md section 5.10, docs/F03.7-BUILD-MAP.md slice 4): options for one input of an
// operation, read from the end user's own account through a reviewed source. Order: the end user and their account,
// the operation, the app being on, a reviewed source, then that source's own read row, which must be Allow (an Ask,
// Never or capped row lists nothing). The list is sent like an execution's read (credentials, then decided again),
// but never becomes a job, an approval or a usage record. It is decided again after the provider answers. The cursor is
// bound to the user, the account and the source.
// F10.11 part o: beside that path (capabilityId, version 1, unchanged), an action's input lists its choices (actionId and definitionHash):
// the source its file names, read from the injected action catalog only (this file never imports an action module), sent as a proxied
// read decided by ProxyPolicy.decide() on the source's own row, Allow only, before the credentials, after them and after the answer.
// `configured` carries only the choice's dependsOn values, each valid for the action's own input schema, and the cursor is also bound to
// them and to the query.
import {createCipheriv, createDecipheriv, randomBytes} from 'node:crypto';
import {TenantError, notFound, invalid} from './errors.mjs';
import {sourceFor} from '../option-sources.mjs';
import {groupFor} from '../permission-groups.mjs';
import {prepareRequest, validateValue, canonicalHash} from '../compiler.mjs';
import {capabilityPermissionHash, sameRoute} from '../permissions.mjs';
import {credentialValues, secretContext, scrubString} from '../redaction.mjs';
import {proxyBase} from '../proxy-request.mjs';

const text = (value, limit) => typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, limit) : '';
/** F10.11 part o: the most an answer to a choice list may hold, as an action's answer (lib/actions.mjs BOUNDS). */
const ANSWER_BYTES = 2 * 1024 * 1024;
/** F10.11 part o: the value at a JSON pointer ('' is the whole value), or undefined. */
function at(value, path) {
  let current = value;
  for (const token of path === '' ? [] : path.slice(1).split('/').map(part => part.replace(/~1/g, '/').replace(/~0/g, '~'))) {
    if (!current || typeof current !== 'object' || !Object.hasOwn(current, token)) return undefined;
    current = current[token];
  }
  return current;
}
const NO_SOURCE = () => new TenantError(422, 'no_option_source', 'Fabric has no reviewed list for this input yet.');
const DENIED = () => new TenantError(403, 'permission_denied', 'This account\'s permissions do not allow listing these choices without asking.');
function pointer(value, path) {
  let at = value;
  for (const part of path.slice(1).split('/')) { if (!at || typeof at !== 'object' || !Object.hasOwn(at, part)) return undefined; at = at[part]; }
  return at;
}

export class TenantOptions {
  /** @param {{stores: any, registry: any, accounts: any, runtimes: any, providerApps: any, appSetting: Function}} deps */
  constructor(deps) { Object.assign(this, deps); }

  /**
   * The source's own operation as reviewed: its capability in the platform catalog, in the row the source names; or no_option_source.
   * F10.13 part 1: a map Discovery stores holds paths below the app's reviewed base (Calendar's /users/me/calendarList under /calendar/v3),
   * so the capability's URL path must be exactly the base path joined to the entry's path, never the entry's path alone. A path that
   * already starts with the base is a whole URL path and is not joined twice.
   */
  #operation(bundle, appId, source) {
    const {env, permissions} = bundle;
    const map = env.repository.get('applicationMaps', appId), operation = Array.isArray(map?.operations) ? map.operations.find(op => op && op.id === source.operation) : null;
    const capability = operation?.capabilityId ? env.repository.get('capabilities', operation.capabilityId) : null;
    // The map entry must be bound to its own operation: a GET capability at exactly the entry's path below the app's base.
    let target = null, joined = null;
    try { target = decodeURIComponent(new URL(capability.request.url).pathname); } catch { target = null; }
    try {
      const {basePath} = proxyBase(bundle.runtime.proxyPolicy.configs.get(appId)?.apiBase);
      if (typeof operation?.path === 'string' && operation.path.startsWith('/')) joined = basePath && !operation.path.startsWith(`${basePath}/`) ? `${basePath}${operation.path}` : operation.path;
    } catch { joined = null; }
    if (!operation || !capability || capability.status !== 'active' || capability.appId !== appId || capability.driver !== 'http' || capability.request?.method !== 'GET' || operation.method !== 'GET'
      || joined === null || target !== joined || groupFor(permissions.groups, appId, operation)?.id !== source.row)
      throw new TenantError(422, 'no_option_source', 'Fabric has no reviewed list for this input yet.');
    return capability;
  }
  /** Allow only: an Ask, Never, capped, sensitive or not-yet-granted read lists nothing. */
  #allowed(permissions, connection, capability) {
    let decision;
    try { decision = permissions.decision(connection, capability); } catch { decision = null; }
    if (!decision || !decision.executable || decision.mode !== 'allow' || decision.sensitivity || decision.providerAccess === 'missing') throw new TenantError(403, 'permission_denied', 'This account\'s permissions do not allow listing these choices without asking.');
  }
  /**
   * Cursors are sealed (AES-256-GCM) under a key of this environment, kept in its vault, with the binding (person,
   * account, list) as additional data: the developer sees no store id and no provider page token, and a cursor opened
   * for another person, account, list or environment fails the same way.
   */
  #cursorKey(env) {
    let stored = env.vault.get('optionCursorKey');
    if (!stored || typeof stored.key !== 'string') { stored = {key: randomBytes(32).toString('base64')}; env.vault.set('optionCursorKey', stored); }
    return Buffer.from(stored.key, 'base64');
  }
  #seal(env, binding, token) {
    const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', this.#cursorKey(env), iv);
    cipher.setAAD(Buffer.from(JSON.stringify(binding)));
    const sealed = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), sealed]).toString('base64url');
  }
  #cursor(env, value, binding) {
    if (value === undefined || value === null || value === '') return null;
    let token = null;
    try {
      const raw = Buffer.from(String(value).slice(0, 4096), 'base64url');
      if (raw.length > 28) {
        const decipher = createDecipheriv('aes-256-gcm', this.#cursorKey(env), raw.subarray(0, 12));
        decipher.setAAD(Buffer.from(JSON.stringify(binding))); decipher.setAuthTag(raw.subarray(12, 28));
        token = Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8');
      }
    } catch { token = null; }
    if (typeof token !== 'string' || token.length > 2048) throw invalid('This cursor belongs to another list.');
    return token;
  }

  /** POST /v1/options */
  async list(caller, body) {
    const fields = ['externalUserId', 'accountRef', 'capabilityId', 'actionId', 'definitionHash', 'input', 'configured', 'query', 'cursor'];
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw invalid('The body must be a JSON object.');
    const unknown = Object.keys(body).find(key => !fields.includes(key));
    if (unknown) throw invalid(`Unknown field: ${unknown.slice(0, 40)}.`);
    if (body.actionId !== undefined || body.definitionHash !== undefined) return this.#actionOptions(caller, body);
    if (typeof body.capabilityId !== 'string' || typeof body.input !== 'string') throw invalid('Send capabilityId and the input to list options for.');
    if (body.query !== undefined && (typeof body.query !== 'string' || body.query.length > 200)) throw invalid('query is up to 200 characters.');
    const bundle = this.runtimes.bundle(caller.scope), env = bundle.env;
    const user = this.accounts.user(env, body.externalUserId);
    if (!user) throw notFound();
    // The account named, or (like an execution) the user's default or only account for the operation's app.
    const owner = this.accounts.ownerOf(user), capability = env.repository.get('capabilities', body.capabilityId);
    const account = body.accountRef !== undefined ? this.accounts.ownedAccount(env, owner, body.accountRef) : capability?.status === 'active' ? this.accounts.chosenAccount(env, owner, capability.appId) : null;
    if (!capability || capability.status !== 'active' || !account || capability.appId !== account.appId) throw notFound();
    // Only the developer's explicit off counts, as for executions: a full or unset shared sign-in app stops new connections only.
    if (this.registry.get('environments', caller.scope.environmentId)?.apps?.[account.appId]?.enabled === false) throw new TenantError(422, 'app_disabled', 'This app is turned off in this environment.');
    if (!Object.hasOwn(capability.inputSchema?.properties || {}, body.input)) throw invalid('That is not an input of this operation.');
    const source = sourceFor(account.appId, body.input);
    if (!source) throw new TenantError(422, 'no_option_source', 'Fabric has no reviewed list for this input yet.');
    const list = this.#operation(bundle, account.appId, source);
    this.#allowed(bundle.permissions, account, list);
    const binding = {u: owner.userRecordId, a: account.id, s: `${account.appId}:${source.id}`}, token = this.#cursor(env, body.cursor, binding);
    if (token !== null && !source.pageToken) throw invalid('This list has no further pages.');
    this.stores.pin(caller.scope);
    let response, secrets = secretContext([]);
    try {
      const authority = await bundle.connections.credentials(account.id);
      secrets = secretContext(credentialValues(authority.headers));
      // Decided again after the credential refresh: a row switched away meanwhile lists nothing.
      const current = env.repository.get('connections', account.id);
      if (!current || current.status !== 'ready') throw notFound();
      this.#allowed(bundle.permissions, current, list);
      const request = prepareRequest(list, {...source.args, ...(token !== null ? {[source.pageToken.parameter]: token} : {})});
      response = await bundle.runtime.request({...request, headers: {...request.headers, ...authority.headers}, allowedOrigins: authority.allowedOrigins});
      // And once more after the answer, as executions and the proxy do: a rule or ceiling switched during the request
      // withholds what came back.
      const after = env.repository.get('connections', account.id);
      if (!after || after.status !== 'ready' || !this.accounts.ownedAccount(env, owner, account.id)) throw notFound();
      this.#allowed(bundle.permissions, after, list);
      if (this.registry.get('environments', caller.scope.environmentId)?.apps?.[account.appId]?.enabled === false) throw new TenantError(422, 'app_disabled', 'This app is turned off in this environment.');
    } catch (error) {
      if (error instanceof TenantError) throw error;
      throw new TenantError(502, 'provider_error', 'The provider could not list these choices now.');
    } finally { try { this.stores.unpin(caller.scope); } catch { /* closed */ } }
    if (!response || response.status < 200 || response.status >= 300) throw new TenantError(502, 'provider_error', 'The provider could not list these choices now.');
    const items = pointer(response.data, source.items), needle = typeof body.query === 'string' ? body.query.toLowerCase() : '';
    const options = [];
    for (const item of Array.isArray(items) ? items.slice(0, source.maxItems) : []) {
      const value = pointer(item, source.value);
      if (!(typeof value === 'string' && value.length && value.length <= 500) && !Number.isSafeInteger(value)) continue;
      const label = text(source.label.map(path => pointer(item, path)).find(candidate => typeof candidate === 'string' && candidate.trim()), 200) || String(value).slice(0, 200);
      if (needle && !label.toLowerCase().includes(needle)) continue;
      options.push({label: scrubString(label, secrets), value: typeof value === 'string' ? scrubString(value, secrets) : value});
    }
    const next = source.pageToken ? pointer(response.data, source.pageToken.response) : undefined;
    return {options, ...(typeof next === 'string' && next && next.length <= 2048 ? {nextCursor: this.#seal(env, binding, next)} : {})};
  }

  // ---- F10.11 part o: an action input's choices ---------------------------------------------------------------------------------------
  /** The action's own source read decided as a proxied read: Allow only, in the source's own row (a configured value that lands the request
   *  on another member, or a body route, moves it out), and executable (not short of a scope, not unavailable). */
  #proxyAllowed(bundle, account, input, source) {
    let decision;
    try { decision = bundle.runtime.proxyPolicy.decide(account.id, input); } catch { decision = null; }
    if (!decision || !decision.executable || decision.mode !== 'allow' || decision.groupId !== source.row) throw DENIED();
    return decision;
  }
  /** `configured`: an object of the choice's dependsOn values only, each valid for the action's own schema of that input. */
  #configured(value, choice, schema) {
    if (value === undefined) value = {};
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid('configured is an object of the values this input\'s choices depend on.');
    const depends = choice.dependsOn ?? [];
    for (const [name, item] of Object.entries(value)) {
      if (!depends.includes(name)) throw invalid(`configured holds only the inputs this input's choices depend on (${depends.join(', ') || 'none'}).`);
      try { validateValue(schema.properties[name], item, name); } catch { throw invalid(`configured.${name.slice(0, 40)} is not a value of that input.`); }
    }
    return value;
  }
  /** The source's arguments: its constants, and the configured arguments its choice fills (by argument name), each from a constant or a
   *  configured value. */
  #arguments(source, choice, configured) {
    const args = {};
    for (const [name, argument] of Object.entries(source.args ?? {})) {
      if (Object.hasOwn(argument, 'const')) { args[name] = argument.const; continue; }
      const filled = choice.args?.[name];
      if (!filled) continue;
      if (Object.hasOwn(filled, 'const')) { args[name] = filled.const; continue; }
      const input = filled.input.slice(1).replace(/~1/g, '/').replace(/~0/g, '~');
      if (!Object.hasOwn(configured, input)) throw invalid(`Send the value of ${input.slice(0, 40)} in configured.`);
      args[name] = configured[input];
    }
    return args;
  }
  /** POST /v1/options with actionId and definitionHash: one page of choices for one input of an action this environment runs now. */
  async #actionOptions(caller, body) {
    if (body.capabilityId !== undefined) throw invalid('Send capabilityId for an operation, or actionId and definitionHash for an action, not both.');
    if (typeof body.actionId !== 'string' || typeof body.definitionHash !== 'string' || typeof body.input !== 'string') throw invalid('Send actionId, definitionHash and the input to list options for.');
    if (body.query !== undefined && (typeof body.query !== 'string' || body.query.length > 200)) throw invalid('query is up to 200 characters.');
    const bundle = this.runtimes.bundle(caller.scope), env = bundle.env, catalog = bundle.permissions.actions;
    const user = this.accounts.user(env, body.externalUserId);
    if (!user) throw notFound();
    // Only an action the catalog runs now, as the developer read it.
    const owner = this.accounts.ownerOf(user), capability = env.repository.get('capabilities', body.actionId);
    if (!capability || capability.driver !== 'action' || capability.status !== 'active' || catalog?.entryOf?.(capability)?.status !== 'active') throw notFound();
    if (capabilityPermissionHash(capability) !== body.definitionHash) throw new TenantError(409, 'capability_changed', 'This action changed since you read it; read it again and send its current definitionHash.');
    const account = body.accountRef !== undefined ? this.accounts.ownedAccount(env, owner, body.accountRef) : this.accounts.chosenAccount(env, owner, capability.appId);
    if (!account || !sameRoute(account, capability)) throw notFound();
    if (this.registry.get('environments', caller.scope.environmentId)?.apps?.[account.appId]?.enabled === false) throw new TenantError(422, 'app_disabled', 'This app is turned off in this environment.');
    if (!Object.hasOwn(capability.inputSchema?.properties || {}, body.input)) throw invalid('That is not an input of this action.');
    const choice = (capability.action?.choices ?? []).find(entry => entry.input === body.input), source = choice ? catalog.choiceSource(capability.appId, choice.source) : null;
    if (!source || source.kind !== 'directory') throw NO_SOURCE();
    const configured = this.#configured(body.configured, choice, capability.inputSchema), args = this.#arguments(source, choice, configured);
    // The cursor is bound to the person, the account, the action's input and the values and query it was read with.
    const binding = {u: owner.userRecordId, a: account.id, s: `${account.appId}:${source.id}`, i: `${capability.id}:${body.input}`, c: canonicalHash({configured, query: body.query ?? null})};
    let page = {t: null, n: 0};
    if (body.cursor !== undefined && body.cursor !== null && body.cursor !== '') {
      try { page = JSON.parse(this.#cursor(env, body.cursor, binding)); } catch (error) { if (error instanceof TenantError) throw error; page = null; }
      if (!page || !(typeof page.t === 'string' || Number.isSafeInteger(page.t)) || !Number.isSafeInteger(page.n) || page.n < 1) throw invalid('This cursor belongs to another list.');
    }
    const search = source.search?.mode === 'provider' && body.query ? body.query : null;
    let built;
    try { built = catalog.choiceRequest(source, {args, cursor: page.t, query: search}); } catch { throw invalid('Fabric cannot build this list from what was sent.'); }
    // A typed operation source is read as version 1 reads one; a request template as a proxied read of its row.
    const list = built.operation !== undefined ? this.#operation(bundle, account.appId, {operation: built.operation, row: source.row}) : null;
    const allowed = connection => list ? (this.#allowed(bundle.permissions, connection, list), null) : this.#proxyAllowed(bundle, connection, built.input, source);
    allowed(account);
    this.stores.pin(caller.scope);
    let response, url, secrets = secretContext([]);
    try {
      const authority = await bundle.connections.credentials(account.id);
      secrets = secretContext(credentialValues(authority.headers));
      // Decided again after the credential refresh: a row switched away meanwhile lists nothing.
      const current = env.repository.get('connections', account.id);
      if (!current || current.status !== 'ready') throw notFound();
      const decision = allowed(current);
      if (list) {
        const request = prepareRequest(list, built.args);
        url = request.url;
        response = await bundle.runtime.request({...request, headers: {...request.headers, ...authority.headers}, allowedOrigins: authority.allowedOrigins});
      } else {
        const request = decision.request, origin = new URL(request.url).origin, {Authorization: credential, Accept: _accept, ...provider} = authority.headers;
        if (!Array.isArray(authority.allowedOrigins) || !authority.allowedOrigins.includes(origin)) throw DENIED();
        url = request.url;
        response = await bundle.runtime.request({url: request.url, method: request.method, headers: {...request.headers, ...provider, ...(credential ? {Authorization: credential} : {}), Accept: request.headers.Accept || 'application/json',
          ...(request.body !== null ? {'Content-Type': 'application/json; charset=utf-8'} : {})}, ...(request.body !== null ? {body: request.body} : {}), allowedOrigins: [origin], timeoutMs: request.timeoutMs, maxBytes: ANSWER_BYTES, responseType: 'json', redirect: 'report'});
      }
      // And once more after the answer: a rule or ceiling switched during the request withholds what came back.
      const after = env.repository.get('connections', account.id);
      if (!after || after.status !== 'ready' || !this.accounts.ownedAccount(env, owner, account.id)) throw notFound();
      allowed(after);
      if (this.registry.get('environments', caller.scope.environmentId)?.apps?.[account.appId]?.enabled === false) throw new TenantError(422, 'app_disabled', 'This app is turned off in this environment.');
    } catch (error) {
      if (error instanceof TenantError) throw error;
      throw new TenantError(502, 'provider_error', 'The provider could not list these choices now.');
    } finally { try { this.stores.unpin(caller.scope); } catch { /* closed */ } }
    if (!response || response.status < 200 || response.status >= 300) throw new TenantError(502, 'provider_error', 'The provider could not list these choices now.');
    const items = at(response.data, source.items), needle = source.search?.mode === 'local' && body.query ? body.query.toLowerCase() : '', excluded = new Set(source.exclude ?? []);
    const words = (entry, pointers) => text(pointers.map(path => at(entry, path)).filter(candidate => typeof candidate === 'string' && candidate.trim()).join(' '), 200);
    const options = [];
    for (const entry of Array.isArray(items) ? items.slice(0, source.maxItems) : []) {
      const value = at(entry, source.value);
      if (!(source.valueType === 'string' ? typeof value === 'string' && value.length && [...value].length <= 1000 : Number.isSafeInteger(value)) || excluded.has(value)) continue;
      const label = words(entry, source.label) || String(value).slice(0, 200);
      if (needle && !label.toLowerCase().includes(needle)) continue;
      const detail = source.detail ? words(entry, source.detail) : '';
      options.push({label: scrubString(label, secrets), value: typeof value === 'string' ? scrubString(value, secrets) : value, ...(detail ? {detail: scrubString(detail, secrets)} : {})});
    }
    let next = null;
    try { next = catalog.choiceNext(source, {status: response.status, headers: response.headers ?? {}, data: response.data}, {pages: page.n + 1, url}); } catch { next = null; }
    const sealed = next === null ? null : JSON.stringify({t: next, n: page.n + 1});
    return {options, ...(sealed && sealed.length <= 2048 ? {nextCursor: this.#seal(env, binding, sealed)} : {})};
  }
}

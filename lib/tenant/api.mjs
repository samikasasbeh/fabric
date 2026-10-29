// F03.1b: the developer API (/v1). Every request runs the same order of checks (docs/F03-DEVELOPER-LAYER.md section
// 5.1): the key, then the route's scope, then the environment's status (inside ServiceKeys.verify), and only then
// the handler. A missing scope therefore never reveals whether anything exists. Browsers are refused: a /v1 request
// carrying Origin or Cookie is a server-to-server call that leaked into a page.
import {randomBytes} from 'node:crypto';
import {KeyError} from './keys.mjs';
import {SessionError} from './connect-sessions.mjs';
import {TenantError} from './errors.mjs';
import {RESERVED_SCOPES, validEmail, validName, TenantRecordError} from '../../contracts/tenant.mts';
import {tenantCatalog, tenantAppDetail, tenantCategories, consentSheet, tenantApps, capabilityView, capabilityRow, optionInputs, signInOf} from './views.mjs';
import {sharedAppId} from './provider-apps.mjs';
import {checkedBrand, BrandError} from './brand.mjs';
import {PERMISSION_GROUPS} from '../permission-groups.mjs';
import {actionChoices, ACTION_WORDS} from '../permissions.mjs';
import {checkedLogo, logoUrl, LOGO_TYPES, LOGO_MAX_BYTES, LogoError} from './logos.mjs';

const MAX_BODY = 256 * 1024;
/** Any one of these reaches POST /v1/connect-sessions and /link; the session's purpose decides which it needs (F03.10). */
const LINK_SCOPES = Object.freeze({anyOf: ['connect:write', 'connect:manage', 'connect:approve']});
const FABRIC_PORTS = ['4188', '4320', '4340'];
const FABRIC_HOSTS = ['connect.runorra.com'];

export class ApiError extends Error {
  constructor(status, code, message, details) { super(message); this.status = status; this.code = code; if (details) this.details = details; }
}
const invalid = message => new ApiError(400, 'invalid_request', message);
const notFound = () => new ApiError(404, 'not_found', 'Nothing with that id exists here.');

function only(body, fields) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) throw invalid('The body must be a JSON object.');
  const unknown = Object.keys(body).filter(key => !fields.includes(key));
  if (unknown.length) throw invalid(`Unknown field: ${unknown[0].slice(0, 40)}.`);
  return body;
}

/** Exact origins only (scheme, host, port); production takes https; Fabric's own origins and ports never. */
export function checkedOrigins(value, kind) {
  if (!Array.isArray(value) || value.length > 10) throw invalid('Give at most 10 origins.');
  return [...new Set(value.map(item => {
    let url;
    try { url = new URL(item); } catch { throw invalid('Each origin must be a full origin such as https://app.example.com.'); }
    if (url.origin !== item || !['https:', 'http:'].includes(url.protocol)) throw invalid('Each origin must be exactly scheme, host and port, with nothing after it.');
    if (kind === 'production' && url.protocol !== 'https:') throw invalid('Production accepts https origins only.');
    const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
    if (FABRIC_HOSTS.includes(url.hostname) || (loopback && FABRIC_PORTS.includes(url.port))) throw invalid('Fabric\'s own origins cannot be used here.');
    return url.origin;
  }))];
}

function projectView(project, environment, origin) {
  const logo = logoUrl(project, origin);
  return {project: {id: project.id, name: project.name, appName: project.appName, supportEmail: project.supportEmail ?? null, ...(logo ? {logoUrl: logo} : {}), ...(project.dataUse ? {dataUse: project.dataUse} : {}), ...(project.brand ? {brand: project.brand} : {}),
    ...(project.pendingBranding ? {pendingReview: true, pendingFields: Object.keys(project.pendingBranding).sort()} : {})},
    environment: {id: environment.id, kind: environment.kind, status: environment.status, productionEnabled: environment.productionEnabled, reach: 'this_machine', openerOrigins: environment.openerOrigins, redirectOrigins: environment.redirectOrigins}};
}

/** Routes: method, path pattern, required scope, handler. ROUTES lists them for the cross-tenant matrix. */
const TABLE = [
  ['GET', /^\/v1\/project$/, 'project:read', ({caller, registry, origin}) => projectView(registry.get('projects', caller.scope.projectId), registry.get('environments', caller.scope.environmentId), origin)],
  ['PATCH', /^\/v1\/project$/, 'project:write', ({caller, registry, body, origin}) => {
    const changes = only(body, ['appName', 'supportEmail', 'dataUse', 'brand']), project = registry.get('projects', caller.scope.projectId), environment = registry.get('environments', caller.scope.environmentId);
    // Everything here is shown to end users on Fabric's pages, so once production is live every field waits for the
    // operator's review, whichever environment's key asks (L10). null removes a field once approved.
    const values = {};
    if ('supportEmail' in changes) values.supportEmail = validEmail(changes.supportEmail);
    if ('dataUse' in changes) {
      if (changes.dataUse === null) values.dataUse = null;
      else {
        const dataUse = only(changes.dataUse, ['text', 'learnMoreUrl']);
        if (typeof dataUse.text !== 'string' || !dataUse.text.trim() || dataUse.text.length > 500 || /[\u0000-\u001f\u007f]/.test(dataUse.text)) throw invalid('dataUse.text must be 1 to 500 characters of plain text.');
        if (dataUse.learnMoreUrl !== undefined) { let url; try { url = new URL(dataUse.learnMoreUrl); } catch { throw invalid('dataUse.learnMoreUrl must be an https link.'); } if (url.protocol !== 'https:' || url.href.length > 500) throw invalid('dataUse.learnMoreUrl must be an https link.'); }
        values.dataUse = {text: dataUse.text.trim(), ...(dataUse.learnMoreUrl ? {learnMoreUrl: dataUse.learnMoreUrl} : {})};
      }
    }
    if ('appName' in changes) values.appName = validName(changes.appName, 'appName');
    // F03.10: colours for Fabric's hosted pages, as named tokens with readable contrast; null returns to Fabric's own.
    if ('brand' in changes) { try { values.brand = changes.brand === null ? null : checkedBrand(changes.brand); } catch (error) { throw invalid(error instanceof BrandError ? error.message : 'brand is not valid.'); } }
    const review = registry.brandingNeedsReview(project.id), pending = review && Object.keys(values).length ? values : null;
    let next = {...project};
    if (pending) next.pendingBranding = {...(project.pendingBranding || {}), ...pending};
    else for (const [field, value] of Object.entries(values)) { if (value === null) delete next[field]; else next[field] = value; }
    registry.put('projects', next);
    registry.audit({type: 'tenant.project_updated', projectId: project.id, fields: Object.keys(changes), byKey: caller.keyId});
    return pending ? {status: 202, body: {...projectView(next, environment, origin), pendingReview: true}} : projectView(next, environment, origin);
  }],
  // F03.6b: the project's logo, as PNG or WebP bytes. Rebuilt without metadata; once production is live it waits for review.
  ['PUT', /^\/v1\/project\/logo$/, 'project:write', ({caller, registry, body, contentType, origin}) => {
    let logo;
    try { logo = checkedLogo(body, contentType); } catch (error) { if (error instanceof LogoError) throw invalid(error.message); throw error; }
    const project = registry.get('projects', caller.scope.projectId), environment = registry.get('environments', caller.scope.environmentId);
    registry.put('projectLogos', {id: `${project.id}.${logo.hash}`, projectId: project.id, hash: logo.hash, contentType: logo.contentType, data: logo.bytes.toString('base64'), createdAt: registry.now()});
    const record = {hash: logo.hash, contentType: logo.contentType, width: logo.width, height: logo.height};
    const review = registry.brandingNeedsReview(project.id), next = review ? {...project, pendingBranding: {...(project.pendingBranding || {}), logo: record}} : {...project, logo: record};
    registry.put('projects', next);
    registry.pruneLogos(project.id, project);
    registry.audit({type: 'tenant.logo_uploaded', projectId: project.id, hash: logo.hash, pendingReview: review, byKey: caller.keyId});
    return review ? {status: 202, body: {pendingReview: true}} : {logoUrl: logoUrl(next, origin)};
  }, {raw: LOGO_TYPES, max: LOGO_MAX_BYTES}],
  ['PATCH', /^\/v1\/environment$/, 'project:write', ({caller, registry, body, origin}) => {
    // eventDestinations is reserved for event delivery (Iteration 9, section 8) and cannot be set yet.
    if (body && typeof body === 'object' && 'eventDestinations' in body) throw new ApiError(422, 'not_available', 'Event destinations arrive with triggers and events.');
    const changes = only(body, ['openerOrigins', 'redirectOrigins']), environment = registry.get('environments', caller.scope.environmentId), next = {...environment};
    for (const field of ['openerOrigins', 'redirectOrigins']) if (field in changes) next[field] = checkedOrigins(changes[field], environment.kind);
    registry.put('environments', next);
    registry.audit({type: 'tenant.environment_updated', environmentId: environment.id, fields: Object.keys(changes), byKey: caller.keyId});
    return projectView(registry.get('projects', caller.scope.projectId), next, origin).environment;
  }],
  ['GET', /^\/v1\/environment\/apps$/, 'project:read', ({caller, registry, providerApps}) => {
    const environment = registry.get('environments', caller.scope.environmentId);
    return {apps: tenantApps().map(app => appSetting(app.id, environment, providerApps))};
  }],
  ['PUT', /^\/v1\/environment\/apps\/([a-z][a-z0-9-]{0,63})$/, 'project:write', ({caller, registry, providerApps, body, match}) => {
    const appId = match[1];
    if (!tenantApps().some(app => app.id === appId)) throw notFound();
    const changes = only(body, ['enabled', 'providerApp', 'ceilings']), environment = registry.get('environments', caller.scope.environmentId);
    const current = environment.apps?.[appId] || {}, next = {...current};
    if ('providerApp' in changes) {
      // Only the literal 'shared' picks Fabric's app (L6); otherwise one of this environment's own apps for the same provider.
      if (changes.providerApp === 'shared') next.providerApp = 'shared';
      else {
        if (typeof changes.providerApp !== 'string' || changes.providerApp === sharedAppId(signInOf(appId)?.providerId)) throw invalid('providerApp is shared or the id of one of this environment\'s own provider apps.');
        const record = providerApps.developer(caller.scope, changes.providerApp);
        if (!record) throw notFound();
        if (record.providerId !== signInOf(appId)?.providerId) throw new ApiError(409, 'provider_mismatch', 'That provider app signs in to another provider.');
        next.providerApp = record.id;
      }
    }
    if ('enabled' in changes) {
      if (typeof changes.enabled !== 'boolean') throw invalid('enabled must be true or false.');
      // Judged with this request's provider app choice applied.
      const planned = {...environment, apps: {...(environment.apps || {}), [appId]: next}}, availability = providerApps.availability(appId, planned);
      if (changes.enabled && availability.state !== 'ready') throw new ApiError(422, 'unavailable', availability.reason);
      next.enabled = changes.enabled;
    }
    if ('ceilings' in changes) {
      if (changes.ceilings === null || typeof changes.ceilings !== 'object' || Array.isArray(changes.ceilings)) throw invalid('ceilings must be an object of row id to ask or deny.');
      const rows = new Map((PERMISSION_GROUPS.get(appId)?.groups || []).map(group => [group.id, group])), ceilings = {...(current.ceilings || {})};
      for (const [groupId, mode] of Object.entries(changes.ceilings)) {
        // null clears a ceiling on any row id, so one left on a row that no longer exists can still be removed.
        if (mode === null) { delete ceilings[groupId]; continue; }
        if (!rows.has(groupId)) throw invalid(`${groupId.slice(0, 80)} is not a permission row of ${appId}.`);
        // T4 (F10.3): a row Fabric locks is Never for everyone, so a ceiling has nothing to lower there.
        if (rows.get(groupId).locked === 'fabric') throw new ApiError(409, 'locked_row', 'Fabric keeps this row off for everyone, so it takes no ceiling.');
        // A ceiling only lowers what end users may allow; it can never raise anything.
        if (mode === 'allow') throw new ApiError(409, 'ceiling_raises', 'A ceiling can only lower a permission (ask or deny); remove it with null.');
        if (mode === 'ask' || mode === 'deny') ceilings[groupId] = mode; else throw invalid('A ceiling is ask, deny or null.');
      }
      next.ceilings = ceilings;
    }
    registry.put('environments', {...environment, apps: {...(environment.apps || {}), [appId]: next}});
    registry.audit({type: 'tenant.app_setting_updated', environmentId: environment.id, appId, fields: Object.keys(changes), byKey: caller.keyId});
    return appSetting(appId, registry.get('environments', environment.id), providerApps);
  }],
  // F03.8: developers' own sign-in apps (section 5.4). Ids are checked in the handler, so a malformed, unknown or another
  // environment's id all answer the same not_found, after the scope check.
  ['GET', /^\/v1\/provider-apps$/, 'provider_apps:read', ({caller, registry, providerApps}) => providerApps.list(caller, registry.get('environments', caller.scope.environmentId))],
  ['POST', /^\/v1\/provider-apps$/, 'provider_apps:write', ({caller, providerApps, body}) => providerApps.create(caller, body)],
  ['PATCH', /^\/v1\/provider-apps\/([^/]{1,100})$/, 'provider_apps:write', ({caller, providerApps, match, body}) => providerApps.update(caller, match[1], body)],
  ['DELETE', /^\/v1\/provider-apps\/([^/]{1,100})$/, 'provider_apps:write', ({caller, registry, providerApps, match}) => providerApps.remove(caller, match[1], registry.get('environments', caller.scope.environmentId))],
  // F03.10: any one of the link powers reaches create and link; each purpose's own scope is checked inside them.
  ['POST', /^\/v1\/connect-sessions$/, LINK_SCOPES, ({caller, sessions, body}) => sessions.create(caller, body)],
  ['GET', /^\/v1\/connect-sessions\/([a-z0-9_]{1,40})$/, 'connect:write', ({caller, sessions, match}) => sessions.get(caller, match[1])],
  ['POST', /^\/v1\/connect-sessions\/([a-z0-9_]{1,40})\/cancel$/, 'connect:write', ({caller, sessions, match}) => sessions.cancel(caller, match[1])],
  ['POST', /^\/v1\/connect-sessions\/([a-z0-9_]{1,40})\/link$/, LINK_SCOPES, ({caller, sessions, match}) => sessions.link(caller, match[1])],
  // F03.5a: end users and their accounts. A user-asserting route names the end user; an environment-wide one finds it from the record.
  ['GET', /^\/v1\/users$/, 'users:read', ({caller, users, url}) => users.list(caller, {q: url.searchParams.get('q') ?? undefined, after: url.searchParams.get('after') ?? undefined, limit: url.searchParams.get('limit') ?? undefined})],
  ['GET', /^\/v1\/users\/([^/]{1,400})$/, 'users:read', ({caller, users, match}) => users.get(caller, segment(match[1]))],
  ['DELETE', /^\/v1\/users\/([^/]{1,400})$/, 'users:write', ({caller, users, match}) => users.delete(caller, segment(match[1]))],
  ['GET', /^\/v1\/users\/([^/]{1,400})\/accounts$/, 'accounts:read', ({caller, accounts, match, url}) => accounts.list(caller, segment(match[1]), {appId: url.searchParams.get('appId') ?? undefined})],
  ['GET', /^\/v1\/users\/([^/]{1,400})\/accounts\/([^/]{1,100})$/, 'accounts:read', ({caller, accounts, match}) => accounts.get(caller, segment(match[1]), match[2])],
  ['POST', /^\/v1\/users\/([^/]{1,400})\/accounts\/([^/]{1,100})\/disconnect$/, 'accounts:write', ({caller, accounts, match, body}) => accounts.disconnect(caller, segment(match[1]), match[2], body)],
  ['POST', /^\/v1\/users\/([^/]{1,400})\/accounts\/([^/]{1,100})\/check$/, 'accounts:write', ({caller, accounts, match}) => accounts.check(caller, segment(match[1]), match[2])],
  ['PUT', /^\/v1\/users\/([^/]{1,400})\/apps\/([a-z][a-z0-9-]{0,63})\/default-account$/, 'accounts:write', ({caller, accounts, match, body}) => accounts.setDefault(caller, segment(match[1]), match[2], body)],
  // F03.5b: one end user's catalog, app page, runnable capabilities and the permission relay (D5).
  ['GET', /^\/v1\/users\/([^/]{1,400})\/catalog$/, ['catalog:read', 'accounts:read'], ({caller, pages, match, url}) => pages.catalog(caller, segment(match[1]), Object.fromEntries(['status', 'q', 'categoryId', 'cursor', 'limit'].map(name => [name, url.searchParams.get(name) ?? undefined])))],
  ['GET', /^\/v1\/users\/([^/]{1,400})\/capabilities$/, ['catalog:read', 'accounts:read'], ({caller, pages, match, url}) => pages.capabilities(caller, segment(match[1]), {appId: url.searchParams.get('appId') ?? undefined})],
  ['GET', /^\/v1\/users\/([^/]{1,400})\/apps\/([a-z][a-z0-9-]{0,63})$/, 'accounts:read', ({caller, pages, match, url}) => pages.view(caller, segment(match[1]), match[2], url.searchParams.get('account') ?? undefined)],
  ['POST', /^\/v1\/users\/([^/]{1,400})\/accounts\/([^/]{1,100})\/permissions$/, 'permissions:write', ({caller, pages, match, body}) => pages.setRow(caller, segment(match[1]), match[2], body)],
  ['POST', /^\/v1\/users\/([^/]{1,400})\/accounts\/([^/]{1,100})\/permissions\/reset$/, 'permissions:write', ({caller, pages, match, body}) => pages.reset(caller, segment(match[1]), match[2], body)],
  ['POST', /^\/v1\/users\/([^/]{1,400})\/accounts\/([^/]{1,100})\/background$/, 'permissions:write', ({caller, pages, match, body}) => pages.setBackground(caller, segment(match[1]), match[2], body)],
  // F03.7b: executions of reviewed operations on one end user's account, with Idempotency-Key and waitMs.
  ['POST', /^\/v1\/executions$/, 'executions:write', ({caller, executions, body, headers}) => executions.create(caller, body, headers['idempotency-key'])],
  ['GET', /^\/v1\/executions\/([^/]{1,100})$/, 'executions:read', ({caller, executions, match, url}) => executions.get(caller, match[1], url.searchParams.get('waitMs') ?? undefined)],
  ['POST', /^\/v1\/executions\/([^/]{1,100})\/cancel$/, 'executions:write', ({caller, executions, match}) => executions.cancel(caller, match[1])],
  // F03.7d: options for one input, from the end user's own account through a reviewed source.
  ['POST', /^\/v1\/options$/, 'executions:write', ({caller, options, body}) => options.list(caller, body)],
  // F03.9's approval relay, pulled forward: one end user's waiting calls, and a decision made in the developer's screens.
  ['GET', /^\/v1\/users\/([^/]{1,400})\/approvals$/, 'approvals:read', ({caller, approvals, match}) => approvals.list(caller, segment(match[1]))],
  ['POST', /^\/v1\/users\/([^/]{1,400})\/approvals\/([^/]{1,100})\/decision$/, 'decisions:write', ({caller, approvals, match, body}) => approvals.decide(caller, segment(match[1]), match[2], body)],
  // F03.9b: agent tokens for one end user (section 5.12): shown once, bound to that user's own accounts.
  ['POST', /^\/v1\/users\/([^/]{1,400})\/agent-tokens$/, 'agents:write', ({caller, agentTokens, match, body}) => agentTokens.create(caller, segment(match[1]), body)],
  ['GET', /^\/v1\/users\/([^/]{1,400})\/agent-tokens$/, 'agents:write', ({caller, agentTokens, match}) => agentTokens.list(caller, segment(match[1]))],
  ['POST', /^\/v1\/users\/([^/]{1,400})\/agent-tokens\/([^/]{1,100})\/revoke$/, 'agents:write', ({caller, agentTokens, match}) => agentTokens.revoke(caller, segment(match[1]), match[2])],
  // F03.9: one end user's activity, newest first, grouped by day, with the waiting approvals first (section 5.11).
  ['GET', /^\/v1\/users\/([^/]{1,400})\/activity$/, 'activity:read', ({caller, activity, match, url}) => activity.list(caller, segment(match[1]), Object.fromEntries(['appId', 'accountRef', 'cursor', 'limit'].map(name => [name, url.searchParams.get(name) ?? undefined])))],
  // F03.7c: governed proxy requests; read back and cancel through the executions routes.
  ['POST', /^\/v1\/proxy\/requests$/, 'proxy:write', ({caller, executions, body, headers}) => executions.createProxy(caller, body, headers['idempotency-key'])],
  ['GET', /^\/v1\/accounts$/, 'accounts:read', ({caller, accounts, url}) => accounts.listAll(caller, {externalUserId: url.searchParams.get('externalUserId') ?? undefined, appId: url.searchParams.get('appId') ?? undefined, after: url.searchParams.get('after') ?? undefined, limit: url.searchParams.get('limit') ?? undefined})],
  ['GET', /^\/v1\/accounts\/([^/]{1,100})$/, 'accounts:read', ({caller, accounts, match}) => accounts.getAny(caller, match[1])],
  ['POST', /^\/v1\/accounts\/([^/]{1,100})\/disconnect$/, 'accounts:write', ({caller, accounts, match, body}) => accounts.disconnectAny(caller, match[1], body)],
  ['GET', /^\/v1\/apps$/, 'catalog:read', ({url, origin}) => {
    const limit = url.searchParams.has('limit') ? Number(url.searchParams.get('limit')) : 50;
    try { return tenantCatalog({origin, q: url.searchParams.get('q') || '', categoryIds: url.searchParams.getAll('categoryId'), sort: url.searchParams.get('sort') || 'featured', order: url.searchParams.get('order') || 'asc', after: url.searchParams.get('after') || undefined, limit}); }
    catch (error) { throw invalid(error.message); }
  }],
  ['GET', /^\/v1\/apps\/([a-z][a-z0-9-]{0,63})$/, 'catalog:read', ({match, origin}) => tenantAppDetail(match[1], {origin}) ?? (() => { throw notFound(); })()],
  ['GET', /^\/v1\/apps\/([a-z][a-z0-9-]{0,63})\/consent-sheet$/, 'catalog:read', ({match, origin, url, caller, registry, providerApps}) => {
    try {
      const project = registry.get('projects', caller.scope.projectId), environment = registry.get('environments', caller.scope.environmentId);
      // F10.7 (g4): the access line says what the environment's chosen sign-in app asks for under its consent policy.
      return consentSheet(match[1], {origin, project: {...project, logoUrl: logoUrl(project, origin)}, level: url.searchParams.get('level') || undefined, providerApp: providerApps.sheetApp(caller.scope, environment, match[1]),
        consentMode: providerApps.sheetConsentMode(caller.scope, environment, match[1])}) ?? (() => { throw notFound(); })();
    }
    catch (error) { if (error instanceof ApiError) throw error; throw invalid(error.message); }
  }],
  ['GET', /^\/v1\/categories$/, 'catalog:read', () => ({categories: tenantCategories()})],
  ['GET', /^\/v1\/capabilities$/, 'catalog:read', ({url, catalog, actions}) => {
    const appId = url.searchParams.get('appId'), limit = url.searchParams.has('limit') ? Number(url.searchParams.get('limit')) : 50, after = url.searchParams.get('after'), kind = url.searchParams.get('kind');
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw invalid('limit must be 1 to 100.');
    if (kind !== null && kind !== 'operation' && kind !== 'action') throw invalid('kind is operation or action.');
    // F10.11 part m: an action is listed only while the action catalog runs it; actions first, then operations, each part by id; `kind`
    // keeps one part. The cursor stays an id.
    const listed = (catalog ? catalog.list('capabilities') : []).filter(capability => capability.status === 'active' && (!appId || capability.appId === appId) && (capability.driver !== 'action' || runs(actions, capability))
      && (kind === null || (capability.driver === 'action' ? 'action' : 'operation') === kind)).sort((a, b) => a.id < b.id ? -1 : 1);
    const all = [...listed.filter(capability => capability.driver === 'action'), ...listed.filter(capability => capability.driver !== 'action')];
    const start = after ? all.findIndex(capability => capability.id === after) + 1 : 0;
    if (after && start === 0) throw invalid('Unknown cursor.');
    // Locked operations stay listed, annotated with their row (F10.3), so a developer sees why a binding of one is refused.
    const page = all.slice(start, start + limit), maps = new Map(), mapOf = id => { if (!maps.has(id)) maps.set(id, catalog.get('applicationMaps', id)); return maps.get(id); };
    return {capabilities: page.map(capability => capabilityView(capability, capabilityRow(capability, mapOf(capability.appId), actions))), pageInfo: {count: page.length, totalCount: all.length, ...(start + limit < all.length ? {endCursor: page.at(-1).id} : {})}};
  }],
  ['GET', /^\/v1\/capabilities\/([A-Za-z0-9._:-]{1,200})$/, 'catalog:read', ({match, catalog, actions}) => {
    // F10.11 part m: an action id a newer version of its file replaced names the action that replaced it.
    const replaced = actions?.superseded?.get?.(match[1]);
    if (replaced) throw new ApiError(409, 'capability_changed', ACTION_WORDS.superseded, {replacedBy: replaced.replacedBy});
    const capability = catalog?.get('capabilities', match[1]);
    if (!capability || capability.status !== 'active' || (capability.driver === 'action' && !runs(actions, capability))) throw notFound();
    const placed = capabilityRow(capability, catalog.get('applicationMaps', capability.appId), actions), view = capabilityView(capability, placed);
    if (capability.driver !== 'action') return {...view, inputSchema: capability.input ?? capability.inputSchema ?? null, optionInputs: optionInputs(capability)};
    // An action's detail adds the schema of its checked output, the rows it touches and its inputs' choices.
    const choices = actionChoices(capability);
    return {...view, inputSchema: capability.inputSchema, optionInputs: choices.map(choice => choice.input).sort(), outputSchema: capability.outputSchema, rows: placed.action.rows, choices};
  }],
];
/** F10.11 part m: whether the action catalog runs this action now: its record is the catalog's current definition and the catalog finds it
 *  active. With no catalog, none runs. */
const runs = (actions, capability) => actions?.entryOf?.(capability)?.status === 'active';
/** A path segment, percent-decoded once; the services check it against the external id rule. */
function segment(value) {
  try { return decodeURIComponent(value); } catch { throw new ApiError(400, 'invalid_external_user_id', 'externalUserId must be 1 to 128 characters: letters, digits and . _ : @ -'); }
}
/** One app's setting in an environment: enabled by default when Fabric's shared app is ready there (D3). */
export function appSetting(appId, environment, providerApps) {
  const availability = providerApps.availability(appId, environment), stored = environment.apps?.[appId] || {};
  const providerApp = typeof stored.providerApp === 'string' && stored.providerApp.startsWith('pa_') ? {kind: 'developer', id: stored.providerApp} : {kind: 'shared'};
  const {providerApp: _ready, ...shown} = availability;
  // Only ceilings on rows that still exist are shown; one left on a removed row is never read and can be cleared with null.
  const rows = new Set((PERMISSION_GROUPS.get(appId)?.groups || []).map(group => group.id)), ceilings = Object.fromEntries(Object.entries(stored.ceilings || {}).filter(([groupId]) => rows.has(groupId)));
  return {appId, enabled: stored.enabled ?? availability.state === 'ready', providerApp, ceilings, availability: shown};
}
export const ROUTES = Object.freeze(TABLE.map(([method, pattern]) => `${method} ${pattern.source.replace(/^\^\\?|\$$/g, '').replace(/\\\//g, '/')}`));

// An oversized body is read and thrown away so the client gets a clear 413, never a dropped connection; only one far
// over the limit (8 times) is cut off. Nothing past the limit is ever kept in memory.
const readBody = req => new Promise((resolve, reject) => {
  let size = 0; const chunks = [];
  req.on('data', chunk => {
    size += chunk.length;
    if (size <= MAX_BODY) chunks.push(chunk);
    else if (size > 8 * MAX_BODY) { reject(new ApiError(413, 'invalid_request', 'The body is larger than 256 KiB.')); req.destroy(); }
  });
  req.on('end', () => size > MAX_BODY ? reject(new ApiError(413, 'invalid_request', 'The body is larger than 256 KiB.')) : resolve(Buffer.concat(chunks)));
  req.on('error', reject);
});

export class TenantApi {
  /** `runtimes` (F10.11 part m) carries the action catalog every environment's runtime reads, so the catalog routes read the same one. */
  constructor({registry, keys, catalog = null, origin, providerApps, sessions, users, accounts, pages, executions, options, approvals, activity, agentTokens, runtimes = null}) { Object.assign(this, {registry, keys, catalog, origin, providerApps, sessions, users, accounts, pages, executions, options, approvals, activity, agentTokens, runtimes}); }
  /** Answers one /v1 request: {status, body}. Never throws. */
  async handle(req, url) {
    const requestId = `req_${randomBytes(9).toString('base64url')}`;
    try {
      if (req.headers.origin !== undefined || req.headers.cookie !== undefined) throw new ApiError(403, 'browser_not_allowed', 'The developer API is for servers; browsers use Connect links.');
      const route = TABLE.find(([method, pattern]) => method === req.method && pattern.test(url.pathname));
      // 1. The key.
      const authorization = req.headers.authorization;
      const caller = this.keys.verify(typeof authorization === 'string' && authorization.startsWith('Bearer ') ? authorization.slice(7) : undefined);
      if (!route) throw notFound();
      // 2. The scope, before anything is looked up.
      const [, pattern, scope, handler, options = {}] = route;
      // Some routes need two scopes (an end user's catalog needs catalog:read and accounts:read); a few take any one of several.
      if (scope?.anyOf) { if (!scope.anyOf.some(item => caller.scopes.includes(item))) throw new ApiError(403, 'forbidden_scope', `This key lacks the ${scope.anyOf.join(' or ')} scope.`); }
      else {
        const lacking = (Array.isArray(scope) ? scope : [scope]).find(item => !caller.scopes.includes(item));
        if (lacking) throw new ApiError(403, 'forbidden_scope', `This key lacks the ${lacking} scope.`);
      }
      if ([scope].flat().some(item => RESERVED_SCOPES.includes(item))) throw new ApiError(422, 'not_available', 'Triggers and events are not available yet.');
      let body;
      const contentType = req.headers['content-type'];
      if (req.method !== 'GET') {
        const raw = await readBody(req);
        if (options.raw) {
          // A file route takes its bytes as sent, with one of its declared types; the handler checks the bytes themselves.
          if (!options.raw.includes(String(contentType || '').split(';')[0].trim().toLowerCase())) throw invalid(`Send ${options.raw.join(' or ')}.`);
          if (raw.length > options.max) throw invalid(`The file is larger than ${Math.round(options.max / 1024)} KiB.`);
          body = raw;
        } else if (raw.length || contentType !== undefined) {
          // An action with no body (cancel, link) may send none; anything sent must be JSON.
          if (!/^application\/json(;|$)/.test(contentType || '')) throw invalid('Send JSON with Content-Type application/json.');
          try { body = JSON.parse(raw.toString('utf8')); } catch { throw invalid('The body is not valid JSON.'); }
        }
      }
      const result = await handler({caller, registry: this.registry, catalog: this.catalog, actions: this.runtimes?.actions ?? null, origin: this.origin, providerApps: this.providerApps, sessions: this.sessions, users: this.users, accounts: this.accounts, pages: this.pages, executions: this.executions, options: this.options, approvals: this.approvals, activity: this.activity, agentTokens: this.agentTokens, url, body, contentType, headers: req.headers, match: url.pathname.match(pattern)});
      return result && typeof result.status === 'number' && (result.body || result.status === 204) ? result : {status: 200, body: result};
    } catch (error) {
      const known = error instanceof ApiError ? error : error instanceof SessionError || error instanceof TenantError ? Object.assign(new ApiError(error.status, error.code, error.message, error.details), error.headers ? {headers: error.headers} : {}) : error instanceof KeyError ? new ApiError(401, 'unauthorized', error.message) : error instanceof TenantRecordError ? new ApiError(400, 'invalid_request', error.message) : null;
      if (!known) return {status: 500, body: {error: {code: 'internal_error', message: 'Something went wrong. Nothing was changed.', requestId}}};
      return {status: known.status, ...(known.headers ? {headers: known.headers} : {}), body: {error: {code: known.code, message: known.message, requestId, ...(known.details ? {details: known.details} : {})}}};
    }
  }
}

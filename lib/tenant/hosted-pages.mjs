// F03.10 (docs/F03-DEVELOPER-LAYER.md sections 5.13 and 6): the data behind Fabric's hosted manage and approval pages.
// Every method starts from the browser's own claimed session (sessions.pageCaller): the person, the environment and the
// party come from the session, never from anything the page sends, and no method takes an external user id. A manage
// link shows one person's connected apps, their permissions, background reads, disconnect and activity (never a
// decision on an approval); an approve link shows and decides its one call. Answers are the person's own view: the
// account fields a person sees, no proxy rows, no provider data from a run.
import {TenantError, notFound, invalid} from './errors.mjs';
import {endUserAccountRow, signInOf, tenantApps} from './views.mjs';
import {approvalPage} from '../ui-contracts.mjs';
import {preparedReader} from './approvals.mjs';

const APP = /^[a-z][a-z0-9-]{0,63}$/;
/** The page's own words for a refusal the developer's API words for a developer. */
const PAGE_WORDS = {
  confirm_required: 'Allow lets the agent do this without asking you first. Confirm to turn it on.',
  etag_mismatch: 'This setting changed since the page loaded. Reload the page and try again.',
  mode_not_allowed: 'That choice is not available for this permission here.',
  decision_not_permitted: 'This choice cannot be made from this page.',
  connection_required: 'This account needs to be connected again before its permissions change.',
};
const worded = error => error instanceof TenantError && PAGE_WORDS[error.code] ? new TenantError(error.status, error.code, PAGE_WORDS[error.code]) : error;
/** Icons as paths on Fabric's own origin, which the page's policy allows. */
const iconPath = card => card && typeof card.iconUrl === 'string' ? {...card, iconUrl: `/assets/icons/${encodeURIComponent(card.id)}`} : card;

export class TenantHostedPages {
  /** @param {{sessions: any, pages: any, accounts: any, approvals: any, activity: any, stores: any, registry: any}} deps */
  constructor({activity, ...deps}) { Object.assign(this, deps, {activities: activity}); }

  #manage(id, binding) {
    const caller = this.sessions.pageCaller(id, binding, ['manage']);
    return {...caller, actor: {scope: caller.scope, owner: caller.owner, party: caller.party}, env: this.stores.open(caller.scope)};
  }
  /** The app a manage request names: an app-scoped link manages that app only, and a malformed or unknown app is not_found. */
  #app(caller, appId) {
    if (typeof appId !== 'string' || !APP.test(appId) || !tenantApps().some(app => app.id === appId)) throw notFound();
    if (caller.session.appId && caller.session.appId !== appId) throw notFound();
    return appId;
  }
  /** One of the person's present accounts of this app, or the same not_found as for anyone else's (N2). */
  #account(caller, appId, accountRef) {
    const connection = this.accounts.ownedAccount(caller.env, caller.owner, accountRef);
    if (connection.appId !== appId) throw notFound();
    return connection;
  }
  #worded(work) { try { return work(); } catch (error) { throw worded(error); } }

  // ---- manage --------------------------------------------------------------------------------------------------
  /** The person's connected apps (Q5): nothing to connect from here, so only what they already have. */
  catalog(id, binding, {q, categoryId, cursor, limit} = {}) {
    const caller = this.#manage(id, binding);
    if (caller.session.appId) throw notFound();
    const page = this.#worded(() => this.pages.catalogFor(caller.actor, {status: 'connected', q, categoryId, cursor, limit}));
    return {...page, featured: page.featured.map(iconPath), categories: page.categories.map(entry => ({...entry, preview: entry.preview.map(iconPath)})), ...(page.results ? {results: page.results.map(iconPath)} : {})};
  }
  /** One app for the person: their accounts of it (by the person's own fields), its permission rows and background reads. */
  app(id, binding, appId, accountRef) {
    const caller = this.#manage(id, binding);
    this.#app(caller, appId);
    const view = this.#worded(() => this.pages.viewFor(caller.actor, appId, accountRef, {endUser: true}));
    return {...view, app: iconPath(view.app), scoped: Boolean(caller.session.appId)};
  }
  setRow(id, binding, appId, accountRef, body) {
    const caller = this.#manage(id, binding);
    this.#account(caller, this.#app(caller, appId), accountRef);
    return this.#worded(() => this.pages.setRowFor(caller.actor, accountRef, body, {proxyAllowed: false}));
  }
  reset(id, binding, appId, accountRef, body) {
    const caller = this.#manage(id, binding);
    this.#account(caller, this.#app(caller, appId), accountRef);
    return this.#worded(() => this.pages.resetFor(caller.actor, accountRef, body));
  }
  background(id, binding, appId, accountRef, body) {
    const caller = this.#manage(id, binding);
    this.#account(caller, this.#app(caller, appId), accountRef);
    return this.#worded(() => this.pages.setBackgroundFor(caller.actor, accountRef, body));
  }
  async disconnect(id, binding, appId, accountRef, body) {
    const caller = this.#manage(id, binding);
    this.#account(caller, this.#app(caller, appId), accountRef);
    // F10.4: this page disconnects here only. A revoke at the provider, and its confirm of the other accounts it signs out, is the
    // developer's API power (N9), so the page never asks for one, whatever the account's sign-in app.
    if (body?.remote === true) throw new TenantError(422, 'remote_unavailable', `This page disconnects the account here only and never asks ${signInOf(appId)?.definition.displayName ?? 'the provider'} to revoke access. To remove the access everywhere, use your account settings there.`);
    try { return await this.accounts.disconnectFor(caller.env, caller.owner, accountRef, body, caller.party, {row: endUserAccountRow}); }
    catch (error) { throw worded(error); }
  }
  /** The person's activity; an app-scoped link sees that app's only. Waiting approvals carry no decision here (D5). */
  activity(id, binding, {appId, accountRef, cursor, limit} = {}) {
    const caller = this.#manage(id, binding);
    const forced = caller.session.appId ?? appId;
    if (appId !== undefined && caller.session.appId && appId !== caller.session.appId) throw notFound();
    return this.activityOf(caller, {...(forced !== undefined ? {appId: forced} : {}), ...(accountRef !== undefined ? {accountRef} : {}), ...(cursor !== undefined ? {cursor} : {}), ...(limit !== undefined ? {limit} : {})});
  }
  activityOf(caller, query) { return this.#worded(() => this.activities.listFor(caller.env, caller.owner, query, {decidePath: null})); }

  // ---- approve -------------------------------------------------------------------------------------------------
  #decidePath(sessionId, callRef) { return `/connect/${sessionId}/v1/approvals/${callRef}/decision`; }
  /**
   * The one call this approve link is for, as its page shows it. F10.11 part n: on a link that continues an action past its phase reads
   * stop, a read that finds the call ended (it ran on under Allow, or failed) finishes the link, and says how (`finished`), so the person
   * gets back to the developer's app.
   */
  approval(id, binding) {
    const caller = this.sessions.pageCaller(id, binding, ['approve']), env = this.stores.open(caller.scope);
    const page = this.approvals.pageFor(env, caller.owner, caller.session.callRef, {decidePath: job => this.#decidePath(id, job.id)});
    if (caller.session.state !== 'continuing' || page.state !== 'settled' || ['queued', 'running'].includes(page.status)) return page;
    return {...page, finished: this.sessions.finishPage(caller.scope, caller.session, {callRef: caller.session.callRef, decision: 'approved'})};
  }
  /**
   * The person's decision on this link's own call (D5, F03.9 rule: only an approve session decides, only its call). The
   * session then ends completed. The answer is what happened, never the execution, which can carry provider data.
   * F10.11 part n: one link carries both phases of an action. Approving its phase reads stop does not end the link: the session continues
   * ({state: 'continuing'}) while Fabric prepares the exact request, and the same link shows the next stop. A reject at either phase, or
   * a decision on the final stop, ends it. A refusal (another digest, a call no longer waiting) leaves it open for the page to reload.
   */
  decide(id, binding, callRef, body) {
    const caller = this.sessions.pageCaller(id, binding, ['approve']), env = this.stores.open(caller.scope);
    if (typeof callRef !== 'string' || callRef !== caller.session.callRef) throw notFound();
    if (body === null || typeof body !== 'object' || Array.isArray(body)) throw invalid('The body must be a JSON object.');
    const job = this.approvals.decideFor(caller.scope, caller.owner, callRef, body, caller.party, {requireComplete: true});
    const stop = job.kind === 'action' ? job.action?.decisions?.at(-1) : null;
    if (stop?.phase === 'reads' && stop.decision === 'approved') {
      this.sessions.continuePage(caller.scope, caller.session);
      return {state: 'continuing', decision: 'approved', phase: 'reads'};
    }
    const finished = this.sessions.finishPage(caller.scope, caller.session, {callRef, decision: job.decision?.decision ?? (body.decision === 'approve' ? 'approved' : 'rejected')});
    const names = new Map(tenantApps().map(app => [app.id, app.name]));
    const page = approvalPage(job, {appName: appId => names.get(appId) ?? appId ?? null, prepared: preparedReader(env), now: Date.parse(this.registry.now())});
    return {state: 'completed', decision: body.decision === 'approve' ? 'approved' : 'rejected', status: page.status ?? job.status, summary: page.summary ?? null, ...(finished.redirect ? {redirect: finished.redirect} : {}), ...(finished.opener ? {opener: finished.opener} : {})};
  }
}

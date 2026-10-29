import {signInTarget} from './sign-in-target.js';
import {visible} from './hosted-text.js';

// Owner page for a missing-access handoff (F02.4). The link carries only the handoff id; every
// fact shown comes from the owner's authenticated session, and every decision sends back the
// digest of exactly what was shown. Every button is data (label plus exact request) built by
// describeHandoff and sent by decide, both exported and tested; the DOM code only maps them.

const EFFECT = {read: 'Reads data', write: 'Changes data', delete: 'Deletes data'};
const ATTEMPT = {
  declined_at_provider: provider => `You declined on ${provider}. You can try again or choose another option.`,
  insufficient_scope: provider => `${provider} did not grant every permission this request needs. No account was connected.`,
  sign_in_failed: provider => `Signing in to ${provider} did not complete. No account was connected.`,
  scope_refused: (provider, signIn) => `${provider} granted a permission Fabric never holds. No account was connected. You can remove Fabric ${signIn?.settingsUrl ? `at ${signIn.settingsUrl}` : `in your ${provider} account settings`}, then sign in again.`,
  sign_in_interrupted: () => 'Fabric restarted while you were signing in. No account was connected; you can try again.',
  wrong_account: () => 'That account was disconnected. Choose another account or sign in again.',
};
const OUTCOME = {
  owner_declined: 'You declined this request. The agent was told no account will be connected.',
  client_cancelled: 'The agent withdrew this request.',
  client_revoked: 'This agent no longer has access, so the request was closed.',
  continuation_expired: 'This request expired before an account was chosen. The agent must ask again.',
  authority_changed: 'Permissions or the operation changed, so nothing was run. The agent can ask again.',
  capability_retired: 'This operation is no longer available.',
  policy_denied: 'The chosen account is not permitted to run this operation. Nothing was run.',
  fabric_failed: 'Fabric could not continue this request.',
};
/** Why an account cannot be used, in owner language; the server's own sentence when it gives one. */
function unavailable(reason) {
  if (reason === 'reconnect_required') return 'Reconnect this account before it can be used.';
  return typeof reason === 'string' && reason.includes(' ') ? reason : 'Not permitted for this operation.';
}
const AFTER = {runs_now: 'Runs right away.', asks_approval: 'You will approve the exact action next.', blocked: 'Not permitted for this operation.'};
/** F10.7: what the sign-in asks the provider for. A version 2 app asks for full access (Notion: the pages you pick); a version 1 app
 *  for its read and write set. Anything else promises nothing. */
function accessWords(signIn) {
  const more = signIn.scopes?.length ? ' plus what this request needs' : '', provider = signIn.providerName;
  if (signIn.access === 'full') return `Asks ${provider} for full access${more}. `;
  if (signIn.access === 'pages') return `${provider} asks you to pick the pages Fabric may use. `;
  return signIn.writeAccess ? `Asks ${provider} for read and write access${more}. ` : '';
}
const RESULT = {
  succeeded: 'Done. The request ran on the account you chose.',
  failed: 'The request did not complete. Nothing further will run automatically.',
  uncertain: 'Fabric could not confirm whether the request took effect. It will not be repeated automatically.',
  cancelled: 'The request was cancelled before it ran.',
  queued: 'Running the request…',
  running: 'Running the request…',
};
export {visible};

/** "createIssue" or "list_repos" read as words; a lowercase lead keeps the sentence natural, acronyms stay. */
function phrase(name) {
  const words = /\s/.test(name) ? name : name.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').toLowerCase();
  return /^[A-Z][a-z]*(\s|$)/.test(words) ? words.charAt(0).toLowerCase() + words.slice(1) : words;
}
/** An account as the owner recognises it: the workspace first where the provider has one. */
function who(identity, fallback) {
  const name = identity?.workspaceName || identity?.displayName || fallback;
  const detail = [identity?.workspaceName ? identity?.displayName : null, identity?.email].filter(Boolean).join(' · ');
  return {name, detail};
}

/** Turns an owner view into what the page shows and the exact request each button sends. No DOM access. */
export function describeHandoff(view, now = Date.now()) {
  const base = `/api/continuations/${encodeURIComponent(view.id)}`;
  const app = view.app?.name || view.app?.id || 'the app';
  const client = view.client?.name || 'An agent';
  const operation = phrase(view.operation?.name || view.operation?.capabilityId?.split('.').pop() || 'run an operation');
  const provider = view.signIn?.providerName || app;
  const model = {
    title: `${client} wants to ${operation} in ${app}`,
    effect: EFFECT[view.operation?.effect] || 'Uses data', args: visible(JSON.stringify(view.arguments ?? {}, null, 2)), argsOpen: false,
    deadline: null, stage: 'closed', notice: null, accounts: [], signIn: null, pending: null, approval: null, result: null, buttons: [],
  };
  if (view.phase === 'awaiting_owner' || view.phase === 'signing_in') {
    model.stage = 'choose'; model.deadline = view.expiresAt; model.argsOpen = true;
    // A failed earlier attempt matters only while the owner is choosing again.
    if (view.lastAttempt && ATTEMPT[view.lastAttempt.outcome]) model.notice = {kind: 'warn', text: ATTEMPT[view.lastAttempt.outcome](provider, view.signIn)};
    model.accounts = (view.accounts || []).map(account => {
      const shown = who(account.identity, account.label || 'Account');
      return {connectionId: account.connectionId, label: shown.name, detail: shown.detail || (shown.name !== account.label ? account.label || '' : ''),
        eligible: account.eligible === true, hint: account.eligible === true ? AFTER[account.afterSelection] || '' : unavailable(account.reason),
        request: account.eligible === true ? {path: `${base}/select`, body: {connectionId: account.connectionId, viewDigest: view.viewDigest}} : null};
    });
    if (view.signIn) {
      const access = accessWords(view.signIn);
      model.signIn = {label: `Sign in to ${view.signIn.providerName}`, providerId: view.signIn.providerId, available: view.signIn.available === true, reason: view.signIn.reason,
        hint: view.signIn.available ? `${view.phase === 'signing_in' ? 'A sign-in is open. ' : ''}${access}${AFTER[view.signIn.afterSignIn] || ''}` : view.signIn.reason,
        request: view.signIn.available === true ? {path: `${base}/sign-in`, body: {viewDigest: view.viewDigest}} : null};
    }
    for (const account of model.accounts) if (account.request) model.buttons.push({key: `use:${account.connectionId}`, label: 'Use this account', variant: 'primary', request: account.request});
    if (model.signIn?.request) model.buttons.push({key: 'sign-in', label: 'Sign in', variant: 'secondary', request: model.signIn.request, signIn: {providerId: model.signIn.providerId}});
  } else if (view.phase === 'awaiting_confirmation' && view.pendingConnection) {
    model.stage = 'confirm'; model.deadline = view.expiresAt; model.argsOpen = true;
    const shown = who(view.pendingConnection.identity, 'Signed-in account');
    model.pending = {name: shown.name, email: view.pendingConnection.identity?.email || '', detail: shown.detail,
      duplicate: Boolean(view.pendingConnection.duplicateOf), hint: AFTER[view.pendingConnection.afterConfirm] || '',
      confirm: {path: `${base}/confirm`, body: {confirmDigest: view.confirmDigest}}, reject: {path: `${base}/reject-account`, body: {}}};
    model.buttons.push({key: 'confirm', label: `Continue as ${shown.name}`, variant: 'primary', request: model.pending.confirm},
      {key: 'reject', label: 'Not this account', variant: 'secondary', request: model.pending.reject});
  } else if (view.phase === 'continuing') {
    model.stage = 'continuing';
  } else if (view.phase === 'awaiting_approval' && view.derived?.approval) {
    const job = `/api/jobs/${encodeURIComponent(view.derived.jobId)}`;
    model.approval = {preview: view.derived.approval.preview || {}, expiresAt: view.derived.approval.expiresAt,
      approve: {path: `${job}/approve`, body: {approvalDigest: view.derived.approval.digest}}, cancel: {path: `${job}/cancel`, body: {}}};
    model.argsOpen = true; model.deadline = view.derived.approval.expiresAt;
    // An approval past its own deadline can no longer run; only cancelling is offered.
    if (!(Date.parse(view.derived.approval.expiresAt) > now)) {
      model.stage = 'approval_expired'; model.deadline = null;
      model.notice = {kind: 'warn', text: 'The time to approve this action has passed. Nothing was run. Cancel the request; the agent can ask again.'};
      model.buttons.push({key: 'cancel', label: 'Cancel request', variant: 'secondary', request: model.approval.cancel});
    } else {
      model.stage = 'approve';
      model.buttons.push({key: 'approve', label: 'Approve', variant: 'primary', request: model.approval.approve}, {key: 'cancel', label: 'Cancel request', variant: 'secondary', request: model.approval.cancel});
    }
  } else if (view.phase === 'connected') {
    model.stage = 'done';
    model.result = {status: view.derived?.status || 'queued', text: RESULT[view.derived?.status] || RESULT.queued, detail: typeof view.derived?.error === 'string' ? view.derived.error : ''};
  } else if (view.outcome) {
    model.notice = {kind: 'info', text: OUTCOME[view.outcome.code] || 'This request is closed.'};
  }
  model.decline = Array.isArray(view.actions) && view.actions.includes('decline') ? {path: `${base}/decline`, body: {}} : null;
  if (model.decline) model.buttons.push({key: 'decline', label: 'Decline request', variant: 'danger', request: model.decline});
  return model;
}

export {signInTarget};

/** Sends one button's exact request; a sign-in button then navigates only to the provider's declared origin. */
export async function decide(button, {send, assign, oauthProviders}) {
  const result = await send(button.request);
  if (button.signIn) assign(signInTarget(result?.authorizationUrl, oauthProviders?.[button.signIn.providerId]?.authorizationOrigin));
  return result;
}

/** True while the page should keep refreshing on its own. */
export function shouldPoll(model) {
  return model.stage === 'continuing' || model.stage === 'done' && ['queued', 'running'].includes(model.result?.status);
}

// ---- browser ------------------------------------------------------------------------
if (typeof document !== 'undefined') {
  const id = location.pathname.split('/').pop();
  const root = document.querySelector('#handoff'), live = document.querySelector('#status');
  let session = null, timer = null, busy = false, shown = '', argsOpen = null, failures = 0;
  const el = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) { if (key === 'onclick') node.addEventListener('click', value); else if (value !== false && value !== undefined && value !== null) node.setAttribute(key, value === true ? '' : value); }
    for (const child of children.flat()) if (child !== null && child !== undefined && child !== false) node.append(child);
    return node;
  };
  const say = (text, kind = 'info') => { live.textContent = text; live.className = `status ${kind}`; live.hidden = !text; };
  async function api(path, body, retried = false) {
    const response = await fetch(path, {method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', headers: body === undefined ? {} : {'Content-Type': 'application/json', 'X-Fabric-CSRF': session?.csrfToken || ''}, body: body === undefined ? undefined : JSON.stringify(body)});
    let data = {};
    try { data = await response.json(); } catch {}
    // After Fabric restarts the session is new: refresh it once and resend the same request.
    if (response.status === 403 && body !== undefined && !retried) { session = await api('/api/state'); return api(path, body, true); }
    if (!response.ok) { const error = new Error(data.error || `Request failed (${response.status})`); error.code = data.code; error.view = data.view; throw error; }
    return data;
  }
  const deps = () => ({send: request => api(request.path, request.body), assign: url => location.assign(url), oauthProviders: session?.settings?.oauthProviders});
  // One decision at a time: a second press while a request is in flight is ignored, never re-sent.
  async function act(button) {
    if (busy) return;
    busy = true; say('');
    for (const node of root.querySelectorAll('button')) node.disabled = true;
    try { await decide(button, deps()); }
    catch (error) {
      // The server sends the fresh view whenever the request changed under the owner; show it with the reason.
      if (error.view) { busy = false; shown = ''; render(error.view); say(error.code === 'view_changed' ? 'Something changed while you were looking. Review the request again.' : error.message, 'warn'); return; }
      say(error.message, 'error');
    }
    busy = false; shown = '';
    await load();
  }
  const buttonNode = button => el('button', {type: 'button', class: `button ${button.variant === 'primary' ? '' : button.variant}`.trim(), 'data-key': button.key, onclick: () => act(button)}, button.label);
  function render(view) {
    const model = describeHandoff(view);
    const signature = JSON.stringify(model);
    if (signature === shown) return schedule(model);
    const focused = document.activeElement?.dataset?.key;
    shown = signature;
    const byKey = new Map(model.buttons.map(button => [button.key, button]));
    const details = el('details', {class: 'arguments', open: argsOpen ?? model.argsOpen}, el('summary', {}, 'Exact request'), el('pre', {}, model.args));
    details.addEventListener('toggle', () => { argsOpen = details.open; });
    const parts = [
      el('p', {class: 'eyebrow'}, 'Account request'),
      el('h1', {}, model.title),
      el('p', {class: 'meta'}, el('span', {class: `badge ${view.operation?.effect || 'read'}`}, model.effect), model.deadline ? ` · Answer before ${new Date(model.deadline).toLocaleString()}` : ''),
      details,
    ];
    if (model.notice) parts.push(el('p', {class: `notice ${model.notice.kind}`}, model.notice.text));
    if (model.stage === 'choose') {
      parts.push(el('h2', {}, 'Choose the account'));
      const list = el('ul', {class: 'choices'});
      for (const account of model.accounts) list.append(el('li', {},
        el('div', {class: 'choice-copy'}, el('strong', {}, account.label), account.detail ? el('span', {}, account.detail) : null, el('span', {class: 'hint'}, account.hint)),
        byKey.has(`use:${account.connectionId}`) ? buttonNode(byKey.get(`use:${account.connectionId}`)) : el('button', {type: 'button', class: 'button', disabled: true}, 'Use this account')));
      if (model.signIn) list.append(el('li', {},
        el('div', {class: 'choice-copy'}, el('strong', {}, model.signIn.label), el('span', {class: 'hint'}, model.signIn.hint || '')),
        byKey.has('sign-in') ? buttonNode(byKey.get('sign-in')) : el('button', {type: 'button', class: 'button secondary', disabled: true}, 'Sign in')));
      if (!list.children.length) list.append(el('li', {}, el('span', {class: 'hint'}, 'No account can be used for this request here.')));
      parts.push(list);
    } else if (model.stage === 'confirm') {
      parts.push(el('h2', {}, 'Confirm the signed-in account'),
        el('div', {class: 'identity'}, el('strong', {}, model.pending.name), model.pending.detail ? el('span', {}, model.pending.detail) : null,
          model.pending.duplicate ? el('span', {class: 'hint'}, 'This account is already connected; the request will use this new connection.') : null, el('span', {class: 'hint'}, model.pending.hint)),
        el('div', {class: 'actions'}, buttonNode(byKey.get('confirm')), buttonNode(byKey.get('reject'))));
    } else if (model.stage === 'continuing') {
      parts.push(el('p', {class: 'notice info'}, 'Connecting the account to the request…'));
    } else if (model.stage === 'approve' || model.stage === 'approval_expired') {
      const {preview} = model.approval;
      parts.push(el('h2', {}, model.stage === 'approve' ? 'Approve the exact action' : 'Approval expired'),
        el('dl', {class: 'preview'}, el('dt', {}, 'Account'), el('dd', {}, preview.account?.displayName || preview.account?.label || ''), el('dt', {}, 'Operation'), el('dd', {}, preview.operation || ''),
          preview.request ? [el('dt', {}, 'Request'), el('dd', {}, visible(`${preview.request.method} ${preview.request.url}`))] : null,
          preview.request?.body !== undefined && preview.request?.body !== null ? [el('dt', {}, 'Body'), el('dd', {}, el('pre', {}, visible(typeof preview.request.body === 'string' ? preview.request.body : JSON.stringify(preview.request.body, null, 2))))] : null),
        el('div', {class: 'actions'}, model.buttons.filter(button => button.key === 'approve' || button.key === 'cancel').map(buttonNode)));
    } else if (model.stage === 'done') {
      parts.push(el('p', {class: `notice ${model.result.status === 'succeeded' ? 'info' : 'warn'}`}, model.result.text));
      if (model.result.detail) parts.push(el('p', {class: 'hint'}, model.result.detail));
    }
    if (byKey.has('decline')) parts.push(el('div', {class: 'actions decline'}, buttonNode(byKey.get('decline'))));
    root.replaceChildren(...parts);
    // Refreshes keep the owner's place: the focused button stays focused when it still exists.
    if (focused) root.querySelector(`[data-key="${CSS.escape(focused)}"]`)?.focus();
    schedule(model);
  }
  function schedule(model) {
    clearTimeout(timer);
    if (shouldPoll(model)) timer = setTimeout(load, 2000);
  }
  async function load() {
    try {
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id)) throw Object.assign(new Error('This link is not a Fabric account request.'), {code: 'not_found'});
      if (!session) session = await api('/api/state');
      render(await api(`/api/continuations/${id}`));
      if (failures) { failures = 0; say(''); }
    } catch (error) {
      // A lost connection keeps the last view and retries; only an answer from Fabric replaces it.
      if (shown && !error.code) {
        failures += 1; say('Cannot reach Fabric right now. Retrying…', 'warn');
        clearTimeout(timer); timer = setTimeout(load, Math.min(2000 * 2 ** failures, 30000));
        return;
      }
      shown = '';
      root.replaceChildren(el('h1', {}, error.code === 'not_found' ? 'This request was not found' : 'This request cannot be shown'), el('p', {}, error.message));
    }
  }
  load();
}

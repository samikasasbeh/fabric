// The approval page a chat card links to (UI-3, docs/UI-3-CARDS.md), served at /approve/<call>.
// Renders only GET /api/ui/approvals/<call>: the exact action while it can still be approved,
// otherwise what happened. Approve posts the digest of the action shown, nothing else. Opened from a developer's
// approval link (F03.10, /connect/<session>/approve) it shows that link's one call; Approve or Reject ends the link.
// F10.11 part n: an action may stop twice. Approving its first stop (phase reads) keeps the link open: the page says Fabric is preparing
// the exact request, reads the approval again once a second, and shows the next stop on the same link.
import {describeApproval} from './hosted-approval.js';
import {visible} from './hosted-text.js';
import {baseFor, makeApi, applyBrand, tellOpener} from './hosted-base.js';

/**
 * What the page says for one approval view: Fabric's heading, the lines under it (the agent's own title
 * labelled as the agent's), the exact action, and which buttons it offers.
 */
export function describePage(page, {tenant = false} = {}) {
  if (page.state === 'pending') {
    const model = describeApproval({...page.approval}, {tenant});
    // On a developer's approval link the person is told which of their own accounts the call acts on.
    const who = tenant ? (model.account ? `On your account ${model.account}` : null) : [model.account, model.agent ? `asked by ${model.agent}` : null].filter(Boolean).join(' · ');
    return {heading: model.heading, notes: [...model.warnings, model.agentSays, who, model.incomplete].filter(Boolean),
      exact: model.blocks, expiresAt: model.expiresAt, approve: model.approve, cancel: model.cancel};
  }
  const heading = `${visible(page.operation)} in ${visible(page.appName)}`, agentSays = page.taskTitle ? `Agent says: “${visible(page.taskTitle)}”` : null;
  if (page.state === 'expired') return {heading, notes: [page.summary, agentSays].filter(Boolean), exact: null, expiresAt: null, approve: null, cancel: page.cancel};
  return {heading, notes: [`${page.summary}.`, 'No approval is waiting for this action.', agentSays].filter(Boolean), exact: null, expiresAt: null, approve: null, cancel: null};
}

/** The page's buttons and the exact request each one sends: Approve posts the approval, Cancel the cancellation. */
export function buttonsFor(model, {tenant = false} = {}) {
  if (tenant) return [model.approve ? {label: 'Approve', request: model.approve, done: 'Approved.'} : null, model.cancel ? {label: 'Reject', request: model.cancel, done: 'Rejected. Nothing ran.'} : null].filter(Boolean);
  return [model.approve ? {label: 'Approve', request: model.approve, done: 'Approved.'} : null,
    model.cancel ? {label: model.approve ? 'Cancel' : 'Remove it', request: model.cancel, done: 'Cancelled. Nothing ran.'} : null].filter(Boolean);
}

/** What the page says once the person decided on an approval link: the outcome, and Return when the app gave an address. F10.11 part n:
 *  an approved first stop of an action keeps the link open while Fabric prepares the exact request (`continuing`). A continued link can
 *  also find its call cancelled (another party rejected the next stop), which did not complete either. */
export function outcomeOf(result) {
  if (result?.state === 'continuing') return {line: 'Approved. Fabric is preparing the exact request.', redirect: null, continuing: true};
  const line = result?.decision === 'approved' ? (result.status === 'succeeded' ? 'Approved. It ran.' : result.status === 'failed' || result.status === 'cancelled' ? 'Approved, but it did not complete.' : result.status === 'uncertain' ? 'Approved. It ran, but Fabric could not confirm the result.' : 'Approved. It is running.') : 'Rejected. Nothing ran.';
  return {line, redirect: typeof result?.redirect === 'string' ? result.redirect : null};
}

/** F10.11 part n: a refusal that means the call moved on since the page loaded it (a decision made elsewhere, or its next stop), so the
 *  page shows the call again instead of ending. */
export const reloadsOn = error => ['digest_mismatch', 'not_awaiting_approval'].includes(error?.code);
/** F10.11 part n: while an approved first stop prepares, whether a fresh read of the approval is something new to show: another approval
 *  (a new digest, in either phase) or an end state. A call still queued or running is neither. */
export const moved = (page, digest) => page?.state === 'pending' ? page.approval?.digest !== digest : !(page?.state === 'settled' && ['queued', 'running'].includes(page.status));

// ---- browser ------------------------------------------------------------------------
if (typeof document !== 'undefined') {
  const root = document.querySelector('#approval'), live = document.querySelector('#status'), base = baseFor(location.pathname), api = makeApi(base, fetch.bind(window));
  const callId = location.pathname.split('/')[2];
  let busy = false, link = null;
  const el = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) { if (key === 'onclick') node.addEventListener('click', value); else if (value !== false && value !== undefined && value !== null) node.setAttribute(key, value === true ? '' : value); }
    for (const child of children.flat()) if (child !== null && child !== undefined && child !== false) node.append(child);
    return node;
  };
  const say = (text, kind = 'info') => { live.textContent = text; live.dataset.kind = kind; live.hidden = !text; };
  async function decide(request, done) {
    if (busy) return;
    busy = true; say('');
    if (base.tenant) {
      // The decision ends the link: show what happened, and Return to the developer's app when it gave an address. An approved first stop
      // of an action keeps it open for the next one; a call that moved on meanwhile is shown again.
      try {
        const result = await api(request.path, request.body);
        if (result?.state === 'continuing') { busy = false; return prepare(request.body.digest); }
        showOutcome({...outcomeOf(result), popup: tellOpener(result, window.opener)});
      } catch (error) { if (reloadsOn(error)) { busy = false; return load(); } say(error.message, 'error'); }
      finally { busy = false; }
      return;
    }
    try { const job = await api(request.path, request.body); say(job?.status === 'succeeded' ? 'Approved. It ran.' : job?.status === 'uncertain' ? 'Approved. It ran, but Fabric could not confirm the result.' : job?.status === 'failed' ? 'Approved, but it did not complete.' : done); }
    catch (error) { say(error.message, 'error'); }
    finally { busy = false; await load(); }
  }
  /** After an approved first stop: re-read the approval once a second until it shows another stop or how the call ended. */
  async function prepare(digest) {
    say(outcomeOf({state: 'continuing'}).line);
    root.setAttribute('aria-busy', 'true');
    for (;;) {
      await new Promise(resolve => setTimeout(resolve, 1000));
      let page;
      try { page = await api(base.approvalApi(callId)); } catch (error) { root.setAttribute('aria-busy', 'false'); return showError(error); }
      if (!moved(page, digest)) continue;
      say('');
      return render(page);
    }
  }
  function showError(error) {
    root.replaceChildren(el('p', {class: 'empty'}, error.code === 'expired' ? 'This link has expired. Ask the app for a new one. Nothing was decided.' : error.code === 'already_finished' ? 'This link has already been used.' : error.message || 'The approval could not be loaded.'));
    root.setAttribute('aria-busy', 'false');
  }
  function showOutcome({line, redirect, popup}) {
    // In a popup the opener was told; Done closes it. On a full page, Return goes back to the developer's app.
    const action = popup ? el('button', {type: 'button', class: 'text-accent', onclick: () => window.close()}, 'Done')
      : redirect ? el('button', {type: 'button', class: 'text-accent', onclick: () => location.assign(redirect)}, `Return to ${link?.developer?.appName || 'the app'}`) : null;
    root.replaceChildren(el('section', {class: 'group approval'}, el('h1', {}, line), action ? el('div', {class: 'confirm-actions'}, action) : el('p', {class: 'lede'}, 'You can close this window.')));
    root.querySelector('h1')?.focus?.();
  }
  function render(page) {
    // A continued link whose call ended without another stop finished there: show how, as after a decision.
    if (base.tenant && page.finished) return showOutcome({...outcomeOf({decision: 'approved', status: page.status, redirect: page.finished.redirect}), popup: tellOpener(page.finished, window.opener)});
    const model = describePage(page, {tenant: base.tenant});
    const parts = [base.tenant ? null : el('a', {class: 'back', href: '/activity'}, '‹ Activity'), el('h1', {}, model.heading), ...model.notes.map(note => el('p', {class: 'lede'}, note))].filter(Boolean);
    if (model.exact) parts.push(el('details', {class: 'exact', open: true}, el('summary', {}, 'Exact action'), model.exact.flatMap(block => [el('span', {class: 'perm-note'}, block.label), el('pre', {}, block.text)])));
    if (model.expiresAt) parts.push(el('p', {class: 'perm-note'}, `Approve before ${new Date(model.expiresAt).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'})}`));
    const buttons = buttonsFor(model, {tenant: base.tenant}).map(button => el('button', {type: 'button', class: button.label === 'Approve' ? 'text-accent' : 'text-muted', onclick: () => decide(button.request, button.done)}, button.label));
    if (buttons.length) parts.push(el('div', {class: 'confirm-actions'}, buttons));
    root.replaceChildren(el('section', {class: 'group approval'}, parts));
    root.setAttribute('aria-busy', 'false');
  }
  async function load() {
    try {
      if (base.tenant && !link) { link = await api.start(); applyBrand(link.developer?.brand, {root: document.documentElement, media: window.matchMedia?.('(prefers-color-scheme: dark)')}); }
      else if (!base.tenant && !api.session()) await api.start();
      render(await api(base.approvalApi(callId)));
    } catch (error) { showError(error); }
  }
  load();
}

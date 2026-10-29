// Hosted activity (UI-4, docs/UI-0-SCREEN-CONTRACTS.md sections 3.10-3.11), served at /activity.
// Renders only the activity view model from GET /api/ui/activity: approvals waiting for the owner, then
// every agent call and account request by day. Lines come from the server; nothing is invented here.
import {describeApproval} from './hosted-approval.js';
import {baseFor, makeApi, applyBrand, finish} from './hosted-base.js';
export {describeApproval};

const STATUS_MARK = {succeeded: '✓', uncertain: '?', failed: '!', cancelled: '–', awaiting_approval: '…', queued: '…', running: '…',
  awaiting_owner: '…', signing_in: '…', awaiting_confirmation: '…', binding: '…', declined: '–', expired: '–'};

/** "Today", "Yesterday" or the date, for a day header. */
export function dayLabel(date, now = new Date()) {
  const day = new Date(`${date}T00:00:00`), today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const diff = Math.round((today - day) / 86_400_000);
  if (diff === 0) return 'Today';
  if (diff === 1) return 'Yesterday';
  return day.toLocaleDateString(undefined, {month: 'short', day: 'numeric', ...(day.getFullYear() !== today.getFullYear() ? {year: 'numeric'} : {})});
}

/** What one timeline line shows: the agent's task title first when it gave one, then Fabric's own result line. */
export function describeItem(item) {
  const heading = item.taskTitle || item.title;
  const detail = [item.taskTitle ? item.title : null, item.summary].filter(Boolean).join(' · ');
  return {heading, detail, mark: STATUS_MARK[item.status] || '•', attention: ['uncertain', 'failed'].includes(item.status),
    open: item.openUrl && /^\/continue\/[0-9a-f-]{36}$/.test(item.openUrl) ? item.openUrl : null, by: item.agent ? `by ${item.agent}` : null};
}

// ---- browser ------------------------------------------------------------------------
if (typeof document !== 'undefined') {
  const root = document.querySelector('#activity'), live = document.querySelector('#status'), base = baseFor(location.pathname), api = makeApi(base, fetch.bind(window));
  let busy = false, cursor = null, shown = [], link = null;
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
    try { const job = await api(request.path, request.body); say(job?.status === 'succeeded' ? 'Approved. It ran.' : job?.status === 'uncertain' ? 'Approved. It ran, but Fabric could not confirm the result.' : job?.status === 'failed' ? 'Approved, but it did not complete.' : done); }
    catch (error) { say(error.message, 'error'); }
    finally { busy = false; cursor = null; shown = []; await load(); }
  }
  function approvalNode(approval) {
    const model = describeApproval(approval);
    const card = el('li', {class: 'approval'},
      el('div', {class: 'perm-copy'}, el('span', {class: 'perm-label'}, model.heading),
        ...model.warnings.map(warning => el('span', {class: 'perm-note attention'}, warning)),
        model.agentSays ? el('span', {class: 'perm-note'}, model.agentSays) : null,
        el('span', {class: 'perm-note'}, [model.account, model.agent ? `asked by ${model.agent}` : null].filter(Boolean).join(' · ')),
        el('span', {class: 'perm-note'}, `Approve before ${new Date(model.expiresAt).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'})}`)),
      el('details', {class: 'exact'}, el('summary', {}, 'Exact action'), model.blocks.flatMap(block => [el('span', {class: 'perm-note'}, block.label), el('pre', {}, block.text)])),
      model.incomplete && (model.approve || model.cancel) ? el('span', {class: 'perm-note'}, model.incomplete) : null,
      // A manage link never decides (D5): the developer's app sends the person a link for that one request.
      model.approve || model.cancel ? el('div', {class: 'confirm-actions'},
        model.approve ? el('button', {type: 'button', class: 'text-accent', onclick: () => decide(model.approve, 'Approved.')}, 'Approve') : null,
        model.cancel ? el('button', {type: 'button', class: 'text-muted', onclick: () => decide(model.cancel, 'Cancelled. Nothing ran.')}, 'Cancel') : null)
        : el('span', {class: 'perm-note'}, `${link?.developer?.appName || 'The app'} sends you a link to approve or reject this.`));
    return card;
  }
  function itemNode(item) {
    const model = describeItem(item);
    return el('li', {class: 'activity-row'},
      el('span', {class: `activity-mark${model.attention ? ' attention' : ''}`, 'aria-hidden': 'true'}, model.mark),
      el('span', {class: 'row-copy'}, el('span', {class: 'row-name'}, model.heading), el('span', {class: 'row-tagline'}, model.detail),
        model.by ? el('span', {class: 'perm-note'}, model.by) : null),
      el('span', {class: 'activity-time'}, new Date(item.at).toLocaleTimeString([], {hour: 'numeric', minute: '2-digit'})),
      model.open ? el('a', {class: 'text-accent', href: model.open}, 'Open') : null);
  }
  function render(page) {
    const back = !base.tenant ? el('a', {class: 'back', href: base.catalog}, '‹ Connectors') : link?.manage?.appId ? el('a', {class: 'back', href: base.app(link.manage.appId)}, '‹ Back') : el('a', {class: 'back', href: base.catalog}, '‹ Your apps');
    const parts = [back, el('h1', {}, 'Activity'), el('p', {class: 'lede'}, base.tenant ? `What ${link?.developer?.appName || 'the app'}'s agent did in your apps, and what is waiting for you.` : 'What your agents did, and what is waiting for you.')];
    if (page.approvals.length) parts.push(el('section', {class: 'group'}, el('h2', {class: 'section-label'}, 'Needs your approval'), el('ul', {class: 'rows'}, page.approvals.map(approvalNode))));
    for (const day of shown) parts.push(el('section', {class: 'group'}, el('h2', {class: 'section-label'}, dayLabel(day.date)), el('ul', {class: 'rows'}, day.items.map(itemNode))));
    if (!page.approvals.length && !shown.length) parts.push(el('p', {class: 'empty'}, 'Nothing yet. When an agent uses one of your apps, it shows up here.'));
    if (page.nextCursor) parts.push(el('button', {type: 'button', class: 'more', onclick: () => { cursor = page.nextCursor; load(true); }}, 'Show earlier'));
    if (base.tenant) {
      const done = el('button', {type: 'button', class: 'text-accent', onclick: async () => {
        done.disabled = true;
        try { const result = await finish(api, base, {assign: url => location.assign(url), opener: window.opener, close: () => window.close()}); if (!result?.redirect) say('Done. You can close this window.'); }
        catch (error) { done.disabled = false; say(error.message, 'error'); }
      }}, 'Done');
      parts.push(el('div', {class: 'confirm-actions'}, done));
    }
    root.replaceChildren(...parts);
    root.setAttribute('aria-busy', 'false');
  }
  async function load(append = false) {
    try {
      if (base.tenant && !link) { link = await api.start(); applyBrand(link.developer?.brand, {root: document.documentElement, media: window.matchMedia?.('(prefers-color-scheme: dark)')}); }
      else if (!base.tenant && !api.session()) await api.start();
      const page = await api(`${base.activityApi}${append && cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`);
      for (const day of page.days) {
        const last = shown.at(-1);
        if (append && last && last.date === day.date) last.items.push(...day.items); else shown.push({date: day.date, items: [...day.items]});
      }
      render(page);
    } catch (error) {
      root.replaceChildren(el('p', {class: 'empty'}, error.code === 'expired' ? 'This link has expired. Ask the app for a new one.' : error.code === 'already_finished' ? 'This link has already been used.' : error.message || 'Activity could not be loaded.'));
      root.setAttribute('aria-busy', 'false');
    }
  }
  load();
}

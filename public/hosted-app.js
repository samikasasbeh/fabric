// Hosted app detail (UI-2, docs/UI-0-SCREEN-CONTRACTS.md section 3.6), served at /connectors/<appId>.
// Renders only the AppDetail view model from GET /api/ui/apps/<appId>; every change is the exact request
// built by describeApp / rowRequest and sent by decide, all exported and tested. Opened from a developer's manage
// link (F03.10, /connect/<session>/apps/<appId>) it reads and changes the person's own app through that link's API.
import {signInTarget} from './sign-in-target.js';
import {baseFor, makeApi, applyBrand, finish, cardText} from './hosted-base.js';

const OWNER = baseFor('/connectors');

export const MODE_LABEL = {allow: 'Allow', ask: 'Ask', deny: 'Never', mixed: 'Mixed'};
const STATUS_NOTE = {reconnect_required: 'Reconnect needed', expired: 'Sign-in expired'};
/** F10.6: the words of a row's notes: why some of its operations can never work through a sign-in, conditions at the provider, and
 *  raw requests that still ask where the row allows. The engine's own words (lib/permission-groups.mjs), which a test keeps equal. */
export const NOTE_WORDS = Object.freeze({
  'service-account-only': 'Google allows this only for a service account acting for a whole domain. A sign-in can never use it.',
  'workspace-cse-only': 'This needs Google Workspace client-side encryption, which a sign-in cannot use.',
  'bot-token-only': 'Slack allows this only with a bot token. Fabric signs in as you.',
  'client-credentials-only': 'Only the app itself can call this, with its own credentials. A sign-in can never use it.',
  'no-oauth-scope': 'No sign-in permission covers this, so a sign-in can never use it.',
  'not-requested': 'Fabric never asks for the permission this needs.',
  beta: 'In beta at the provider. It may change or stop working.', 'plan-dependent': 'Works only on some of the provider\'s plans.',
  raw_requests_ask: 'Raw requests still ask: a request sent straight to the app\'s API waits for your approval.',
});
const NOT_OFFERED = /^Not offered: /;

/** Allow on a row is confirmed by the row's own flag when the server sends one: a developer's environment (a write member inside a
 *  read row counts too), and the owner's rows from F10.6, which count the row's proxy record (correction 4). Otherwise Allow needs
 *  confirming for changes, and for reads that return secrets or may change something (row.sensitive), above an Allow default. */
const allowAsks = (row, mode) => mode === 'allow' && (typeof row.allowNeedsConfirm === 'boolean' ? row.allowNeedsConfirm : (row.effect !== 'read' || Boolean(row.sensitive)) && row.defaultMode !== 'allow');
/** What a mode change on a row needs before it is sent: a review of generated operations, or the standing-consent confirmation. */
export function needsConfirm(row, mode) {
  if (row.reviewRequired && mode !== 'deny') return 'review';
  return allowAsks(row, mode) ? 'allow' : null;
}

/** What the confirmation box says. Turning on a generated row that would also need the Allow confirmation says both,
 *  including that its operations can return keys or secrets, or may change something (F09.1). */
export function confirmText(row, mode, kind) {
  const allowToo = allowAsks(row, mode);
  const risk = row.sensitive === 'secrets' ? ' These operations can return keys or secrets.' : row.sensitive ? ' These reads may change something.' : '';
  const allow = `${row.label}: Allow means the agent can do this without asking you, with any details.${risk} You can change it back at any time.`;
  if (kind !== 'review') return allow;
  const review = 'These operations were generated from the provider\'s documentation. Turning them on reviews them.';
  return allowToo ? `${review} ${allow}` : review;
}

/** The exact request for setting one row, bound to the row token the owner saw. */
export function rowRequest(detail, row, mode, {review = false, confirmAllow = false} = {}, base = OWNER) {
  return {path: `${base.accountPath(detail.app.id, detail.selectedAccountRef)}/permissions`,
    body: {groupId: row.groupId, mode, etag: row.etag, ...(review ? {review: true} : {}), ...(confirmAllow ? {confirmAllow: true} : {})}};
}
/** The request a confirmed change sends: a review also confirms Allow when Allow on the row needs confirming. */
export function confirmedRowRequest(detail, row, mode, kind, base = OWNER) {
  return rowRequest(detail, row, mode, kind === 'review' ? {review: true, confirmAllow: allowAsks(row, mode)} : {confirmAllow: true}, base);
}

/** The same sign-in, confirming the card the owner saw by its etag; the action shown is left as it was. */
export function confirmedRequest(action, etag) {
  return {...action, request: {...action.request, body: {...action.request.body, confirmRows: etag}}};
}
/**
 * F10.4: a disconnect that would sign the same account out of other apps here (one Google grant) waits for the owner. The owner's
 * page offers the two answers the server takes: everywhere (confirmSiblings) or here only (remote: false). A manage link
 * disconnects here only, so it never offers them.
 */
export function siblingChoices(action, error, base = OWNER) {
  if (base.tenant || error?.code !== 'confirm_required' || !error.siblings?.length) return null;
  const answer = body => ({...action, request: {...action.request, body}, disconnects: true});
  return {text: error.message, everywhere: answer({confirmSiblings: true}), hereOnly: answer({remote: false})};
}
const accountName = account => account.workspaceName || account.email || account.displayName;
/** F10.17 (spec line 1147): an organization that limits Fabric, one line each; Fabric knows only the organizations that refused. */
const organizationLine = organization => `${organization}: this organization limits what Fabric can reach. Ask its admin to approve Fabric.`;
const signInAction = item => ({request: {path: `/api/oauth/${encodeURIComponent(item.providerId)}/start`, body: item.body}, signIn: {providerId: item.providerId}});
/** The card a sign-in must confirm, only when it lists rows (T7); within what was approved there is nothing to confirm. */
const cardOf = upgrade => upgrade?.rows?.length && typeof upgrade.etag === 'string' ? {card: {rows: upgrade.rows, etag: upgrade.etag}} : {};

/** One row as the page shows it. A row Fabric locks (F10.3) is Never with no choice. A row the account lacks access for needs more
 *  access and keeps its choice beside Add; with no Add it says why (F10.6). A row none of whose operations can work through a sign-in
 *  says why once; a row where some cannot says how many work, and its notes say why. */
function rowModel(row) {
  const needsAccess = row.access === 'missing' && row.locked !== true, accessNote = needsAccess ? 'Needs more access' : row.access === 'unavailable' ? row.accessReason || null : null;
  return {...row, modeLabel: MODE_LABEL[row.mode], options: row.locked === true ? [] : row.allowedModes.map(mode => ({mode, label: MODE_LABEL[mode]})),
    locked: row.locked === true, needsAccess, accessNote,
    add: row.addAccess ? {...signInAction(row.addAccess), ...cardOf(row.upgrade)} : null,
    addNote: needsAccess && !row.addAccess && row.addBlocked ? String(row.addBlocked).replace(NOT_OFFERED, '') : null,
    noteText: [...new Set((Array.isArray(row.notes) ? row.notes : []).map(code => Object.hasOwn(NOTE_WORDS, code) ? NOTE_WORDS[code] : null).filter(text => text && text !== accessNote))],
    count: Number.isInteger(row.working) && Number.isInteger(row.total) ? `${row.working} of ${row.total} work` : null,
    providerNote: row.access === 'unknown' ? 'Permission enforced by the provider' : null};
}

/** Turns the AppDetail view model into what the page shows and the request behind each action. */
export function describeApp(detail, base = OWNER) {
  const appId = detail.app.id, ref = detail.selectedAccountRef, accountPath = base.accountPath;
  const selected = detail.accounts.find(account => account.accountRef === ref) || null;
  return {
    title: detail.app.displayName || detail.app.name, tagline: detail.app.tagline, iconUrl: detail.app.iconUrl, accessSummary: detail.accessSummary || null,
    connected: detail.connectionState === 'connected', connectBlocked: detail.connectBlocked || null,
    // F10.4: what needs attention on each account's current sign-in; with several accounts, each says which.
    notices: (detail.notices || []).map(notice => {
      const account = detail.accounts.find(item => item.accountRef === notice.accountRef), message = typeof notice.organization === 'string' ? organizationLine(notice.organization) : notice.message;
      return {accountRef: notice.accountRef, text: detail.accounts.length > 1 && account ? `${accountName(account)}: ${message}` : message};
    }),
    accounts: detail.accounts.map(account => ({ref: account.accountRef, name: accountName(account),
      detail: [account.workspaceName ? account.displayName : null, account.workspaceName && account.email ? account.email : null].filter(Boolean).join(' · '),
      initial: account.initial, selected: account.accountRef === ref, note: STATUS_NOTE[account.status] || null,
      // F10.7 (T3): what the account holds, in the account row's words ("Full access", "Pages you shared", "Partial access (...)").
      access: typeof account.accessLabel === 'string' ? account.accessLabel : null})),
    selected,
    addAccount: detail.addAccount?.kind === 'oauth' ? signInAction(detail.addAccount) : detail.addAccount?.kind === 'owner_ui' ? {href: detail.addAccount.href} : null,
    // F10.7: an app with a read level (Gmail) also offers a read-only account, apart from the full one.
    addReadOnlyAccount: detail.addReadOnlyAccount?.kind === 'oauth' ? {label: detail.addReadOnlyAccount.label, ...signInAction(detail.addReadOnlyAccount)} : null,
    upgrade: detail.upgrade ? {label: detail.upgrade.label, ...signInAction(detail.upgrade), ...cardOf(detail.upgrade)} : null,
    // The selected account must sign in again: a renewal on it, which keeps its settings.
    renew: detail.renew ? {label: detail.renew.label, ...signInAction(detail.renew)} : null,
    disconnect: selected ? {label: `Disconnect ${selected.workspaceName || selected.email || selected.displayName}`, request: {path: `${accountPath(appId, ref)}/disconnect`, body: {}}} : null,
    sections: (detail.sections || []).map(section => ({label: section.label, rows: section.rows.map(row => rowModel(row))})),
    // A developer's environment binds the change to the setting shown (etag); the owner's takes the mode alone.
    background: detail.background ? {mode: detail.background.mode, request: mode => ({path: `${accountPath(appId, ref)}/background`, body: {mode, ...(detail.background.etag ? {etag: detail.background.etag} : {})}}),
      note: base.tenant ? 'Reads only.' : detail.background.runsWhile === 'runtime_running' ? 'Runs only while Fabric is running on this computer. Reads only.' : 'Reads only.'} : null,
    reset: detail.canReset && ref ? {path: `${accountPath(appId, ref)}/reset`, body: {}} : null,
    discovery: detail.discovery?.state === 'missing' ? detail.discovery.message : null,
  };
}

/** Sends one action; a sign-in action then navigates only to the provider's declared origin. */
export async function decide(action, {send, assign, oauthProviders}) {
  const result = await send(action.request);
  if (action.signIn) assign(signInTarget(result?.authorizationUrl, oauthProviders?.[action.signIn.providerId]?.authorizationOrigin));
  return result;
}

// ---- browser ------------------------------------------------------------------------
if (typeof document !== 'undefined') {
  const appId = decodeURIComponent(location.pathname.split('/').filter(Boolean).pop() || '');
  const root = document.querySelector('#app'), live = document.querySelector('#status'), base = baseFor(location.pathname), api = makeApi(base, fetch.bind(window));
  let detail = null, busy = false, account = new URLSearchParams(location.search).get('account') || '', link = null;
  const el = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) { if (key === 'onclick') node.addEventListener('click', value); else if (key === 'onchange') node.addEventListener('change', value); else if (value !== false && value !== undefined && value !== null) node.setAttribute(key, value === true ? '' : value); }
    for (const child of children.flat()) if (child !== null && child !== undefined && child !== false) node.append(child);
    return node;
  };
  const say = (text, kind = 'info') => { live.textContent = text; live.dataset.kind = kind; live.hidden = !text; };
  const deps = () => ({send: request => api(request.path, request.body), assign: url => location.assign(url), oauthProviders: api.session()?.settings?.oauthProviders});
  async function act(action, after) {
    if (busy) return;
    busy = true; say('');
    try {
      const result = await decide(action, deps());
      // After a disconnect the account is gone: show the next one, with the server's own words about the provider.
      if (action.disconnects) { account = ''; await load(''); say(result?.message || after); return; }
      if (result?.app && result?.sections) render(result); else await load();
      if (after) say(after);
    } catch (error) {
      if (error.view) render(error.view);
      // F10.4: the server asks for a confirm first and nothing changed: the card as it is now, or the other accounts a disconnect
      // signs out. The page shows what to confirm instead of an error.
      const card = action.signIn && error.code === 'confirm_required' ? error.upgrade : null, choices = siblingChoices(action, error, base);
      if (!card && !choices) say(error.message, 'error');
      if (!error.view) await load();
      if (card) ask(confirmBox(cardText(card), 'Continue', () => act(confirmedRequest(action, card.etag))));
      else if (choices) ask(choiceBox(choices.text, [{label: 'Disconnect everywhere', run: () => act(choices.everywhere, 'Disconnected.'), danger: true}, {label: 'Disconnect here only', run: () => act(choices.hereOnly, 'Disconnected here.')}]));
    } finally { busy = false; }
  }
  // Inline confirmations instead of browser dialogs: the owner reads the consequence, then chooses.
  function choiceBox(text, choices) {
    const box = el('div', {class: 'confirm', role: 'group', 'aria-label': choices[0].label},
      el('p', {}, text),
      el('div', {class: 'confirm-actions'},
        choices.map(choice => el('button', {type: 'button', class: choice.danger ? 'text-danger' : 'text-accent', onclick: () => { box.remove(); choice.run(); }}, choice.label)),
        el('button', {type: 'button', class: 'text-muted', onclick: () => { box.remove(); render(detail); }}, 'Cancel')));
    return box;
  }
  function confirmBox(text, confirmLabel, onConfirm, danger = false) { return choiceBox(text, [{label: confirmLabel, run: onConfirm, danger}]); }
  /** A confirm the server asked for, under the app's heading, with focus on its first choice. */
  function ask(box) {
    const head = root.querySelector('.app-head');
    if (head) head.after(box); else root.prepend(box);
    box.querySelector('button')?.focus();
  }
  /** A sign-in that would turn rows on at Allow shows its card first; continuing confirms that card (T7). */
  function confirmFirst(action, anchor) {
    if (!action.card) return act(action);
    anchor.after(confirmBox(cardText(action.card), 'Continue', () => act(confirmedRequest(action, action.card.etag))));
  }
  function rowNode(model, row) {
    if (row.locked) return el('li', {class: 'perm-row locked'}, el('span', {class: 'perm-copy'}, el('span', {class: 'perm-label'}, row.label), el('span', {class: 'perm-note'}, 'Never. Fabric keeps this off.')));
    const note = text => text ? el('span', {class: 'perm-note'}, text) : null;
    const select = el('select', {'aria-label': `${row.label} permission`}, row.mode === 'mixed' ? el('option', {value: 'mixed', selected: true, disabled: true}, 'Mixed') : null,
      row.options.map(option => el('option', {value: option.mode, selected: option.mode === row.mode}, option.label)));
    // A row that needs more access keeps its choice beside Add (F10.6); with no Add it says "Not offered" and why.
    const item = el('li', {class: row.needsAccess ? 'perm-row needs-access' : 'perm-row'}, el('span', {class: 'perm-copy'}, el('span', {class: 'perm-label'}, row.label),
      note(row.accessNote), note(row.addNote), note(row.providerNote), note(row.policySource === 'stale' ? 'The account changed since this was set. Review it.' : null), note(row.count), row.noteText.map(note)), select,
      !row.needsAccess ? null : row.add ? el('button', {type: 'button', class: 'text-accent', 'aria-label': `Add ${row.label}`, onclick: () => confirmFirst(row.add, item)}, 'Add') : el('span', {class: 'perm-note', title: row.addBlocked || ''}, 'Not offered'));
    select.addEventListener('change', () => {
      const mode = select.value, kind = needsConfirm(row, mode);
      if (!kind) return act({request: rowRequest(detail, row, mode, {}, base)});
      item.after(confirmBox(confirmText(row, mode, kind), kind === 'review' ? 'Review and turn on' : 'Allow without asking', () => act({request: confirmedRowRequest(detail, row, mode, kind, base)})));
    });
    return item;
  }
  function render(view) {
    detail = view; account = view.selectedAccountRef || '';
    const model = describeApp(view, base), parts = [], summary = model.connected ? model.accessSummary : 'Not connected';
    parts.push(backLink(view),
      el('header', {class: 'app-head'}, el('span', {class: 'app-icon large', 'aria-hidden': 'true'}, model.title.charAt(0)), el('div', {}, el('h1', {}, model.title), el('p', {class: 'lede'}, model.tagline))),
      summary ? el('p', {class: 'summary'}, summary) : null,
      model.notices.length ? el('ul', {class: 'notices', role: 'status'}, model.notices.map(notice => el('li', {}, notice.text))) : null,
      !model.connected && model.accessSummary ? el('p', {class: 'summary-detail'}, model.accessSummary) : null,
      model.connectBlocked ? el('p', {class: 'empty'}, model.connectBlocked) : null);
    if (model.disconnect) {
      const card = el('div', {class: 'rows single'});
      const button = el('button', {type: 'button', class: 'row-button text-danger', onclick: () => card.replaceChildren(confirmBox(`${model.disconnect.label}? The agent loses access to this account.`, 'Disconnect', () => act({...model.disconnect, disconnects: true}, 'Disconnected.'), true))}, 'Disconnect');
      card.append(button); parts.push(card);
    }
    const list = el('ul', {class: 'rows'});
    if (!model.accounts.length && !model.addAccount) list.hidden = true;
    for (const entry of model.accounts) list.append(el('li', {class: `account-row${entry.selected ? ' selected' : ''}`},
      el('span', {class: 'avatar', 'aria-hidden': 'true'}, entry.initial),
      el('span', {class: 'row-copy'}, el('span', {class: 'row-name'}, entry.name), entry.detail ? el('span', {class: 'row-tagline'}, entry.detail) : null, entry.access ? el('span', {class: 'row-tagline'}, entry.access) : null, entry.note ? el('span', {class: 'row-attention'}, entry.note) : null),
      entry.selected ? el('span', {class: 'row-note'}, 'Selected') : el('button', {type: 'button', class: 'text-accent', onclick: () => load(entry.ref)}, 'Choose')));
    if (model.renew) list.append(el('li', {class: 'account-row'}, el('button', {type: 'button', class: 'text-accent', onclick: () => act(model.renew)}, model.renew.label)));
    if (model.addAccount) list.append(el('li', {class: 'account-row'}, model.addAccount.href ? el('a', {class: 'text-accent', href: model.addAccount.href}, 'Add account') : el('button', {type: 'button', class: 'text-accent', onclick: () => act(model.addAccount)}, 'Add account')));
    if (model.addReadOnlyAccount) list.append(el('li', {class: 'account-row'}, el('button', {type: 'button', class: 'text-accent', onclick: () => act(model.addReadOnlyAccount)}, model.addReadOnlyAccount.label)));
    if (model.upgrade) { const item = el('li', {class: 'account-row'}); item.append(el('button', {type: 'button', class: 'text-accent', onclick: () => confirmFirst(model.upgrade, item)}, model.upgrade.label)); list.append(item); }
    parts.push(list);
    if (model.discovery) parts.push(el('p', {class: 'empty'}, model.discovery));
    for (const section of model.sections) parts.push(el('section', {class: 'group'}, el('h2', {class: 'section-label'}, section.label), el('ul', {class: 'rows'}, section.rows.map(row => rowNode(model, row)))));
    if (model.background) {
      const select = el('select', {'aria-label': 'Background sync permission'}, ['allow', 'deny'].map(mode => el('option', {value: mode, selected: mode === model.background.mode}, mode === 'allow' ? 'Allow' : 'Never')));
      select.addEventListener('change', () => act({request: model.background.request(select.value)}));
      parts.push(el('section', {class: 'group'}, el('h2', {class: 'section-label'}, 'Background actions'),
        el('ul', {class: 'rows'}, el('li', {class: 'perm-row'}, el('span', {class: 'perm-copy'}, el('span', {class: 'perm-label'}, 'Background sync'), el('span', {class: 'perm-note'}, model.background.note)), select))));
    }
    if (model.reset) {
      const holder = el('div', {class: 'reset'});
      // On a manage link, anything that would come back as Allow on a change comes back as Ask (the person turns it on row by row).
      const resetText = base.tenant ? 'Reset every permission for this account to its default? Changes that would be allowed without asking come back as Ask; you can allow them again one by one.' : 'Reset every permission for this account to its default?';
      holder.append(el('button', {type: 'button', class: 'text-danger', onclick: () => holder.replaceChildren(confirmBox(resetText, 'Reset to defaults', () => act({request: model.reset}, 'Permissions reset to their defaults.'), true))}, 'Reset to defaults'));
      parts.push(holder);
    }
    if (base.tenant) parts.push(el('div', {class: 'confirm-actions'}, el('a', {class: 'text-accent', href: base.activity}, 'Activity'), doneButton()));
    root.replaceChildren(...parts.filter(Boolean));
    root.setAttribute('aria-busy', 'false');
  }
  /** Back to the catalog; a link for one app only has no catalog to go back to. */
  function backLink(view) { return base.tenant && view?.scoped ? null : el('a', {class: 'back', href: base.catalog}, base.tenant ? '‹ Your apps' : '‹ Connectors'); }
  function doneButton() {
    const done = el('button', {type: 'button', class: 'text-accent', onclick: async () => {
      done.disabled = true;
      try { const result = await finish(api, base, {assign: url => location.assign(url), opener: window.opener, close: () => window.close()}); if (!result?.redirect) say('Done. You can close this window.'); }
      catch (error) { done.disabled = false; say(error.message, 'error'); }
    }}, 'Done');
    return done;
  }
  async function load(ref = account) {
    try {
      if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(appId)) throw Object.assign(new Error('This is not a Fabric app page.'), {code: 'not_found'});
      if (base.tenant) {
        if (!link) { link = await api.start(); applyBrand(link.developer?.brand, {root: document.documentElement, media: window.matchMedia?.('(prefers-color-scheme: dark)')}); }
      } else if (!api.session()) await api.start();
      render(await api(`${base.appApi(appId)}${ref ? `?account=${encodeURIComponent(ref)}` : ''}`));
    } catch (error) {
      const words = error.code === 'not_found' ? 'This app or account was not found.' : error.code === 'expired' ? 'This link has expired. Ask the app for a new one.' : error.code === 'already_finished' ? 'This link has already been used.' : error.message;
      root.replaceChildren(...[base.tenant ? null : el('a', {class: 'back', href: base.catalog}, '‹ Connectors'), el('p', {class: 'empty'}, words)].filter(Boolean));
      root.setAttribute('aria-busy', 'false');
    }
  }
  load();
}

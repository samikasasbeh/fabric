// F03.6c: Fabric's hosted Connect page (docs/F03-DEVELOPER-LAYER.md section 6). It reads the link's secret from the
// fragment and removes it from history, claims the session for this browser, and shows one screen at a time: the
// consent sheet (or the apps to choose from), the confirm screen after sign-in, the done screen, or how the link ended.
// Sign-in starts only on a click. All text goes in as text; nothing from the server is ever parsed as HTML.
const id = location.pathname.split('/')[2];
const main = document.getElementById('main');
const secret = new URLSearchParams(location.hash.slice(1)).get('k');
if (location.hash) history.replaceState(null, '', location.pathname);

/** The page's CSRF value from claim or view, kept in page memory only and sent with every action. */
let csrf = null;
async function api(path, body, query) {
  const url = `/connect/${encodeURIComponent(id)}/v1/${path}${query ? `?${new URLSearchParams(query)}` : ''}`;
  const response = await fetch(url, body === undefined ? {credentials: 'same-origin'} : {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json', ...(csrf ? {'X-Fabric-CSRF': csrf} : {})}, body: JSON.stringify(body)});
  const data = await response.json().catch(() => ({}));
  // F10.4: an upgrade card refused for being stale comes back with the current one in details.
  if (!response.ok) throw Object.assign(new Error(data?.error?.message || 'Something went wrong.'), {code: data?.error?.code, details: data?.error?.details});
  if (typeof data?.csrf === 'string') csrf = data.csrf;
  return data;
}
const el = (tag, {attrs = {}, ...props} = {}, ...children) => {
  const node = Object.assign(document.createElement(tag), props);
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
  for (const child of children) if (child !== null && child !== undefined && child !== false) node.append(child);
  return node;
};
/** Appends what is present; a missing part of a screen is skipped, never written out as text. */
const add = (parent, ...children) => { for (const child of children) if (child !== null && child !== undefined && child !== false) parent.append(child); return parent; };
const button = (label, onClick, kind = 'primary') => { const node = el('button', {type: 'button', className: kind, textContent: label}); node.addEventListener('click', onClick); return node; };
/** One screen at a time; focus moves to its heading so keyboards and screen readers start at the top. */
function show(...nodes) {
  main.replaceChildren(...nodes);
  const heading = main.querySelector('h1');
  if (heading) { heading.tabIndex = -1; heading.focus({preventScroll: false}); }
}
/** A note inside the current screen (an error from an action), announced without moving focus. */
function note(screen, text) {
  screen.querySelector('.note')?.remove();
  add(screen, el('p', {className: 'note', role: 'alert', textContent: text}));
}
/** Runs a button's action with the button disabled and a plain-words label while it works. */
function busy(control, label, work, screen) {
  const before = control.textContent;
  control.disabled = true; control.textContent = label;
  return work().catch(error => { control.disabled = false; control.textContent = before; note(screen, error.message); });
}

const OPEN = new Set(['created', 'opened', 'signing_in', 'awaiting_confirmation']);
const appNameOf = view => view?.developer?.appName || 'the app';
const WORDS = {
  consent_denied: view => `You declined access at ${view.providerName || view.appName || 'the provider'}. Nothing was connected.`,
  insufficient_scope: view => `${view.providerName || 'The provider'} gave less access than ${appNameOf(view)} asked for. Nothing was connected.`,
  never_requested: view => `${view.providerName || 'The provider'} granted a permission Fabric never holds, so nothing was connected. You can remove the app ${view.settingsUrl ? `at ${view.settingsUrl}` : `in your ${view.providerName || 'provider'} account settings`}, then connect again.`,
  setup_required: () => 'This app can\'t be connected yet. Nothing was connected.',
  expired: view => `This link has expired. Ask ${appNameOf(view)} for a new one.`,
  identity_mismatch: () => 'That is a different account. Nothing changed.',
  account_changed: () => 'The account this link was for is no longer connected. Nothing changed.',
  session_in_use: view => `This link was already opened in another browser. Ask ${appNameOf(view)} for a new one.`,
  cancelled: () => 'You closed this page. Nothing was connected.',
  declined: () => 'You declined. Nothing was connected and nothing ran.',
  user_cap_reached: view => `${appNameOf(view)} has reached the number of Google accounts it can connect while it is in testing. Nothing was connected.`,
  provider_app_disabled: view => `${appNameOf(view)}'s sign-in app is not set up correctly, so nothing was connected. Let ${appNameOf(view)} know.`,
  provider_error: view => `${view.providerName || 'The provider'} could not finish the sign-in. Nothing was connected.`,
  not_found: () => 'This link is not valid. Ask the app that sent it for a new one.',
};
const wordsFor = (code, view = {}) => (WORDS[code] || (() => 'This link can\'t be used any more. Nothing was connected.'))(view);
/** How a manage or approval link ended (F03.10): nothing is connected there, so the words say what did happen. */
const PAGE_ENDINGS = {
  completed: {title: 'Done', manage: view => `Your choices for ${appNameOf(view)} are saved.`, approve: () => 'Your decision is recorded.'},
  cancelled: {title: 'Closed', manage: () => 'You closed this page.', approve: () => 'You closed this page. Nothing was decided.'},
  expired: {title: 'Link expired', manage: view => `This link has expired. Ask ${appNameOf(view)} for a new one.`, approve: view => `This link has expired. Ask ${appNameOf(view)} for a new one. Nothing was decided.`},
};

/** The developer's name and logo, with Close while the link is still open. */
function topBar(view) {
  if (!view.developer) return null;
  const brand = el('div', {className: 'brand-bar'},
    view.developer?.logoUrl ? el('img', {className: 'developer-logo', src: view.developer.logoUrl, alt: ''}) : null,
    el('span', {className: 'developer-name', textContent: appNameOf(view)}));
  if (!OPEN.has(view.state)) return brand;
  const close = el('button', {type: 'button', className: 'close', attrs: {'aria-label': 'Close this page'}, title: 'Close', textContent: '×'});
  close.addEventListener('click', () => busy(close, '×', async () => {
    const closed = await api('close', {});
    if (window.opener && !window.opener.closed) { window.close(); }
    render({...view, state: 'cancelled', errorCode: 'cancelled', redirect: closed.redirect});
  }, main));
  add(brand, close);
  return brand;
}

/** T7: the rows a sign-in turns on at Allow, shown before it starts; starting sends the card's etag as the person's confirmation. */
function upgradeCard(upgrade, view) {
  if (!upgrade?.rows?.length) return el('div', {className: 'upgrade'});
  return el('section', {className: 'upgrade', attrs: {'aria-labelledby': 'upgrade-title'}},
    el('h2', {id: 'upgrade-title', textContent: 'This adds access'}),
    el('p', {textContent: `After you sign in, ${appNameOf(view)} can do these without asking you first:`}),
    el('ul', {}, ...upgrade.rows.map(row => el('li', {textContent: row.label}))),
    el('p', {textContent: 'Anything you set to Allow before asks you again. Anything set to Never stays off.'}));
}

function sheetScreen(view, {back} = {}) {
  const sheet = view.sheet, screen = el('section', {className: 'sheet', attrs: {'aria-labelledby': 'sheet-title'}});
  const levels = sheet.levels.length > 1 ? sheet.levels : [];
  const chosen = () => screen.querySelector('input[name="level"]:checked')?.value;
  let upgrade = view.upgrade, card = upgradeCard(upgrade, view);
  const connect = button(sheet.action.label, () => busy(connect, `Opening ${view.providerName || sheet.app.name}…`, async () => {
    const level = chosen();
    try {
      // A link for one app already names it; a link for any app sends the chosen one. Starting confirms the card shown.
      const {authorizationUrl} = await api('start', {...(view.apps ? {appId: sheet.app.id} : {}), ...(level ? {level} : {}), ...(upgrade ? {confirmRows: upgrade.etag} : {})});
      location.assign(authorizationUrl);
    } catch (error) {
      // What this sign-in turns on changed since the page showed it: show the new list; the next click confirms that one.
      if (error.code === 'confirm_required' && error.details?.upgrade) { upgrade = error.details.upgrade; const next = upgradeCard(upgrade, view); card.replaceWith(next); card = next; }
      throw error;
    }
  }, screen));
  add(screen, 
    topBar(view),
    back ? button('Back to apps', back, 'link') : null,
    el('header', {className: 'sheet-head'},
      el('img', {className: 'app-icon', src: sheet.app.iconUrl, alt: ''}),
      el('h1', {id: 'sheet-title', textContent: `${sheet.developer.appName} wants to use ${sheet.app.name}`}),
      el('p', {className: 'access', textContent: sheet.accessLine}),
      sheet.userHint ? el('p', {className: 'hint', textContent: `Connecting for ${sheet.userHint}`}) : null),
    el('ul', {className: 'points'}, ...sheet.points.map(point => el('li', {}, el('strong', {textContent: point.title}), el('span', {textContent: point.text})))),
    el('p', {className: 'defaults', textContent: sheet.defaultsLine}),
    ...sheet.notices.map(text => el('p', {className: 'notice', textContent: text})),
    card,
    levels.length ? el('details', {className: 'levels'}, el('summary', {textContent: 'Access level'}),
      el('fieldset', {}, el('legend', {className: 'visually-hidden', textContent: 'Access level'}),
        ...levels.map(level => el('label', {className: 'level'}, el('input', {type: 'radio', name: 'level', value: level.level, checked: level.isDefault}), el('span', {textContent: level.label}))))) : null,
    connect,
    el('p', {className: 'screen-name', textContent: `${view.providerName || sheet.app.name}'s sign-in screen will show "${sheet.providerApp.consentScreenName}".`}),
    el('div', {className: 'fine'}, ...sheet.finePrint.map(item => el('p', {}, item.text,
      ...(item.termsUrl ? [' ', el('a', {href: item.termsUrl, rel: 'noreferrer', target: '_blank', textContent: 'Terms'}), ' · ', el('a', {href: item.privacyUrl, rel: 'noreferrer', target: '_blank', textContent: 'Privacy'})] : []),
      ...(item.learnMoreUrl ? [' ', el('a', {href: item.learnMoreUrl, rel: 'noreferrer', target: '_blank', textContent: 'Learn more'})] : [])))));
  return screen;
}

function appsScreen(view) {
  const screen = el('section', {className: 'sheet', attrs: {'aria-labelledby': 'apps-title'}});
  add(screen, topBar(view), el('header', {className: 'sheet-head'}, el('h1', {id: 'apps-title', textContent: `Connect an app to ${appNameOf(view)}`}),
    view.userHint ? el('p', {className: 'hint', textContent: `Connecting for ${view.userHint}`}) : null),
    el('ul', {className: 'apps'}, ...view.apps.map(app => {
      const choose = el('button', {type: 'button', className: 'app-row'}, el('img', {src: app.iconUrl, alt: ''}), el('span', {className: 'app-name', textContent: app.name}),
        el('span', {className: app.state === 'connected' ? 'app-state connected' : 'app-state', textContent: app.state === 'connected' ? 'Connected' : 'Connect'}));
      choose.addEventListener('click', () => busy(choose, `Opening ${app.name}…`, async () => {
        const chosen = await api('view', undefined, {appId: app.id});
        show(sheetScreen(chosen, {back: () => render(view)}));
      }, screen));
      return el('li', {}, choose);
    })));
  return screen;
}

/** Sign-in finished in another browser: this one cannot see or confirm that account. */
function elsewhereScreen(view) {
  const screen = el('section', {className: 'sheet', attrs: {'aria-labelledby': 'elsewhere-title'}});
  add(screen, topBar(view), el('header', {className: 'sheet-head'}, el('h1', {id: 'elsewhere-title', textContent: 'Finish in the other browser'}),
    el('p', {className: 'access', textContent: `The sign-in for this link finished in another browser. Confirm it there, or close this page and ask ${appNameOf(view)} for a new link.`})));
  return screen;
}

/** T7 at confirm: a sign-in that gave more than the person approved says so and lists what it turns on; confirming sends the card's etag. */
function confirmCard(upgrade, view) {
  if (!upgrade) return el('div', {className: 'upgrade'});
  const rows = upgrade.rows?.length ? upgrade.rows : null;
  return el('section', {className: 'upgrade', attrs: {'aria-labelledby': 'confirm-upgrade-title'}},
    el('h2', {id: 'confirm-upgrade-title', textContent: 'This adds access'}),
    rows ? el('p', {textContent: `Once you connect, ${appNameOf(view)} can do these without asking you first:`}) : null,
    rows ? el('ul', {}, ...rows.map(row => el('li', {textContent: row.label}))) : null,
    el('p', {textContent: 'Anything you set to Allow before asks you again. Anything set to Never stays off.'}));
}

function confirmScreen(view) {
  const screen = el('section', {className: 'sheet', attrs: {'aria-labelledby': 'confirm-title'}});
  const name = view.pendingAccount?.displayName || 'this account';
  let upgrade = view.upgrade, card = confirmCard(upgrade, view);
  const yes = button(upgrade?.rows?.length ? 'Connect and allow' : 'Connect', () => busy(yes, 'Connecting…', async () => {
    try { await api('confirm', upgrade ? {confirmRows: upgrade.etag} : {}); }
    catch (error) {
      // What the sign-in turns on changed since the page showed it: show the new list; the next click confirms that one.
      if (error.code === 'confirm_required' && error.details?.upgrade) { upgrade = error.details.upgrade; const next = confirmCard(upgrade, view); card.replaceWith(next); card = next; }
      throw error;
    }
    render(await api('view'));
  }, screen));
  const no = button('Not this account', () => busy(no, 'Removing it…', async () => { await api('reject', {}); render(await api('view')); }, screen), 'secondary');
  add(screen, topBar(view), el('header', {className: 'sheet-head'},
    el('h1', {id: 'confirm-title', textContent: `Connect ${name} to ${appNameOf(view)}${view.userHint ? ` for ${view.userHint}` : ''}?`}),
    el('p', {className: 'access', textContent: `This is the ${view.appName || ''} account you just signed in with${view.providerName ? ` at ${view.providerName}` : ''}. You can disconnect it at any time.`})),
    card,
    el('div', {className: 'actions'}, yes, no));
  return screen;
}

/** A call is waiting for an account (F03.9d): use one the person already has, connect another, or decline. */
function handoffScreen(view) {
  const screen = el('section', {className: 'sheet', attrs: {'aria-labelledby': 'handoff-title'}}), task = view.handoff.operation ? ` to ${view.handoff.operation.toLowerCase()}` : '';
  const decline = button('Decline', () => busy(decline, 'Declining…', async () => { await api('decline', {}); render(await api('view')); }, screen), 'secondary');
  const another = button(view.handoff.accounts.length ? 'Connect a different account' : `Connect ${view.appName || 'an account'}`, () => show(sheetScreen(view, {back: () => render(view)})), view.handoff.accounts.length ? 'secondary' : 'primary');
  add(screen, topBar(view), el('header', {className: 'sheet-head'},
    el('h1', {id: 'handoff-title', textContent: `${appNameOf(view)} needs a ${view.appName || ''} account${task}`}),
    el('p', {className: 'access', textContent: view.handoff.accounts.length ? 'Choose one of your accounts, or connect another. Nothing runs until you confirm.' : 'Connect an account to continue. Nothing runs until you confirm.'})),
    view.handoff.accounts.length ? el('ul', {className: 'apps'}, ...view.handoff.accounts.map(account => {
      const use = button(`Use ${account.displayName}`, () => busy(use, 'Choosing…', async () => { await api('select', {choice: account.choice}); render(await api('view')); }, screen), 'app-row');
      return el('li', {}, use);
    })) : null,
    el('div', {className: 'actions'}, another, decline));
  return screen;
}

/** The person chose an existing account for the waiting call: confirm it, or go back. */
function chosenScreen(view) {
  const screen = el('section', {className: 'sheet', attrs: {'aria-labelledby': 'chosen-title'}}), name = view.handoff.selectedAccount.displayName;
  const yes = button('Use this account', () => busy(yes, 'Continuing…', async () => { await api('confirm', {}); render(await api('view')); }, screen));
  const back = button('Back', () => busy(back, 'Going back…', async () => { await api('reject', {}); render(await api('view')); }, screen), 'secondary');
  add(screen, topBar(view), el('header', {className: 'sheet-head'}, el('h1', {id: 'chosen-title', textContent: `Use ${name} for ${appNameOf(view)}?`}),
    el('p', {className: 'access', textContent: `${appNameOf(view)} will use this ${view.appName || ''} account for what it asked. Your permissions for it still apply.`})),
    el('div', {className: 'actions'}, yes, back));
  return screen;
}

/**
 * Section 6.6: a finished session tells the developer's popup that opened it, once, at the session's own opener origin
 * only (never '*'), with the message Fabric built: the session id, its state, and refs or an error code, never a name.
 */
let told = false;
const inPopup = view => Boolean(view?.opener && typeof view.opener.origin === 'string' && window.opener && !window.opener.closed);
function tellOpener(view) {
  if (told || !inPopup(view)) return;
  try { window.opener.postMessage(view.opener.message, view.opener.origin); told = true; } catch { /* the opener went elsewhere; polling is authoritative */ }
}

function doneScreen(view) {
  const screen = el('section', {className: 'sheet', attrs: {'aria-labelledby': 'done-title'}});
  const done = button('Done', () => { if (inPopup(view)) window.close(); else if (view.redirect) location.assign(view.redirect); else { window.close(); note(screen, 'You can close this window.'); } });
  add(screen, topBar(view), el('header', {className: 'sheet-head'}, el('h1', {id: 'done-title', textContent: 'Connected'}),
    el('p', {className: 'access', textContent: view.account ? `Connected as ${view.account.displayName}. ${view.account.accessLabel}.` : `${view.appName || 'The app'} is connected to ${appNameOf(view)}.`})), done);
  return screen;
}

function endedScreen(view, code) {
  const screen = el('section', {className: 'sheet', attrs: {'aria-labelledby': 'ended-title'}}), ending = PAGE_ENDINGS[code], page = ending && ending[view.purpose];
  add(screen, topBar(view), el('header', {className: 'sheet-head'},
    el('h1', {id: 'ended-title', textContent: page ? ending.title : code === 'cancelled' ? 'Closed' : code === 'declined' ? 'Declined' : 'Not connected'}),
    el('p', {className: 'access', textContent: page ? page(view) : wordsFor(code, view)}),
    view.developer?.supportEmail ? el('p', {className: 'support', textContent: `Need help? Contact ${view.developer.supportEmail}.`}) : null),
    inPopup(view) ? button('Done', () => window.close()) : view.redirect ? button(`Return to ${appNameOf(view)}`, () => location.assign(view.redirect)) : null);
  return screen;
}

/**
 * The developer's colours (F03.10): only Fabric's named custom properties, only #rrggbb values, set through the CSS
 * object model (never markup); the dark set applies while the system is dark. Anything else is ignored.
 */
const BRAND_PROPERTIES = new Set(['--surface', '--surface-raised', '--ink', '--muted', '--line', '--accent', '--on-accent', '--danger', '--attention']);
let brandApplied = false;
function applyBrand(brand) {
  if (brandApplied || !brand || typeof brand !== 'object') return;
  brandApplied = true;
  const root = document.documentElement, dark = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
  const paint = () => {
    for (const name of BRAND_PROPERTIES) root.style.removeProperty(name);
    const set = dark?.matches ? brand.dark : brand.light;
    for (const [name, value] of Object.entries(set && typeof set === 'object' ? set : {})) if (BRAND_PROPERTIES.has(name) && /^#[0-9a-f]{6}$/.test(value)) root.style.setProperty(name, value);
  };
  paint(); dark?.addEventListener?.('change', paint);
}

function render(view) {
  applyBrand(view.developer?.brand);
  if (!OPEN.has(view.state)) tellOpener(view);
  if (view.state === 'connected') return show(doneScreen(view));
  if (!OPEN.has(view.state)) return show(endedScreen(view, view.state === 'completed' ? 'completed' : view.errorCode || view.state));
  // F03.10: a manage or approval link opens Fabric's hosted pages under this session's address.
  const base = `/connect/${encodeURIComponent(id)}`;
  if (view.purpose === 'manage') return location.replace(view.manage?.appId ? `${base}/apps/${encodeURIComponent(view.manage.appId)}` : `${base}/apps`);
  if (view.purpose === 'approve') return location.replace(`${base}/approve`);
  if (view.state === 'awaiting_confirmation') return show(view.finishElsewhere ? elsewhereScreen(view) : confirmScreen(view));
  if (view.handoff) return show(view.handoff.selectedAccount ? chosenScreen(view) : handoffScreen(view));
  if (view.sheet) return show(sheetScreen(view));
  if (view.apps) return show(appsScreen(view));
  return show(endedScreen(view, 'not_found'));
}

(async () => {
  try { if (secret) await api('claim', {secret}); render(await api('view')); }
  catch (error) { show(endedScreen({state: 'failed'}, ['expired', 'session_in_use'].includes(error.code) ? error.code : 'not_found')); }
})();

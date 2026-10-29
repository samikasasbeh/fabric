// Hosted Connectors catalog, served at /connectors (UI-1, docs/UI-0-SCREEN-CONTRACTS.md). Renders the CatalogPage view
// model from GET /api/ui/catalog and nothing else: no joins, no client-side categories or copy. Opened from a
// developer's manage link (F03.10, /connect/<session>/apps) it shows the person's connected apps from that link's API.
// Pure helpers are exported for tests; DOM code runs only in a browser.
import {baseFor, makeApi, applyBrand, finish} from './hosted-base.js';

const OWNER = baseFor('/connectors');

const ACTION = {
  view: {label: 'View', kind: 'link'},
  connect: {label: 'Connect', kind: 'link'},
  setup_required: {label: 'Setup needed', kind: 'note'},
  unavailable: {label: 'Not available', kind: 'note'},
};

/** The row's action: a link to the app's page for View and Connect, plain text otherwise. */
export function rowAction(card, base = OWNER) {
  const action = ACTION[card?.primaryAction] || ACTION.unavailable;
  return {...action, href: action.kind === 'link' ? base.app(card.id) : null,
    name: `${action.label} ${card?.displayName || card?.name || 'app'}`};
}

/** A short line about the account state, only when the owner must act. */
export function connectionNote(card) {
  const state = card?.connectionState;
  if (!state || state.state === 'available') return null;
  if (state.state === 'attention') return 'Reconnect needed';
  if (state.needsAttention) return `${state.needsAttention} account${state.needsAttention === 1 ? '' : 's'} need${state.needsAttention === 1 ? 's' : ''} attention`;
  return null;
}

/** Only Fabric's own icon route is ever used as an image source. */
export function iconSource(card, base = OWNER) {
  return typeof card?.iconUrl === 'string' && base.icon.test(card.iconUrl) ? card.iconUrl : null;
}

/** The catalog request for a view state; the query string is built from known keys only. */
export function catalogUrl({status = 'all', q = '', category = '', cursor = ''} = {}, base = OWNER) {
  const params = new URLSearchParams();
  // A manage link shows connected apps only; the server decides that, so the page never sends a status there.
  if (status !== 'all' && !base.tenant) params.set('status', status);
  if (q.trim()) params.set('q', q.trim());
  if (category) params.set('category', category);
  if (cursor) params.set('cursor', cursor);
  const query = params.toString();
  return `${base.catalogApi}${query ? `?${query}` : ''}`;
}

// ---- browser ------------------------------------------------------------------------
if (typeof document !== 'undefined') {
  const root = document.querySelector('#catalog'), live = document.querySelector('#status'), base = baseFor(location.pathname), api = makeApi(base, fetch.bind(window));
  const state = {status: base.tenant ? 'connected' : 'all', q: '', category: '', cursor: '', results: []};
  let timer = null, sequence = 0;
  const el = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) { if (key === 'onclick') node.addEventListener('click', value); else if (value !== false && value !== undefined && value !== null) node.setAttribute(key, value === true ? '' : value); }
    for (const child of children.flat()) if (child !== null && child !== undefined && child !== false) node.append(child);
    return node;
  };
  const say = text => { live.textContent = text; };
  function icon(card, size) {
    const holder = el('span', {class: `app-icon ${size}`, 'aria-hidden': 'true'}, (card.displayName || card.name || '?').charAt(0));
    const src = iconSource(card, base);
    if (src) {
      // Not lazy: the image is not on the page until it has loaded, and a browser never fetches a lazy image off the page.
      const image = el('img', {src, alt: '', decoding: 'async', referrerpolicy: 'no-referrer'});
      image.addEventListener('load', () => holder.replaceChildren(image), {once: true});
    }
    return holder;
  }
  function action(card) {
    const {label, kind, href, name} = rowAction(card, base);
    return kind === 'link' ? el('a', {class: 'row-action', href, 'aria-label': name}, label) : el('span', {class: 'row-note'}, label);
  }
  function row(card) {
    const note = connectionNote(card);
    return el('li', {class: 'app-row'}, icon(card, 'small'),
      el('span', {class: 'row-copy'}, el('span', {class: 'row-name'}, card.displayName || card.name), el('span', {class: 'row-tagline'}, card.tagline), note ? el('span', {class: 'row-attention'}, note) : null),
      action(card));
  }
  function tile(card) {
    const {href, kind, label} = rowAction(card, base);
    const body = [icon(card, 'large'), el('span', {class: 'tile-name'}, card.displayName || card.name), el('span', {class: 'tile-tagline', title: card.tagline}, card.tagline)];
    return kind === 'link' ? el('a', {class: 'tile', href, 'aria-label': `${label} ${card.displayName || card.name}`}, body) : el('div', {class: 'tile disabled'}, body);
  }
  const group = (title, cards, extra = null) => el('section', {class: 'group'}, el('div', {class: 'group-head'}, el('h2', {}, title), extra), el('ul', {class: 'rows'}, cards.map(row)));
  function render(page) {
    const parts = [];
    if (state.category || state.q) {
      const label = state.category ? page.categories.find(entry => entry.category.id === state.category)?.category.label || 'Apps' : 'Results';
      if (state.category) parts.push(el('button', {type: 'button', class: 'back', onclick: () => { Object.assign(state, {category: '', cursor: '', results: []}); load(); }}, '‹ All apps'));
      if (!state.results.length) parts.push(el('p', {class: 'empty'}, state.q ? `No ${state.status === 'connected' ? 'connected ' : ''}apps match “${state.q.trim()}”.` : 'No apps here yet.'));
      else parts.push(group(label, state.results));
      if (page.nextCursor) parts.push(el('button', {type: 'button', class: 'more', onclick: () => { state.cursor = page.nextCursor; load(true); }}, 'Show more'));
    } else {
      if (page.featured.length) parts.push(el('section', {class: 'group'}, el('div', {class: 'group-head'}, el('h2', {}, 'Featured')), el('div', {class: 'tiles'}, page.featured.slice(0, 3).map(tile))));
      for (const entry of page.categories) {
        if (!entry.preview.length) continue;
        const seeAll = entry.more ? el('button', {type: 'button', class: 'see-all', 'aria-label': `See all ${entry.category.label}`, onclick: () => { Object.assign(state, {category: entry.category.id, cursor: '', results: []}); load(); }}, 'See all ›') : null;
        parts.push(group(entry.category.label, entry.preview, seeAll));
      }
      if (!parts.length) parts.push(el('p', {class: 'empty'}, base.tenant ? 'You have no connected apps here yet.' : state.status === 'connected' ? 'No connected apps yet. Choose Available to connect one.' : 'No apps are available here yet.'));
    }
    root.replaceChildren(...parts);
    root.setAttribute('aria-busy', 'false');
  }
  async function load(append = false) {
    const mine = ++sequence;
    root.setAttribute('aria-busy', 'true');
    try {
      const page = await api(catalogUrl(state, base));
      if (mine !== sequence) return;
      state.results = append ? [...state.results, ...(page.results || [])] : page.results || [];
      render(page);
      say(state.q || state.category ? `${state.results.length} app${state.results.length === 1 ? '' : 's'} shown` : '');
    } catch (error) {
      if (mine !== sequence) return;
      root.replaceChildren(el('p', {class: 'empty'}, error.message || 'The catalog could not be loaded.'));
      root.setAttribute('aria-busy', 'false');
      say('The catalog could not be loaded.');
    }
  }
  const search = document.querySelector('#search');
  search.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => { Object.assign(state, {q: search.value, cursor: '', results: []}); load(); }, 180); });
  for (const segment of document.querySelectorAll('[data-status]')) segment.addEventListener('click', () => {
    Object.assign(state, {status: segment.dataset.status, cursor: '', results: []});
    for (const other of document.querySelectorAll('[data-status]')) other.setAttribute('aria-pressed', String(other === segment));
    load();
  });
  // A manage link: the developer's name and colours, no segments (connected apps only), and Done to go back.
  async function boot() {
    if (!base.tenant) return load();
    try {
      const view = await api.start();
      applyBrand(view.developer?.brand, {root: document.documentElement, media: window.matchMedia?.('(prefers-color-scheme: dark)')});
      const name = view.developer?.appName || 'the app';
      document.title = `${name} · Your apps`;
      document.querySelector('#brand')?.replaceChildren(name);
      document.querySelector('#brand')?.removeAttribute('href');
      document.querySelector('#activity-link')?.setAttribute('href', base.activity);
      document.querySelector('.segments')?.setAttribute('hidden', '');
      document.querySelector('.lede').textContent = `Your apps connected to ${name}. Choose what its agent may read, change or must ask about.`;
      const done = el('button', {type: 'button', class: 'text-accent', onclick: async () => {
        done.disabled = true;
        try { const result = await finish(api, base, {assign: url => location.assign(url), opener: window.opener, close: () => window.close()}); if (!result?.redirect) say('Done. You can close this window.'); }
        catch (error) { done.disabled = false; say(error.message); }
      }}, 'Done');
      document.querySelector('.head-row')?.append(done);
      return load();
    } catch (error) {
      root.replaceChildren(el('p', {class: 'empty'}, error.code === 'expired' ? 'This link has expired. Ask the app for a new one.' : error.code === 'already_finished' ? 'This link has already been used.' : 'This link is not valid. Ask the app for a new one.'));
      root.setAttribute('aria-busy', 'false');
    }
  }
  boot();
}

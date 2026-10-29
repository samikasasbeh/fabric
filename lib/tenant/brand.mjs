// F03.10 (docs/F03-DEVELOPER-LAYER.md, P28; docs/UI-0-SCREEN-CONTRACTS.md "Brand and color are tokens"): a project's
// colours for Fabric's hosted pages. Only the named tokens, only #rrggbb, a light and an optional dark set; anything not
// set keeps Fabric's own colour. Text must stay readable: the accent and the text on it, every colour the pages draw
// text in (ink, muted, accent, danger, attention) on both surfaces, and the ink on Fabric's own hover colour, which a
// brand cannot change, need a contrast of at least 4.5:1 (WCAG AA for body text), checked on the set as it will be
// shown. Otherwise a key could hide Fabric's warnings, Reject, Disconnect or fine print. The line colour is not
// checked: it draws only dividers and borders (Fabric's own is about 1.2:1), never text or a control's only mark.

export const BRAND_TOKENS = Object.freeze(['surface', 'surfaceRaised', 'ink', 'muted', 'line', 'accent', 'onAccent', 'danger', 'attention']);
/** Fabric's own palette (public/hosted.css), which a brand overrides token by token. */
export const DEFAULT_BRAND = Object.freeze({
  light: Object.freeze({surface: '#f4f5f2', surfaceRaised: '#ffffff', ink: '#172e2d', muted: '#63726e', line: '#e1e6e1', accent: '#126f61', onAccent: '#ffffff', danger: '#a3352c', attention: '#126f61'}),
  dark: Object.freeze({surface: '#151817', surfaceRaised: '#202523', ink: '#eef2f0', muted: '#9aa8a3', line: '#2f3633', accent: '#5fd0bb', onAccent: '#0b1f1b', danger: '#ff8b80', attention: '#5fd0bb'}),
});
export const MIN_CONTRAST = 4.5;
const HEX = /^#[0-9a-fA-F]{6}$/;
/** public/hosted.css --surface-hover, not a brand token: hovered and selected rows keep their text in ink on it. */
const SURFACE_HOVER = Object.freeze({light: '#eef1ed', dark: '#2a302d'});
const TEXT = Object.freeze({ink: 'the text', muted: 'the muted text', accent: 'the accent text', danger: 'the danger text', attention: 'the attention text'});
/** Every pair to check, in order: [text, background, what]. */
const PAIRS = Object.freeze([['accent', 'onAccent', 'the accent and the text on it'],
  ...Object.entries(TEXT).flatMap(([token, what]) => [[token, 'surface', `${what} and the page`], [token, 'surfaceRaised', `${what} and the cards`]]),
  ['ink', 'surfaceHover', 'the text and Fabric\'s hover colour']]);

export class BrandError extends Error {}

/** WCAG 2 contrast ratio of two #rrggbb colours. */
export function contrast(a, b) {
  const luminance = hex => {
    const [r, g, b2] = [1, 3, 5].map(at => parseInt(hex.slice(at, at + 2), 16) / 255).map(c => c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
    return 0.2126 * r + 0.7152 * g + 0.0722 * b2;
  };
  const [high, low] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (high + 0.05) / (low + 0.05);
}

/** A brand as sent: {light?, dark?}, each a partial set of tokens. Returns it normalised (lowercase), or throws BrandError. */
export function checkedBrand(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new BrandError('brand is {light?, dark?}, each a set of colour tokens.');
  const unknown = Object.keys(value).find(key => !['light', 'dark'].includes(key));
  if (unknown) throw new BrandError(`brand has light and dark sets only, not ${unknown.slice(0, 40)}.`);
  if (!value.light && !value.dark) throw new BrandError('brand needs a light or a dark set.');
  const out = {};
  for (const scheme of ['light', 'dark']) {
    if (value[scheme] === undefined) continue;
    const set = value[scheme];
    if (!set || typeof set !== 'object' || Array.isArray(set) || !Object.keys(set).length) throw new BrandError(`brand.${scheme} is a set of colour tokens.`);
    const extra = Object.keys(set).find(key => !BRAND_TOKENS.includes(key));
    if (extra) throw new BrandError(`${extra.slice(0, 40)} is not a colour token; use ${BRAND_TOKENS.join(', ')}.`);
    for (const [token, colour] of Object.entries(set)) if (typeof colour !== 'string' || !HEX.test(colour)) throw new BrandError(`brand.${scheme}.${token} must be a #rrggbb colour.`);
    const normal = Object.fromEntries(Object.entries(set).map(([token, colour]) => [token, colour.toLowerCase()]));
    const shown = {...DEFAULT_BRAND[scheme], ...normal, surfaceHover: SURFACE_HOVER[scheme]};
    for (const [a, b, what] of PAIRS) {
      const ratio = contrast(shown[a], shown[b]);
      if (ratio < MIN_CONTRAST) throw new BrandError(`In the ${scheme} set, ${what} (${shown[a]} on ${shown[b]}) have a contrast of ${ratio.toFixed(2)}:1; at least ${MIN_CONTRAST}:1 is needed so people can read it.`);
    }
    out[scheme] = normal;
  }
  return out;
}

/**
 * The CSS custom properties a page sets for a brand (only tokens the developer chose; the rest stay Fabric's). A set
 * that fails today's checks, such as one stored before they were added, is left out and the page keeps Fabric's own.
 */
export function brandCss(brand) {
  const name = token => `--${token.replace(/[A-Z]/g, letter => `-${letter.toLowerCase()}`)}`;
  const readable = scheme => { try { return checkedBrand({[scheme]: brand[scheme]})[scheme]; } catch { return null; } };
  return Object.fromEntries(['light', 'dark'].filter(scheme => brand?.[scheme]).map(scheme => [scheme, readable(scheme)]).filter(([, set]) => set).map(([scheme, set]) => [scheme, Object.fromEntries(Object.entries(set).map(([token, colour]) => [name(token), colour]))]));
}

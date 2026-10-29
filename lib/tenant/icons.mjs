// The five apps' icons on Fabric's pages (F03.1, docs/F03-DEVELOPER-LAYER.md section 6.3): the bundled, reviewed brand
// marks from catalog/icons.json (Simple Icons, CC0), drawn by Fabric on a white tile, or Fabric's own monogram. Only
// path data and a colour are read from the file, both checked here, so nothing in it can run in a browser.
import {readFileSync} from 'node:fs';

const PATH = /^[MmLlHhVvCcSsQqTtAaZz0-9.,\s+\-eE]{1,4000}$/, HEX = /^[0-9A-Fa-f]{6}$/;
const FILE = JSON.parse(readFileSync(new URL('../../catalog/icons.json', import.meta.url), 'utf8'));
export const BRAND_ICONS = Object.freeze(Object.fromEntries(Object.entries(FILE.icons || {}).map(([appId, icon]) => {
  if (!PATH.test(icon.path) || !HEX.test(icon.hex)) throw new Error(`catalog/icons.json: the ${appId} icon is not plain path data and a colour.`);
  return [appId, Object.freeze({path: icon.path, hex: icon.hex.toUpperCase(), title: String(icon.title)})];
})));

/** A plain monogram icon Fabric draws itself; never a publisher fetch. */
export function monogram(name) {
  const letter = (String(name).match(/[A-Za-z0-9]/)?.[0] || '?').toUpperCase();
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#5b4bdb"/><text x="32" y="42" font-family="Helvetica,Arial,sans-serif" font-size="30" font-weight="600" fill="#ffffff" text-anchor="middle">${letter}</text></svg>`;
}

/** The app's icon: its reviewed brand mark on a white tile, or the monogram. */
export function appIcon(appId, name) {
  const icon = BRAND_ICONS[appId];
  if (!icon) return monogram(name);
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#ffffff"/><g transform="translate(14 14) scale(1.5)"><path fill="#${icon.hex}" d="${icon.path}"/></g></svg>`;
}

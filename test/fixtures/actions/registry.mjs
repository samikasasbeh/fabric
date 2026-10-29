// F10.9 part a (docs/F10.9-BUILD-MAP.md part a, R14, R17 and open point Minor 2): the fixture transform registry. It holds F10.8's real
// TRANSFORMS plus a stub, in the real entry shape, of one transform no step ships: ids.linkPage@1 (cut from step 17, kept for the Link paging
// grammar). F10.17 shipped collections.stringValues@1 (an outputMap result) and F10.19 shipped notion.schema@1 (a schema entry) and
// notion.propertyValues@1 (a resolvedValues argument and an outputFrom result), so their stubs are gone and the fixture registry holds the
// real ones. Each stub passes F10.8's checkEntry() when this module loads, so the fixture cannot drift from the real
// entry shape. PINS is the registry's own pins map: the shipped pins of lib/transforms/pins.json for the real transforms, and a hash of
// each stub's source for the stubs, so an action that names a stub has an id, and a test can swap one pin to see the id move.
// Test data only: nothing in lib/ imports it.
import {readFileSync} from 'node:fs';
import {canonicalHash} from '../../../lib/compiler.mjs';
import {TRANSFORMS as SHIPPED, checkEntry} from '../../../lib/transforms/index.mjs';
import {deepFreeze} from '../../../lib/transforms/run.mjs';
import {TransformError} from '../../../lib/transforms/_shared/error.v1.mjs';

const OBJECT = (properties, required = Object.keys(properties)) => ({type: 'object', properties, required, additionalProperties: false});
const BASE = {pointerArgs: [], stepData: {}, resolvedValues: {}, usesClock: false, runtimeFacts: [], refuses: [], excludes: []};

// ---- ids.linkPage@1: a Link header to a next page number, never a URL (F10.8 map part k) ----------------------------------------
const LINK = /<([^<>]*)>\s*;\s*rel="([^"]*)"/g;
const linkPage = {...BASE, name: 'ids.linkPage', version: 1, kind: 'map',
  input: OBJECT({link: {type: 'string', maxLength: 8192}, url: {type: 'string', minLength: 1, maxLength: 2048}, param: {type: 'string', minLength: 1, maxLength: 64}}),
  output: OBJECT({page: {type: 'integer', minimum: 1, maximum: 100_000}}, []),
  maxInputBytes: 16_384, maxOutputBytes: 256,
  example: {input: {link: '<https://api.fixture.test/items?page=2>; rel="next", <https://api.fixture.test/items?page=9>; rel="last"', url: 'https://api.fixture.test/items?page=1', param: 'page'},
    output: {page: 2}},
  run({link, url, param}) {
    const next = [...link.matchAll(LINK)].find(match => match[2].split(/\s+/).includes('next'));
    if (!next) return {};
    let target, request;
    try { target = new URL(next[1]); request = new URL(url); } catch { throw new TransformError('input_invalid'); }
    // Only the page number of a next URL on the request's own origin and path; the URL itself is never followed (I4).
    if (target.origin !== request.origin || target.pathname !== request.pathname) return {};
    const page = target.searchParams.get(param);
    return page !== null && /^[1-9][0-9]{0,4}$/.test(page) ? {page: Number(page)} : {};
  }};

/** The stubs, each with the module file its real version will have. */
export const STUBS = Object.freeze([
  {file: 'ids/linkPage.v1.mjs', entry: linkPage},
]);
for (const {file, entry} of STUBS) checkEntry(entry, file);
const idOf = entry => `${entry.name}@${entry.version}`;
for (const {entry} of STUBS) if (SHIPPED.has(idOf(entry))) throw new Error(`${idOf(entry)} is shipped now: drop its stub from test/fixtures/actions/registry.mjs.`);

/** F10.8's registry plus the stubs, by name@version. */
export const TRANSFORMS = new Map([...SHIPPED, ...STUBS.map(({entry}) => [idOf(entry), deepFreeze(entry)])]);
const SHIPPED_PINS = JSON.parse(readFileSync(new URL('../../../lib/transforms/pins.json', import.meta.url), 'utf8')).transforms;
/** The fixture registry's own pins: the shipped pin of each real transform, and for each stub the hash of its source in this file. */
export const PINS = Object.freeze({...SHIPPED_PINS, ...Object.fromEntries(STUBS.map(({entry}) => [idOf(entry),
  canonicalHash({kind: 'fabric-fixture-stub', transform: idOf(entry), run: entry.run.toString(), entry: JSON.parse(JSON.stringify(entry))})]))});

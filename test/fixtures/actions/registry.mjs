// F10.9 part a (docs/F10.9-BUILD-MAP.md part a, R14, R17 and open point Minor 2): the fixture transform registry. It holds F10.8's real
// TRANSFORMS plus a stub, in the real entry shape, of each transform no step ships. F10.17 shipped collections.stringValues@1 (an outputMap
// result), F10.19 shipped notion.schema@1 (a schema entry) and notion.propertyValues@1 (a resolvedValues argument and an outputFrom result), and
// Iteration 9 shipped ids.linkPage@1 (docs/I07-BUILD-MAP.md step 6), so their stubs are gone and the list is empty. Each stub passes F10.8's
// checkEntry() when this module loads, so the fixture cannot drift from the real entry shape. PINS is the registry's own pins map: the shipped
// pins of lib/transforms/pins.json for the real transforms, and a hash of each stub's source for the stubs, so an action that names a stub has
// an id, and a test can swap one pin to see the id move. Test data only: nothing in lib/ imports it.
import {readFileSync} from 'node:fs';
import {canonicalHash} from '../../../lib/compiler.mjs';
import {TRANSFORMS as SHIPPED, checkEntry} from '../../../lib/transforms/index.mjs';
import {deepFreeze} from '../../../lib/transforms/run.mjs';

/** The stubs, each with the module file its real version will have. */
export const STUBS = Object.freeze([]);
for (const {file, entry} of STUBS) checkEntry(entry, file);
const idOf = entry => `${entry.name}@${entry.version}`;
for (const {entry} of STUBS) if (SHIPPED.has(idOf(entry))) throw new Error(`${idOf(entry)} is shipped now: drop its stub from test/fixtures/actions/registry.mjs.`);

/** F10.8's registry plus the stubs, by name@version. */
export const TRANSFORMS = new Map([...SHIPPED, ...STUBS.map(({entry}) => [idOf(entry), deepFreeze(entry)])]);
const SHIPPED_PINS = JSON.parse(readFileSync(new URL('../../../lib/transforms/pins.json', import.meta.url), 'utf8')).transforms;
/** The fixture registry's own pins: the shipped pin of each real transform, and for each stub the hash of its source in this file. */
export const PINS = Object.freeze({...SHIPPED_PINS, ...Object.fromEntries(STUBS.map(({entry}) => [idOf(entry),
  canonicalHash({kind: 'fabric-fixture-stub', transform: idOf(entry), run: entry.run.toString(), entry: JSON.parse(JSON.stringify(entry))})]))});

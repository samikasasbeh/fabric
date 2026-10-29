// F10.11 part c (docs/F10.11-BUILD-MAP.md part c): the action catalog. loadActionCatalog() reads the reviewed action files and choice
// sources of a folder (catalog/actions and catalog/choices by default) one app at a time, so a bad file refuses only its own app, and says
// for each action whether it is active: only when its file is reviewed, it is certified, every step places, every transform it names
// still has its pinned code, and its live evidence passes (I8). seedActions() writes each action's capability into a store with that
// status, and nothing else. The catalog also carries runPlan() and the runner (lib/actions-runtime.mjs, parts g to j): server code reaches
// the action modules only through the object loadActionsSafely() returns (part p), never by importing this file. Nothing here sends a request
// or runs a transform.
import {readdirSync, readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {canonicalHash} from './compiler.mjs';
import {capabilityPermissionHash} from './permissions.mjs';
import {validateActionFile, actionCapability, runPlan} from './actions.mjs';
import {validateChoiceSources, sourceById} from './choice-sources.mjs';
import {OPTION_SOURCES} from './option-sources.mjs';
import {evaluate, buildRequest, checkConcrete, acceptAction, prepareAction, executeAction, verifyAction, runAction, actionDigest, assertActionAuthorization,
  staticInputs, choiceRequest, choiceNext} from './actions-runtime.mjs';
import {TRANSFORMS} from './transforms/index.mjs';
import {computePins, PINS, ROOT} from './transform-pins.mjs';

const DIRECTORY = new URL('../catalog/actions/', import.meta.url);
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const listWords = items => items.length <= 1 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items.at(-1)}`;
const deepFreeze = value => { if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) { Object.freeze(value); for (const item of Object.values(value)) deepFreeze(item); } return value; };

/** Why an action is a candidate, in the order the status rule reads them. */
export const STATUS_WORDS = Object.freeze({
  unreviewed: 'The action file is a candidate: no reviewer has marked it reviewed yet (I8).',
  uncertified: 'This action names no live evidence yet, so it stays a candidate (I8).',
  unplaced: 'A step of this action cannot be placed: its app is reviewed by method id and Fabric has no map of it yet.',
  repinned: ids => `The code of ${listWords(ids)} changed since it was pinned, so this action waits for a reviewed re-pin.`,
  evidence: 'Its live evidence does not pass: no record for this id passed with the current pins of its transforms and this definition.',
});

/**
 * Whether one live evidence record certifies one validated action: it passed, it holds the current pins (`pins`, by transform id) of
 * exactly the transforms the action names, and its definition hash, when it names one, is the action's. A record of any other shape
 * fails; nothing throws. scripts/app-template-check.mjs check 6 reads evidence through this too, so the gate and the start agree.
 */
export function evidencePasses(entry, evidence, pins) {
  if (!record(evidence) || evidence.passed !== true || !record(evidence.transforms)) return false;
  const ids = entry.transforms;
  if (Object.keys(evidence.transforms).length !== ids.length || !ids.every(id => typeof pins?.[id] === 'string' && evidence.transforms[id] === pins[id])) return false;
  return evidence.definitionHash === undefined || evidence.definitionHash === entry.definitionHash;
}

/** The parsed JSON of a file, or `refuse(words)` when it cannot be read as JSON. */
function readJson(file, refuse) {
  let text;
  try { text = readFileSync(file, 'utf8'); } catch { refuse(); }
  try { return JSON.parse(text); } catch { return refuse(); }
}
const jsonNames = directory => { try { return readdirSync(directory).filter(name => name.endsWith('.json')).sort(); } catch { return []; } };

/**
 * The action catalog of `directory` (catalog/actions by default) and its choice sources (the choices folder beside it). `maps` are the
 * stored application maps by app; `deps` the validator's other dependencies (lib/actions.mjs validateActionFile()), a `choices` map in it
 * replacing the choices folder; `evidenceRoot` is where docs/live-evidence/<appId>/actions.json is read (the repository root by default);
 * `codeHashes(ids)` gives the code hash each named transform has now (computePins() over the repository by default).
 * Returns {entries, superseded, choices, refused, transforms, pins, runPlan, the runner (evaluate, buildRequest, checkConcrete, acceptAction,
 * prepareAction, executeAction, verifyAction, runAction, actionDigest, assertActionAuthorization, staticInputs), entryOf, pinned, reload}:
 *   entries     action id to {appId, file, entry, capability, status, reason}: the validated entry, the capability it is (with its
 *               status) and, for a candidate, why
 *   superseded  old id to {appId, replacedBy, reason, stopsAfter}, replacedBy being the current id
 *   choices     app id to its validated choice sources
 *   refused     app id (or the name of a file not named after its app) to the words that refused it
 *   transforms, pins     the transform registry the actions run and its pins
 *   entryOf(capability)  the entry of that capability, only when the ids match and the capability hashes to the entry's definitionHash
 *   pinned(item)         true while every transform the item's action names has, as read at load, the code its pin names (F10.11 part h)
 *   choiceSource(appId, id)          the source a choice of that app names: its choice source, or a version 1 option source read as one
 *   choiceRequest, choiceNext        one page of a directory choice source and its next cursor, for POST /v1/options (F10.11 part o)
 *   seed(store, {audit, appId})      seedActions() with this catalog, so a server seeds without importing this file (F10.11 part p)
 *   reload(appId, map)   validates one app again with its new map, in place, and returns the catalog
 */
export function loadActionCatalog({directory = DIRECTORY, evidenceRoot = ROOT, maps = new Map(), deps = {}, codeHashes = ids => computePins(ROOT, ids).transforms} = {}) {
  const base = directory instanceof URL ? fileURLToPath(directory) : String(directory), choiceBase = path.join(base, '..', 'choices');
  const ownMaps = new Map(maps instanceof Map ? maps : Object.entries(record(maps) ? maps : {}));
  const pins = deps.pins ?? PINS?.transforms ?? {};
  const entries = new Map(), superseded = new Map(), choices = new Map(), refused = new Map(), hashesOf = new Map();

  function entryOf(capability) {
    const item = typeof capability?.id === 'string' ? entries.get(capability.id) : undefined;
    if (!item) return null;
    try { return capabilityPermissionHash(capability) === item.entry.definitionHash ? item : null; } catch { return null; }
  }
  function forget(appId) {
    for (const [id, item] of entries) if (item.appId === appId) entries.delete(id);
    for (const [id, item] of superseded) if (item.appId === appId) superseded.delete(id);
    choices.delete(appId);
    refused.delete(appId);
    hashesOf.delete(appId);
  }
  /** One app's choice sources: from deps.choices when given, else its file in the choices folder; null when it has none. */
  function sourcesOf(appId) {
    if (deps.choices instanceof Map) return deps.choices.get(appId) ?? null;
    const name = `${appId}.json`;
    if (!jsonNames(choiceBase).includes(name)) return null;
    const file = readJson(path.join(choiceBase, name), () => { throw new Error(`Choice source file ${name} is not JSON.`); });
    if (!record(file) || file.appId !== appId) throw new Error(`Choice source file ${name} must be named after its appId.`);
    return validateChoiceSources(file, {...deps, maps: ownMaps});
  }
  /** One app's live evidence by action id; evidence that is not a JSON object counts as none. */
  function evidenceOf(appId) {
    try { const value = JSON.parse(readFileSync(path.join(evidenceRoot, 'docs', 'live-evidence', appId, 'actions.json'), 'utf8')); return record(value) ? value : {}; } catch { return {}; }
  }
  function loadApp(appId) {
    forget(appId);
    try {
      const sources = sourcesOf(appId), name = `${appId}.json`;
      if (!jsonNames(base).includes(name)) {
        if (sources) choices.set(appId, sources);
        return;
      }
      const file = readJson(path.join(base, name), () => { throw new Error(`Action file ${name} is not JSON.`); });
      if (!record(file) || file.appId !== appId) throw new Error(`Action file ${name} must be named after its appId.`);
      const {actions} = validateActionFile(file, {...deps, maps: ownMaps, choices: new Map(sources ? [[appId, sources]] : [])});
      // F10.9 map section 9: a choice source never holds an id an action file retired, so no choice names an old action.
      const old = new Set((file.superseded ?? []).map(item => item.id));
      const stale = (sources ?? []).find(source => old.has(source.id));
      if (stale) throw new Error(`Choice sources for ${appId}: ${stale.id} is a superseded action id: a choice names a current source, never an id an action file retired.`);
      let hashes;
      const named = [...new Set(actions.flatMap(entry => [...entry.transforms, ...entry.pollTransforms]))].sort();
      try { hashes = named.length ? codeHashes(named) : {}; } catch { hashes = {}; }
      hashesOf.set(appId, Object.freeze({...(record(hashes) ? hashes : {})}));
      let evidence = null;
      for (const entry of actions) {
        const [status, reason] = statusOf(file, entry, {pins, hashes: record(hashes) ? hashes : {}, evidence: () => evidence ??= evidenceOf(appId)});
        entries.set(entry.id, deepFreeze({appId, file: name, entry, capability: {...actionCapability(file, entry), status}, status, reason}));
      }
      for (const item of file.superseded ?? []) {
        const current = actions.find(entry => entry.key === item.replacedBy.key && entry.version === item.replacedBy.version);
        superseded.set(item.id, deepFreeze({appId, replacedBy: current.id, reason: item.reason, stopsAfter: item.stopsAfter}));
      }
      if (sources) choices.set(appId, sources);
    } catch (error) {
      forget(appId);
      refused.set(appId, String(error?.message ?? error));
    }
  }
  const options = deps.options ?? OPTION_SOURCES;
  const catalog = Object.freeze({entries, superseded, choices, refused, transforms: deps.transforms ?? TRANSFORMS, pins, runPlan, evaluate, buildRequest, checkConcrete,
    acceptAction, prepareAction, executeAction, verifyAction, runAction, actionDigest, assertActionAuthorization, staticInputs, entryOf,
    choiceSource: (appId, id) => sourceById(id, choices.get(appId) ?? [], (options instanceof Map ? options.get(appId) : options?.[appId]) ?? []),
    choiceRequest: (source, request) => choiceRequest(source, {...request, transforms: catalog.transforms}),
    choiceNext: (source, answer, page) => choiceNext(source, answer, {...page, transforms: catalog.transforms}),
    seed: (store, options) => seedActions(store, catalog, options),
    // F10.21: the reviewed sign-in a caller gave for an app (deps.identities), which may add a success rule for an app that has none.
    identityOf: appId => deps.identities instanceof Map ? deps.identities.get(appId) ?? null : null,
    pinned(item) {
      const hashes = hashesOf.get(item?.appId) ?? {};
      return Array.isArray(item?.entry?.transforms) && item.entry.transforms.every(id => typeof pins[id] === 'string' && hashes[id] === pins[id]);
    },
    reload(appId, map) {
      if (map === null || map === undefined) ownMaps.delete(appId); else ownMaps.set(appId, map);
      loadApp(appId);
      return catalog;
    }});
  // Each app named by an action file or a choices file, one at a time; a file not named after its app is refused under its own name.
  const apps = [...new Set([...jsonNames(base), ...(deps.choices instanceof Map ? [] : jsonNames(choiceBase))].map(name => name.slice(0, -'.json'.length)))].sort();
  for (const appId of apps) loadApp(appId);
  return catalog;
}

/** The status rule, in order: the file is reviewed, the action certified, every step placed, every named transform still pinned, and
 *  its evidence passes. Returns [status, reason], reason null when active. */
function statusOf(file, entry, {pins, hashes, evidence}) {
  if (file.reviewStatus !== 'reviewed') return ['candidate', STATUS_WORDS.unreviewed];
  if (entry.action.certified === undefined) return ['candidate', STATUS_WORDS.uncertified];
  if (entry.unplaced) return ['candidate', STATUS_WORDS.unplaced];
  const changed = [...new Set([...entry.transforms, ...entry.pollTransforms])].sort().filter(id => typeof pins[id] !== 'string' || hashes[id] !== pins[id]);
  if (changed.length) return ['candidate', STATUS_WORDS.repinned(changed)];
  if (!evidencePasses(entry, evidence()[entry.id], pins)) return ['candidate', STATUS_WORDS.evidence];
  return ['active', null];
}

/**
 * Writes the catalog's actions into a store's capabilities: each current action as exactly its capability with its status, written only
 * when the stored record is missing or differs (which also repairs a tampered one); a stored action id that is superseded or that no file
 * lists any more becomes disabled; an active action of a refused app becomes a candidate. It never deletes, and never overwrites a record
 * of another driver that holds an action's id (audited with reason action_id_taken). Each write is audited as action.status with its
 * definition hash and reason (missing, changed, superseded, orphaned, app_refused); `audit` replaces store.audit() (the platform catalog
 * audits its own type). `appId` seeds that app's actions only (F10.11 part p: a map stored for one app). Returns the ids written; a second
 * run writes nothing.
 */
export function seedActions(store, catalog, {audit, appId} = {}) {
  const note = audit ?? (event => store.audit(event)), written = [], ours = item => appId === undefined || item?.appId === appId;
  const write = (capability, reason) => {
    store.put('capabilities', capability);
    note({type: 'action.status', capabilityId: capability.id, appId: capability.appId, status: capability.status, definitionHash: capabilityPermissionHash(capability), reason});
    written.push(capability.id);
  };
  for (const [id, item] of catalog.entries) {
    if (!ours(item)) continue;
    const stored = store.get('capabilities', id);
    if (stored && stored.driver !== 'action') { note({type: 'action.status', capabilityId: id, appId: item.appId, reason: 'action_id_taken'}); continue; }
    if (stored && canonicalHash(stored) === canonicalHash(item.capability)) continue;
    write(structuredClone(item.capability), stored ? 'changed' : 'missing');
  }
  for (const stored of store.list('capabilities')) {
    if (stored?.driver !== 'action' || !ours(stored) || catalog.entries.has(stored.id)) continue;
    if (catalog.refused.has(stored.appId)) { if (stored.status === 'active') write({...stored, status: 'candidate'}, 'app_refused'); continue; }
    if (stored.status !== 'disabled') write({...stored, status: 'disabled'}, catalog.superseded.has(stored.id) ? 'superseded' : 'orphaned');
  }
  return written;
}

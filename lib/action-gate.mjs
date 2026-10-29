// F10.11 part p (docs/F10.11-BUILD-MAP.md part p; critique resolutions 5 and 7): how both servers and the operator's catalog command load
// the action catalog, and what each does when it will not load. This file imports no action module. loadActionsSafely() holds the one
// import() of lib/action-catalog.mjs that any server-reachable file makes, inside a try: importing the action modules runs every
// transform's examples and reads the pins, so an example that throws, or pins that are not JSON, leave the catalog null instead of
// stopping a server. With no catalog every action reads unsupported and never runs; demoteActions() turns each stored active action
// record into a candidate, and gateCatalog() serves a developer environment's platform catalog with no action more active than the catalog
// computes. Both only demote: nothing here makes an action active.
import {capabilityPermissionHash} from './permissions.mjs';

/**
 * The action catalog (lib/action-catalog.mjs loadActionCatalog()) of `directory` with the stored `maps`, or null when it cannot be loaded.
 * `evidenceRoot`, `codeHashes` and `deps` are the catalog's own options (test seams); `importer` replaces the import (a test seam for a load
 * that fails). It never throws.
 */
export async function loadActionsSafely({directory, evidenceRoot, codeHashes, deps, maps = new Map()} = {}, {importer = () => import('./action-catalog.mjs')} = {}) {
  try {
    const {loadActionCatalog} = await importer();
    return loadActionCatalog({...(directory !== undefined ? {directory} : {}), ...(evidenceRoot !== undefined ? {evidenceRoot} : {}), ...(codeHashes !== undefined ? {codeHashes} : {}),
      ...(deps !== undefined ? {deps} : {}), maps});
  } catch { return null; }
}

/**
 * After a catalog that would not load: every stored active action record becomes a candidate, audited as action.status with reason
 * catalog_failed (`audit` replaces store.audit()). A disabled record stays disabled. Returns the ids it demoted; a second run demotes none.
 */
export function demoteActions(store, {audit} = {}) {
  const note = audit ?? (event => store.audit(event)), demoted = [];
  for (const stored of store.list('capabilities')) {
    if (stored?.driver !== 'action' || stored.status !== 'active') continue;
    const candidate = {...stored, status: 'candidate'};
    store.put('capabilities', candidate);
    note({type: 'action.status', capabilityId: stored.id, appId: stored.appId, status: 'candidate', definitionHash: capabilityPermissionHash(candidate), reason: 'catalog_failed'});
    demoted.push(stored.id);
  }
  return demoted;
}

/**
 * One stored action record as a developer environment is served it. Disabled stays disabled. With no catalog it is a candidate. An id the
 * catalog no longer holds is disabled. It is active only when the stored record says active, is exactly the catalog's current definition
 * (catalog.entryOf()) and the catalog computes it active; otherwise a candidate.
 */
export function servedAction(record, catalog) {
  if (record.status === 'disabled') return record;
  if (!catalog) return {...record, status: 'candidate'};
  if (!catalog.entries.has(record.id)) return {...record, status: 'disabled'};
  return record.status === 'active' && catalog.entryOf(record)?.status === 'active' ? record : {...record, status: 'candidate'};
}

/**
 * The developer server's start gate: the read-only platform catalog `reader` (lib/tenant/platform.mjs PlatformCatalog) with every action
 * record served through servedAction(). Every other record, and every other collection, passes through unchanged. Null without a reader.
 */
export function gateCatalog(reader, catalog) {
  if (!reader) return null;
  const served = record => record?.driver === 'action' ? servedAction(record, catalog) : record;
  return Object.freeze({
    get: (collection, id) => collection === 'capabilities' ? served(reader.get(collection, id)) : reader.get(collection, id),
    list: collection => collection === 'capabilities' ? reader.list(collection).map(served) : reader.list(collection),
    close: () => reader.close(),
  });
}

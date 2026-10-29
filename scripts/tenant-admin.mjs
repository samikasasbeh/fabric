// F03.0b: the operator's platform catalog command. Writes the shared catalog every developer environment reads.
//
//   node cli.mjs tenant catalog discover <appId> --root <tenant data root>
//   node cli.mjs tenant catalog promote <appId> --capabilities <id,id> --root <tenant data root>
//   node cli.mjs tenant catalog actions [appId] --root <tenant data root>
//
// discover runs the reviewed discovery source of a catalog app into the platform catalog (operations arrive as
// candidates); promote activates named, reviewed candidates and audits each with its definition hash; actions (F10.11
// part p) writes the reviewed action files' statuses (catalog/actions) into it, each audited with its definition hash. Run
// with the tenant server stopped: the platform store takes an exclusive lock. Nothing here reads a local runtime folder.
import {readFileSync, writeFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {DiscoveryEngine} from '../lib/discovery.mjs';
import {AcquisitionEngine} from '../lib/acquisition.mjs';
import {canonicalHash, validateCapability} from '../lib/compiler.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {TenantRegistry} from '../lib/tenant/registry.mjs';
import {ServiceKeys} from '../lib/tenant/keys.mjs';
import {EnvironmentStores} from '../lib/tenant/environments.mjs';
import {loadActionsSafely, demoteActions} from '../lib/action-gate.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
/** The reviewed catalog apps (catalog/apps.json); custom tenant apps never reach the platform catalog. */
export function reviewedApps() {
  const data = JSON.parse(readFileSync(path.join(ROOT, 'catalog', 'apps.json'), 'utf8'));
  return Array.isArray(data) ? data : data.apps;
}

/** Discovers one reviewed app into the platform catalog. `request` is the network seam (tests inject a fixture); `actions` is the action
 *  catalog's (F10.11 part p, as seedActionsInPlatform() takes it). */
export async function discoverToPlatform({root, appId, apps = reviewedApps(), request, forbiddenRoots, actions = {}}) {
  const store = new PlatformStore({root, forbiddenRoots});
  try {
    const catalog = () => apps;
    // The acquisition engine is required by discovery; the platform command never calls a model.
    const acquisition = new AcquisitionEngine({store, catalog, modelUrl: null, modelKey: null, modelName: null, request: async () => { throw new Error('The platform catalog command makes no model calls.'); }});
    const map = await new DiscoveryEngine({store, catalog, acquisition, ...(request ? {request} : {})}).discover({appId});
    store.audit({type: 'platform.discovered', appId, operations: map.operations?.length ?? 0, candidates: (map.operations || []).filter(operation => operation.support === 'candidate').length});
    // F10.11 part p: the app's actions are placed on the map just stored, and their statuses written again.
    await seedPlatformActions(store, {appId, actions});
    return map;
  } finally { store.close(); }
}

/** One platform store's action records from the action catalog (lib/action-gate.mjs), each write audited as platform.action_seeded; after a
 *  catalog that will not load, every active action record becomes a candidate instead. Returns the ids written. */
async function seedPlatformActions(store, {appId, actions = {}} = {}) {
  const audit = event => store.audit({...event, type: 'platform.action_seeded'});
  const loaded = await loadActionsSafely({...actions, maps: new Map(store.list('applicationMaps').map(map => [map.appId ?? map.id, map]))}, actions.importer ? {importer: actions.importer} : {});
  return loaded ? loaded.seed(store, {audit, ...(appId !== undefined ? {appId} : {})}) : demoteActions(store, {audit});
}

/**
 * F10.11 part p: writes the reviewed action files' statuses (catalog/actions by default) into the platform catalog, one app's only when
 * `appId` is given: each current action exactly as its capability with the status its file, certification, placement, pins and live
 * evidence give it; superseded and orphaned ids disabled. Developer environments never write an action; this command is the only writer, and
 * the developer server's start gate only demotes. `actions` is a test seam ({directory, evidenceRoot, codeHashes, deps, importer}).
 */
export async function seedActionsInPlatform({root, appId, forbiddenRoots, actions = {}}) {
  const store = new PlatformStore({root, forbiddenRoots});
  try { return {seeded: await seedPlatformActions(store, {appId, actions})}; } finally { store.close(); }
}

/** Activates reviewed candidate capabilities of one app in the platform catalog, each audited with its definition hash. */
export function promoteInPlatform({root, appId, capabilityIds, forbiddenRoots}) {
  if (!Array.isArray(capabilityIds) || !capabilityIds.length || capabilityIds.length > 500) throw new Error('Name 1 to 500 capability ids to promote.');
  const store = new PlatformStore({root, forbiddenRoots});
  try {
    const promoted = [];
    // Check every id before changing any, so a bad list changes nothing.
    const capabilities = capabilityIds.map(id => {
      const capability = store.get('capabilities', id);
      if (!capability || capability.appId !== appId) throw new Error(`${id} is not a capability of ${appId} in the platform catalog.`);
      // F10.11 (part d): an action's status comes only from its reviewed file and live evidence (tenant catalog actions), never from here.
      if (capability.driver === 'action') throw new Error(`${id}: Actions become active only from a reviewed file with live evidence.`);
      if (capability.status !== 'candidate') throw new Error(`${id} is ${capability.status}, not a candidate.`);
      if (capability.driver === 'http') validateCapability(capability);
      return capability;
    });
    for (const capability of capabilities) {
      const active = {...capability, status: 'active'};
      store.put('capabilities', active);
      store.audit({type: 'platform.capability_promoted', appId, capabilityId: active.id, definitionHash: canonicalHash(active)});
      promoted.push(active.id);
    }
    return promoted;
  } finally { store.close(); }
}

const USAGE = `Usage (every command also takes --root TENANT_DATA_ROOT):
  node cli.mjs tenant org create --name NAME
  node cli.mjs tenant project create --org ORG_ID --name NAME [--app-name NAME] [--support-email EMAIL]
  node cli.mjs tenant project show-branding PRJ_ID [--logo-out FILE]
  node cli.mjs tenant project approve-branding PRJ_ID --digest DIGEST
  node cli.mjs tenant env create --project PRJ_ID --kind development|production
  node cli.mjs tenant env enable-production ENV_ID
  node cli.mjs tenant key create --env ENV_ID [--preset connect-only|standard|full | --scopes A,B] [--name NAME]
  node cli.mjs tenant key rotate SVC_ID
  node cli.mjs tenant key revoke KEY_ID [--with-agent-tokens]
  node cli.mjs tenant key list --env ENV_ID
  node cli.mjs tenant key update-scopes SVC_ID --scopes A,B
  node cli.mjs tenant catalog discover|promote APP_ID [--capabilities ID,ID]
  node cli.mjs tenant catalog actions [APP_ID]`;

/** Customers, projects, environments and keys. Prints a new key once; it is never shown again. */
export function registryCommand(argv, {forbiddenRoots, clock} = {}) {
  const option = name => { const at = argv.indexOf(name); return at < 0 ? undefined : argv[at + 1]; };
  const [scope, verb, target] = argv, root = option('--root');
  if (!root) throw new Error(USAGE);
  const registry = new TenantRegistry({root: path.resolve(root), forbiddenRoots, clock});
  try {
    const keys = new ServiceKeys(registry), list = value => String(value || '').split(',').map(item => item.trim()).filter(Boolean);
    const command = `${scope} ${verb}`;
    if (command === 'org create') return registry.createOrganization({name: option('--name')});
    if (command === 'project create') return registry.createProject({organizationId: option('--org'), name: option('--name'), appName: option('--app-name') ?? option('--name'), supportEmail: option('--support-email')});
    if (command === 'project show-branding') {
      // What is waiting for review, with its digest; the pending logo can be written to a file to look at.
      const found = registry.pendingBranding(target);
      if (!found) return {projectId: target, pending: null};
      if (option('--logo-out') && found.logoBytes) writeFileSync(path.resolve(option('--logo-out')), found.logoBytes, {flag: 'wx', mode: 0o600});
      return {projectId: target, pending: found.pending, digest: found.digest, note: 'Approve exactly this with: tenant project approve-branding PRJ_ID --digest DIGEST'};
    }
    if (command === 'project approve-branding') { const {appName, logo} = registry.approveBranding(target, option('--digest')); return {projectId: target, appName, logo: logo ? {hash: logo.hash, contentType: logo.contentType} : null}; }
    if (command === 'env create') {
      const stores = new EnvironmentStores({root: path.resolve(root), forbiddenRoots, clock});
      try { return registry.createEnvironment({projectId: option('--project'), kind: option('--kind')}, stores); } finally { stores.closeAll(); }
    }
    if (command === 'env enable-production') return registry.enableProduction(target);
    if (command === 'key create') return {...keys.mint({environmentId: option('--env'), name: option('--name'), preset: option('--preset'), scopes: option('--scopes') ? list(option('--scopes')) : undefined}), note: 'Store this key now; Fabric keeps only its hash and cannot show it again.'};
    if (command === 'key rotate') return {...keys.rotate(target), note: 'The previous key keeps working for 7 days.'};
    if (command === 'key revoke') { const result = keys.revoke(target, {withAgentTokens: argv.includes('--with-agent-tokens')}); return {revoked: target, ...result}; }
    if (command === 'key list') return keys.list(option('--env'));
    if (command === 'key update-scopes') return {serviceClientId: target, scopes: keys.updateScopes(target, list(option('--scopes')))};
    throw new Error(USAGE);
  } finally { registry.close(); }
}

/** `tenant ...` from cli.mjs. */
export async function main(argv) {
  const option = name => { const at = argv.indexOf(name); return at < 0 ? undefined : argv[at + 1]; };
  const [scope, verb, appId] = argv;
  const root = option('--root');
  if (['org', 'project', 'env', 'key'].includes(scope)) return registryCommand(argv);
  // F10.11 part p: tenant catalog actions [APP_ID] --root ROOT.
  if (scope === 'catalog' && verb === 'actions' && root) return seedActionsInPlatform({root: path.resolve(root), ...(appId && !appId.startsWith('--') ? {appId} : {})});
  if (scope !== 'catalog' || !['discover', 'promote'].includes(verb) || !appId || !root) throw new Error(USAGE);
  if (verb === 'discover') {
    const map = await discoverToPlatform({root: path.resolve(root), appId});
    return {appId, operations: map.operations?.length ?? 0, candidates: (map.operations || []).filter(operation => operation.support === 'candidate').length};
  }
  return {appId, promoted: promoteInPlatform({root: path.resolve(root), appId, capabilityIds: String(option('--capabilities') || '').split(',').map(id => id.trim()).filter(Boolean)})};
}

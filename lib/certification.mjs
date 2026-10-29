// F10.12 part 1 (docs/F10.12-BUILD-MAP.md part 1): what a certification Fabric is, for server.mjs createApp(). The live-test harness
// (scripts/live-certify.mjs) starts Fabric in-process with `certification: {guard}`; createApp() checks the option with checkCertification()
// and the folder with certificationFolderRefusal() before any local state opens. This file decides the folder and nothing else: it imports
// no action, transform or guard module, so server.mjs may import it, and it never writes.
import {closeSync, existsSync, lstatSync, openSync, readSync, readdirSync, realpathSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {insideTenantData} from './tenant/environments.mjs';
import {MARKER} from './local-authority.mts';

/** The one port a certification Fabric listens on: never 4188, the owner's own. */
export const CERTIFICATION_PORT = 4320;
const REPOSITORY = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
// What a folder may hold before the harness made its store: the folder lock and the guard's own files (and macOS's folder settings).
const BEFORE_STORE = new Set(['runtime.lock', 'live-certify', '.DS_Store']);
const SQLITE = 'SQLite format 3\u0000';

/** The fixed words of every folder refusal. */
export const FOLDER_WORDS = Object.freeze({
  relative: 'Give the live-test folder as an absolute path.',
  main: 'The live-test harness never uses the main data folder (.fabric), a folder inside it or a folder that holds it.',
  repository: 'The live-test harness never uses the repository folder or a folder inside it.',
  developer: 'This folder belongs to the developer layer (a tenant root, an environment, the platform catalog or the registry); the live-test harness cannot use it.',
  legacy: 'A Fabric started without the live-test harness wrote this folder, so the harness will not use it. Choose a new, empty folder.',
  busy: 'This folder holds other files. Choose a new, empty folder for the live tests, or one the harness made.',
});

/** The folder as the file system reaches it: its nearest existing parent through every link, then the part that does not exist yet. */
function reached(folder) {
  let current = path.resolve(folder);
  const rest = [];
  while (!existsSync(current) && current !== path.dirname(current)) { rest.unshift(path.basename(current)); current = path.dirname(current); }
  return path.join(realpathSync.native(current), ...rest);
}
const within = (inner, outer) => inner === outer || inner.startsWith(outer.endsWith(path.sep) ? outer : outer + path.sep);
/** True when the store's header carries the designated marker: it reads the 100-byte SQLite header and nothing more. */
function designated(store) {
  if (lstatSync(store).isSymbolicLink()) return false;
  const descriptor = openSync(store, 'r');
  try {
    const header = Buffer.alloc(100);
    return readSync(descriptor, header, 0, 100, 0) === 100 && header.toString('latin1', 0, 16) === SQLITE && header.readUInt32BE(68) === MARKER;
  } finally { closeSync(descriptor); }
}

/**
 * Why the live-test harness may not use `dataDir`, in words, or null when it may. It refuses a relative path; the main data folder
 * `<root>/.fabric`, a folder inside it or one that holds it; the repository folder or anything inside it; a developer folder; a folder whose
 * fabric.sqlite does not carry the designated marker (a Fabric started without the harness, such as S7.13's folder); and a folder with no
 * store that holds other files. Both paths are resolved through links first. It reads at most one store header and writes nothing.
 */
export function certificationFolderRefusal(dataDir, {root = REPOSITORY} = {}) {
  if (typeof dataDir !== 'string' || !path.isAbsolute(dataDir)) return FOLDER_WORDS.relative;
  const folder = reached(dataDir), repository = reached(root), main = reached(path.join(root, '.fabric'));
  if (within(folder, main) || within(main, folder)) return FOLDER_WORDS.main;
  if (within(folder, repository)) return FOLDER_WORDS.repository;
  if (insideTenantData(folder)) return FOLDER_WORDS.developer;
  const store = path.join(folder, 'fabric.sqlite');
  if (existsSync(store)) return designated(store) ? null : FOLDER_WORDS.legacy;
  if (existsSync(folder) && readdirSync(folder).some(name => !BEFORE_STORE.has(name))) return FOLDER_WORDS.busy;
  return null;
}

/** The `certification` option of createApp(): exactly {guard}, whose wrap and signIn are functions. Returns it; anything else throws. */
export function checkCertification(value) {
  const guard = value?.guard;
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).join() !== 'guard' || !guard || typeof guard !== 'object'
    || typeof guard.wrap !== 'function' || typeof guard.signIn !== 'function') throw new Error('Certification takes exactly {guard}: a live guard with wrap and signIn (lib/live-guard.mjs).');
  return value;
}

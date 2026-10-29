import { readFileSync, readdirSync } from 'node:fs';
import { validateAuthDefinition } from '../../contracts/auth-definition.mts';
import { ConnectionError } from './errors.mjs';

// Built-in auth definitions are reviewed repository data under catalog/auth.
// The provider ID selects a file by exact name; no path, URL or caller-supplied
// location is ever resolved, and a definition never names code to load.
const DIRECTORY = new URL('../../catalog/auth/', import.meta.url);
const PROVIDER = /^[a-z][a-z0-9-]{1,39}$/;
const cache = new Map();

/** @param {string} providerId @returns {import('../../contracts/auth-definition.mts').AuthDefinition} */
export function definitionFor(providerId) {
  if (typeof providerId !== 'string' || !PROVIDER.test(providerId)) throw new ConnectionError('Unsupported provider.', 'invalid_input');
  if (cache.has(providerId)) return cache.get(providerId);
  let raw;
  try { raw = readFileSync(new URL(`${providerId}.json`, DIRECTORY), 'utf8'); }
  catch { throw new ConnectionError('Unsupported provider.', 'invalid_input'); }
  const definition = validateAuthDefinition(JSON.parse(raw));
  if (definition.providerId !== providerId) throw new ConnectionError('Auth definition does not match its provider file.', 'invalid_input');
  cache.set(providerId, definition);
  return definition;
}

/** Provider IDs of every reviewed built-in definition, in stable name order. */
export function reviewedProviderIds() {
  return readdirSync(DIRECTORY,{withFileTypes:true})
    .filter(entry => entry.isFile() && /^[a-z][a-z0-9-]{1,39}\.json$/.test(entry.name))
    .map(entry => entry.name.slice(0,-5)).sort()
    .filter(id => definitionFor(id).reviewStatus === 'reviewed');
}

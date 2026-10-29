// F10.11 part a (docs/F10.11-BUILD-MAP.md part a): the application maps of Gmail and Calendar as DiscoveryEngine would store them, built
// from Google's recorded method paths (google-method-paths.json) and the scope facts beside them (google-method-scopes.json) by the one
// builder scripts/google-method-paths.mjs methodMap() and scripts/app-template-check.mjs use. Test data only: nothing in lib/ reads it.
import {readFileSync} from 'node:fs';
import {methodMap} from '../../../scripts/google-method-paths.mjs';

const read = file => JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8'));
/** A fresh copy of the recorded paths file. */
export const googlePaths = () => read('./google-method-paths.json');
/** A fresh copy of the scope facts. */
export const googleScopes = () => read('./google-method-scopes.json');
/** One app's map, {id, appId, operations: [{id, method, path, requiredScopes, scopeSets}]}, by method id. */
export function googleMap(appId) {
  const map = methodMap(googlePaths(), googleScopes(), appId);
  if (!map) throw new Error(`${appId} has no recorded Google method paths.`);
  return map;
}

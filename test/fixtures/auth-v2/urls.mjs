// F10.7: authorization URLs of the shipped version 2 definitions (catalog/auth), for every app and level under each consent policy,
// with the two random values (state and the PKCE challenge) masked. urls.golden.json holds them; test/f10-7-catalog.test.mjs keeps the
// catalog to them byte for byte. Version 1 URL stability (T6) is ../auth-v1, which never changes.
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {OAuth2Provider} from '../../../lib/providers/oauth2.mjs';
import {Store} from '../../../lib/store.mjs';
import {Vault} from '../../../lib/vault.mjs';
import {offeredLevels} from '../../../lib/access-levels.mjs';
import {normalizeAuthApp} from '../../../contracts/auth-definition.mts';

export const PROVIDERS = ['google', 'github', 'notion', 'slack'];
const HOSTED = {notion: true, slack: true};
export const catalogDefinition = providerId => JSON.parse(readFileSync(new URL(`../../../catalog/auth/${providerId}.json`, import.meta.url), 'utf8'));
const mask = href => { const url = new URL(href); for (const key of ['state', 'code_challenge']) if (url.searchParams.has(key)) url.searchParams.set(key, key.toUpperCase()); return url.href; };

/** Every case's masked authorization URL, keyed `provider/app/level/publishing`. A pages grant (Notion) signs in at its full level. */
export function versionTwoUrls(definitionOf = catalogDefinition) {
  const urls = {};
  for (const providerId of PROVIDERS) for (const publishing of ['testing', 'production']) {
    const directory = mkdtempSync(path.join(tmpdir(), 'fabric-f107-urls-'));
    try {
      const store = new Store({dataDir: directory}), vault = new Vault(directory), definition = definitionOf(providerId);
      const provider = new OAuth2Provider(definition, {store, vault, connections: {}, clientId: 'fixture-client', clientSecret: 'fixture-secret', clock: () => Date.UTC(2026, 9, 18), publishing,
        ...(HOSTED[providerId] ? {redirectUri: `https://connect.example.com/oauth/${providerId}/4320`, allowHostedRedirect: true} : {})});
      for (const app of definition.apps) for (const level of offeredLevels(normalizeAuthApp(definition, app)).map(item => item === 'pages' ? 'full' : item))
        urls[`${providerId}/${app.appId}/${level}/${publishing}`] = mask(provider.start({appId: app.appId, level}).authorizationUrl);
      store.close();
    } finally { rmSync(directory, {recursive: true, force: true}); }
  }
  return urls;
}

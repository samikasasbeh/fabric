// T6 (docs/F10-FIVE-APPS-DEEP.md): authorization URLs for the version 1 definitions in this folder, with the two random
// values (state and the PKCE challenge) masked. urls.golden.json holds the URLs the version 1 engine produced before
// version 2 existed; the version 2 engine must reproduce them byte for byte.
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {OAuth2Provider} from '../../../lib/providers/oauth2.mjs';
import {Store} from '../../../lib/store.mjs';
import {Vault} from '../../../lib/vault.mjs';

export const PROVIDERS = ['google', 'github', 'notion', 'slack'];
const HOSTED = {notion: true, slack: true};
export const v1Definition = providerId => JSON.parse(readFileSync(new URL(`${providerId}.json`, import.meta.url), 'utf8'));
const mask = href => { const url = new URL(href); for (const key of ['state', 'code_challenge']) if (url.searchParams.has(key)) url.searchParams.set(key, key.toUpperCase()); return url.href; };

/** Every case's masked authorization URL, keyed `provider/app/case`. */
export function authorizationUrls(definitionOf = v1Definition) {
  const urls = {};
  for (const providerId of PROVIDERS) {
    const directory = mkdtempSync(path.join(tmpdir(), 'fabric-t6-'));
    try {
      const store = new Store({dataDir: directory}), vault = new Vault(directory), definition = definitionOf(providerId);
      const provider = new OAuth2Provider(definition, {store, vault, connections: {}, clientId: 'fixture-client', clientSecret: 'fixture-secret', clock: () => Date.UTC(2026, 9, 13),
        ...(HOSTED[providerId] ? {redirectUri: `https://connect.example.com/oauth/${providerId}/4320`, allowHostedRedirect: true} : {})});
      for (const app of definition.apps) {
        const key = `${providerId}/${app.appId}`;
        urls[`${key}/read`] = mask(provider.start({appId: app.appId}).authorizationUrl);
        urls[`${key}/write`] = mask(provider.start({appId: app.appId, writeAccess: true}).authorizationUrl);
        // A reconnect carries the app's own granted scopes forward and drops anything else.
        const carried = [...(app.scopes?.write || []), ...(app.userScopes?.write || []), 'https://www.googleapis.com/auth/drive', 'admin:org'];
        store.put('connections', {id: `c-${app.appId}`, appId: app.appId, authMethod: 'oauth', status: 'ready', authRevision: 1, scopes: [...carried, ...(app.upgradeScopes?.exact || []).slice(0, 1)]});
        urls[`${key}/reconnect`] = mask(provider.start({connectionId: `c-${app.appId}`, appId: app.appId}).authorizationUrl);
        urls[`${key}/reconnect-write`] = mask(provider.start({connectionId: `c-${app.appId}`, appId: app.appId, writeAccess: true}).authorizationUrl);
      }
    } finally { rmSync(directory, {recursive: true, force: true}); }
  }
  return urls;
}

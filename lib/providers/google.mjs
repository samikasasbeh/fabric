import { OAuth2Provider } from './oauth2.mjs';
import { definitionFor } from './definitions.mjs';

const GOOGLE = definitionFor('google');
const GOOGLE_APPS = Object.freeze(['google-calendar','gmail']);
// The typed SPI below still names exactly these two applications; refuse to start
// if the reviewed data definition drifts from the compile-time contract.
if (JSON.stringify(GOOGLE.apps.map(app => app.appId)) !== JSON.stringify(GOOGLE_APPS)) throw new Error('Google auth definition does not match the provider contract.');

/**
 * Google Calendar and Gmail on the provider-neutral OAuth 2.0 engine. Endpoints,
 * scopes, probes and revocation come from catalog/auth/google.json.
 * @implements {import('../../contracts/provider.mts').ProviderAdapter}
 */
export class GoogleProvider extends OAuth2Provider {
  /** @returns {'google'} */
  get providerId() { return 'google'; }
  /** @returns {readonly import('../../contracts/provider.mts').GoogleAppId[]} */
  get appIds() { return GOOGLE_APPS; }
  /** @param {import('../../contracts/provider.mts').GoogleProviderOptions} options */
  constructor(options) { super(GOOGLE,options); }
}

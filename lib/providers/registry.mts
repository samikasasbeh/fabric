import { validateProviderBinding } from '../../contracts/provider.mts';
import type { ProviderAdapter, ProviderBinding } from '../../contracts/provider.mts';
import { GoogleProvider } from './google.mjs';
import { OAuth2Provider } from './oauth2.mjs';
import { ConnectionError } from './errors.mjs';

// Constructed by trusted application code only. No paths, plugin names, or
// caller-supplied provider implementations are resolved from serialized input.
// Every adapter is an OAuth2Provider built from a reviewed auth definition, and
// each application is served by exactly one provider.
export class TrustedProviderRegistry {
  #providers = new Map<string, ProviderAdapter>();
  #apps = new Map<string, string>();
  #routes: readonly ProviderBinding[] = Object.freeze([]);
  constructor(google: GoogleProvider, ...others: OAuth2Provider[]) {
    if (!(google instanceof GoogleProvider)) throw new ConnectionError('A trusted Google provider is required.', 'invalid_input');
    this.#install(google);
    for (const provider of others) this.bind(provider);
  }
  #install(provider: ProviderAdapter): void {
    for (const appId of provider.appIds) {
      const owner = this.#apps.get(appId);
      if (owner !== undefined && owner !== provider.providerId) throw new ConnectionError('Application is already served by another trusted provider.', 'invalid_input');
    }
    this.#providers.set(provider.providerId, provider);
    for (const appId of provider.appIds) this.#apps.set(appId, provider.providerId);
    this.#routes = Object.freeze([...this.#providers.values()].flatMap(item => item.appIds.map(appId => Object.freeze({ providerId: item.providerId, appId }))));
  }
  list(): readonly ProviderBinding[] { return this.#routes; }
  supportsApp(appId: unknown): boolean { return typeof appId === 'string' && this.#apps.has(appId); }
  /** The single provider serving an application, or null when none is installed. */
  providerFor(appId: unknown): string | null { return typeof appId === 'string' ? this.#apps.get(appId) ?? null : null; }
  has(providerId: unknown): boolean { return typeof providerId === 'string' && this.#providers.has(providerId); }
  resolve(binding: unknown): ProviderAdapter {
    let checked: ProviderBinding;
    try { checked = validateProviderBinding(binding); }
    catch { throw new ConnectionError('Unsupported provider/application binding.', 'invalid_input'); }
    const provider = this.#providers.get(checked.providerId);
    if (!provider || this.#apps.get(checked.appId) !== checked.providerId) throw new ConnectionError('Unsupported provider/application binding.', 'invalid_input');
    return provider;
  }
  /** Existing trusted facade binding only; this is not arbitrary registration. */
  bindGoogleOAuth(google: GoogleProvider): void {
    if (!(google instanceof GoogleProvider)) throw new ConnectionError('A trusted Google provider is required.', 'invalid_input');
    this.#install(google);
  }
  /** Binds a trusted non-Google adapter constructed from a reviewed definition. */
  bind(provider: OAuth2Provider): void {
    if (!(provider instanceof OAuth2Provider) || provider instanceof GoogleProvider) throw new ConnectionError('A trusted provider adapter is required.', 'invalid_input');
    this.#install(provider);
  }
}

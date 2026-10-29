import { canonicalHash } from '../lib/compiler.mjs';
import { definitionFor } from '../lib/providers/definitions.mjs';

// Trusted-code SPI for the local OAuth lifecycle. Credentials below are private
// process values, never public connection responses or serialized grants.
// Routes come from reviewed auth definitions in catalog/auth; GoogleAppId remains
// the narrow type of the original Google adapter.
export type GoogleAppId = 'google-calendar' | 'gmail';
export type ProviderBinding = Readonly<{ providerId: string; appId: string }>;
export type ProviderIdentity = Readonly<{ id: string; displayName: string; email?: string }>;
export type ProviderConfiguration = Readonly<{
  configured: boolean; redirectUri: string; requiredEnvironment: readonly string[]; defaultAccess: 'read-only' | 'full';
}>;
/** `fullUpgrade` (F10.7): the owner's explicit full upgrade of the account `connectionId` names, at level 'full' and with no scopes.
 *  It asks for the whole full level under any consent policy; a plain sign-in keeps the policy. */
export type ProviderStartInput = Readonly<{
  connectionId?: string; label?: string; writeAccess?: boolean; level?: 'full' | 'read'; appId?: string; scopes?: readonly string[]; fullUpgrade?: boolean;
}>;
export type ProviderStartResult = Readonly<{ authorizationUrl: string; expiresAt: string; flowId: string }>;
export type ProviderCallbackInput = Readonly<{ state?: string; code?: string; error?: string; flowId?: string }>;
export type ProviderTokens = Readonly<{
  accessToken: string; refreshToken?: string | undefined; expiresAt: number | null; scopes?: readonly string[] | undefined;
}>;
export type ProviderConnection = Readonly<{
  id: string; appId: string; status: string; authMethod?: string; identity?: ProviderIdentity;
  [key: string]: unknown;
}>;
export type ProviderRevokeResult = Readonly<{ connection: ProviderConnection; remoteRevoked: boolean; message: string }>;
export type ProviderRequest = Readonly<{
  url: string; method?: string; headers?: Readonly<Record<string, string>>; body?: string; allowedOrigins: readonly string[];
}>;
export type ProviderResponse = Readonly<{ status: number; data: unknown }>;
export type ProviderRequester = (request: ProviderRequest) => Promise<ProviderResponse>;
/** Trusted in-process check around every identity-probe hop; never request input. */
export type ProviderAuthorizationGuard = () => void;
export type ProviderStateRecord = Record<string, unknown>;
export interface ProviderStore {
  get(collection: string, id: string): ProviderStateRecord | null;
  list(collection: string): ProviderStateRecord[];
  put(collection: string, record: ProviderStateRecord): unknown;
  delete(collection: string, id: string): unknown;
  audit(event: ProviderStateRecord): unknown;
}
export interface ProviderVault {
  get(id: string): ProviderStateRecord | null;
  set(id: string, credentials: ProviderStateRecord): unknown;
  delete(id: string): unknown;
}
export interface ProviderConnections {
  request: ProviderRequester;
  get(id: string): ProviderConnection | null;
  observe(appId: string, accessToken: string, binding?: ProviderStateRecord, authorize?: ProviderAuthorizationGuard): Promise<ProviderIdentity>;
  establishOAuth(input: { tokens: ProviderTokens; label?: string | null; connectionId?: string | null; appId?: string; providerId?: string }): Promise<ProviderConnection>;
  revoke(id: string): ProviderConnection;
}
export type GoogleProviderOptions = {
  store: ProviderStore; vault: ProviderVault; connections: ProviderConnections;
  request?: ProviderRequester; clientId?: string | undefined; clientSecret?: string | undefined;
  redirectUri?: string; clock?: () => number;
};
export type ProviderOptions = GoogleProviderOptions;
export interface ProviderAdapter {
  readonly providerId: string;
  readonly appIds: readonly string[];
  readonly configured: boolean;
  configuration(): ProviderConfiguration;
  start(input?: ProviderStartInput): ProviderStartResult;
  callback(input: ProviderCallbackInput): Promise<ProviderConnection>;
  observeIdentity(input: { appId: string; accessToken: string; authorize?: ProviderAuthorizationGuard }): Promise<ProviderIdentity>;
  refresh(connectionId: string): Promise<ProviderTokens>;
  revoke(connectionId: string): Promise<ProviderRevokeResult>;
}

export class ProviderContractError extends Error {
  readonly code = 'invalid_input';
  constructor() { super('Unsupported provider/application binding.'); this.name = 'ProviderContractError'; }
}

/**
 * A fixed routing declaration only: an exact provider/application pair named by a
 * reviewed auth definition. This is not an account grant or certification.
 */
export function validateProviderBinding(value: unknown): ProviderBinding {
  try { canonicalHash(value); } catch { throw new ProviderContractError(); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ProviderContractError();
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 2 || !Object.hasOwn(record, 'providerId') || !Object.hasOwn(record, 'appId') ||
      typeof record.providerId !== 'string' || typeof record.appId !== 'string') throw new ProviderContractError();
  let definition;
  try { definition = definitionFor(record.providerId); } catch { throw new ProviderContractError(); }
  if (definition.reviewStatus !== 'reviewed' || !definition.apps.some(app => app.appId === record.appId)) throw new ProviderContractError();
  return Object.freeze({ providerId: definition.providerId, appId: record.appId });
}

// F03.1 (docs/F03-DEVELOPER-LAYER.md sections 3.2, 3.3 and 5.2): the developer layer's platform records. These are
// shapes and rules only; lib/tenant/registry.mjs stores them and lib/tenant/keys.mjs issues and checks keys.

export type RecordStatus = 'active' | 'suspended';
export type EnvironmentKind = 'development' | 'production';
export type Organization = Readonly<{ id: string; name: string; status: RecordStatus; createdAt: string }>;
export type Project = Readonly<{ id: string; organizationId: string; name: string; appName: string; supportEmail: string | null; createdAt: string }>;
export type Environment = Readonly<{
  id: string; projectId: string; organizationId: string; kind: EnvironmentKind; status: RecordStatus;
  /** False until the operator enables production; keys for it are refused until then. */
  productionEnabled: boolean; openerOrigins: readonly string[]; redirectOrigins: readonly string[]; createdAt: string;
}>;
export type ServiceClient = Readonly<{
  id: string; organizationId: string; projectId: string; environmentId: string; name: string;
  /** Stored literally: a later change to a preset never changes an existing client. */
  scopes: readonly string[]; preset: string | null; status: RecordStatus; createdAt: string;
}>;
export type ServiceKey = Readonly<{
  id: string; serviceClientId: string; environmentId: string; prefix: 'fab_sk_dev' | 'fab_sk_prod';
  /** SHA-256 of the secret, hex. The secret itself is shown once and never stored. */
  secretHash: string; createdAt: string; expiresAt: string | null; revokedAt: string | null; lastUsedDay: string | null;
}>;
/** Defined for I03; not stored in F03 (developers have no implicit ownership of end-user records). */
export type DeveloperMember = Readonly<{ id: string; organizationId: string; email: string; role: 'owner' | 'admin' | 'developer' | 'viewer'; status: RecordStatus }>;

export const ID_PREFIXES = Object.freeze({organization: 'org_', project: 'prj_', environment: 'env_', serviceClient: 'svc_', serviceKey: 'key_', user: 'usr_', connectSession: 'cs_', providerApp: 'pa_'} as const);
/** A prefix plus 26 lowercase base32 characters; lowercase because the disk ignores case. */
export const RECORD_ID = /^(org|prj|env|svc|key|usr|cs|pa)_[a-z2-7]{26}$/;

export const KEY_SCOPES: readonly string[] = Object.freeze([
  'project:read', 'project:write', 'provider_apps:read', 'provider_apps:write', 'users:read', 'users:write',
  'connect:write', 'connect:manage', 'connect:approve', 'accounts:read', 'accounts:write', 'catalog:read',
  'permissions:write', 'decisions:write', 'executions:read', 'executions:write', 'proxy:write',
  'approvals:read', 'activity:read', 'agents:write', 'subscriptions:read', 'subscriptions:write', 'events:read',
]);
/** Scopes reserved for triggers and events (I07): grantable, but their routes answer not_available until then. */
export const RESERVED_SCOPES: readonly string[] = Object.freeze(['subscriptions:read', 'subscriptions:write', 'events:read']);
/** Decision powers: a key with them can decide for an end user, so the standard preset leaves them out. */
export const DECISION_SCOPES: readonly string[] = Object.freeze(['connect:manage', 'connect:approve', 'decisions:write']);
export const PRESETS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  'connect-only': Object.freeze(['connect:write', 'accounts:read', 'catalog:read']),
  standard: Object.freeze(KEY_SCOPES.filter(scope => !DECISION_SCOPES.includes(scope))),
  full: KEY_SCOPES,
});

export class TenantRecordError extends Error {
  readonly code = 'invalid_request';
  constructor(message: string) { super(message); this.name = 'TenantRecordError'; }
}
const NAME = /^[^\u0000-\u001f\u007f]{1,80}$/;
const EMAIL = /^[^\s@<>"]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/;

export function validName(value: unknown, field = 'name'): string {
  if (typeof value !== 'string' || !NAME.test(value.trim())) throw new TenantRecordError(`${field} must be 1 to 80 printable characters.`);
  return value.trim();
}
export function validEmail(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || !EMAIL.test(value)) throw new TenantRecordError('supportEmail must be an email address.');
  return value;
}
export function validScopes(value: unknown): string[] {
  if (!Array.isArray(value) || !value.length || value.length > KEY_SCOPES.length) throw new TenantRecordError('A key needs between one and all of the known scopes.');
  const unknown = value.filter(scope => typeof scope !== 'string' || !KEY_SCOPES.includes(scope));
  if (unknown.length) throw new TenantRecordError(`Unknown scope: ${String(unknown[0]).slice(0, 40)}.`);
  return [...new Set(value as string[])].sort();
}
/** L9: a provider client id is 1 to 256 characters from letters, digits and . _ -, never starting with '.'; never echoed. */
const CLIENT_ID = /^(?!\.)[A-Za-z0-9._-]{1,256}$/;
export function validClientId(value: unknown): string {
  if (typeof value !== 'string' || !CLIENT_ID.test(value)) throw new TenantRecordError('clientId must be 1 to 256 letters, digits, dots, underscores or hyphens, and cannot start with a dot.');
  return value;
}
export function assertRecordId(value: unknown, kind: keyof typeof ID_PREFIXES): string {
  if (typeof value !== 'string' || !RECORD_ID.test(value) || !value.startsWith(ID_PREFIXES[kind])) throw new TenantRecordError(`Not a valid ${kind} id.`);
  return value;
}

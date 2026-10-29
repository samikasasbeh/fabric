import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { assertOwnedRecord, assertSameScope, validatePrincipal, validateScope } from '../contracts/identity.mts';

const localScope = () => ({ schemaVersion: 1, kind: 'local', localOwnerId: 'local-owner' });
const tenantScope = () => ({ schemaVersion: 1, kind: 'tenant', organizationId: 'org-one', projectId: 'product-one', environmentId: 'production' });
const localOwner = () => ({ schemaVersion: 1, kind: 'local_owner', id: 'local-owner', scope: localScope() });
const localClient = () => ({ schemaVersion: 1, kind: 'local_client', id: 'authenticated-grant-one', scope: localScope(), delegatedBy: { kind: 'local_owner', id: 'local-owner' } });
const developer = () => ({ schemaVersion: 1, kind: 'developer', id: 'developer-one', scope: tenantScope() });
const service = () => ({ schemaVersion: 1, kind: 'service_client', id: 'service-one', scope: tenantScope() });
const user = () => ({ schemaVersion: 1, kind: 'product_user', id: 'fabric-principal-one', subjectId: 'upstream-user-one', scope: tenantScope() });
const userAgent = () => ({ schemaVersion: 1, kind: 'agent', id: 'agent-one', subjectId: 'upstream-user-one', scope: tenantScope(), delegatedBy: { kind: 'product_user', id: 'upstream-user-one' }, delegationId: 'delegation-one' });
const serviceAgent = () => ({ schemaVersion: 1, kind: 'agent', id: 'agent-one', scope: tenantScope(), delegatedBy: { kind: 'service_client', id: 'service-one' }, delegationId: 'delegation-one' });
const owned = (kind = 'product_user', id = 'upstream-user-one', scope = tenantScope()) => ({ schemaVersion: 1, scope, owner: { kind, id } });
const principalFixtures = [localOwner, localClient, developer, service, user, userAgent, serviceAgent];
const schema = JSON.parse(readFileSync(new URL('../contracts/identity.schema.json', import.meta.url), 'utf8'));

// Validate the schema's deliberately small keyword subset independently of the
// runtime contract code, so its published field/union definitions cannot drift.
function matchesSchema(value, definition) {
  if (definition.$ref) return matchesSchema(value, schema.$defs[definition.$ref.split('/').at(-1)]);
  if (definition.oneOf && definition.oneOf.filter(item => matchesSchema(value, item)).length !== 1) return false;
  if (Object.hasOwn(definition, 'const') && value !== definition.const) return false;
  if (definition.enum && !definition.enum.includes(value)) return false;
  if (definition.type === 'string') {
    if (typeof value !== 'string' || value.length < (definition.minLength ?? 0) || value.length > (definition.maxLength ?? Infinity)) return false;
    if (definition.pattern && !new RegExp(definition.pattern).test(value)) return false;
  }
  if (definition.type === 'object') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    if (definition.required?.some(key => !Object.hasOwn(value, key))) return false;
    for (const key of Object.keys(value)) {
      if (!Object.hasOwn(definition.properties ?? {}, key)) { if (definition.additionalProperties === false) return false; }
      else if (!matchesSchema(value[key], definition.properties[key])) return false;
    }
  }
  return true;
}

test('native TypeScript contract accepts every documented principal and scope fixture', () => {
  for (const make of principalFixtures) {
    const input = make();
    assert.deepEqual(validatePrincipal(input), input);
    assert.equal(matchesSchema(input, schema), true, input.kind);
    assert.equal(matchesSchema(input.scope, schema.$defs.Scope), true);
    assert.deepEqual(validateScope(input.scope), input.scope);
  }
});

test('scope equality isolates organizations, projects, environments, local owners and hosting modes', () => {
  const original = tenantScope();
  assertSameScope(original, structuredClone(original));
  for (const key of ['organizationId', 'projectId', 'environmentId']) {
    assert.throws(() => assertSameScope(original, { ...original, [key]: 'different' }), /scope mismatch/);
  }
  assertSameScope(localScope(), localScope());
  assert.throws(() => assertSameScope(localScope(), { ...localScope(), localOwnerId: 'another-owner' }), /scope mismatch/);
  assert.throws(() => assertSameScope(localScope(), tenantScope()), /scope mismatch/);
  assert.throws(() => assertSameScope(tenantScope(), localScope()), /scope mismatch/);
});

test('scope versions, ownership dimensions, and authority-like extras fail closed', () => {
  for (const value of [
    null, [], {}, { ...tenantScope(), schemaVersion: 2 }, { ...tenantScope(), schemaVersion: '1' },
    { ...tenantScope(), localOwnerId: 'local-owner' }, { ...localScope(), organizationId: 'org-one' },
    { schemaVersion: 1, kind: 'tenant', organizationId: 'org-one', environmentId: 'production' },
    { ...tenantScope(), admin: true }, { ...tenantScope(), kind: 'global' },
  ]) {
    assert.throws(() => validateScope(value), /^Error: Invalid identity contract\.$/);
    assert.equal(matchesSchema(value, schema.$defs.Scope), false);
  }
});

test('identifiers are bounded and cannot smuggle paths, whitespace or credential text', () => {
  for (const id of ['', ' leading', 'trailing ', 'a/b', '../owner', 'a\\b', 'line\nbreak', 'a'.repeat(129), '*', 17, null, 'Bearer secret']) {
    assert.throws(() => validatePrincipal({ ...service(), id }));
    assert.throws(() => validateScope({ ...localScope(), localOwnerId: id }));
    assert.equal(matchesSchema({ ...service(), id }, schema), false);
  }
  assert.equal(validatePrincipal({ ...service(), id: 'svc:production-1@example.com' }).id, 'svc:production-1@example.com');
  assert.equal(validatePrincipal({ ...service(), id: 'a'.repeat(128) }).id.length, 128);
});

test('local owner identity must agree with local scope and cannot become a tenant principal', () => {
  assert.throws(() => validatePrincipal({ ...localOwner(), id: 'another-owner' }));
  assert.throws(() => validatePrincipal({ ...localOwner(), scope: tenantScope() }));
  assert.throws(() => validatePrincipal({ ...localOwner(), workspaceId: 'workspace-one' }));
  for (const make of [developer, service, user, userAgent, serviceAgent]) {
    assert.throws(() => validatePrincipal({ ...make(), scope: localScope() }));
  }
});

test('local client grant identity is detached and frozen without becoming direct ownership', () => {
  const source = localClient(), client = validatePrincipal(source);
  assert.deepEqual(client, source);
  assert.equal(client.id, 'authenticated-grant-one');
  for (const value of [client, client.scope, client.delegatedBy]) assert.equal(Object.isFrozen(value), true);
  assert.notEqual(client.scope, source.scope); assert.notEqual(client.delegatedBy, source.delegatedBy);
  source.id = 'replacement-grant'; source.delegatedBy.id = 'other-owner'; source.scope.localOwnerId = 'other-owner';
  assert.equal(client.id, 'authenticated-grant-one'); assert.equal(client.delegatedBy.id, 'local-owner');
  assert.throws(() => { client.delegatedBy.id = 'other-owner'; }, TypeError);
  assert.throws(() => assertOwnedRecord(client, owned('local_owner', 'local-owner', localScope())), /Direct record ownership/);
  assert.throws(() => assertOwnedRecord(client, owned('local_client', client.id, localScope())), /Invalid identity contract/);
});

test('local clients reject tenant or workspace context, ambiguous grant IDs and delegation chains', () => {
  const missing = localClient(); delete missing.delegatedBy;
  for (const value of [
    missing, {...localClient(), scope: tenantScope()}, {...localClient(), subjectId: 'user'},
    {...localClient(), workspaceId: 'workspace'}, {...localClient(), delegationId: 'second-grant'},
    {...localClient(), grantId: 'second-grant'}, {...localClient(), id: 'fab_client.full.token/credential'},
    {...localClient(), delegatedBy: {kind: ['local_owner'], id: 'local-owner'}},
    {...localClient(), delegatedBy: {kind: 'local_client', id: 'parent-client'}},
    {...localClient(), delegatedBy: {kind: 'agent', id: 'parent-agent'}},
    {...localClient(), delegatedBy: {kind: 'local_owner', id: 'local-owner', delegatedBy: {kind: 'local_owner', id: 'other'}}},
    {...localClient(), delegatedBy: {kind: 'local_owner', id: 'local-owner', scope: localScope()}},
    {...userAgent(), delegatedBy: {kind: 'local_client', id: 'authenticated-grant-one'}},
  ]) {
    assert.throws(() => validatePrincipal(value), /^Error: Invalid identity contract\.$/);
    assert.equal(matchesSchema(value, schema), false);
  }
});

test('local client semantic validation requires the exact scoped owner and a distinct grant ID', () => {
  for (const value of [
    {...localClient(), id: 'local-owner'},
    {...localClient(), delegatedBy: {kind: 'local_owner', id: 'other-owner'}},
    {...localClient(), scope: {...localScope(), localOwnerId: 'other-owner'}},
  ]) {
    assert.equal(matchesSchema(value, schema), true, 'JSON Schema shapes cannot assert cross-field equality');
    assert.throws(() => validatePrincipal(value), /^Error: Invalid identity contract\.$/);
  }
});

test('product users require an upstream subject and other principal kinds cannot impersonate one', () => {
  const missing = user(); delete missing.subjectId;
  assert.throws(() => validatePrincipal(missing));
  assert.equal(matchesSchema(missing, schema), false);
  assert.notEqual(validatePrincipal(user()).id, validatePrincipal(user()).subjectId);
  for (const make of [localOwner, developer, service]) {
    assert.throws(() => validatePrincipal({ ...make(), subjectId: 'upstream-user-one' }));
    assert.throws(() => validatePrincipal({ ...make(), delegationId: 'claimed-grant' }));
    assert.throws(() => validatePrincipal({ ...make(), delegatedBy: { kind: 'product_user', id: 'upstream-user-one' } }));
  }
});

test('agents require matching user delegation and cannot self-delegate, chain, or claim user context from service authority', () => {
  for (const mutate of [
    p => { delete p.delegationId; },
    p => { delete p.delegatedBy; },
    p => { p.delegatedBy.kind = 'agent'; },
    p => { p.delegatedBy.kind = 'developer'; },
    p => { p.id = p.delegatedBy.id; },
    p => { p.subjectId = 'different-user'; },
    p => { delete p.subjectId; },
    p => { p.delegatedBy.delegatedBy = { kind: 'product_user', id: 'other' }; },
    p => { p.delegatedBy.scope = tenantScope(); },
    p => { p.grants = ['all']; },
  ]) { const principal = userAgent(); mutate(principal); assert.throws(() => validatePrincipal(principal)); }
  assert.throws(() => validatePrincipal({ ...serviceAgent(), subjectId: 'upstream-user-one' }));
  const self = serviceAgent(); self.id = self.delegatedBy.id;
  assert.throws(() => validatePrincipal(self));
});

test('unknown versions and fields are rejected rather than retained as apparent authority', () => {
  for (const make of principalFixtures) {
    for (const extra of [{ schemaVersion: 2 }, { role: 'admin' }, { authenticated: true }, { permissions: ['all'] }, { token: 'DO-NOT-PRINT' }]) {
      const invalid = { ...make(), ...extra };
      assert.throws(() => validatePrincipal(invalid), error => error.message === 'Invalid identity contract.' && !error.message.includes('DO-NOT-PRINT'));
      assert.equal(matchesSchema(invalid, schema), false);
    }
  }
});

test('descriptor-first JSON guard rejects getters and serializers without invoking them', () => {
  let invoked = false;
  const scopeGetter = { ...tenantScope(), get organizationId() { invoked = true; return 'org-one'; } };
  const principalGetter = { ...user(), get scope() { invoked = true; return tenantScope(); } };
  const delegateGetter = userAgent(); Object.defineProperty(delegateGetter.delegatedBy, 'id', { enumerable: true, get() { invoked = true; return 'upstream-user-one'; } });
  const localDelegateGetter = localClient(); Object.defineProperty(localDelegateGetter.delegatedBy, 'id', { enumerable: true, get() { invoked = true; return 'local-owner'; } });
  const serializer = { ...user(), toJSON() { invoked = true; return user(); } };
  assert.throws(() => validateScope(scopeGetter));
  for (const value of [principalGetter, delegateGetter, localDelegateGetter, serializer]) assert.throws(() => validatePrincipal(value));
  const recordGetter = owned(); Object.defineProperty(recordGetter.owner, 'id', { enumerable: true, get() { invoked = true; return 'upstream-user-one'; } });
  assert.throws(() => assertOwnedRecord(user(), recordGetter));
  assert.equal(invoked, false);
});

test('non-JSON values, prototype tricks, cycles and oversized metadata have generic errors', () => {
  const cyclic = user(); cyclic.self = cyclic;
  const custom = Object.assign(Object.create({ admin: true }), user());
  const hidden = user(); Object.defineProperty(hidden, 'hidden', { value: 'secret' });
  const symbol = user(); symbol[Symbol('authority')] = true;
  for (const value of [undefined, NaN, Infinity, 1n, () => user(), new Date(), new Map(), cyclic, custom, hidden, symbol, JSON.parse('{"__proto__":{"admin":true}}'), { ...user(), secret: 'x'.repeat(9000) }]) {
    assert.throws(() => validatePrincipal(value), /^Error: Invalid identity contract\.$/);
  }
  assert.equal({}.admin, undefined);
  const nullPrototype = Object.assign(Object.create(null), tenantScope());
  assert.deepEqual(validateScope(nullPrototype), tenantScope());
});

test('validated principal values are detached and frozen at every nested identity boundary', () => {
  const input = userAgent(); input.workspaceId = 'workspace-one';
  const result = validatePrincipal(input);
  assert.notEqual(result, input);
  assert.notEqual(result.scope, input.scope);
  assert.notEqual(result.delegatedBy, input.delegatedBy);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.scope), true);
  assert.equal(Object.isFrozen(result.delegatedBy), true);
  assert.throws(() => { result.id = 'changed'; }, TypeError);
  assert.throws(() => { result.scope.environmentId = 'development'; }, TypeError);
  assert.throws(() => { result.delegatedBy.id = 'changed'; }, TypeError);
  input.scope.environmentId = 'development'; input.delegatedBy.id = 'another-user';
  assert.equal(result.scope.environmentId, 'production');
  assert.equal(result.delegatedBy.id, 'upstream-user-one');
  const scope = validateScope(localScope());
  assert.equal(Object.isFrozen(scope), true);
});

test('direct ownership uses exact local IDs, upstream user subjects and service principal IDs', () => {
  assertOwnedRecord(localOwner(), owned('local_owner', 'local-owner', localScope()));
  assertOwnedRecord(user(), owned());
  assertOwnedRecord(service(), owned('service_client', 'service-one'));
  assert.throws(() => assertOwnedRecord(user(), owned('product_user', user().id)), /Direct record ownership/);
  assert.throws(() => assertOwnedRecord(user(), owned('product_user', 'different-user')), /Direct record ownership/);
  assert.throws(() => assertOwnedRecord(service(), owned('service_client', 'other-service')), /Direct record ownership/);
  const anotherSession = { ...user(), id: 'another-authenticated-fabric-principal' };
  assertOwnedRecord(anotherSession, owned());
});

test('matching owner IDs never override cross-tenant or cross-local scope boundaries', () => {
  for (const field of ['organizationId', 'projectId', 'environmentId']) {
    assert.throws(() => assertOwnedRecord(user(), owned('product_user', 'upstream-user-one', { ...tenantScope(), [field]: 'other' })), /scope mismatch/);
  }
  assert.throws(() => assertOwnedRecord(localOwner(), owned('local_owner', 'other-local', { ...localScope(), localOwnerId: 'other-local' })), /scope mismatch/);
  assert.throws(() => assertOwnedRecord(localOwner(), owned()), /scope mismatch/);
});

test('developers, agents and workspace labels do not imply ownership or sharing rights', () => {
  for (const actor of [developer(), userAgent(), serviceAgent()]) {
    assert.throws(() => assertOwnedRecord(actor, owned()), /Direct record ownership/);
    assert.throws(() => assertOwnedRecord(actor, owned('service_client', 'service-one')), /Direct record ownership/);
  }
  for (const make of [developer, service, user, userAgent, serviceAgent]) {
    const actor = { ...make(), workspaceId: 'workspace-one' };
    assert.deepEqual(validatePrincipal(actor), actor);
    assert.throws(() => assertOwnedRecord(actor, owned('workspace', 'workspace-one')), /Direct record ownership/);
  }
  assert.throws(() => assertOwnedRecord({ ...developer(), id: 'upstream-user-one' }, owned()), /Direct record ownership/);
});

test('ownership envelopes reject extra fields, inconsistent local ownership and invalid owner kinds', () => {
  for (const target of [
    { ...owned(), schemaVersion: 2 }, { ...owned(), admin: true }, { ...owned(), owner: { ...owned().owner, shared: true } },
    owned('agent', 'agent-one'), owned('developer', 'developer-one'), owned('local_owner', 'local-owner'),
    owned('product_user', 'upstream-user-one', localScope()), owned('local_owner', 'different-local', localScope()),
  ]) assert.throws(() => assertOwnedRecord(user(), target), /^Error: Invalid identity contract\.$/);
  for (const target of [owned(), owned('service_client', 'service-one'), owned('workspace', 'workspace-one'), owned('local_owner', 'local-owner', localScope())]) {
    assert.equal(matchesSchema(target, schema.$defs.OwnedRecord), true);
  }
});

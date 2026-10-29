import test from 'node:test';
import assert from 'node:assert/strict';
import {canonicalHash} from '../lib/compiler.mjs';
import {assertOwnedRecord, validatePrincipal, validateScope} from '../contracts/identity.mts';
import {assertDispatchable, validateApproval, validateCapabilityReference, validateContinuation, validateExecutionRequest} from '../contracts/execution.mts';
import {assessCertification, validateCertificationEvidence, validateCertificationTarget, validateProviderReadiness} from '../contracts/certification.mts';

function inheritedSerializer({accessor = false} = {}) {
  let calls = 0;
  const hook = accessor
    ? {get() { calls++; return () => []; }}
    : {value() { calls++; return []; }};
  const array = ['item'];
  Object.setPrototypeOf(array, Object.create(Array.prototype, {toJSON: hook}));
  return {array, calls: () => calls};
}

test('canonical JSON still accepts ordinary nested arrays and plain or null-prototype objects', () => {
  const nullPrototype = Object.assign(Object.create(null), {items: [null, true, 2, 'text', {nested: []}]});
  assert.match(canonicalHash(nullPrototype), /^[a-f0-9]{64}$/);
  assert.equal(canonicalHash(nullPrototype), canonicalHash({items: [null, true, 2, 'text', {nested: []}]}));
  assert.equal(canonicalHash(Object.freeze([1, Object.freeze([2])])), canonicalHash([1, [2]]));
});

test('inherited array serializer methods and accessors are rejected without invocation', () => {
  for (const accessor of [false, true]) {
    for (const nested of [false, true]) {
      const fixture = inheritedSerializer({accessor});
      assert.throws(() => canonicalHash(nested ? {inside: [fixture.array]} : fixture.array), /plain JSON/);
      assert.equal(fixture.calls(), 0);
    }
  }
});

test('array subclass serializers and traversal overrides cannot run during hashing', () => {
  let calls = 0;
  class CustomArray extends Array {
    toJSON() { calls++; return []; }
    map() { calls++; return []; }
    [Symbol.iterator]() { calls++; return [][Symbol.iterator](); }
  }
  assert.throws(() => canonicalHash({items: new CustomArray('item')}), /plain JSON/);
  assert.equal(calls, 0);
});

test('identity execution and certification guards never invoke nested inherited serializers', () => {
  const scope = {schemaVersion: 1, kind: 'local', localOwnerId: 'owner'};
  const principal = {schemaVersion: 1, kind: 'local_owner', id: 'owner', scope};
  const validators = [
    ['identity scope', array => validateScope({...scope, unknown: array})],
    ['identity principal', array => validatePrincipal({...principal, unknown: array})],
    ['identity ownership', array => assertOwnedRecord(principal, {schemaVersion: 1, scope, owner: {kind: 'local_owner', id: 'owner'}, unknown: array})],
    ['execution capability', array => validateCapabilityReference({unknown: array})],
    ['execution request', array => validateExecutionRequest({args: {items: array}})],
    ['execution approval', array => validateApproval({unknown: array}, {})],
    ['execution continuation', array => validateContinuation({unknown: array}, {})],
    ['execution dispatch', array => assertDispatchable({unknown: array})],
    ['certification readiness', array => validateProviderReadiness({accountTypes: array})],
    ['certification evidence', array => validateCertificationEvidence({checks: array})],
    ['certification target', array => validateCertificationTarget({requiredScopes: array})],
    ['certification assessment', array => assessCertification({evidence: array})],
  ];
  for (const [name, validate] of validators) {
    const fixture = inheritedSerializer();
    assert.throws(() => validate(fixture.array), undefined, name);
    assert.equal(fixture.calls(), 0, name);
  }
});

test('existing custom-object sparse-array and own-accessor restrictions remain enforced', () => {
  let calls = 0;
  const customObject = Object.create({toJSON() { calls++; return {}; }});
  const accessor = [1]; Object.defineProperty(accessor, '0', {enumerable: true, get() { calls++; return 1; }});
  const extra = [1]; extra.authority = 'unexpected';
  const nullArray = Object.setPrototypeOf([1], null);
  for (const value of [customObject, accessor, extra, Array(1), nullArray]) assert.throws(() => canonicalHash(value));
  assert.equal(calls, 0);
});

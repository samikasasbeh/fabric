import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import {canonicalHash, compileOpenApi, validateCapability} from '../lib/compiler.mjs';
import {validateCapabilityReference, validateExecutionRequest, hashExecutionRequest} from '../contracts/execution.mts';

const ajv = new Ajv2020({strict: true, allErrors: true});
addFormats(ajv);
for (const name of ['identity', 'execution']) ajv.addSchema(JSON.parse(readFileSync(new URL(`../contracts/${name}.schema.json`, import.meta.url))));
const schema = name => ajv.getSchema(`https://fabric.invalid/contracts/execution.schema.json#/$defs/${name}`);
const reference = id => ({appId: 'fixture', id, version: 1, definitionHash: 'a'.repeat(64), effect: 'read'});
const scope = {schemaVersion: 1, kind: 'local', localOwnerId: 'owner'};
const request = capability => ({schemaVersion: 1, id: 'request', scope, principal: {schemaVersion: 1, kind: 'local_owner', id: 'owner', scope},
  access: {kind: 'connection', id: 'account', generation: 1}, capability, args: {}, policyRevision: 1, idempotencyKey: 'key',
  createdAt: '2026-10-11T00:00:00Z', deadline: '2026-10-11T01:00:00Z'});
const invalid = callback => assert.throws(callback, error => error.code === 'invalid_contract');

test('actual compiler-generated 160-character capability IDs cross the execution boundary unchanged', () => {
  const compiled = compileOpenApi({appId: 'a'.repeat(64), document: {
    openapi: '3.1.0', servers: [{url: 'https://api.example.com'}],
    paths: {'/items': {get: {operationId: 'b'.repeat(70), responses: {'200': {description: 'Fixture'}}}}},
  }}).capabilities[0];
  validateCapability(compiled);
  assert.equal(compiled.id.length, 160);
  const capability = {appId: compiled.appId, id: compiled.id, version: compiled.version, definitionHash: canonicalHash(compiled), effect: compiled.effect};
  assert.deepEqual(validateCapabilityReference(capability), capability);
  assert.equal(schema('capability')(capability), true);
  const accepted = validateExecutionRequest(request(capability));
  assert.equal(accepted.capability.id, compiled.id);
  assert.equal(schema('request')(accepted), true);
  assert.equal(hashExecutionRequest(accepted), canonicalHash(request(capability)));
});

test('only capability IDs accept up to 200 safe characters in semantic and structural validators', () => {
  for (const length of [1, 128, 129, 160, 199, 200]) {
    const capability = reference('c'.repeat(length));
    assert.equal(validateCapabilityReference(capability).id, capability.id);
    assert.equal(schema('capability')(capability), true);
    assert.equal(validateExecutionRequest(request(capability)).capability.id, capability.id);
    assert.equal(schema('request')(request(capability)), true);
  }
  const exact = reference(`c${'._:@-'.repeat(39)}abcd`);
  assert.equal(exact.id.length, 200);
  assert.equal(validateCapabilityReference(exact).id, exact.id);
  assert.equal(schema('capability')(exact), true);
  for (const id of ['c'.repeat(201), '', '-leading', 'unsafe/path', 'unsafe%20escape', 'unsafe space', 'unsafe\nnewline', 'nonascii-é']) {
    const capability = reference(id);
    invalid(() => validateCapabilityReference(capability));
    invalid(() => validateExecutionRequest(request(capability)));
    assert.equal(schema('capability')(capability), false);
    assert.equal(schema('request')(request(capability)), false);
  }
});

test('request, principal, scope, idempotency and access IDs retain the 128-character boundary', () => {
  const mutations = [
    (value, id) => {value.id = id;},
    (value, id) => {value.idempotencyKey = id;},
    (value, id) => {value.access.id = id;},
    (value, id) => {value.access = {kind: 'missing', appId: value.capability.appId, accountSelection: {kind: 'exact', accountId: id}};},
    (value, id) => {value.scope.localOwnerId = id; value.principal.scope.localOwnerId = id; value.principal.id = id;},
  ];
  for (const mutate of mutations) {
    for (const length of [128, 129]) {
      const value = structuredClone(request(reference('c'.repeat(200))));
      mutate(value, 'x'.repeat(length));
      assert.equal(schema('request')(value), length === 128);
      if (length === 128) assert.deepEqual(validateExecutionRequest(value), value);
      else invalid(() => validateExecutionRequest(value));
    }
  }
});

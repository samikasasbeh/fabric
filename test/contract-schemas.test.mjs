import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import {validatePrincipal} from '../contracts/identity.mts';
import {bindingForRequest, validateExecutionRequest, validateApproval, validateContinuation, validateExecutionError} from '../contracts/execution.mts';
import {validateProviderReadiness, validateCertificationTarget, validateCertificationEvidence, assessCertification} from '../contracts/certification.mts';

// All schemas are loaded locally; schema identifiers are not fetched from a server.
const ajv = new Ajv2020({strict: true, allErrors: true});
addFormats(ajv);
for (const name of ['identity', 'execution', 'certification']) ajv.addSchema(JSON.parse(readFileSync(new URL(`../contracts/${name}.schema.json`, import.meta.url))));
const schema = name => ajv.getSchema(`https://fabric.invalid/contracts/${name}.schema.json`);
const localScope = {schemaVersion: 1, kind: 'local', localOwnerId: 'owner'};
const owner = {schemaVersion: 1, id: 'owner', kind: 'local_owner', scope: localScope};
const localClient = {schemaVersion: 1, id: 'grant', kind: 'local_client', scope: localScope, delegatedBy: {kind: 'local_owner', id: 'owner'}};
const tenantScope = {schemaVersion: 1, kind: 'tenant', organizationId: 'org', projectId: 'project', environmentId: 'dev'};
const time = '2026-10-11T00:00:00Z', deadline = '2026-10-11T01:00:00Z';
const request = {schemaVersion: 1, id: 'request', scope: localScope, principal: owner, policyRevision: 1, access: {kind: 'connection', id: 'account', generation: 1}, capability: {appId: 'example', id: 'example.read', version: 1, definitionHash: 'a'.repeat(64), effect: 'read'}, args: {}, idempotencyKey: 'key', createdAt: time, deadline};
function accepted(name, value) { const validator = schema(name); assert.ok(validator(value), JSON.stringify(validator.errors)); }

test('all contract schemas compile strictly with locally resolved references', () => {
  for (const name of ['identity', 'execution', 'certification']) assert.equal(typeof schema(name), 'function');
});

test('each identity variant accepted by runtime matches its structural schema', () => {
  const values = [owner, localClient, ...['developer', 'service_client'].map(kind => ({schemaVersion: 1, kind, id: kind, scope: tenantScope})),
    {schemaVersion: 1, kind: 'product_user', id: 'principal', subjectId: 'subject', scope: tenantScope},
    {schemaVersion: 1, kind: 'agent', id: 'agent', subjectId: 'subject', delegationId: 'grant', delegatedBy: {kind: 'product_user', id: 'subject'}, scope: tenantScope},
    {schemaVersion: 1, kind: 'agent', id: 'agent', delegationId: 'grant', delegatedBy: {kind: 'service_client', id: 'service'}, scope: tenantScope}];
  for (const value of values) accepted('identity', validatePrincipal(value));
  assert.equal(schema('identity')({...owner, schemaVersion: 2}), false);
  assert.equal(schema('identity')({...owner, extraAuthority: true}), false);
});

test('local delegated requests and owner approvals have schema parity without granting ownership', () => {
  const delegated = {...request, principal: localClient};
  accepted('execution', validateExecutionRequest(delegated));
  const approval = {schemaVersion: 1, id: 'owner-approval', ...bindingForRequest(delegated), approver: owner, decision: 'approved', createdAt: time, expiresAt: deadline};
  accepted('execution', validateApproval(approval, {request: delegated, now: time}));
  assert.equal(schema('execution')({...approval, approver: localClient}), false);
  assert.throws(() => validateApproval({...approval, approver: localClient}, {request: delegated, now: time}));
  for (const mutation of [{scope: tenantScope}, {workspaceId: 'workspace'}, {subjectId: 'user'}, {delegationId: 'nested'},
    {delegatedBy: {kind: 'local_client', id: 'parent'}}, {delegatedBy: {kind: 'local_owner', id: 'owner', anotherGrant: true}}]) {
    assert.equal(schema('identity')({...localClient, ...mutation}), false);
    assert.throws(() => validatePrincipal({...localClient, ...mutation}));
  }
  // Cross-field owner identity equality is enforced by semantic validation.
  const mismatched = {...localClient, delegatedBy: {kind: 'local_owner', id: 'other'}};
  accepted('identity', mismatched);
  assert.throws(() => validatePrincipal(mismatched));
});

test('execution request approval continuation and errors match structural schemas', () => {
  accepted('execution', validateExecutionRequest(request));
  accepted('execution', validateApproval({schemaVersion: 1, id: 'approval', ...bindingForRequest(request), approver: owner, decision: 'approved', createdAt: time, expiresAt: deadline}, {request, now: time}));
  const missing = {...request, access: {kind: 'missing', appId: 'example', accountSelection: {kind: 'owner_required'}}};
  accepted('execution', validateExecutionRequest(missing));
  accepted('execution', validateContinuation({schemaVersion: 1, id: 'handoff', ...bindingForRequest(missing), kind: 'connection', createdAt: time, expiresAt: deadline}, {request: missing, now: time}));
  accepted('execution', validateExecutionError({schemaVersion: 1, code: 'outcome_uncertain', source: 'provider', retryable: false, message: 'Outcome is unknown.'}));
  for (const mutation of [{schemaVersion: 2}, {idempotencyKey: ''}, {access: {...request.access, generation: 0}}, {capability: {...request.capability, effect: 'anything'}}]) assert.equal(schema('execution')({...request, ...mutation}), false);
});

test('certification metadata and assessment match structural schemas', () => {
  const target = {schemaVersion: 1, scope: localScope, appId: 'example', authKind: 'none', configurationGeneration: 1, packageHash: 'a'.repeat(64), capabilityId: 'example.read', definitionHash: 'b'.repeat(64), accountType: 'user', requiredScopes: [], effect: 'read'};
  const readiness = {schemaVersion: 1, id: 'ready', scope: localScope, appId: 'example', authKind: 'none', configurationGeneration: 1, status: 'testing', owner: 'primary', backupOwner: 'backup', accountTypes: ['user'], supportedScopes: [], checks: [{id: 'access-route', outcome: 'not_run'}], checkedAt: time, expiresAt: deadline};
  const {effect, ...binding} = target;
  const evidence = {...binding, id: 'test', environment: 'fixture', grantedScopes: [], performedBy: owner, checks: [{id: 'read', outcome: 'failed'}], startedAt: time, completedAt: time, expiresAt: deadline};
  accepted('certification', validateCertificationTarget(target));
  accepted('certification', validateProviderReadiness(readiness));
  accepted('certification', validateCertificationEvidence(evidence));
  accepted('certification', assessCertification({target, readiness, evidence: [evidence], now: time}));
  assert.equal(schema('certification')({...evidence, environment: 'pretend'}), false);
  assert.equal(schema('certification')({...evidence, checks: [{id: 'read', outcome: 'passed'}]}), false);
  assert.equal(schema('certification')({...target, requiredScopes: ['duplicate', 'duplicate']}), false);
});

test('runtime additionally checks semantic rules that structural JSON Schema cannot prove', () => {
  const swapped = {...request, principal: {...owner, id: 'other', scope: {...localScope, localOwnerId: 'other'}}};
  accepted('execution', swapped);
  assert.throws(() => validateExecutionRequest(swapped));
  const expiredWindow = {...request, deadline: time};
  accepted('execution', expiredWindow);
  assert.throws(() => validateExecutionRequest(expiredWindow));
});

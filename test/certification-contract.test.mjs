import test from 'node:test';
import assert from 'node:assert/strict';
import {assessCertification, validateCertificationEvidence, validateCertificationTarget, validateProviderReadiness} from '../contracts/certification.mts';

const scope = {schemaVersion: 1, kind: 'local', localOwnerId: 'operator'};
const principal = {schemaVersion: 1, id: 'operator', kind: 'local_owner', scope};
const check = id => ({id, outcome: 'passed', artifactId: `artifact:${id}`});
const target = () => ({schemaVersion: 1, scope, appId: 'fixture', authKind: 'oauth2', configurationGeneration: 1, packageHash: 'a'.repeat(64), capabilityId: 'fixture.list', definitionHash: 'b'.repeat(64), accountType: 'user', requiredScopes: ['items:read'], effect: 'read'});
const readiness = () => ({schemaVersion: 1, id: 'readiness', scope, appId: 'fixture', authKind: 'oauth2', configurationGeneration: 1, status: 'production_ready', owner: 'maintainer', backupOwner: 'backup', accountTypes: ['user'], supportedScopes: ['items:read'], checks: ['registration', 'callback', 'scope-mapping'].map(check), checkedAt: '2026-10-10T00:00:00Z', expiresAt: '2026-11-10T00:00:00Z'});
const evidence = environment => {
  const {effect, ...binding} = target();
  return {...binding, id: environment, environment, grantedScopes: environment === 'live' ? ['items:read'] : [], performedBy: principal, checks: (environment === 'fixture' ? ['input-validation', 'output-validation', 'policy-denial'] : ['identity', 'read']).map(check), startedAt: '2026-10-10T00:00:00Z', completedAt: '2026-10-10T01:00:00Z', expiresAt: '2026-11-10T00:00:00Z'};
};
const input = () => ({target: target(), readiness: readiness(), evidence: [evidence('fixture'), evidence('live')], now: '2026-10-11T00:00:00Z'});

test('valid metadata only makes the target ready for independent release review', () => {
  const result = assessCertification(input());
  assert.equal(result.status, 'ready_for_release_review');
  assert.equal(result.publicationAuthorized, false);
  assert.deepEqual(result.blockers, []);
  assert.deepEqual(result.evidenceIds, ['fixture', 'live']);
  assert.ok(Object.isFrozen(result.blockers));
});

test('fixture-only evidence never satisfies live certification', () => {
  const sample = input(); sample.evidence.pop();
  assert.deepEqual(assessCertification(sample).blockers, ['live_evidence_missing']);
  sample.evidence = [];
  assert.deepEqual(assessCertification(sample).blockers, ['fixture_evidence_missing', 'live_evidence_missing']);
});

test('writes require a separate readback check before release review', () => {
  const sample = input(); sample.target.effect = 'write';
  sample.evidence[1].checks = ['identity', 'write'].map(check);
  assert.deepEqual(assessCertification(sample).blockers, ['live_check_missing:readback']);
  sample.evidence[1].checks.push(check('readback'));
  assert.equal(assessCertification(sample).status, 'ready_for_release_review');
});

test('deletes need their own effect check and separate readback evidence', () => {
  const sample = input(); sample.target.effect = 'delete';
  sample.evidence[1].checks = ['identity', 'write', 'readback'].map(check);
  assert.deepEqual(assessCertification(sample).blockers, ['live_check_missing:delete']);
  sample.evidence[1].checks = ['identity', 'delete'].map(check);
  assert.deepEqual(assessCertification(sample).blockers, ['live_check_missing:readback']);
  sample.evidence[1].checks.push(check('readback'));
  assert.equal(assessCertification(sample).status, 'ready_for_release_review');
});

test('provider state, scope setup and account type remain separate blockers', () => {
  const sample = input(); sample.readiness.status = 'testing'; sample.readiness.accountTypes = ['bot'];
  sample.readiness.checks[2] = {id: 'scope-mapping', outcome: 'not_run'};
  assert.deepEqual(assessCertification(sample).blockers, ['account_type_unsupported', 'provider_check_missing:scope-mapping', 'provider_not_production_ready']);
});

test('expired evidence and readiness block exactly at expiry', () => {
  const sample = input(); sample.now = sample.readiness.expiresAt;
  assert.deepEqual(assessCertification(sample).blockers, ['fixture_evidence_expired', 'live_evidence_expired', 'provider_readiness_expired']);
});

test('newer failed and equally timed failed runs cannot be hidden by an older pass', () => {
  for (const completedAt of ['2026-10-10T01:00:00Z', '2026-10-10T02:00:00Z']) {
    const sample = input(); const failure = structuredClone(sample.evidence[1]);
    failure.id = 'new-failure'; failure.completedAt = completedAt; failure.checks[1].outcome = 'failed';
    sample.evidence.push(failure);
    for (const records of [sample.evidence, [...sample.evidence].reverse()]) {
      const result = assessCertification({...sample, evidence: records});
      assert.equal(result.status, 'blocked'); assert.ok(result.blockers.includes('live_check_failed'));
    }
  }
});

test('mismatched application, package, operation, definition, account and scope are rejected', () => {
  for (const [field, value] of [['appId', 'other'], ['packageHash', 'c'.repeat(64)], ['capabilityId', 'other'], ['definitionHash', 'd'.repeat(64)], ['accountType', 'bot'], ['scope', {...scope, localOwnerId: 'other'}]]) {
    const sample = input(); sample.evidence[0][field] = value;
    assert.throws(() => assessCertification(sample), undefined, field);
  }
  const sample = input(); sample.evidence.push(sample.evidence[0]);
  assert.throws(() => assessCertification(sample));
});

test('future observations, invalid dates and reversed windows are rejected', () => {
  for (const [field, value] of [['startedAt', '2026-10-12T00:00:00Z'], ['completedAt', '2026-02-30T00:00:00Z'], ['completedAt', '2026-10-12T00:00:00Z'], ['expiresAt', '2026-10-10T01:00:00Z']]) {
    const sample = input(); sample.evidence[0][field] = value; assert.throws(() => assessCertification(sample));
  }
  const sample = input(); sample.readiness.checkedAt = '2026-10-12T00:00:00Z'; assert.throws(() => assessCertification(sample));
});

test('strict shapes reject new authority, secrets, coerced enums and unsupported checks', () => {
  for (const mutate of [r => {r.status = ['production_ready'];}, r => {r.authKind = ['oauth2'];}, r => {r.token = 'SECRET';}, r => {r.owner = r.backupOwner;}, r => {r.checks[0].outcome = ['passed'];}, r => {r.checks[0].id = 'made-up';}, r => {delete r.checks[0].artifactId;}, r => {r.checks.push(r.checks[0]);}]) {
    const r = readiness(); mutate(r); assert.throws(() => validateProviderReadiness(r));
  }
  assert.throws(() => validateCertificationTarget({...target(), effect: ['read']}));
  assert.throws(() => validateCertificationEvidence({...evidence('live'), environment: ['live']}));
});

test('validators reject getters without invoking them and return detached frozen records', () => {
  let invoked = false; const r = readiness();
  Object.defineProperty(r, 'token', {enumerable: true, get() {invoked = true; return 'SECRET';}});
  assert.throws(() => validateProviderReadiness(r), /^Error: Invalid certification contract\.$/);
  assert.equal(invoked, false);
  const e = evidence('fixture'); const result = validateCertificationEvidence(e);
  e.checks[0].outcome = 'failed'; assert.equal(result.checks[0].outcome, 'passed');
  assert.ok(Object.isFrozen(result.performedBy.scope));
});

test('auth strategies have distinct readiness requirements without requiring user tokens', () => {
  for (const [authKind, ids] of [['api-key', ['credential-flow', 'scope-mapping']], ['none', ['access-route']]]) {
    const sample = input(); sample.readiness.authKind = authKind; sample.readiness.checks = ids.map(check);
    sample.target.authKind = authKind; sample.evidence.forEach(record => {record.authKind = authKind;});
    if (authKind === 'none') { sample.target.requiredScopes = []; sample.readiness.supportedScopes = []; sample.evidence.forEach(record => {record.requiredScopes = []; record.grantedScopes = [];}); }
    assert.equal(assessCertification(sample).status, 'ready_for_release_review');
  }
});

test('authentication kind and configuration generation cannot be substituted under existing evidence', () => {
  for (const [field, value] of [['authKind', 'api-key'], ['configurationGeneration', 2]]) {
    const sample = input(); sample.readiness[field] = value;
    assert.throws(() => assessCertification(sample));
    sample.target[field] = value;
    assert.throws(() => assessCertification(sample));
  }
  assert.throws(() => validateCertificationTarget({...target(), configurationGeneration: 0}));
  assert.throws(() => validateCertificationTarget({...target(), authKind: 'none'}));
  assert.throws(() => validateProviderReadiness({...readiness(), authKind: 'none'}));
  assert.throws(() => validateCertificationEvidence({...evidence('live'), authKind: 'none'}));
});

test('declared operation scopes, provider setup and observed live grants stay separate', () => {
  const sample = input(); sample.readiness.supportedScopes = []; sample.evidence[1].grantedScopes = [];
  assert.deepEqual(assessCertification(sample).blockers, ['live_scope_missing', 'provider_scope_unsupported']);
  sample.evidence[1].requiredScopes = [];
  assert.throws(() => assessCertification(sample));
  for (const requiredScopes of [['items:read', 'items:read'], ['a scope'], ['x'.repeat(257)]]) assert.throws(() => validateCertificationTarget({...target(), requiredScopes}));
});

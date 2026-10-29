import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {EnvironmentStores} from '../lib/tenant/environments.mjs';
import {ConnectionManager} from '../lib/connections.mjs';
import {LOCAL_DEPLOYMENT, tenantDeployment, endUser, stampOwner, ownershipOf, ownedBy} from '../lib/tenant/deployment.mjs';

// F03.2a: inside one developer environment, each end user's connections belong to that user alone.
const U1 = endUser({subjectId: 'aura-user-1', userRecordId: 'usr_' + 'a'.repeat(26)});
const U2 = endUser({subjectId: 'aura-user-2', userRecordId: 'usr_' + 'b'.repeat(26)});
const U1_RECREATED = endUser({subjectId: 'aura-user-1', userRecordId: 'usr_' + 'c'.repeat(26)});

function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-ownership-'));
  const stores = new EnvironmentStores({root});
  t.after(() => { stores.closeAll(); rmSync(root, {recursive: true, force: true}); });
  const env = stores.open({organizationId: 'org_' + 'a'.repeat(26), projectId: 'prj_' + 'a'.repeat(26), environmentId: 'env_' + 'a'.repeat(26)});
  let identity = 17;
  const manager = new ConnectionManager({store: env.repository, vault: env.vault, deployment: tenantDeployment(env.scope), request: async () => ({status: 200, data: {id: identity++, login: 'fixture-user'}})});
  return {env, manager};
}

test('a connection in a developer environment is owned by one end user; other users see nothing', async t => {
  const {env, manager} = setup(t);
  await assert.rejects(manager.connect({appId: 'github', token: 'synthetic-token-1'}), /needs its end user/);
  const mine = await manager.connect({appId: 'github', token: 'synthetic-token-1', user: U1});
  const stored = env.repository.get('connections', mine.id);
  assert.deepEqual(stored.ownership, {owner: {kind: 'product_user', id: 'aura-user-1'}});
  assert.equal(stored.userRecordId, U1.userRecordId);
  assert.deepEqual(manager.list(U1).map(connection => connection.id), [mine.id]);
  assert.deepEqual(manager.list(U2), []);
  assert.equal(manager.get(mine.id, U2), null);
  assert.equal(manager.get(mine.id, U1).id, mine.id);
  // A deleted user re-created with the same external id is a new user: none of the old records.
  assert.deepEqual(manager.list(U1_RECREATED), []);
  assert.deepEqual(manager.list(undefined), [], 'no owner, nothing');
});

test('one end user can never reconnect, and so take over, another user\'s connection', async t => {
  const {manager} = setup(t);
  const theirs = await manager.connect({appId: 'github', token: 'synthetic-token-1', user: U1});
  await assert.rejects(manager.connect({appId: 'github', token: 'synthetic-token-2', connectionId: theirs.id, user: U2}), /does not match/);
  await assert.rejects(manager.connect({appId: 'github', token: 'synthetic-token-2', connectionId: theirs.id, user: U1_RECREATED}), /does not match/);
  assert.equal(manager.list(U2).length, 0);
});

test('ownership rules: stamped records carry both ids; a tenant record without them fails closed; local has one owner', () => {
  const tenant = tenantDeployment({schemaVersion: 1, kind: 'tenant', organizationId: 'o', projectId: 'p', environmentId: 'e'});
  const record = stampOwner({id: 'c1'}, U1);
  assert.deepEqual(ownershipOf(record, tenant), {subjectId: 'aura-user-1', userRecordId: U1.userRecordId});
  assert.throws(() => ownershipOf({id: 'c2'}, tenant), {code: 'not_found'});
  assert.throws(() => ownershipOf({...record, userRecordId: undefined}, tenant), {code: 'not_found'});
  assert.equal(ownedBy(record, U1, tenant), true);
  assert.equal(ownedBy(record, U2, tenant), false);
  assert.equal(ownedBy(record, {subjectId: U1.subjectId, userRecordId: U2.userRecordId}, tenant), false, 'the external id alone is not enough');
  assert.equal(ownedBy({id: 'c2'}, U1, tenant), false);
  assert.equal(ownershipOf({id: 'c3'}, LOCAL_DEPLOYMENT), null);
  assert.equal(ownedBy({id: 'c3'}, undefined, LOCAL_DEPLOYMENT), true);
  assert.throws(() => endUser({subjectId: 'x', userRecordId: 'usr_short'}), /usr_ record id/);
  assert.throws(() => tenantDeployment({kind: 'local'}), /tenant scope/);
});

test('the app page shows each end user only their own accounts, and never picks another user\'s as the default', async t => {
  const {env, manager} = setup(t);
  const {AppDetailService} = await import('../lib/app-detail.mjs');
  const theirs = await manager.connect({appId: 'github', token: 'synthetic-token-1', user: U1});
  const service = new AppDetailService({store: env.repository, deployment: tenantDeployment(env.scope), catalog: () => [{id: 'github', name: 'GitHub', authMethods: ['token']}]});
  assert.deepEqual(service.present('github'), [], 'no end user, no accounts');
  assert.deepEqual(service.forUser(U1).present('github').map(account => account.id), [theirs.id]);
  assert.deepEqual(service.forUser(U2).present('github'), []);
  assert.equal(service.forUser(U2).account('github', undefined), null, 'the default account is never another user\'s');
  assert.throws(() => service.forUser(U2).account('github', theirs.id), {code: 'not_found'});
  assert.throws(() => service.forUser(U2).ready('github', theirs.id), {code: 'not_found'});
  assert.equal(service.forUser(U1).account('github', undefined).id, theirs.id);
  assert.throws(() => service.forUser({subjectId: 'x'}), /usr_ record id/);
});

test('account requests stay off in developer environments until they gain owners (F03.9): they refuse, never show accounts', async t => {
  const {env} = setup(t);
  const {ContinuationService} = await import('../lib/continuations.mjs');
  const service = new ContinuationService({store: env.repository, runtime: {}, origin: 'http://127.0.0.1:4340'});
  assert.equal(service.enabled, false);
  assert.throws(() => service.ownerList(), {code: 'unsupported_route'});
  assert.throws(() => service.ownerView('any'), {code: 'unsupported_route'});
  assert.throws(() => service.prepare({id: 'client'}, {}), {code: 'unsupported_route'});
});

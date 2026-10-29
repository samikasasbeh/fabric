import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync, mkdtempSync, readdirSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {TenantRegistry, newId} from '../lib/tenant/registry.mjs';
import {ServiceKeys} from '../lib/tenant/keys.mjs';
import {EnvironmentStores} from '../lib/tenant/environments.mjs';
import {PRESETS, RECORD_ID, KEY_SCOPES, DECISION_SCOPES} from '../contracts/tenant.mts';
import {registryCommand} from '../scripts/tenant-admin.mjs';

// F03.1a: customers, projects, environments and service keys. A key reaches exactly its own environment; every
// failure looks the same; the plaintext is never stored.
function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-keys-'));
  let now = Date.UTC(2026, 9, 13);
  const clock = () => now, registry = new TenantRegistry({root, clock}), stores = new EnvironmentStores({root, clock});
  t.after(() => { registry.close(); stores.closeAll(); rmSync(root, {recursive: true, force: true}); });
  const org = registry.createOrganization({name: 'Acme'}), project = registry.createProject({organizationId: org.id, name: 'Agent', supportEmail: 'help@acme.example'});
  const dev = registry.createEnvironment({projectId: project.id, kind: 'development'}, stores);
  const prod = registry.createEnvironment({projectId: project.id, kind: 'production'}, stores);
  return {root, registry, stores, keys: new ServiceKeys(registry), org, project, dev, prod, advance: ms => { now += ms; }};
}
const files = dir => { const out = []; const walk = folder => { for (const entry of readdirSync(folder, {withFileTypes: true})) { const full = path.join(folder, entry.name); if (entry.isDirectory()) walk(full); else out.push(full); } }; walk(dir); return out; };

test('records get prefixed lowercase ids; each environment has its own sealed folder; production starts disabled', t => {
  const {registry, stores, org, project, dev, prod} = setup(t);
  for (const id of [org.id, project.id, dev.id, prod.id, newId('serviceKey')]) assert.match(id, RECORD_ID);
  assert.equal(dev.productionEnabled, false); assert.equal(prod.productionEnabled, false);
  assert.ok(existsSync(stores.folder(registry.scopeOf(dev)))); assert.ok(existsSync(stores.folder(registry.scopeOf(prod))));
  assert.throws(() => registry.createEnvironment({projectId: project.id, kind: 'development'}, stores), /already has a development environment/);
  assert.throws(() => registry.createProject({organizationId: 'org_' + 'a'.repeat(26), name: 'X'}), /No such organization/);
  assert.throws(() => registry.createProject({organizationId: org.id, name: 'X', supportEmail: 'not an email'}), /supportEmail/);
  assert.equal(registry.enableProduction(prod.id).productionEnabled, true);
  assert.throws(() => registry.enableProduction(dev.id), /No such production environment/);
});

test('a key reaches exactly its own environment; a development key never reaches production', t => {
  const {registry, keys, dev, prod} = setup(t);
  const devKey = keys.mint({environmentId: dev.id, preset: 'standard'});
  assert.match(devKey.token, /^fab_sk_dev\.key_[a-z2-7]{26}\.[A-Za-z0-9_-]{43}$/);
  const caller = keys.verify(devKey.token);
  assert.deepEqual(caller.scope, registry.scopeOf(dev));
  assert.equal(caller.environment.kind, 'development');
  registry.enableProduction(prod.id);
  const prodKey = keys.mint({environmentId: prod.id, preset: 'connect-only'});
  assert.match(prodKey.token, /^fab_sk_prod\./);
  assert.deepEqual(keys.verify(prodKey.token).scope, registry.scopeOf(prod));
  // Relabelling a development key as production does not move it.
  assert.throws(() => keys.verify(devKey.token.replace('fab_sk_dev', 'fab_sk_prod')), {code: 'unauthorized'});
});

test('unknown, wrong, revoked, expired, suspended and not-yet-enabled keys all get the same 401', t => {
  const {registry, keys, org, dev, prod, advance} = setup(t);
  const good = keys.mint({environmentId: dev.id, preset: 'full'});
  const message = (() => { try { keys.verify('fab_sk_dev.key_' + 'a'.repeat(26) + '.' + 'b'.repeat(43)); } catch (error) { return error.message; } })();
  const refused = token => assert.throws(() => keys.verify(token), error => error.code === 'unauthorized' && error.status === 401 && error.message === message);
  refused('fab_sk_dev.key_' + 'a'.repeat(26) + '.' + 'b'.repeat(43));
  refused(good.token.slice(0, -1) + (good.token.endsWith('A') ? 'B' : 'A'));
  refused('not a key'); refused(undefined); refused(good.token + 'x');
  refused(keys.mint({environmentId: prod.id, preset: 'standard'}).token);
  const revoked = keys.mint({environmentId: dev.id, preset: 'standard'});
  keys.revoke(revoked.keyId); refused(revoked.token);
  // Rotation: the old key keeps working for seven days, then stops; the client and its scopes stay.
  const rotated = keys.rotate(good.serviceClientId);
  assert.equal(rotated.serviceClientId, good.serviceClientId);
  assert.ok(keys.verify(good.token)); assert.ok(keys.verify(rotated.token));
  advance(7 * 24 * 60 * 60 * 1000 + 1000);
  refused(good.token); assert.ok(keys.verify(rotated.token));
  registry.setStatus('organizations', org.id, 'suspended'); refused(rotated.token);
  registry.setStatus('organizations', org.id, 'active'); assert.ok(keys.verify(rotated.token));
  registry.setStatus('environments', dev.id, 'suspended'); refused(rotated.token);
});

test('scopes are stored literally from the preset; only update-scopes changes them, with an audit row', t => {
  const {registry, keys, dev} = setup(t);
  const standard = keys.mint({environmentId: dev.id, preset: 'standard'});
  assert.deepEqual([...keys.verify(standard.token).scopes], [...PRESETS.standard].sort());
  for (const scope of DECISION_SCOPES) assert.equal(PRESETS.standard.includes(scope), false, `${scope} is a decision power`);
  assert.deepEqual([...PRESETS.full], [...KEY_SCOPES]);
  assert.throws(() => { PRESETS.standard.push('x'); }, TypeError, 'presets cannot change under existing keys');
  keys.updateScopes(standard.serviceClientId, ['catalog:read']);
  assert.deepEqual([...keys.verify(standard.token).scopes], ['catalog:read']);
  assert.ok(registry.activity().some(event => event.type === 'tenant.scopes_updated'));
  assert.throws(() => keys.mint({environmentId: dev.id, scopes: ['catalog:read', 'root:everything']}), /Unknown scope/);
  assert.throws(() => keys.mint({environmentId: dev.id, preset: 'admin'}), /Unknown preset/);
  // At most two active keys per client.
  keys.rotate(standard.serviceClientId);
  assert.throws(() => keys.rotate(standard.serviceClientId), /already has two active keys/);
});

test('a key\'s plaintext never appears in any store, vault or registry file, and list never shows hashes', t => {
  const {root, keys, dev} = setup(t);
  const minted = keys.mint({environmentId: dev.id, preset: 'standard'}), secret = minted.token.split('.')[2];
  keys.verify(minted.token);
  for (const file of files(root)) assert.equal(readFileSync(file).includes(secret), false, file);
  const listed = keys.list(dev.id);
  assert.equal(listed.length, 1); assert.equal('secretHash' in listed[0], false); assert.equal(listed[0].active, true);
});

test('the operator command creates a customer end to end and prints the key once', t => {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-cli-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const run = (...args) => registryCommand([...args, '--root', root]);
  const org = run('org', 'create', '--name', 'Acme');
  const project = run('project', 'create', '--org', org.id, '--name', 'Agent');
  const env = run('env', 'create', '--project', project.id, '--kind', 'development');
  const key = run('key', 'create', '--env', env.id, '--preset', 'connect-only', '--name', 'Agent backend');
  assert.match(key.token, /^fab_sk_dev\./); assert.match(key.note, /cannot show it again/);
  assert.equal(run('key', 'list', '--env', env.id).length, 1);
  assert.deepEqual(run('key', 'update-scopes', key.serviceClientId, '--scopes', 'catalog:read,accounts:read').scopes, ['accounts:read', 'catalog:read']);
  assert.deepEqual(run('key', 'revoke', key.keyId), {revoked: key.keyId, agentTokensRevoked: 0}, 'without --with-agent-tokens, the tokens it minted keep working');
  assert.throws(() => registryCommand(['org', 'create', '--name', 'X']), /Usage/);
  assert.throws(() => run('key', 'explode'), /Usage/);
});

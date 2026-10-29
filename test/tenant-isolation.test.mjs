import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {EnvironmentStores} from '../lib/tenant/environments.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {ConnectionManager} from '../lib/connections.mjs';
import {stampOwner, tenantDeployment} from '../lib/tenant/deployment.mjs';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {current, raise} from '../lib/connection-notices.mjs';
import {buildCells, runMatrix, uncoveredRoutes, SHARED} from './tenant/matrix.mjs';

// F03.0b: the cross-tenant matrix over today's storage operations, strengthened after the F03.0 review. Every later
// developer-layer slice adds its routes here, and a route without a row fails the test.
function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-matrix-'));
  new PlatformStore({root}).close();
  const stores = new EnvironmentStores({root});
  t.after(() => { stores.closeAll(); rmSync(root, {recursive: true, force: true}); });
  return {root, stores, cells: buildCells(stores, root)};
}
const manager = actor => new ConnectionManager({store: actor.handle.repository, vault: actor.handle.vault, deployment: tenantDeployment(actor.handle.scope)});
/** F10.4: the sign-in adapter of the actor's own environment, as a developer's own Google app builds it (every value explicit). */
const google = actor => new OAuth2Provider(definitionFor('google'), {store: actor.handle.repository, vault: actor.handle.vault, connections: manager(actor), clientId: 'matrix-client', clientSecret: 'matrix-secret', publishing: 'testing', consentDays: null});
const own = actor => actor.handle.repository.get('connections', `${SHARED.connection}-${actor.userName}`);

// Each operation names what an attacker in `actor` would do to reach `target`. Shared ids resolve in the actor's own
// environment; a target's unique id must answer exactly like an id that never existed.
const OPERATIONS = [
  {name: 'read a connection by its shared id', run: actor => actor.handle.repository.get('connections', SHARED.connection)},
  {name: 'read a connection by the target\'s unique id', run: (actor, target) => [actor.handle.repository.get('connections', target.uniqueIds.connection), actor.marker]},
  {name: 'list connections', run: actor => actor.handle.repository.list('connections').filter(connection => !connection.userMarker)},
  {name: 'read an approval by its shared id', run: actor => actor.handle.repository.get('approvals', SHARED.approval)},
  {name: 'read a connect session by its shared id', run: actor => actor.handle.repository.get('connectSessions', SHARED.session)},
  {name: 'list activity', run: actor => actor.handle.repository.list('activity')},
  {name: 'read a stored credential by its shared id', run: actor => [actor.handle.vault.get(SHARED.connection), actor.marker]},
  {name: 'read a credential by the target\'s unique id', run: (actor, target) => [actor.handle.vault.get(target.uniqueIds.connection), actor.marker]},
  {name: 'list my connections as an end user', run: actor => [manager(actor).list(actor.user).map(connection => connection.id), actor.marker]},
  {name: 'read another end user\'s connection by id', run: (actor, target) => [manager(actor).get(`${SHARED.connection}-${actor.userName === 'u1' ? 'u2' : 'u1'}`, actor.user), target === actor ? null : null, actor.marker]},
  {name: 'overwrite then read back a connection', run: actor => { actor.handle.repository.put('connections', {id: 'probe', marker: actor.marker}); return actor.handle.repository.get('connections', 'probe'); }},
  // F10.4: the accounts a grant-wide revoke would sign out are the actor's own, beside a Calendar account of the same Google account.
  {name: 'list the accounts a grant-wide revoke signs out', run: actor => {
    actor.handle.repository.put('connections', stampOwner({id: `${SHARED.connection}-${actor.userName}-calendar`, appId: 'google-calendar', identity: {subject: SHARED.subject, email: SHARED.email}, marker: actor.marker, userMarker: `${actor.marker}/${actor.userName}`}, actor.user));
    return [google(actor).siblings(own(actor), actor.user).map(item => item.userMarker), actor.marker];
  }},
  {name: 'read my account\'s connection notices', run: actor => {
    raise(actor.handle.repository, {connection: own(actor), kind: 'grant_narrowed', now: Date.parse('2026-10-17T00:00:00.000Z')});
    return [current(actor.handle.repository, own(actor)).map(notice => [notice.kind, actor.handle.repository.get('connections', notice.connectionId)?.userMarker]), actor.marker];
  }},
  // F10.5: the not-granted notice is derived from the actor's own account, never stored, so nothing of it reaches anyone else.
  {name: 'read my account\'s not-granted notice', run: actor => {
    actor.handle.repository.put('connections', {...own(actor), status: 'ready', scopes: [], grant: {level: 'full', missing: ['https://www.googleapis.com/auth/gmail.settings.basic']}});
    const notices = current(actor.handle.repository, own(actor)).filter(notice => notice.kind === 'not_granted');
    if (!notices.length) throw Object.assign(new Error('No not-granted notice.'), {code: 'no_notice'});
    return [notices.map(notice => [notice.count, actor.handle.repository.get('connections', notice.connectionId)?.userMarker]), actor.marker];
  }},
];

test('no environment or end user can read, count, change, copy or detect another\'s data through any storage operation', t => {
  const {cells} = setup(t);
  assert.equal(cells.length, 4);
  const result = runMatrix({cells, operations: OPERATIONS});
  assert.deepEqual(result.violations, []);
  assert.deepEqual(result.controlFailures, []);
  assert.equal(result.attempts, OPERATIONS.length * 4 * 2 * 3);
});

test('the matrix catches every blind spot the review found, and refuses a refuse-everything pass', t => {
  const {stores, cells} = setup(t);
  const caught = operation => runMatrix({cells, operations: [operation]}).violations;
  // Direct leak: reading straight from the target's handle.
  assert.ok(caught({name: 'leaking route', run: (actor, target) => target.handle?.repository.get('connections', SHARED.connection) ?? null}).length > 0);
  // Existence oracle: a different refusal for a real target than for a ghost.
  assert.ok(caught({name: 'existence oracle', run: (actor, target) => [target.handle ? 'already_decided' : 'not_found', actor.marker]}).length > 0);
  // A count of the target's connections.
  assert.ok(caught({name: 'count leak', run: (actor, target) => [target.handle ? target.handle.repository.list('connections').length : 0, actor.marker]}).length > 0);
  // Copying the target's record into the actor's own store.
  assert.ok(caught({name: 'copy-in', run: (actor, target) => { if (target.handle && target !== actor) { const copy = target.handle.repository.get('connections', SHARED.connection); actor.handle.repository.put('connections', {...copy, id: `copied-${target.key.length}`, scope: undefined}); } return actor.handle.repository.get('connections', SHARED.connection); }}).some(line => line.includes('holds')));
  stores.closeAll();
  const fresh = setup(t);
  // A write that changes the shared platform catalog.
  const platformWrite = runMatrix({cells: fresh.cells, operations: [{name: 'platform write', run: (actor, target) => { if (target.handle && target !== actor) { const platform = new PlatformStore({root: fresh.root}); platform.put('capabilities', {id: `cap-${Math.random()}`}); platform.close(); } return actor.handle.repository.get('connections', SHARED.connection); }}]});
  assert.ok(platformWrite.violations.some(line => line.includes('changed platform')));
  // Another end user's data inside the same environment.
  assert.ok(runMatrix({cells: fresh.cells, operations: [{name: 'cross-user', run: actor => actor.handle.repository.list('connections')}]}).violations.some(line => line.includes('in its own environment')));
  // Refusing everything cannot pass: the control on the actor's own data fails.
  const refusing = runMatrix({cells: fresh.cells, operations: [{name: 'refuse everything', run: () => { throw Object.assign(new Error('no'), {code: 'not_found'}); }}]});
  assert.equal(refusing.controlFailures.length, 8);
  assert.deepEqual(uncoveredRoutes(['GET /v1/connections', 'POST /v1/connect-sessions'], [{route: 'GET /v1/connections'}]), ['POST /v1/connect-sessions']);
});

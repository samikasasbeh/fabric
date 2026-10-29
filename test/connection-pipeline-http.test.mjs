import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createApp} from '../server.mjs';

// These tests use the actual Fabric HTTP server, permission engine, store and
// local-device adapter. Public website responses and extension pairing are
// explicit fixtures, not evidence of a live third-party account connection.
async function setup(t, providerRequest = async()=>{throw new Error('Unexpected provider request in isolated fixture.');}) {
  const dataDir = await mkdtemp(path.join(tmpdir(), 'fabric-connection-pipeline-'));
  const app = await createApp({dataDir, port:54000 + Math.floor(Math.random() * 2000), request:providerRequest});
  t.after(async()=>{await app.close(); await rm(dataDir, {recursive:true, force:true});});
  app.oauth.clientId = '';
  app.oauth.clientSecret = '';
  await app.start();
  const boot = await fetch(`${app.origin}/api/state`);
  const initialState = await boot.json();
  assert.equal(boot.status, 200);
  const cookie = boot.headers.get('set-cookie').split(';')[0];
  const request = async(route, {method='GET', data, expected=200, headers={}}={}) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers:{Cookie:cookie, ...(method === 'POST' ? {'Content-Type':'application/json', 'X-Fabric-CSRF':initialState.csrfToken} : {}), ...headers}, ...(data !== undefined ? {body:JSON.stringify(data)} : {})});
    const body = await response.json();
    // Error output contains status and a public error only, never inventories,
    // generated pairing secrets, cookies, or other response payloads.
    assert.equal(response.status, expected, body.error || `Unexpected status for ${route}`);
    return body;
  };
  return {app, initialState, request, post:(route, data, expected=200)=>request(route, {method:'POST', data, expected})};
}

test('HTTP connection pipeline performs real computer reads with read permissions and no provider credentials', async t=>{
  let providerCalls = 0;
  const {app, initialState, request, post} = await setup(t, async()=>{providerCalls++; throw new Error('Local device reads must not contact a provider.');});
  assert.equal(initialState.connections.some(connection=>connection.appId === 'local-device'), false);
  const started = await post('/api/connect/start', {appId:'local-device'});
  assert.equal(started.kind, 'connected');
  assert.equal(started.connection.driver, 'device');
  assert.equal(started.connection.status, 'ready');
  assert.equal(started.connection.authMethod, 'local-consent');
  assert.deepEqual(started.connection.allowedOrigins, []);
  const again = await post('/api/connect/start', {appId:'local-device', method:'device'});
  assert.equal(again.connection.id, started.connection.id);

  const detail = await request('/api/connectors/local-device');
  const permissions = detail.permissionsByConnection[started.connection.id];
  assert.equal(permissions.length, 3);
  for (const permission of permissions) {
    assert.equal(permission.effect, 'read');
    assert.equal(permission.mode, 'allow');
    assert.equal(permission.providerAccess, 'local');
    assert.equal(permission.executable, true);
    assert.equal(permission.requiresApproval, false);
  }
  const exported = await request(`/api/connectors/local-device/tools?connectionId=${started.connection.id}`);
  assert.equal(exported.tools.length, 3);
  assert.ok(exported.tools.every(tool=>tool.driver === 'device' && tool.permission.effect === 'read'));

  const system = await post('/api/jobs', {connectionId:started.connection.id, capabilityId:'local-device.system.v1', args:{}}, 201);
  assert.equal(system.status, 'succeeded');
  assert.equal(system.effect, 'read');
  assert.equal(system.result.verification.status, 'observed');
  assert.equal(system.result.data.readOnly, true);
  assert.ok(system.result.data.logicalProcessors > 0);
  assert.ok(system.result.data.totalMemoryBytes > 0);
  for (const field of ['hostname','username','serialNumber','serial_number','homeDirectory','networkInterfaces','accessToken']) assert.equal(Object.hasOwn(system.result.data, field), false);

  const tools = await post('/api/jobs', {connectionId:started.connection.id, capabilityId:'local-device.tools.v1', args:{}}, 201);
  assert.equal(tools.status, 'succeeded');
  assert.equal(tools.result.verification.status, 'observed');
  assert.equal(tools.result.data.count, tools.result.data.tools.length);
  assert.ok(tools.result.data.count <= 6);
  for (const tool of tools.result.data.tools) {
    assert.equal(tool.accountConnected, false);
    assert.equal(tool.runnableByFabric, false);
  }
  assert.equal(app.vault.get(started.connection.id), null);
  assert.equal(providerCalls, 0);
});

test('HTTP device deny and revoke block before adapter dispatch; Ask waits for exact approval', async t=>{
  const {app, request, post} = await setup(t);
  const {connection} = await post('/api/connect/start', {appId:'local-device'});
  const operation = 'local-device.system.v1';
  const jobArgs = {connectionId:connection.id, capabilityId:operation, args:{}};
  let dispatched = 0;
  const execute = app.device.execute.bind(app.device);
  app.device.execute = async(...args)=>{dispatched++; return execute(...args);};

  const denied = await post(`/api/connections/${connection.id}/permissions`, {capabilityId:operation, mode:'deny'});
  assert.equal(denied.effect, 'read');
  assert.equal(denied.executable, false);
  const blocked = await post('/api/jobs', jobArgs, 400);
  assert.match(blocked.error, /denied/i);
  assert.equal(dispatched, 0);

  await post(`/api/connections/${connection.id}/permissions`, {capabilityId:operation, mode:'ask'});
  const waiting = await post('/api/jobs', jobArgs, 201);
  assert.equal(waiting.status, 'awaiting_approval');
  assert.equal(dispatched, 0);
  const approved = await post(`/api/jobs/${waiting.id}/approve`, {approvalDigest:waiting.approvalDigest});
  assert.equal(approved.status, 'succeeded');
  assert.equal(dispatched, 1);

  const revoked = await post(`/api/connections/${connection.id}/revoke`, {});
  assert.equal(revoked.status, 'revoked');
  const refused = await post('/api/jobs', jobArgs, 400);
  assert.match(refused.error, /not ready|revoked/i);
  assert.equal(dispatched, 1);
  const exported = await request(`/api/connectors/local-device/tools?connectionId=${connection.id}`);
  assert.ok(exported.tools.every(tool=>tool.permission.executable === false));
});

test('known social and work application starts create pending pairings, not pretend account connections', async t=>{
  let providerCalls = 0;
  const {request, post} = await setup(t, async()=>{providerCalls++; throw new Error('Known applications do not require a website request to begin pairing.');});
  for (const appId of ['facebook','notion','spotify']) {
    const resolved = await post('/api/resolve', {query:appId});
    assert.equal(resolved.status, 'resolved');
    assert.equal(resolved.created, false);
    assert.equal(resolved.plan.recommended, 'browser');
    assert.equal(resolved.plan.connectionEstablished, false);
    const start = await post('/api/connect/start', {appId});
    assert.equal(start.kind, 'browser');
    assert.equal(start.app.id, appId);
    assert.equal(start.connection, undefined);
    assert.ok(start.pairing.origins.includes(start.origin));
    const status = await request(`/api/pair/${start.pairing.pairingId}/status`);
    assert.equal(status.status, 'pending');
    assert.equal(status.connectionId, undefined);
    assert.equal(JSON.stringify(status).includes(start.pairing.code), false);
    const detail = await request(`/api/connectors/${appId}`);
    assert.equal(detail.connections.length, 0);
  }
  assert.equal(providerCalls, 0);
});

test('unknown application name requires its website without guessing a service or account', async t=>{
  let requests = 0;
  const {app, post} = await setup(t, async()=>{requests++; throw new Error('Do not guess an unknown application domain.');});
  const result = await post('/api/resolve', {query:'Unknown fixture application'});
  assert.equal(result.status, 'website_required');
  assert.equal(result.app, null);
  assert.equal(requests, 0);
  assert.equal(app.store.list('applications').length, 0);
  assert.equal(app.store.list('connections').length, 0);
});

test('injected public website redirect resolves one actual registered origin then supports explicit fixture pairing', async t=>{
  const providerRequests = [];
  const target = 'https://app.fabric-fixture.example';
  const {app, request, post} = await setup(t, async options=>{
    providerRequests.push({url:options.url, allowedOrigins:options.allowedOrigins, headers:options.headers});
    assert.equal(options.method, 'GET');
    assert.equal(Object.keys(options.headers || {}).some(name=>/authorization|cookie/i.test(name)), false);
    if (options.url === 'https://redirect.fabric-fixture.example/') return {status:302, headers:{location:`${target}/home`}, data:''};
    if (options.url === `${target}/home`) return {status:200, headers:{'content-type':'text/html; charset=utf-8'}, data:'<!doctype html><title>Explicit Fixture Workspace &amp; Tools</title><main>Fixture only</main>'};
    throw new Error('Unexpected fixture URL; no outbound networking is permitted by this test.');
  });
  const result = await post('/api/resolve', {query:'https://redirect.fabric-fixture.example/'});
  assert.equal(result.status, 'resolved');
  assert.equal(result.created, true);
  assert.equal(result.app.name, 'Explicit Fixture Workspace & Tools');
  assert.deepEqual(result.app.webOrigins, [target]);
  assert.deepEqual(result.app.apiOrigins, []);
  assert.equal(result.app.discoveryEvidence.observedOrigin, target);
  assert.equal(result.app.discoveryEvidence.accountVerified, false);
  assert.equal(result.plan.connectionEstablished, false);
  assert.equal(result.plan.recommended, 'browser');
  assert.equal(app.store.list('applications').length, 1);
  assert.equal(app.store.list('connections').length, 0);
  assert.deepEqual(providerRequests.map(item=>item.allowedOrigins), [['https://redirect.fabric-fixture.example'], [target]]);

  const duplicate = await post('/api/resolve', {query:`${target}/another-page`});
  assert.equal(duplicate.created, false);
  assert.equal(duplicate.app.id, result.app.id);
  assert.equal(app.store.list('applications').length, 1);
  assert.equal(providerRequests.length, 2);

  const launch = await post('/api/connect/start', {appId:result.app.id});
  assert.equal(launch.kind, 'browser');
  assert.equal(launch.origin, target);
  assert.deepEqual(launch.pairing.origins, [target]);
  assert.equal((await request(`/api/pair/${launch.pairing.pairingId}/status`)).status, 'pending');
  await post('/api/connect/start', {appId:result.app.id, origin:'https://redirect.fabric-fixture.example'}, 400);

  // Explicitly simulate only the extension's handshake. This does not establish
  // any provider account or claim that real Chrome/Edge was tested here.
  const extensionOrigin = `chrome-extension://${'a'.repeat(32)}`;
  const paired = await request('/api/browser/pair', {method:'POST', data:{code:launch.pairing.code, origin:target, label:'HTTP fixture tab — not a live account', bridgeVersion:'0.2'}, headers:{Origin:extensionOrigin}, expected:201});
  assert.equal(paired.connection.appId, result.app.id);
  assert.equal(paired.connection.status, 'session_ready');
  assert.equal(paired.connection.driver, 'browser');
  assert.match(paired.connection.identity.binding, /not independently verified/);
  const status = await request(`/api/pair/${launch.pairing.pairingId}/status`);
  assert.equal(status.status, 'paired');
  assert.equal(status.connectionId, paired.connection.id);
  const detail = await request(`/api/connectors/${result.app.id}`);
  assert.equal(detail.connections.length, 1);
  assert.equal(detail.permissionsByConnection[paired.connection.id].length, 4);
  for (const permission of detail.permissionsByConnection[paired.connection.id]) assert.equal(permission.mode, 'ask');
  for (const response of [status, detail, await request('/api/state')]) {
    const encoded = JSON.stringify(response);
    assert.equal(encoded.includes(paired.token), false);
    assert.equal(encoded.includes(launch.pairing.code), false);
  }
  assert.equal(providerRequests.length, 2);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm, readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {createApp} from '../server.mjs';
import {FabricClient} from '../lib/fabric-client.mjs';
import {FABRIC_PROTOCOL, protocolManifest} from '../lib/fabric-protocol.mjs';
import {canonicalHash} from '../lib/compiler.mjs';

async function setup(t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-protocol-'));
  const app = await createApp({dataDir: dir});
  t.after(async () => {await app.close(); await rm(dir, {recursive: true, force: true});});
  const connection = {id: randomUUID(), appId: 'workspace', driver: 'workspace', authMethod: 'workspace', status: 'ready', identity: {id: 'isolated-test-workspace'}, allowedOrigins: [], createdAt: new Date().toISOString()};
  app.store.put('connections', connection);
  const grant = (ids = ['workspace.list.v1'], name = 'Test client') => app.protocol.createClient({name, bindings: ids.map(capabilityId => ({connectionId: connection.id, capabilityId}))});
  const invoke = (token, method, params = {}, id = randomUUID()) => app.protocol.handle(`Bearer ${token}`, {protocol: FABRIC_PROTOCOL, id, method, params});
  const input = (client, capabilityId = 'workspace.list.v1', args = {}) => ({connectionId: connection.id, capabilityId, definitionHash: client.bindings.find(x => x.capabilityId === capabilityId).definitionHash, args});
  return {...app, dir, connection, grant, invoke, input};
}

test('Fabric protocol grants disclose tokens once and discover exact scoped typed operations', async t => {
  const app = await setup(t), {client, token} = app.grant();
  assert.equal(protocolManifest.features.mcpCompatible, false);
  assert.equal(JSON.stringify(app.store.list('clientGrants')).includes(token), false);
  assert.equal(JSON.stringify(app.protocol.listClients()).includes('tokenHash'), false);
  assert.equal(JSON.stringify(app.store.list('activity')).includes(token), false);
  const found = await app.invoke(token, 'capabilities.list');
  assert.equal(found.result.capabilities.length, 1);
  assert.equal(found.result.capabilities[0].id, 'workspace.list.v1');
  assert.equal(found.result.capabilities[0].definitionHash, client.bindings[0].definitionHash);
  assert.deepEqual(found.result.capabilities[0].inputSchema, app.store.get('capabilities', 'workspace.list.v1').inputSchema);
  assert.equal(JSON.stringify(found).includes('isolated-test-workspace'), false);
  assert.equal((await app.invoke(token, 'fabric.discover')).result.protocol, FABRIC_PROTOCOL);
});

test('Fabric protocol executes a real local read and deduplicates request IDs concurrently', async t => {
  const app = await setup(t), {client, token} = app.grant(), params = app.input(client);
  const [a, b] = await Promise.all([app.invoke(token, 'calls.create', params, 'same-request'), app.invoke(token, 'calls.create', params, 'same-request')]);
  assert.equal(a.result.status, 'succeeded'); assert.equal(a.result.result.verification.status, 'observed');
  assert.equal(a.result.id, b.result.id); assert.equal(app.store.list('jobs').length, 1);
  assert.equal((await app.invoke(token, 'calls.create', params, 'same-request')).result.id, a.result.id);
  const conflict = await app.invoke(token, 'calls.create', {...params, args: {unexpected: 'value'}}, 'same-request');
  assert.equal(conflict.error.code, 'idempotency_conflict');
});

test('Fabric client cannot self-approve; owner approves an exact real workspace write', async t => {
  const app = await setup(t), {client, token} = app.grant(['workspace.write.v1']);
  const pending = await app.invoke(token, 'calls.create', app.input(client, 'workspace.write.v1', {path: 'proof.txt', content: 'Protocol write proof'}));
  assert.equal(pending.result.status, 'awaiting_approval'); assert.equal(pending.result.approvalRequired, true);
  assert.equal('approvalDigest' in pending.result, false); assert.equal('preview' in pending.result, false);
  assert.equal((await app.invoke(token, 'calls.approve', {callId: pending.result.id})).error.code, 'method_not_found');
  assert.equal((await app.invoke(token, 'permissions.set', {})).error.code, 'method_not_found');
  const ownerJob = app.store.get('jobs', pending.result.id);
  await app.runtime.approve(ownerJob.id, ownerJob.approvalDigest);
  const completed = await app.invoke(token, 'calls.get', {callId: ownerJob.id});
  assert.equal(completed.result.status, 'succeeded'); assert.equal(completed.result.result.verification.status, 'verified');
  assert.equal(await readFile(path.join(app.dir, 'workspace', 'proof.txt'), 'utf8'), 'Protocol write proof');
});

test('Fabric protocol rejects cross-client call reads, ungranted capabilities and altered hashes', async t => {
  const app = await setup(t), one = app.grant(), two = app.grant(['workspace.list.v1'], 'Second');
  const call = await app.invoke(one.token, 'calls.create', app.input(one.client));
  assert.equal((await app.invoke(two.token, 'calls.get', {callId: call.result.id})).error.code, 'not_found');
  assert.equal((await app.invoke(one.token, 'calls.create', {...app.input(one.client), capabilityId: 'workspace.read.v1'})).error.code, 'permission_denied');
  assert.equal((await app.invoke(one.token, 'calls.create', {...app.input(one.client), definitionHash: 'wrong'})).error.code, 'grant_changed');
});

test('Fabric protocol rechecks client revocation before owner approval can dispatch', async t => {
  const app = await setup(t), {client, token} = app.grant(['workspace.write.v1']);
  const pending = await app.invoke(token, 'calls.create', app.input(client, 'workspace.write.v1', {path: 'no-write.txt', content: 'must not exist'}));
  const ownerJob = app.store.get('jobs', pending.result.id); app.protocol.revokeClient(client.id);
  const blocked = await app.runtime.approve(ownerJob.id, ownerJob.approvalDigest);
  assert.equal(blocked.status, 'failed'); assert.match(blocked.error, /expired or revoked/);
  await assert.rejects(readFile(path.join(app.dir, 'workspace', 'no-write.txt')), {code: 'ENOENT'});
  assert.equal((await app.invoke(token, 'capabilities.list')).error.code, 'unauthorized');
});

test('Fabric client grants bind account identity and immutable capability definition', async t => {
  const app = await setup(t), first = app.grant();
  const cap = app.store.get('capabilities', 'workspace.list.v1'); app.store.put('capabilities', {...cap, description: 'Changed definition'});
  assert.equal((await app.invoke(first.token, 'calls.create', app.input(first.client))).error.code, 'grant_changed');
  assert.equal((await app.invoke(first.token, 'capabilities.list')).result.capabilities[0].status, 'unavailable');
  app.store.put('capabilities', cap); const second = app.grant();
  app.store.put('connections', {...app.connection, identity: {id: 'different-account'}});
  assert.equal((await app.invoke(second.token, 'calls.create', app.input(second.client))).error.code, 'grant_changed');
});

test('Fabric protocol cannot override the owner deny policy', async t => {
  const app = await setup(t), {client, token} = app.grant();
  app.runtime.permissions.set({connectionId: app.connection.id, capabilityId: 'workspace.list.v1', mode: 'deny'});
  assert.equal((await app.invoke(token, 'calls.create', app.input(client))).error.code, 'permission_denied');
  assert.throws(() => app.grant(), /currently permitted/);
});

test('Fabric protocol validates grants, malformed envelopes, unsupported versions and credentials', async t => {
  const app = await setup(t), {token, client} = app.grant();
  assert.throws(() => app.protocol.createClient({name: 'Client', bindings: []}), /between 1 and 100/);
  assert.throws(() => app.protocol.createClient({name: 'Client', bindings: client.bindings, expiresInSeconds: Infinity}), /expire/);
  assert.equal((await app.invoke(`${token.slice(0, -1)}!`, 'fabric.discover')).error.code, 'unauthorized');
  assert.equal((await app.protocol.handle(`Bearer ${token}`, {protocol: 'MCP', id: 'x', method: 'fabric.discover'})).error.code, 'unsupported_version');
  assert.equal((await app.invoke(token, 'fabric.discover', {extra: true})).error.code, 'invalid_request');
  assert.equal((await app.invoke(token, 'fabric.discover', {}, 'bad\nid')).error.code, 'invalid_request');
  app.protocol.clock = () => Date.parse(client.expiresAt) + 1;
  assert.equal((await app.invoke(token, 'fabric.discover')).error.code, 'unauthorized');
});

test('Fabric refuses replay after a persisted incomplete request reservation', async t => {
  const app = await setup(t), {client, token} = app.grant(), params = app.input(client), requestId = 'crash-reservation';
  app.store.put('protocolRequests', {id: canonicalHash({clientId: client.id, requestId}), clientId: client.id, requestId, requestHash: canonicalHash(params), status: 'reserved'});
  assert.equal((await app.invoke(token, 'calls.create', params, requestId)).error.code, 'outcome_unknown');
  assert.equal(app.store.list('jobs').length, 0);
});

test('Fabric HTTP endpoint works with the SDK and keeps administration behind owner CSRF', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-protocol-http-')), port = 44000 + Math.floor(Math.random() * 500);
  const app = await createApp({dataDir: dir, port}); await app.start();
  t.after(async () => {await app.close(); await rm(dir, {recursive: true, force: true});});
  const boot = await fetch(`${app.origin}/api/state`), state = await boot.json(), cookie = boot.headers.get('set-cookie').split(';')[0];
  const post = async (route, data) => {
    const response = await fetch(`${app.origin}${route}`, {method: 'POST', headers: {'Content-Type': 'application/json', Cookie: cookie, 'X-Fabric-CSRF': state.csrfToken}, body: JSON.stringify(data)});
    assert.equal(response.ok, true); return response.json();
  };
  const connection = await post('/api/connections/local', {});
  const grant = await post('/api/clients', {name: 'SDK test', bindings: [{connectionId: connection.id, capabilityId: 'workspace.list.v1'}]});
  const client = new FabricClient({endpoint: `${app.origin}/fabric/v1`, token: grant.token});
  assert.equal((await client.discover()).protocol, FABRIC_PROTOCOL);
  const {capabilities} = await client.capabilities(), cap = capabilities[0];
  const result = await client.invoke({connectionId: cap.connectionId, capabilityId: cap.id, definitionHash: cap.definitionHash});
  assert.equal(result.status, 'succeeded'); assert.equal((await client.getCall(result.id)).id, result.id);
  const unauthorized = await fetch(`${app.origin}/fabric/v1`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'});
  assert.equal(unauthorized.status, 401);
  assert.equal((await fetch(`${app.origin}/api/clients`, {method: 'POST', headers: {'Content-Type': 'application/json', Authorization: `Bearer ${grant.token}`}, body: '{}'})).status, 403);
  await post(`/api/clients/${grant.client.id}/revoke`, {});
  await assert.rejects(client.capabilities(), {code: 'unauthorized'});
});

test('Fabric SDK never forwards its client grant through redirects', async () => {
  let options;
  const client = new FabricClient({endpoint: 'http://127.0.0.1:4188/fabric/v1', token: 'fab_client.test', fetch: async (_url, value) => {options = value; return {ok: true, json: async () => ({protocol: FABRIC_PROTOCOL, id: JSON.parse(value.body).id, result: {}})};}});
  await client.discover(); assert.equal(options.redirect, 'error');
  assert.throws(() => new FabricClient({endpoint: 'http://external.example/fabric/v1', token: 'fab_client.test'}), /HTTPS/);
});

test('Fabric SDK requires correlation on a successful response', async () => {
  const client = new FabricClient({endpoint: 'http://127.0.0.1:4188/fabric/v1', token: 'fab_client.test', fetch: async () => ({ok: true, json: async () => ({protocol: FABRIC_PROTOCOL, id: null, result: {}})})});
  await assert.rejects(client.discover(), /Unexpected Fabric protocol response/);
});

test('Fabric withholds a completed read if the client is revoked while awaiting its response', async t => {
  const app = await setup(t), {client, token} = app.grant();
  let began, release;
  const started = new Promise(resolve => {began = resolve;}), barrier = new Promise(resolve => {release = resolve;});
  const original = app.local.execute.bind(app.local);
  app.local.execute = async (...args) => {const outcome = await original(...args); began(); await barrier; return outcome;};
  const pending = app.invoke(token, 'calls.create', app.input(client));
  await started; app.protocol.revokeClient(client.id); release();
  assert.equal((await pending).error.code, 'unauthorized');
  assert.equal(app.store.list('jobs')[0].status, 'succeeded'); // effect is recorded for the owner, not erased
});

async function browserFixture(t) {
  const app=await setup(t),pair=app.browser.createPair('notion'),origin=pair.origins[0];
  const linked=app.browser.pair({code:pair.code,origin,bridgeVersion:'0.2',label:'Synthetic browser fixture'});
  const ids=['notion.browser.observe.v1','notion.browser.click.v2','notion.browser.fill.v2'];
  const grant=()=>app.protocol.createClient({name:'Browser proposal client',bindings:ids.map(capabilityId=>({connectionId:linked.connection.id,capabilityId}))});
  const client=grant();
  const call=(op,args={},credentials=client,id=randomUUID())=>app.invoke(credentials.token,'calls.create',{
    connectionId:linked.connection.id,capabilityId:`notion.browser.${op}.${op==='observe'?'v1':'v2'}`,
    definitionHash:credentials.client.bindings.find(b=>b.capabilityId===`notion.browser.${op}.${op==='observe'?'v1':'v2'}`).definitionHash,args
  },id);
  const observe=async(credentials=client)=>{
    const request=await call('observe',{},credentials);assert.equal(request.result.status,'awaiting_approval');
    const job=app.store.get('jobs',request.result.id),pending=app.runtime.approve(job.id,job.approvalDigest);
    const command=app.browser.poll(linked.token).command;
    assert.ok(command);
    const data={origin,url:`${origin}/fixture`,title:'Synthetic notes',snapshotId:randomUUID(),expiresAt:new Date(Date.now()+119000).toISOString(),
      controls:[{targetId:randomUUID(),label:'Save note',role:'button',canClick:true,canFill:false},
        {targetId:randomUUID(),label:'Note',role:'textbox',canClick:false,canFill:true}]};
    app.browser.result(linked.token,{id:command.id,ok:true,data});
    assert.equal((await pending).status,'succeeded');return {data,jobId:job.id};
  };
  return {...app,linked,origin,client,grant,call,observe};
}

test('AI browser action proposals need an owned observation and owner approval; clients cannot self-approve',async t=>{
  const app=await browserFixture(t);
  const noEvidence=await app.call('click',{snapshotId:'invented',targetId:'invented'});
  assert.ok(noEvidence.error);assert.equal(app.store.list('browserCommands').length,0);
  const {data}=await app.observe(),args={snapshotId:data.snapshotId,targetId:data.controls[0].targetId};
  const proposal=await app.call('click',args,app.client,'deduplicated-proposal');
  assert.equal(proposal.result.status,'awaiting_approval');
  assert.equal(app.browser.poll(app.linked.token).command,null,'No write is dispatched before owner approval');
  const job=app.store.get('jobs',proposal.result.id);
  assert.equal(job.preview.browserTarget.label,'Save note');assert.equal(job.preview.browserTarget.origin,app.origin);
  assert.equal(job.preview.browserTarget.operation,'click');
  assert.equal(proposal.result.approvalDigest,undefined);
  assert.equal((await app.invoke(app.client.token,'calls.approve',{callId:job.id})).error.code,'method_not_found');
  assert.equal((await app.call('click',args,app.client,'deduplicated-proposal')).result.id,job.id);
  const pending=app.runtime.approve(job.id,job.approvalDigest),command=app.browser.poll(app.linked.token).command;
  assert.equal(command.action.op,'click');
  app.browser.result(app.linked.token,{id:command.id,ok:true,data:{origin:app.origin,operation:'click',targetId:args.targetId,dispatchStatus:'dispatched',persistentEffect:'unverified'}});
  assert.equal((await pending).status,'uncertain','A browser click is not independent proof of persistence');
});

test('AI writes reject other clients snapshots, non-actionable targets, extra inputs and stale inspections',async t=>{
  const app=await browserFixture(t),other=app.grant(),{data,jobId}=await app.observe();
  const args={snapshotId:data.snapshotId,targetId:data.controls[0].targetId};
  assert.ok((await app.call('click',args,other)).error);
  assert.ok((await app.call('fill',{...args,value:'Cannot fill a button'})).error);
  assert.ok((await app.call('click',{...args,label:'Made-up safe label'})).error);
  const read=app.store.get('jobs',jobId);read.result.data.expiresAt=new Date(Date.now()-1).toISOString();app.store.put('jobs',read);
  assert.ok((await app.call('click',args)).error);
  await assert.rejects(app.runtime.createJob({connectionId:app.linked.connection.id,capabilityId:'notion.browser.click.v2',args,source:{kind:'heartbeat'}}),/interactive/);
});

test('browser proposal review is digest-bound and rechecks client revocation before dispatch',async t=>{
  const app=await browserFixture(t),{data}=await app.observe();
  const proposal=await app.call('fill',{snapshotId:data.snapshotId,targetId:data.controls[1].targetId,value:'Approved text only'});
  const job=app.store.get('jobs',proposal.result.id),original=structuredClone(job);
  job.preview.browserTarget.label='Misleading replacement';app.store.put('jobs',job);
  await assert.rejects(app.runtime.approve(job.id,original.approvalDigest),/exact action/);
  app.store.put('jobs',original);app.protocol.revokeClient(app.client.client.id);
  const blocked=await app.runtime.approve(job.id,original.approvalDigest);
  assert.equal(blocked.status,'failed');assert.match(blocked.error,/revoked/);
  assert.equal(app.browser.poll(app.linked.token).command,null);
});

test('an expired inspected target cannot dispatch even with an unexpired owner approval',async t=>{
  const app=await browserFixture(t),{data,jobId}=await app.observe();
  const proposal=await app.call('click',{snapshotId:data.snapshotId,targetId:data.controls[0].targetId});
  const job=app.store.get('jobs',proposal.result.id),read=app.store.get('jobs',jobId);
  read.result.data.expiresAt=new Date(Date.now()-1).toISOString();app.store.put('jobs',read);
  const blocked=await app.runtime.approve(job.id,job.approvalDigest);
  assert.equal(blocked.status,'failed');assert.match(blocked.error,/Inspect this page again/);
  assert.equal(app.browser.poll(app.linked.token).command,null);
});

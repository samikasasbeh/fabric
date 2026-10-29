import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {Client} from '@modelcontextprotocol/client';
import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
import {createApp} from '../server.mjs';

const entry=fileURLToPath(new URL('../mcp.mts',import.meta.url));
const owner={schemaVersion:1,kind:'local_owner',id:'isolated-owner',scope:{schemaVersion:1,kind:'local',localOwnerId:'isolated-owner'}};
async function freePort(){const s=createServer();s.listen(0,'127.0.0.1');await once(s,'listening');const port=s.address().port;await new Promise(resolve=>s.close(resolve));return port;}

test('independent MCP child uses persisted local authority through approval readback restart and revocation',async t=>{
  const dir=await mkdtemp(path.join(tmpdir(),'fabric-mcp-authority-')),port=await freePort();
  let app=await createApp({dataDir:dir,port,localAuthority:{mode:'new',ownerPrincipal:owner}});await app.start();
  let client,stderr='';
  t.after(async()=>{await client?.close();await app.close();await rm(dir,{recursive:true,force:true});});
  const session=await fetch(`${app.origin}/api/state`),state=await session.json(),cookie=session.headers.get('set-cookie').split(';')[0];
  const post=async(route,data)=>{
    const response=await fetch(`${app.origin}${route}`,{method:'POST',headers:{'content-type':'application/json',cookie,'x-fabric-csrf':state.csrfToken},body:JSON.stringify(data)});
    assert.equal(response.ok,true);return response.json();
  };
  const connection=await post('/api/connections/local',{});
  const grant=await post('/api/clients',{name:'Independent fixture client',bindings:['workspace.list.v1','workspace.write.v1'].map(capabilityId=>({connectionId:connection.id,capabilityId}))});
  client=new Client({name:'isolated-authority-client',version:'1.0.0'},{versionNegotiation:{mode:{pin:'2026-07-28'}}});
  const transport=new StdioClientTransport({command:process.execPath,args:[entry],cwd:dir,stderr:'pipe',env:{FABRIC_ENDPOINT:`${app.origin}/fabric/v1`,FABRIC_CLIENT_TOKEN:grant.token}});
  transport.stderr.on('data',value=>{stderr+=value;});await client.connect(transport);
  const invoke=(capabilityId,requestId,args={})=>client.callTool({name:'fabric_invoke',arguments:{requestId,connectionId:connection.id,capabilityId,definitionHash:grant.client.bindings.find(item=>item.capabilityId===capabilityId).definitionHash,args}});
  const get=callId=>client.callTool({name:'fabric_get_call',arguments:{callId}});
  const read=await invoke('workspace.list.v1','read-before-restart');assert.equal(read.isError,false);
  assert.equal(read.structuredContent.status,'succeeded');
  const pending=await invoke('workspace.write.v1','write-once',{path:'proof.txt',content:'temporary integration proof'});
  assert.equal(pending.isError,false);assert.equal(pending.structuredContent.status,'awaiting_approval');
  const job=app.store.get('jobs',pending.structuredContent.id),accepted=structuredClone(job.executionRequest);
  assert.equal(accepted.principal.kind,'local_client');assert.equal(accepted.principal.id,grant.client.id);
  const unsupported=await client.callTool({name:'fabric_approve',arguments:{callId:job.id}});assert.equal(unsupported.isError,true);
  const completed=await post(`/api/jobs/${job.id}/approve`,{approvalDigest:job.approvalDigest});
  assert.equal(completed.status,'succeeded');assert.equal(completed.executionApproval.approver.id,owner.id);
  assert.equal(await readFile(path.join(app.local.root,'proof.txt'),'utf8'),'temporary integration proof');
  assert.equal((await get(job.id)).structuredContent.result.verification.status,'verified');
  const repeated=await invoke('workspace.write.v1','write-once',{path:'proof.txt',content:'temporary integration proof'});
  assert.equal(repeated.structuredContent.id,job.id);assert.deepEqual(app.store.get('jobs',job.id).executionRequest,accepted);
  assert.equal(app.store.get('capabilityStats','workspace.write.v1').runs,1);
  // Restore the same legacy default policy/hash while incrementing persisted
  // history; the grant remains active, but its old requests cannot be disclosed.
  const policy=app.runtime.permissions.policyId(connection.id,'workspace.list.v1');
  app.runtime.permissions.set({connectionId:connection.id,capabilityId:'workspace.list.v1',mode:'deny'});app.store.delete('permissions',policy);
  await app.close();app=await createApp({dataDir:dir,port,localAuthority:{mode:'require',ownerPrincipal:owner}});await app.start();
  assert.equal((await get(read.structuredContent.id)).isError,true);
  assert.equal((await invoke('workspace.list.v1','read-after-restart')).structuredContent.status,'succeeded');
  assert.deepEqual(app.store.get('jobs',job.id).executionRequest,accepted);
  app.connections.revoke(connection.id);
  assert.equal((await get(job.id)).isError,true);assert.equal((await invoke('workspace.list.v1','after-revoke')).isError,true);
  assert.equal(stderr.includes(grant.token),false);
});

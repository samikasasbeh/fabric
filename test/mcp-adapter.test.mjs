import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomUUID} from 'node:crypto';
import {createServer} from 'node:net';
import {createServer as createHttpServer} from 'node:http';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {Client} from '@modelcontextprotocol/client';
import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
import {InMemoryTransport} from '@modelcontextprotocol/server';
import {createMcpAdapter, readMcpEnvironment} from '../lib/mcp-adapter.mts';
import {createApp} from '../server.mjs';
import {canonicalHash} from '../lib/compiler.mjs';
import {PERMISSION_GROUPS,validatePermissionGroups} from '../lib/permission-groups.mjs';
import {fixture as handoffFixture} from './fixtures/continuation-fixture.mjs';

const ROOT=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const ENTRY=path.join(ROOT,'mcp.mts');
const TOKEN=`fab_client.${randomUUID()}.${'a'.repeat(43)}`;
const ENV={FABRIC_ENDPOINT:'http://127.0.0.1:4188/fabric/v1',FABRIC_CLIENT_TOKEN:TOKEN};
const NAMES=['fabric_get_call','fabric_invoke','fabric_list_capabilities','fabric_list_events','fabric_proxy_request','fabric_watch'];
const args={requestId:'explicit-request-1',connectionId:'connection',capabilityId:'operation',definitionHash:'a'.repeat(64),args:{}};
const result={id:'job',status:'succeeded',connectionId:'connection',capabilityId:'operation',createdAt:'2026-01-01T00:00:00.000Z',updatedAt:'2026-01-01T00:00:00.000Z',result:{data:{ok:true},verification:{status:'observed'}},error:null,approvalRequired:false};
const response=(input,value={capabilities:[]})=>new Response(JSON.stringify({protocol:'fabric/0.1',id:JSON.parse(input.body).id,result:value}),{headers:{'content-type':'application/json'}});

async function memory(t,options={}) {
  const server=createMcpAdapter({env:ENV,...options}),client=new Client({name:'isolated-test',version:'1.0.0'});
  const [left,right]=InMemoryTransport.createLinkedPair();
  await server.connect(left);await client.connect(right);
  t.after(async()=>{await client.close();await server.close();});
  return client;
}
const invoke=(client,input=args)=>client.callTool({name:'fabric_invoke',arguments:input});
const data=reply=>reply.structuredContent;
async function freePort() {const server=createServer();server.listen(0,'127.0.0.1');await once(server,'listening');const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;}
async function fixture(t,ids=['workspace.list.v1','workspace.write.v1']) {
  const dir=await mkdtemp(path.join(tmpdir(),'fabric-mcp-')),port=await freePort();
  const app=await createApp({dataDir:dir,port});await app.start();
  t.after(async()=>{await app.close();await rm(dir,{recursive:true,force:true});});
  const connection={id:randomUUID(),appId:'workspace',driver:'workspace',authMethod:'workspace',status:'ready',identity:{id:'isolated-mcp-workspace'},createdAt:new Date().toISOString()};
  app.store.put('connections',connection);
  const grant=(name='MCP fixture')=>app.protocol.createClient({name,bindings:ids.map(capabilityId=>({connectionId:connection.id,capabilityId}))});
  const credentials=grant();
  const connect=async (access=credentials)=>{
    const client=new Client({name:'independent-mcp-fixture',version:'1.0.0'},{versionNegotiation:{mode:{pin:'2026-07-28'}}});
    const transport=new StdioClientTransport({command:process.execPath,args:[ENTRY],cwd:dir,stderr:'pipe',env:{FABRIC_ENDPOINT:`${app.origin}/fabric/v1`,FABRIC_CLIENT_TOKEN:access.token}});
    let stderr='';transport.stderr.on('data',chunk=>{stderr+=chunk;});
    await client.connect(transport);t.after(async()=>{await client.close();assert.equal(stderr.includes(access.token),false);});
    return client;
  };
  const client=await connect();
  const input=(capabilityId='workspace.list.v1',values={},requestId=randomUUID())=>({requestId,connectionId:connection.id,capabilityId,definitionHash:credentials.client.bindings.find(item=>item.capabilityId===capabilityId).definitionHash,args:values});
  return {...app,dir,connection,credentials,grant,connect,client,input};
}

test('MCP environment accepts only canonical loopback Fabric endpoint and a bounded environment grant',()=>{
  assert.equal(readMcpEnvironment(ENV).endpoint,ENV.FABRIC_ENDPOINT);
  assert.equal(readMcpEnvironment({FABRIC_CLIENT_TOKEN:TOKEN}).endpoint,ENV.FABRIC_ENDPOINT);
  for(const endpoint of ['https://example.com/fabric/v1','http://localhost:4188/fabric/v1','http://2130706433:4188/fabric/v1','http://127.1:4188/fabric/v1','http://127.0.0.1:4188/api/state','http://127.0.0.1:4188/fabric/v1?token=secret','http://user:secret@127.0.0.1:4188/fabric/v1','http://127.0.0.1:4188/fabric/v1#secret','http://127.0.0.1:65536/fabric/v1','http://127.0.0.1:4188/fabric/../fabric/v1']) assert.throws(()=>readMcpEnvironment({...ENV,FABRIC_ENDPOINT:endpoint}),/Invalid MCP environment/);
  for(const token of ['',undefined,'fab_client.invalid',TOKEN+'\n'])assert.throws(()=>readMcpEnvironment({...ENV,FABRIC_CLIENT_TOKEN:token}),/Invalid MCP environment/);
});

test('MCP lists only six fixed tools without touching the runtime',async t=>{
  const client=await memory(t,{fetch:async()=>{assert.fail('tool metadata must not access accounts');}});
  const listed=await client.listTools();assert.deepEqual(listed.tools.map(tool=>tool.name).sort(),NAMES);
  assert.equal(listed.tools.find(tool=>tool.name==='fabric_invoke').inputSchema.additionalProperties,false);
  assert.equal(listed.tools.find(tool=>tool.name==='fabric_get_call').annotations.readOnlyHint,true);
});

test('MCP validates malformed, extra, large and deep inputs before network; errors never echo supplied secrets',async t=>{
  let requests=0;const client=await memory(t,{fetch:async()=>{requests++;assert.fail('invalid input reached network');}});
  let deep={};for(let i=0;i<50;i++)deep={next:deep};
  for(const input of [{...args,token:TOKEN},{...args,endpoint:'https://evil.example'},{...args,method:'calls.approve'},{...args,source:{kind:'user'}},{...args,approvalDigest:TOKEN},{...args,args:null},{...args,args:[]},{...args,args:{content:'x'.repeat(70000)}},{...args,args:deep},{...args,requestId:'bad\nid'},{...args,definitionHash:'bad'},{}]) {
    const reply=await invoke(client,input);assert.equal(reply.isError,true);assert.equal(JSON.stringify(reply).includes(TOKEN),false);
  }
  const unknown=await client.callTool({name:TOKEN,arguments:{}});assert.equal(unknown.isError,true);assert.equal(JSON.stringify(unknown).includes(TOKEN),false);
  assert.equal(requests,0);
});

test('MCP preserves explicit idempotency key, exact binding, no redirects and sanitized result projection',async t=>{
  let options;const client=await memory(t,{fetch:async(_url,input)=>{options=input;return response(input,{...result,preview:{secret:TOKEN},approvalDigest:TOKEN,result:{data:{authorization:TOKEN,note:`echo ${TOKEN}`},verification:{status:'observed'}}});}});
  const reply=await invoke(client);assert.equal(reply.isError,false);
  const envelope=JSON.parse(options.body);assert.equal(envelope.id,args.requestId);assert.equal(envelope.method,'calls.create');assert.deepEqual(envelope.params,{connectionId:args.connectionId,capabilityId:args.capabilityId,definitionHash:args.definitionHash,args:{}});
  assert.equal(options.redirect,'error');assert.equal(new Headers(options.headers).get('authorization'),`Bearer ${TOKEN}`);
  assert.equal(JSON.stringify(reply).includes(TOKEN),false);assert.equal('preview' in data(reply),false);assert.equal('approvalDigest' in data(reply),false);
});

test('MCP upstream errors and malformed responses are fixed, bounded and secret-free',async t=>{
  const cases=[
    input=>new Response(JSON.stringify({protocol:'fabric/0.1',id:JSON.parse(input.body).id,error:{code:'permission_denied',message:TOKEN}}),{status:403,headers:{'content-type':'application/json'}}),
    input=>new Response(JSON.stringify({protocol:'fabric/0.1',id:'wrong',result}),{headers:{'content-type':'application/json'}}),
    ()=>new Response(TOKEN,{headers:{'content-type':'text/plain'}}),
    input=>response(input,{id:'bad',status:'made-up',error:TOKEN}),
    ()=>new Response('x'.repeat(2*1024*1024+1),{headers:{'content-type':'application/json'}}),
    ()=>{throw new Error(TOKEN);},
  ];
  for(const make of cases){const client=await memory(t,{fetch:async(_url,input)=>make(input)});const reply=await invoke(client);assert.equal(reply.isError,true);assert.equal(JSON.stringify(reply).includes(TOKEN),false);assert.ok(JSON.stringify(reply).length<1000);}
});

test('MCP timeout aborts one upstream request without replay',async t=>{
  let requests=0,aborted=false;
  const client=await memory(t,{timeoutMs:20,fetch:async(_url,options)=>{requests++;return new Promise((_resolve,reject)=>options.signal.addEventListener('abort',()=>{aborted=true;reject(new Error(TOKEN));},{once:true}));}});
  const reply=await invoke(client);assert.equal(reply.isError,true);assert.equal(data(reply).error.code,'request_interrupted');assert.equal(requests,1);assert.equal(aborted,true);
});

test('MCP rejects coerced capability enums and contradictory or malformed call states',async t=>{
  const capability={id:'operation',connectionId:'connection',definitionHash:'a'.repeat(64),status:'available',name:'Read',description:'Fixture',appId:'workspace',driver:'workspace',inputSchema:{type:'object'},effect:'read',approval:'allow'};
  for(const bad of [{...capability,effect:['read']},{...capability,approval:['allow']}]) {
    const client=await memory(t,{fetch:async(_url,input)=>response(input,{capabilities:[bad]})});const reply=await client.callTool({name:'fabric_list_capabilities',arguments:{}});assert.equal(data(reply).error.code,'invalid_response');
  }
  for(const bad of [{...result,approvalRequired:true},{...result,status:'awaiting_approval',approvalRequired:false},{...result,error:{message:TOKEN}},{...result,createdAt:'not-a-date'},{...result,updatedAt:'2026-02-30T00:00:00.000Z'}]) {
    const client=await memory(t,{fetch:async(_url,input)=>response(input,bad)});const reply=await invoke(client);assert.equal(data(reply).error.code,'invalid_response');assert.equal(JSON.stringify(reply).includes(TOKEN),false);
  }
});

test('MCP bounds simultaneous requests even when input validators yield together',async t=>{
  let requests=0;const releases=[];
  const client=await memory(t,{fetch:async(_url,input)=>{requests++;await new Promise(resolve=>releases.push(resolve));return response(input,result);}});
  const pending=Array.from({length:12},(_,i)=>invoke(client,{...args,requestId:`concurrent-${i}`}));
  await new Promise(resolve=>setImmediate(resolve));assert.equal(requests,8);for(const release of releases)release();
  const replies=await Promise.all(pending);assert.equal(replies.filter(reply=>data(reply).error?.code==='busy').length,4);assert.equal(requests,8);
});

test('real SDK stdio client discovers grants, reads, waits for exact owner approval and verifies persisted write',async t=>{
  const f=await fixture(t);assert.equal(f.client.getNegotiatedProtocolVersion(),'2026-07-28');assert.equal(f.client.getProtocolEra(),'modern');assert.ok((await f.client.discover()).supportedVersions.includes('2026-07-28'));assert.deepEqual((await f.client.listTools()).tools.map(x=>x.name).sort(),NAMES);
  const listed=data(await f.client.callTool({name:'fabric_list_capabilities',arguments:{}}));assert.equal(listed.capabilities.length,2);
  const read=data(await invoke(f.client,f.input()));assert.equal(read.status,'succeeded');assert.equal(read.result.verification.status,'observed');
  const pending=data(await invoke(f.client,f.input('workspace.write.v1',{path:'proof.txt',content:'MCP persisted proof'})));
  assert.equal(pending.status,'awaiting_approval');assert.equal('approvalDigest' in pending,false);assert.equal('preview' in pending,false);
  assert.equal((await f.client.callTool({name:'calls.approve',arguments:{callId:pending.id}})).isError,true);
  await assert.rejects(readFile(path.join(f.dir,'workspace','proof.txt')),{code:'ENOENT'});
  const job=f.store.get('jobs',pending.id);await f.runtime.approve(job.id,job.approvalDigest);
  const completed=data(await f.client.callTool({name:'fabric_get_call',arguments:{callId:job.id}}));assert.equal(completed.status,'succeeded');assert.equal(completed.result.verification.status,'verified');assert.equal(await readFile(path.join(f.dir,'workspace','proof.txt'),'utf8'),'MCP persisted proof');
});

test('real stdio repeats exact request once, rejects conflict and preserves incomplete reservation',async t=>{
  const f=await fixture(t),input=f.input('workspace.list.v1',{},'stable-key');
  const [first,second]=await Promise.all([invoke(f.client,input),invoke(f.client,input)]),a=data(first),b=data(second);assert.equal(a.id,b.id);assert.equal(data(await invoke(f.client,input)).id,a.id);assert.equal(f.store.list('jobs').length,1);
  assert.equal(data(await invoke(f.client,{...input,args:{different:true}})).error.code,'idempotency_conflict');
  const reserved=f.input('workspace.list.v1',{},'reserved-key'),{requestId,...params}=reserved;
  f.store.put('protocolRequests',{id:canonicalHash({clientId:f.credentials.client.id,requestId}),requestHash:canonicalHash(params),status:'reserved'});
  assert.equal(data(await invoke(f.client,reserved)).error.code,'outcome_unknown');assert.equal(f.store.list('jobs').length,1);
});

test('real stdio prevents cross-client reads and revocation before owner dispatch',async t=>{
  const f=await fixture(t),other=await f.connect(f.grant('Other client'));
  const read=data(await invoke(f.client,f.input()));assert.equal(data(await other.callTool({name:'fabric_get_call',arguments:{callId:read.id}})).error.code,'not_found');
  const pending=data(await invoke(f.client,f.input('workspace.write.v1',{path:'blocked.txt',content:'must not appear'})));
  f.protocol.revokeClient(f.credentials.client.id);const job=f.store.get('jobs',pending.id);assert.equal((await f.runtime.approve(job.id,job.approvalDigest)).status,'failed');
  assert.equal(data(await invoke(f.client,f.input())).error.code,'unauthorized');await assert.rejects(readFile(path.join(f.dir,'workspace','blocked.txt')),{code:'ENOENT'});
});

test('real stdio rechecks policy, definition and account authority after discovery',async t=>{
  const f=await fixture(t),input=f.input(),cap=f.store.get('capabilities',input.capabilityId);
  await f.client.callTool({name:'fabric_list_capabilities',arguments:{}});
  f.runtime.permissions.set({connectionId:f.connection.id,capabilityId:cap.id,mode:'deny'});assert.equal(data(await invoke(f.client,input)).error.code,'permission_denied');
  f.runtime.permissions.set({connectionId:f.connection.id,capabilityId:cap.id,mode:'allow'});
  f.store.put('capabilities',{...cap,description:'Changed'});assert.equal(data(await invoke(f.client,{...input,requestId:'changed-definition'})).error.code,'grant_changed');
  f.store.put('capabilities',cap);f.store.put('connections',{...f.connection,authRevision:randomUUID()});assert.equal(data(await invoke(f.client,{...input,requestId:'changed-account'})).error.code,'grant_changed');assert.equal(f.store.list('jobs').length,0);
});

test('real stdio withholds read result when grant is revoked during execution',async t=>{
  const f=await fixture(t);let began,release;const started=new Promise(resolve=>{began=resolve;}),barrier=new Promise(resolve=>{release=resolve;});
  const original=f.local.execute.bind(f.local);f.local.execute=async(...input)=>{const result=await original(...input);began();await barrier;return result;};
  const pending=invoke(f.client,f.input());await started;f.protocol.revokeClient(f.credentials.client.id);release();assert.equal(data(await pending).error.code,'unauthorized');assert.equal(f.store.list('jobs')[0].status,'succeeded');
});

test('real stdio pending approval cannot survive Deny then Ask policy changes',async t=>{
  const f=await fixture(t),input=f.input('workspace.write.v1',{path:'policy-blocked.txt',content:'must not appear'});
  const pending=data(await invoke(f.client,input));assert.equal(pending.status,'awaiting_approval');
  f.runtime.permissions.set({connectionId:f.connection.id,capabilityId:input.capabilityId,mode:'deny'});
  f.runtime.permissions.set({connectionId:f.connection.id,capabilityId:input.capabilityId,mode:'ask'});
  const job=f.store.get('jobs',pending.id);assert.equal((await f.runtime.approve(job.id,job.approvalDigest)).status,'failed');
  const completed=await f.client.callTool({name:'fabric_get_call',arguments:{callId:job.id}});assert.equal(data(completed).status,'failed');assert.equal(completed.isError,true);
  await assert.rejects(readFile(path.join(f.dir,'workspace','policy-blocked.txt')),{code:'ENOENT'});
});

test('real stdio preserves uncertain write and duplicate request never replays it',async t=>{
  const f=await fixture(t),input=f.input('workspace.write.v1',{path:'uncertain.txt',content:'persisted once'},'uncertain-write');
  const pending=data(await invoke(f.client,input));let writes=0;const original=f.local.execute.bind(f.local);
  f.local.execute=async(...args)=>{const result=await original(...args);writes++;return {...result,verification:{...result.verification,status:'failed'}};};
  const job=f.store.get('jobs',pending.id);assert.equal((await f.runtime.approve(job.id,job.approvalDigest)).status,'uncertain');
  const replay=await invoke(f.client,input);assert.equal(data(replay).status,'uncertain');assert.equal(replay.isError,true);assert.equal(data(replay).id,job.id);assert.equal(writes,1);assert.equal(await readFile(path.join(f.dir,'workspace','uncertain.txt'),'utf8'),'persisted once');
});

test('real SDK cancellation does not claim to cancel runtime work or replay it',async t=>{
  const f=await fixture(t);let began,release,finished;const started=new Promise(resolve=>{began=resolve;}),barrier=new Promise(resolve=>{release=resolve;}),done=new Promise(resolve=>{finished=resolve;});
  t.after(()=>release());let executions=0;const original=f.local.execute.bind(f.local);
  f.local.execute=async(...args)=>{executions++;const result=await original(...args);began();await barrier;setImmediate(finished);return result;};
  const controller=new AbortController(),input=f.input('workspace.list.v1',{},'cancelled-delivery');
  const pending=f.client.callTool({name:'fabric_invoke',arguments:input},{signal:controller.signal});await started;controller.abort();await assert.rejects(pending);release();await done;
  assert.equal(executions,1);assert.equal(f.store.list('jobs').length,1);assert.equal(f.store.list('jobs')[0].status,'succeeded');
  assert.equal(data(await invoke(f.client,input)).id,f.store.list('jobs')[0].id);assert.equal(executions,1);
});

test('MCP cancels bounded upstream body consumption and rejects malformed capability projections',async t=>{
  let aborted=false,requests=0;
  const client=await memory(t,{timeoutMs:20,fetch:async()=>{requests++;return new Response(new ReadableStream({cancel(){aborted=true;}}),{headers:{'content-type':'application/json'}});}});
  const interrupted=await client.callTool({name:'fabric_list_capabilities',arguments:{}});assert.equal(data(interrupted).error.code,'request_interrupted');assert.equal(aborted,true);assert.equal(requests,1);
  const invalid=await memory(t,{fetch:async(_url,input)=>response(input,{capabilities:[{id:'operation',connectionId:'connection',definitionHash:'a'.repeat(64),status:'available',inputSchema:null,error:TOKEN}]})});
  const reply=await invalid.callTool({name:'fabric_list_capabilities',arguments:{}});assert.equal(data(reply).error.code,'invalid_response');assert.equal(JSON.stringify(reply).includes(TOKEN),false);
});

test('MCP preserves exact capability schemas with credential-like property names',async t=>{
  const inputSchema={type:'object',properties:{token:{type:'string'},preview:{type:'boolean'},password:{type:'string'},authorization:{type:'string'}},required:['token'],additionalProperties:false};
  const capability={id:'operation',connectionId:'connection',definitionHash:'a'.repeat(64),status:'available',name:'Fixture',description:'Fixture',appId:'workspace',driver:'workspace',inputSchema,effect:'read',approval:'allow'};
  const client=await memory(t,{fetch:async(_url,input)=>response(input,{capabilities:[capability]})});
  const reply=await client.callTool({name:'fabric_list_capabilities',arguments:{}});assert.deepEqual(data(reply).capabilities[0].inputSchema,inputSchema);
  const secretSchema=await memory(t,{fetch:async(_url,input)=>response(input,{capabilities:[{...capability,inputSchema:{type:'object',properties:{value:{type:'string',const:TOKEN}}}}]})});
  const blocked=await secretSchema.callTool({name:'fabric_list_capabilities',arguments:{}});assert.equal(data(blocked).error.code,'invalid_response');assert.equal(JSON.stringify(blocked).includes(TOKEN),false);
});

test('MCP rejects a correlated response for a different account, operation or call',async t=>{
  for(const bad of [{...result,connectionId:'another-account'},{...result,capabilityId:'another-operation'}]) {
    const client=await memory(t,{fetch:async(_url,input)=>response(input,bad)});const reply=await invoke(client);assert.equal(data(reply).error.code,'invalid_response');
  }
  const client=await memory(t,{fetch:async(_url,input)=>response(input,result)});const reply=await client.callTool({name:'fabric_get_call',arguments:{callId:'another-job'}});assert.equal(data(reply).error.code,'invalid_response');
});

// F10.3 (docs/F10.3-BUILD-MAP.md section 4): the adapter needs no change for locked rows or body routes. A bound or request-only
// operation Fabric locks lists as unavailable with permission_denied, and a body a route sends to another row is invalid_request in
// the adapter's own fixed words: the row's name stays with Fabric. The handoff fixture's protocol answers in memory, no socket.
test('MCP lists a locked operation as unavailable and refuses a routed body in its fixed words',async t=>{
  const f=await handoffFixture(t),ISSUE='POST /repos/{owner}/{repo}/issues';
  const rows=change=>{const raw=JSON.parse(JSON.stringify(PERMISSION_GROUPS.get('github'))),groups=new Map([...PERMISSION_GROUPS,['github',validatePermissionGroups({...raw,schemaVersion:2,groups:change(raw.groups)})]]);f.runtime.permissions.groups=groups;f.runtime.proxyPolicy.groups=groups;};
  const adapter=token=>memory(t,{env:{...ENV,FABRIC_CLIENT_TOKEN:token},fetch:async(_url,input)=>new Response(JSON.stringify(await f.protocol.handle(new Headers(input.headers).get('authorization'),JSON.parse(input.body))),{headers:{'content-type':'application/json'}})});
  f.account('acct-a','101');
  const before=f.grant({bindings:[{connectionId:'acct-a',capabilityId:f.write.id}]}),client=await adapter(before.token),hash=before.client.bindings[0].definitionHash;
  const input=(requestId,body,where={connectionId:'acct-a'})=>({requestId,...where,capabilityId:f.write.id,definitionHash:hash,args:{owner:'o',repo:'r',body}});
  rows(groups=>[...groups.filter(group=>group.id!=='github.access.grant').map(group=>({...group,requests:group.requests.filter(request=>request!==ISSUE)})),{id:'github.access.grant',label:'Give access to other people or services',effect:'write',defaultMode:'deny',locked:'fabric',requests:[...(groups.find(group=>group.id==='github.access.grant')?.requests??[]),ISSUE]}]);
  const listed=data(await client.callTool({name:'fabric_list_capabilities',arguments:{}})).capabilities.filter(item=>item.id===f.write.id);
  assert.deepEqual(listed.map(item=>[item.connectionId,item.status,item.reason]),[['acct-a','unavailable','permission_denied'],[null,'unavailable','permission_denied']]);
  for(const where of [{connectionId:'acct-a'},{appId:'github'}])assert.deepEqual(data(await invoke(client,input(`locked-${Object.keys(where)[0]}`,{title:'t'},where))).error,{code:'permission_denied',message:'The owner has not permitted this account and operation.'});
  rows(groups=>groups.map(group=>group.requests.includes(ISSUE)?{...group,bodyRoutes:[{member:ISSUE,pointer:'/title',equals:'delete everything',to:'github.permanent.delete'}]}:group));
  const routed=f.grant({bindings:[{connectionId:'acct-a',capabilityId:f.write.id}]}),other=await adapter(routed.token);
  assert.deepEqual(data(await invoke(other,input('routed',{title:'Delete Everything'}))).error,{code:'invalid_request',message:'Invalid tool arguments. Use the listed schema and bounded JSON inputs.'});
  // Fabric's own answer names the row the body belongs to; only the adapter replaces the words.
  assert.deepEqual((await f.invoke(routed.token,'calls.create',{connectionId:'acct-a',capabilityId:f.write.id,definitionHash:hash,args:{owner:'o',repo:'r',body:{title:'delete everything'}}})).error,
    {code:'invalid_request',message:'This change belongs to "Permanently delete repos, comments, releases and gists". Use that operation instead. Nothing was sent.'});
  assert.equal(data(await invoke(other,input('plain',{title:'t'}))).status,'awaiting_approval','the control: an ordinary body');
  assert.deepEqual([f.jobs().length,f.calls.length],[1,0]);
});

test('MCP cancels a fresh body when cancellation wins the fetch-header race',async t=>{
  let cancelled=0,returned;const ready=new Promise(resolve=>{returned=resolve;}),controller=new AbortController();
  const client=await memory(t,{fetch:async()=>{
    controller.abort();await new Promise(resolve=>setImmediate(resolve));
    const response=new Response(new ReadableStream({cancel(){cancelled++;}}),{headers:{'content-type':'application/json'}});setImmediate(returned);return response;
  }});
  await assert.rejects(client.callTool({name:'fabric_list_capabilities',arguments:{}},{signal:controller.signal}));await ready;
  assert.equal(cancelled,1);
});

test('stdio entry fails closed without echoing invalid environment or arguments',{timeout:5000},async t=>{
  const child=spawn(process.execPath,[ENTRY,TOKEN],{env:{FABRIC_CLIENT_TOKEN:TOKEN,FABRIC_ENDPOINT:`https://example.com/${TOKEN}`},stdio:['pipe','pipe','pipe']});
  t.after(()=>{if(child.exitCode===null)child.kill();});
  let stdout='',stderr='';child.stdout.on('data',chunk=>{stdout+=chunk;});child.stderr.on('data',chunk=>{stderr+=chunk;});
  const [code]=await once(child,'exit');assert.equal(code,1);assert.equal(stdout,'');assert.equal(stderr.includes(TOKEN),false);assert.match(stderr,/Invalid MCP environment/);
});

test('stdio legacy initialize is supported and EOF exits cleanly with protocol-only stdout',{timeout:5000},async t=>{
  const child=spawn(process.execPath,[ENTRY],{env:ENV,stdio:['pipe','pipe','pipe']});
  t.after(()=>{if(child.exitCode===null)child.kill();});
  let stdout='',stderr='';child.stdout.on('data',chunk=>{stdout+=chunk;});child.stderr.on('data',chunk=>{stderr+=chunk;});
  const opened=new Promise(resolve=>child.stdout.once('data',resolve));
  child.stdin.write(JSON.stringify({jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'legacy-fixture',version:'1'}}})+'\n');
  await opened;const exited=once(child,'exit');child.stdin.end();const [code,signal]=await exited;
  assert.equal(code,0);assert.equal(signal,null);const lines=stdout.trim().split('\n').map(line=>JSON.parse(line));assert.equal(lines[0].result.protocolVersion,'2025-11-25');assert.equal(stderr.includes(TOKEN),false);
});

test('stdio rejects an oversized wire buffer before parsing without echoing its contents',{timeout:5000},async t=>{
  const child=spawn(process.execPath,[ENTRY],{env:ENV,stdio:['pipe','pipe','pipe']});t.after(()=>{if(child.exitCode===null)child.kill();});
  let stdout='',stderr='';child.stdout.on('data',chunk=>{stdout+=chunk;});child.stderr.on('data',chunk=>{stderr+=chunk;});child.stdin.on('error',()=>{});
  const exited=once(child,'exit');child.stdin.end(TOKEN+'x'.repeat(128*1024));const [code]=await exited;
  assert.equal(code,0);assert.equal(stdout,'');assert.match(stderr,/transport rejected a message/);assert.equal(stderr.includes(TOKEN),false);
});

test('stdio EOF during an upstream request aborts delivery and exits without retry',{timeout:5000},async t=>{
  let received,closed,requests=0;const started=new Promise(resolve=>{received=resolve;}),disconnected=new Promise(resolve=>{closed=resolve;});
  const server=createHttpServer((req,res)=>{requests++;req.resume();res.once('close',closed);received();});server.listen(0,'127.0.0.1');await once(server,'listening');
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
  const child=spawn(process.execPath,[ENTRY],{env:{...ENV,FABRIC_ENDPOINT:`http://127.0.0.1:${server.address().port}/fabric/v1`},stdio:['pipe','pipe','pipe']});t.after(()=>{if(child.exitCode===null)child.kill();});
  let stdout='',stderr='';child.stdout.on('data',chunk=>{stdout+=chunk;});child.stderr.on('data',chunk=>{stderr+=chunk;});
  const opened=new Promise(resolve=>child.stdout.once('data',resolve));
  child.stdin.write(JSON.stringify({jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'eof-fixture',version:'1'}}})+'\n');await opened;
  child.stdin.write(JSON.stringify({jsonrpc:'2.0',method:'notifications/initialized'})+'\n');
  child.stdin.write(JSON.stringify({jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'fabric_list_capabilities',arguments:{}}})+'\n');await started;
  const exited=once(child,'exit');child.stdin.end();const [code,signal]=await exited;await disconnected;
  assert.equal(code,0);assert.equal(signal,null);assert.equal(requests,1);assert.equal(stdout.trim().split('\n').map(line=>JSON.parse(line)).some(message=>message.id===2),false);assert.equal(stderr.includes(TOKEN),false);
});

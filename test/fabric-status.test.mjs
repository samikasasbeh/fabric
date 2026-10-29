import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {parseStatusArgs,statusEndpoint,readStatus,formatStatus,runStatus,runStatusCLI} from '../scripts/fabric-status.mjs';

// HTTP-shaped dependency fixtures only. No live runtime/account/network access.
const fixture=()=>({product:'Fabric',runtime:{running:true,startedAt:'2026-10-10T01:00:00.000Z',backgroundMode:'while-runtime-running',healthCheck:{enabled:true,intervalSeconds:60,nextRunAt:'2026-10-10T01:01:00.000Z'},browserPollSeconds:30,browserStaleAfterSeconds:90},connections:[{id:'fixture-session',appId:'fixture-app',driver:'browser',status:'session_ready',browserEvidence:{bridge:{status:'alive',lastHeartbeatAt:'2026-10-10T01:00:30.000Z'},account:{status:'unverified',verified:false},page:{status:'not_observed',lastAttempt:null},observedPage:null},lifecycle:{health:{nextRunAt:'2026-10-10T01:01:00.000Z'}}}],discovery:{autonomous:false,applications:[{appId:'fixture-api',discoveredAt:'2026-10-10T00:00:00.000Z',counts:{total:3,candidate:2,unsupported:1}}],capabilityCount:6},execution:{pendingApprovals:1,jobCount:2},agent:{transport:'fabric/0.1',alwaysOnAgent:false,activeClients:0}});
const response=data=>new Response(JSON.stringify(data),{headers:{'Content-Type':'application/json'}});

test('status CLI accepts only the bounded read-only status grammar',()=>{
  assert.deepEqual(parseStatusArgs(['status']),{json:false,watch:false,intervalSeconds:5});
  assert.deepEqual(parseStatusArgs(['status','--json','--watch','--interval','3']),{json:true,watch:true,intervalSeconds:3});
  for(const args of [[],['connect'],['status','--run'],['status','--json','--json'],['status','--interval','2'],['status','--watch','--interval','0'],['status','--watch','--interval','3601'],['status','--watch','--interval','1.2'],['status','--watch','--interval'],['status','anything']])assert.throws(()=>parseStatusArgs(args),/Usage/);
});
test('status endpoint permits explicit loopback only with the fixed status route',()=>{
  assert.equal(statusEndpoint(),'http://127.0.0.1:4188/api/status');
  assert.equal(statusEndpoint('http://127.0.0.1:54123/api/status'),'http://127.0.0.1:54123/api/status');
  for(const url of ['https://example.com','http://localhost:4188','http://127.1:4188','http://2130706433:4188','http://127.0.0.1:4188@evil.example','http://127.0.0.1:4188/api/jobs','http://127.0.0.1:4188/?q=secret','http://127.0.0.1:4188/#x','http://127.0.0.1:0','http://127.0.0.1:65536','file:///tmp/fabric'])assert.throws(()=>statusEndpoint(url),/FABRIC_STATUS_URL/);
});
test('status fetch uses GET only, rejects redirects, and never creates connections or jobs',async()=>{
  const calls=[];
  const snapshot=await readStatus('http://127.0.0.1:4188',{fetchImpl:async(...args)=>{calls.push(args);return response(fixture());},now:()=>0});
  assert.equal(snapshot.online,true);assert.equal(snapshot.checkedAt,'1970-01-01T00:00:00.000Z');assert.equal(calls.length,1);
  assert.equal(calls[0][0],'http://127.0.0.1:4188/api/status');
  assert.equal(calls[0][1].method,'GET');assert.equal(calls[0][1].redirect,'error');assert.equal(calls[0][1].body,undefined);assert.equal(calls[0][1].headers.Authorization,undefined);assert.ok(calls[0][1].signal);
});
test('offline, HTTP error, malformed and oversized responses cannot claim a running runtime',async()=>{
  const cases=[async()=>{throw new Error('secret credential details');},async()=>new Response('redirect',{status:302}),async()=>new Response('not-json',{headers:{'Content-Type':'application/json'}}),async()=>response({product:'Other',runtime:{running:true},connections:[]}),async()=>new Response('x'.repeat(1048577),{headers:{'Content-Type':'application/json'}}),async()=>new Response('<html>login</html>',{headers:{'Content-Type':'text/html'}})];
  for(const fetchImpl of cases){const result=await readStatus('http://127.0.0.1:4188',{fetchImpl});assert.equal(result.online,false);assert.equal(JSON.stringify(result).includes('secret credential'),false);assert.match(formatStatus(result),/OFFLINE/);}
});
test('human output separates heartbeat, account and observation, and describes the actual scheduler',()=>{
  const data=fixture(),snapshot={...data,online:true,checkedAt:'fixture time'};
  let output=formatStatus(snapshot,{watch:true,intervalSeconds:3});
  assert.match(output,/Health scheduler: enabled.*next check/);assert.match(output,/Bridge: alive/);assert.match(output,/Account: unverified · page: not_observed/);assert.match(output,/3 documented · 2 candidates · 1 unsupported/);assert.match(output,/on demand, not autonomous/);assert.match(output,/always-on agent: no/);assert.match(output,/does not install a daemon or run an agent/);
  data.connections[0].browserEvidence.observedPage={observedAt:'fixture read time',origin:'https://fixture.example',title:'Fixture\u001b[2J\nPage'};
  data.connections[0].browserEvidence.page={status:'stale',lastAttempt:{status:'timed_out',at:'fixture failure time'}};
  output=formatStatus(snapshot);assert.match(output,/page: stale/);assert.match(output,/Last read attempt: timed_out/);assert.equal(output.includes('\u001b'),false);assert.equal(output.includes('Fixture\nPage'),false);
});
test('one-shot status JSON returns evidence, offline exits nonzero and bad arguments never fetch',async()=>{
  const out=[],err=[];
  assert.equal(await runStatus({args:['status','--json'],env:{},fetchImpl:async()=>response(fixture()),stdout:s=>out.push(s),stderr:s=>err.push(s)}),0);
  assert.equal(JSON.parse(out[0]).connections[0].browserEvidence.account.verified,false);assert.equal(err.length,0);
  assert.equal(await runStatus({args:['status'],env:{},fetchImpl:async()=>{throw new Error('offline');},stdout:s=>out.push(s)}),1);assert.match(out[1],/OFFLINE/);
  let calls=0;
  assert.equal(await runStatus({args:['status','--delete'],fetchImpl:async()=>{calls++;},stdout:()=>{},stderr:s=>err.push(s)}),2);assert.equal(calls,0);
});
test('watch produces foreground snapshots, recovers from offline, and stops without changing runtime state',async()=>{
  const controller=new AbortController(),out=[],delays=[];let calls=0;
  const code=await runStatus({args:['status','--json','--watch','--interval','2'],env:{},signal:controller.signal,fetchImpl:async()=>{calls++;if(calls===1)throw new Error('offline');return response(fixture());},stdout:s=>out.push(JSON.parse(s)),wait:async ms=>{delays.push(ms);if(calls===2)controller.abort();}});
  assert.equal(code,0);assert.equal(calls,2);assert.deepEqual(delays,[2000,2000]);assert.deepEqual(out.map(item=>item.online),[false,true]);
});
test('aborting an in-flight watch exits quietly without an offline-success claim',async()=>{
  const controller=new AbortController(),out=[];
  const code=await runStatus({args:['status','--watch'],env:{},signal:controller.signal,fetchImpl:async()=>{controller.abort();throw new Error('cancelled');},stdout:s=>out.push(s)});
  assert.equal(code,0);assert.deepEqual(out,[]);
});
test('the existing CLI can delegate status directly without a preceding state request',async()=>{
  const calls=[],out=[];
  assert.equal(await runStatusCLI(['status','--json'],{env:{FABRIC_STATUS_URL:'http://127.0.0.1:54001'},fetchImpl:async(url)=>{calls.push(url);return response(fixture());},stdout:s=>out.push(s)}),0);
  assert.deepEqual(calls,['http://127.0.0.1:54001/api/status']);assert.equal(JSON.parse(out[0]).online,true);
});

// Real subprocess/loopback transport tests, serving only the fixture above.
async function localStatusServer(t) {
  const requests=[];
  const server=createServer((req,res)=>{
    requests.push({method:req.method,url:req.url});
    if(req.method!=='GET'||req.url!=='/api/status'){res.writeHead(404);res.end('Only the status fixture exists.');return;}
    res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify(fixture()));
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  const origin=`http://127.0.0.1:${server.address().port}`;
  const close=async()=>{server.closeAllConnections();await new Promise((resolve,reject)=>server.close(error=>error&&error.code!=='ERR_SERVER_NOT_RUNNING'?reject(error):resolve()));};
  t.after(close);
  return {requests,origin,close};
}
function rootCLI(args,origin,{onOutput}={}) {
  return new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,[fileURLToPath(new URL('../cli.mjs',import.meta.url)),...args],{stdio:['ignore','pipe','pipe'],shell:false,env:{FABRIC_STATUS_URL:origin,FABRIC_URL:origin}});
    let stdout='',stderr='',done=false;
    const finish=(error,result)=>{if(done)return;done=true;clearTimeout(timer);error?reject(error):resolve(result);};
    const timer=setTimeout(()=>{child.kill('SIGKILL');finish(new Error('Isolated status CLI fixture exceeded five seconds.'));},5000);
    child.stdout.setEncoding('utf8');child.stderr.setEncoding('utf8');
    child.stdout.on('data',chunk=>{
      stdout+=chunk;
      if(stdout.length>100000){child.kill('SIGKILL');finish(new Error('Fixture CLI output exceeded its bound.'));return;}
      try{onOutput?.({child,stdout});}catch(error){child.kill('SIGKILL');finish(error);}
    });
    child.stderr.on('data',chunk=>{stderr+=chunk;});
    child.once('error',error=>finish(error));child.once('close',(code,signal)=>finish(null,{code,signal,stdout,stderr}));
  });
}
test('root cli.mjs status --json makes exactly one isolated GET /api/status and never GET /api/state',async t=>{
  const server=await localStatusServer(t),result=await rootCLI(['status','--json'],server.origin);
  assert.equal(result.code,0);assert.equal(result.signal,null);assert.equal(result.stderr,'');
  assert.deepEqual(server.requests,[{method:'GET',url:'/api/status'}]);
  const output=JSON.parse(result.stdout);assert.equal(output.online,true);assert.equal(output.connections[0].browserEvidence.account.verified,false);assert.equal(output.connections[0].browserEvidence.page.status,'not_observed');
});
test('root status CLI exits one when its isolated local runtime is offline',async t=>{
  const server=await localStatusServer(t);await server.close();
  const result=await rootCLI(['status','--json'],server.origin);
  assert.equal(result.code,1);assert.equal(result.signal,null);assert.equal(result.stderr,'');
  const output=JSON.parse(result.stdout);assert.equal(output.online,false);assert.match(output.error,/offline|unreachable/);assert.deepEqual(server.requests,[]);
});
test('root status --watch stops cleanly on SIGINT without changing or stopping its fixture server',async t=>{
  const server=await localStatusServer(t);let interrupted=false;
  const result=await rootCLI(['status','--json','--watch','--interval','1'],server.origin,{onOutput:({child,stdout})=>{if(!interrupted&&stdout.includes('\n')){assert.equal(JSON.parse(stdout.trim().split('\n')[0]).online,true);interrupted=true;child.kill('SIGINT');}}});
  assert.equal(interrupted,true);assert.equal(result.code,0);assert.equal(result.signal,null);assert.equal(result.stderr,'');
  assert.ok(server.requests.length>=1);assert.ok(server.requests.every(request=>request.method==='GET'&&request.url==='/api/status'));
  const response=await fetch(`${server.origin}/api/status`);assert.equal(response.status,200);assert.equal((await response.json()).runtime.running,true);
});

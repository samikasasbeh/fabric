#!/usr/bin/env node
const [command,...args]=process.argv.slice(2);
if(command==='pipeline'){
  const {runIntegrationPipelineCLI}=await import('./scripts/integration-pipeline.mjs');
  process.exitCode=await runIntegrationPipelineCLI(args);
}else if(command==='tenant'){
  // F03.0b: the operator's platform catalog command; never contacts a running runtime.
  const {main}=await import('./scripts/tenant-admin.mjs');
  try{process.stdout.write(`${JSON.stringify(await main(args),null,2)}\n`);}catch(error){process.stderr.write(`${error.message}\n`);process.exitCode=1;}
}else if(command==='status'){
  const {runStatusCLI}=await import('./scripts/fabric-status.mjs');
  const controller=new AbortController(),stop=()=>controller.abort();
  process.once('SIGINT',stop);process.once('SIGTERM',stop);
  try{process.exitCode=await runStatusCLI([command,...args],{signal:controller.signal});}
  catch{process.stderr.write('Fabric status could not complete. No actions were executed.\n');process.exitCode=1;}
  finally{process.removeListener('SIGINT',stop);process.removeListener('SIGTERM',stop);}
}else{
const base=process.env.FABRIC_URL||'http://127.0.0.1:4188';const target=new URL(base);
if(target.protocol!=='http:'||target.hostname!=='127.0.0.1'||target.pathname!=='/'||target.username||target.password) throw new Error('CLI requires an explicit local Fabric URL.');
const response=await fetch(`${base}/api/state`);if(!response.ok) throw new Error(`Fabric unavailable: ${response.status}`);const state=await response.json();const cookie=response.headers.get('set-cookie')?.split(';')[0];
async function post(route,data){const r=await fetch(`${base}${route}`,{method:'POST',headers:{'Content-Type':'application/json','X-Fabric-CSRF':state.csrfToken,Cookie:cookie},body:JSON.stringify(data)});const body=await r.json();if(!r.ok)throw new Error(body.error);return body;}
async function get(route){const r=await fetch(`${base}${route}`,{headers:{Cookie:cookie}});const body=await r.json();if(!r.ok)throw new Error(body.error);return body;}
let result;
switch(command){
case 'catalog':result=state.catalog;break;
case 'search':result=state.catalog.filter(app=>`${app.id} ${app.name} ${app.description||''}`.toLowerCase().includes(args.join(' ').toLowerCase()));break;
case 'discover':if(args.length!==1)throw new Error('Usage: node cli.mjs discover APP_ID');result=await post('/api/discover',{appId:args[0]});break;
case 'describe':if(args.length!==1)throw new Error('Usage: node cli.mjs describe APP_ID');result=await get(`/api/connectors/${encodeURIComponent(args[0])}`);break;
case 'tools':if(!args.length||args.length>2)throw new Error('Usage: node cli.mjs tools APP_ID [CONNECTION_ID]');result=await get(`/api/connectors/${encodeURIComponent(args[0])}/tools${args[1]?`?connectionId=${encodeURIComponent(args[1])}`:''}`);break;
case 'history':if(args.length!==1)throw new Error('Usage: node cli.mjs history APP_ID');result=await get(`/api/connectors/${encodeURIComponent(args[0])}/history`);break;
case 'permission':if(args.length<3||args.length>4||args[3]&&args[3]!=='--review')throw new Error('Usage: node cli.mjs permission CONNECTION_ID CAPABILITY_ID allow|ask|deny [--review]');result=await post(`/api/connections/${encodeURIComponent(args[0])}/permissions`,{capabilityId:args[1],mode:args[2],review:args[3]==='--review'});break;
case 'connections':result=state.connections;break;
case 'capabilities':result=state.capabilities;break;
case 'heartbeats':result=state.heartbeats;break;
case 'jobs':result=state.jobs;break;
case 'run':if(args.length<2)throw new Error('Usage: node cli.mjs run CONNECTION_ID CAPABILITY_ID [ARGUMENTS_JSON]');result=await post('/api/jobs',{connectionId:args[0],capabilityId:args[1],args:JSON.parse(args[2]||'{}')});break;
case 'approve':if(args.length!==2)throw new Error('Usage: node cli.mjs approve JOB_ID EXACT_APPROVAL_DIGEST');result=await post(`/api/jobs/${encodeURIComponent(args[0])}/approve`,{approvalDigest:args[1]});break;
case 'pause':result=await post(`/api/heartbeats/${encodeURIComponent(args[0])}/pause`,{});break;
default:result={product:'Fabric',commands:['status [--json] [--watch] [--interval N]','catalog','search QUERY','discover APP_ID','describe APP_ID','tools APP_ID [CONNECTION_ID]','history APP_ID','permission CONNECTION_ID CAPABILITY_ID allow|ask|deny [--review]','connections','capabilities','heartbeats','jobs','run CONNECTION_ID CAPABILITY_ID [JSON]','approve JOB_ID DIGEST','pause HEARTBEAT_ID'],note:'Ask prepares an exact approval request. Allow is standing consent for this operation/account, including writes. Deny blocks UI, CLI and scheduler alike. --review explicitly promotes a candidate; inspect its definition first.'};
}
console.log(JSON.stringify(result,null,2));
}

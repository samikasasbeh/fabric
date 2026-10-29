import path from 'node:path';
import {fileURLToPath} from 'node:url';

const DEFAULT_ORIGIN='http://127.0.0.1:4188';
const MAX_RESPONSE_BYTES=1_048_576;
const USAGE='Usage: node scripts/fabric-status.mjs status [--json] [--watch] [--interval N]\nN is 1–3600 seconds and requires --watch. This is a read-only local status client, not an installed daemon or autonomous agent.';
const line=value=>String(value??'unknown').replace(/[\u0000-\u001f\u007f-\u009f]/g,' ').slice(0,240);
const count=value=>Number.isSafeInteger(value)&&value>=0?value:0;

export function parseStatusArgs(args) {
  if(!Array.isArray(args)||args[0]!=='status')throw new Error(USAGE);
  const options={json:false,watch:false,intervalSeconds:5},seen=new Set();
  for(let i=1;i<args.length;i++){
    const flag=args[i];
    if(!['--json','--watch','--interval'].includes(flag)||seen.has(flag))throw new Error(USAGE);
    seen.add(flag);
    if(flag==='--interval'){
      const raw=args[++i];
      if(typeof raw!=='string'||!/^\d{1,4}$/.test(raw)||Number(raw)<1||Number(raw)>3600)throw new Error(USAGE);
      options.intervalSeconds=Number(raw);
    }else options[flag.slice(2)]=true;
  }
  if(seen.has('--interval')&&!options.watch)throw new Error(USAGE);
  return options;
}

export function statusEndpoint(value=DEFAULT_ORIGIN) {
  // Explicit IPv4 loopback only: no DNS, credentials, arbitrary routes or query
  // strings. The status command cannot be turned into an external HTTP client.
  if(typeof value!=='string'||!/^http:\/\/127\.0\.0\.1(?::[0-9]{1,5})?(?:\/api\/status|\/)?$/.test(value))throw new Error('FABRIC_STATUS_URL must be an explicit http://127.0.0.1[:port] local Fabric address.');
  let url;try{url=new URL(value);}catch{throw new Error('FABRIC_STATUS_URL has an invalid local port.');}
  if(url.port==='0')throw new Error('FABRIC_STATUS_URL has an invalid local port.');
  return `${url.origin}/api/status`;
}

export async function readStatus(endpoint,{fetchImpl=fetch,signal,now=Date.now}={}) {
  // Validate again for programmatic callers, not just command-line input.
  endpoint=statusEndpoint(endpoint);
  const checkedAt=new Date(now()).toISOString();
  try{
    const response=await fetchImpl(endpoint,{method:'GET',headers:{Accept:'application/json'},redirect:'error',signal:signal?AbortSignal.any([signal,AbortSignal.timeout(5000)]):AbortSignal.timeout(5000)});
    if(!response.ok)return {product:'Fabric',online:false,checkedAt,error:`The local runtime returned HTTP ${response.status}.`};
    if(!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type')||''))return {product:'Fabric',online:false,checkedAt,error:'The local endpoint did not return Fabric status JSON.'};
    const reader=response.body?.getReader();
    if(!reader)throw new Error('Empty response');
    const decoder=new TextDecoder();let bytes=0,text='';
    try{
      for(;;){const {done,value}=await reader.read();if(done)break;bytes+=value.byteLength;if(bytes>MAX_RESPONSE_BYTES){await reader.cancel();return {product:'Fabric',online:false,checkedAt,error:'The local status response exceeded its size limit.'};}text+=decoder.decode(value,{stream:true});}
      text+=decoder.decode();
    }finally{reader.releaseLock();}
    let data;try{data=JSON.parse(text);}catch{return {product:'Fabric',online:false,checkedAt,error:'The local endpoint returned invalid status JSON.'};}
    if(!data||typeof data!=='object'||Array.isArray(data)||data.product!=='Fabric'||typeof data.runtime?.running!=='boolean'||!Array.isArray(data.connections))return {product:'Fabric',online:false,checkedAt,error:'The local endpoint did not return a recognized Fabric status response.'};
    return {...data,online:true,checkedAt};
  }catch{
    if(signal?.aborted)throw signal.reason||new Error('Status watch stopped.');
    return {product:'Fabric',online:false,checkedAt,error:'Fabric is offline or unreachable. Start the local runtime and check its loopback address.'};
  }
}

export function formatStatus(snapshot,{watch=false,intervalSeconds=5}={}) {
  const lines=[`Fabric status · ${line(snapshot.checkedAt)}`];
  if(!snapshot.online)lines.push(`Runtime: OFFLINE · ${line(snapshot.error)}`);
  else{
    const runtime=snapshot.runtime||{},health=runtime.healthCheck||{},discovery=snapshot.discovery||{};
    lines.push(`Runtime: ${runtime.running?'running':'stopped'} · started ${line(runtime.startedAt)}`);
    lines.push('Lifecycle: active only while the local Fabric runtime is running.');
    lines.push(`Health scheduler: ${health.enabled?'enabled':'disabled'} · next check ${line(health.nextRunAt||'none scheduled')} · interval ${health.intervalSeconds?`${count(health.intervalSeconds)}s`:'none'}`);
    lines.push(`Browser helper: polls every ${count(runtime.browserPollSeconds)}s · stale after ${count(runtime.browserStaleAfterSeconds)}s. This is not account verification.`);
    const connections=Array.isArray(snapshot.connections)?snapshot.connections:[];
    lines.push(`Connections: ${connections.length}`);
    for(const connection of connections){
      lines.push(`  ${line(connection.appId)} · route ${line(connection.driver)} · ${line(connection.status)}`);
      if(connection.driver==='browser'){
        const evidence=connection.browserEvidence||{};
        if(connection.transport==='persistent'||connection.lifecycle?.kind==='persistent-browser')lines.push(`    Saved session: ${line(connection.lifecycle?.sessionState||evidence.session?.state||'dormant')} · kept until disconnected · reopens on approved use`);
        else lines.push(`    Bridge: ${line(evidence.bridge?.status||'unknown')} · last heartbeat ${line(evidence.bridge?.lastHeartbeatAt||'not observed')}`);
        // Browser observations are never independent provider identity checks.
        lines.push(`    Account: unverified · page: ${line(evidence.page?.status||'not_observed')}`);
        if(evidence.observedPage)lines.push(`    Last page observation: ${line(evidence.observedPage.observedAt)} · ${line(evidence.observedPage.origin)} · ${line(evidence.observedPage.title||'untitled')}`);
        if(evidence.page?.lastAttempt)lines.push(`    Last read attempt: ${line(evidence.page.lastAttempt.status)} · ${line(evidence.page.lastAttempt.at)}`);
      }
      const lifecycle=connection.lifecycle||{};
      if(lifecycle.expiresAt)lines.push(`    Credential expiry: ${line(lifecycle.expiresAt)} · refresh available: ${lifecycle.refreshAvailable?'yes':'no'}`);
      if(lifecycle.health)lines.push(`    Next connection check: ${line(lifecycle.health.nextRunAt||'none scheduled')}`);
    }
    const apps=Array.isArray(discovery.applications)?discovery.applications:[];
    lines.push(`Discovery: ${apps.length} inspected interfaces · ${count(discovery.capabilityCount)} capability definitions · ${discovery.autonomous?'autonomous enabled':'on demand, not autonomous'}`);
    for(const app of apps)lines.push(`  ${line(app.appId)} · ${count(app.counts?.total)} documented · ${count(app.counts?.candidate)} candidates · ${count(app.counts?.unsupported)} unsupported · checked ${line(app.discoveredAt)}`);
    lines.push(`Execution: ${count(snapshot.execution?.jobCount)} recorded jobs · ${count(snapshot.execution?.pendingApprovals)} awaiting approval.`);
    lines.push(`Agent interface: ${line(snapshot.agent?.transport)} · ${count(snapshot.agent?.activeClients)} active client grants · always-on agent: ${snapshot.agent?.alwaysOnAgent?'yes':'no'}.`);
  }
  if(watch)lines.push(`Foreground status watch: checking every ${intervalSeconds}s. Ctrl-C stops this watcher; it does not stop Fabric. Observer, not an always-on agent. This does not install a daemon or run an agent.`);
  return lines.join('\n');
}

function waitForPoll(ms,signal) {
  return new Promise(resolve=>{
    if(signal?.aborted){resolve();return;}
    const finish=()=>{clearTimeout(timer);signal?.removeEventListener('abort',finish);resolve();};
    const timer=setTimeout(finish,ms);signal?.addEventListener('abort',finish,{once:true});
  });
}

export async function runStatus({args=process.argv.slice(2),env=process.env,fetchImpl=fetch,signal,wait=waitForPoll,stdout=value=>process.stdout.write(`${value}\n`),stderr=value=>process.stderr.write(`${value}\n`)}={}) {
  let options,endpoint;
  try{options=parseStatusArgs(args);endpoint=statusEndpoint(env.FABRIC_STATUS_URL??DEFAULT_ORIGIN);}
  catch(error){stderr(error.message);return 2;}
  for(;;){
    if(signal?.aborted)return 0;
    let snapshot;
    try{snapshot=await readStatus(endpoint,{fetchImpl,signal});}
    catch(error){if(signal?.aborted)return 0;throw error;}
    stdout(options.json?JSON.stringify(snapshot):formatStatus(snapshot,options));
    if(!options.watch)return snapshot.online?0:1;
    await wait(options.intervalSeconds*1000,signal);
  }
}

// cli.mjs passes its complete command arguments, including the leading "status".
export function runStatusCLI(args,deps={}) {return runStatus({...deps,args});}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const controller=new AbortController(),stop=()=>controller.abort();
  process.once('SIGINT',stop);process.once('SIGTERM',stop);
  try{process.exitCode=await runStatus({signal:controller.signal});}
  catch{process.stderr.write('Fabric status could not complete. No actions were executed.\n');process.exitCode=1;}
  finally{process.removeListener('SIGINT',stop);process.removeListener('SIGTERM',stop);}
}

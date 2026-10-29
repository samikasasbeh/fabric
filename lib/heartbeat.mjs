import {randomUUID} from 'node:crypto';
import {canonicalHash} from './compiler.mjs';
import {backgroundAllowed} from './app-detail.mjs';

/** F10.11 (part d): an action never runs unattended; a trigger, not a heartbeat, will watch for changes. */
const ACTION_WORDS='Actions run only when asked. Watching for changes comes with triggers.';

export class HeartbeatScheduler {
  constructor({store,runtime,checkConnection,clock=Date.now}) { Object.assign(this,{store,runtime,checkConnection,clock}); this.busy=false; }
  create(data,principal) {
    if(this.store.authorityEnabled){canonicalHash(data);if(Object.keys(data).some(key=>!['name','intervalSeconds','connectionId','capabilityId','args'].includes(key)))throw new Error('Unexpected heartbeat input fields.');}
    const {name,intervalSeconds=60,connectionId,capabilityId,args={}}=structuredClone(data);
    let permissionBindingHash=null;
    let authority=null;
    if(typeof name!=='string'||!name.trim()||name.length>120) throw new Error('Heartbeat needs a name up to 120 characters.');
    if(!Number.isInteger(intervalSeconds)||intervalSeconds<30||intervalSeconds>86400) throw new Error('Heartbeat interval must be 30–86400 seconds.');
    if(connectionId&&!this.store.get('connections',connectionId)) throw new Error('Connection not found.');
    if(capabilityId) {
      const cap=this.store.get('capabilities',capabilityId);
      // F10.11 (part d): checked before effectOf(), which reads a read action as read.
      if(cap?.driver==='action') throw new Error(ACTION_WORDS);
      if(!cap||cap.status!=='active'||this.runtime.effectOf(cap)!=='read') throw new Error('Only active read-only capabilities can run unattended in v0.1.');
      if(cap.driver==='browser') throw new Error('Browser account identity is not independently bound. Browser operations require an interactive request, not a heartbeat.');
      if(!connectionId) throw new Error('Choose a connection for this capability.');
      if(!backgroundAllowed(this.store,connectionId)) throw new Error('Background actions are turned off for this account.');
      const {permission}=this.runtime.validateJob({capabilityId,connectionId,args});
      if(permission.mode!=='allow'||!permission.executable) throw new Error('A heartbeat requires an allowed operation with sufficient provider access. Ask and Deny cannot run unattended.');
      permissionBindingHash=permission.bindingHash;
      if(this.store.authorityEnabled)authority={principal:this.runtime.assertOwner(principal),connectionGeneration:permission.connectionGeneration,policyRevision:permission.policyRevision};
    }
    const now=this.clock();
    const heartbeat={id:randomUUID(),name:name.trim(),intervalSeconds,connectionId:connectionId||null,capabilityId:capabilityId||null,permissionBindingHash,args,...(authority?{authority}:{}),enabled:true,nextRunAt:new Date(now+intervalSeconds*1000).toISOString(),lastRunAt:null,lastResult:null,runs:0,createdAt:new Date(now).toISOString()};
    this.store.put('heartbeats',heartbeat); this.store.audit({type:'heartbeat.created',heartbeatId:heartbeat.id}); return heartbeat;
  }
  setEnabled(id,enabled) {const h=this.store.get('heartbeats',id); if(!h) throw new Error('Heartbeat not found.'); h.enabled=enabled; if(enabled) h.nextRunAt=new Date(this.clock()+h.intervalSeconds*1000).toISOString();this.store.put('heartbeats',h);this.store.audit({type:enabled?'heartbeat.resumed':'heartbeat.paused',heartbeatId:id});return h;}
  assertJobAuthority(job) {
    if(!this.store.authorityEnabled)return;
    const h=this.store.get('heartbeats',job.source?.heartbeatId);
    if(!h?.enabled||!h.authority||h.connectionId!==job.connectionId||h.capabilityId!==job.capabilityId||canonicalHash(h.args)!==canonicalHash(job.args))throw new Error('Scheduled authorization is missing or changed. Create a new heartbeat.');
    if(!backgroundAllowed(this.store,job.connectionId))throw new Error('Background actions are turned off for this account.');
    this.runtime.assertOwner(h.authority.principal);
    const {permission}=this.runtime.validateJob(job);
    if(permission.mode!=='allow'||permission.bindingHash!==h.permissionBindingHash||permission.connectionGeneration!==h.authority.connectionGeneration||permission.policyRevision!==h.authority.policyRevision||canonicalHash(job.executionRequest?.principal)!==canonicalHash(h.authority.principal))throw new Error('Scheduled authority changed. Create a new heartbeat after review.');
  }
  async tick() {
    if(this.busy) return; this.busy=true;
    try {
      for(const h of this.store.list('heartbeats')) {
        if(!h.enabled||Date.parse(h.nextRunAt)>this.clock()) continue;
        // Advance durably before dispatch. After sleep/restart coalesce missed ticks,
        // never replay a burst of old work. Only read operations may be scheduled.
        const now=this.clock();h.lastRunAt=new Date(now).toISOString();h.nextRunAt=new Date(now+h.intervalSeconds*1000).toISOString();h.runs++;h.lastResult={status:'running'};this.store.put('heartbeats',h);
        try {
          if(h.capabilityId) {
            const currentCap=this.store.get('capabilities',h.capabilityId);
            if(currentCap?.driver==='action') throw new Error(ACTION_WORDS);
            if(!currentCap||currentCap.driver==='browser'||this.runtime.effectOf(currentCap)!=='read') throw new Error('Scheduled capability no longer qualifies for unattended reads.');
            if(!backgroundAllowed(this.store,h.connectionId)) throw new Error('Background actions are turned off for this account. Nothing ran.');
            const {permission}=this.runtime.validateJob({connectionId:h.connectionId,capabilityId:h.capabilityId,args:h.args});
            if(permission.mode!=='allow'||!permission.executable) throw new Error('The scheduled operation now requires approval or is denied. No unattended request was dispatched.');
            if(!h.permissionBindingHash||permission.bindingHash!==h.permissionBindingHash) throw new Error('Scheduled account authorization or operation definition changed. Create a new heartbeat after review.');
            if(this.store.authorityEnabled){
              if(!h.authority)throw new Error('Historical schedule has no accepted authority. Create a new heartbeat.');
              this.runtime.assertOwner(h.authority.principal);
              if(permission.connectionGeneration!==h.authority.connectionGeneration||permission.policyRevision!==h.authority.policyRevision)throw new Error('Scheduled authority changed. Create a new heartbeat after review.');
            }
            const job=await this.runtime.createJob({connectionId:h.connectionId,capabilityId:h.capabilityId,args:h.args,source:{heartbeatId:h.id}},h.authority?.principal);
            h.lastResult={status:job.status,jobId:job.id,error:job.error||null};
          } else {
            const targets=h.connectionId?[this.store.get('connections',h.connectionId)]:this.store.list('connections').filter(c=>c.status!=='revoked');
            const states=[];for(const c of targets) {try {const checked=await this.checkConnection(c.id);states.push({id:c.id,status:checked.status});}catch {states.push({id:c.id,status:'unavailable'});}}
            h.lastResult={status:states.some(c=>!['ready','session_ready'].includes(c.status))?'attention':'succeeded',connections:states,message:states.length?'Connection health checked.':'Scheduler awake; no accounts connected.'};
          }
        } catch(error) {h.lastResult={status:'failed',error:error.message};}
        // Do not undo a pause received during an asynchronous provider call.
        const current=this.store.get('heartbeats',h.id);h.enabled=current?.enabled??false;
        this.store.put('heartbeats',h);this.store.audit({type:'heartbeat.ticked',heartbeatId:h.id,status:h.lastResult.status,run:h.runs});
      }
    } finally {this.busy=false;}
  }
  start() {this.timer=setInterval(()=>this.tick().catch(()=>{}),1000);this.timer.unref();this.tick().catch(()=>{});}
  stop() {clearInterval(this.timer);}
}

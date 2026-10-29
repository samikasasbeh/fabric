import {randomUUID} from 'node:crypto';
import {LOCAL_DEPLOYMENT,endUser,ownedBy,ownershipOf,stampOwner} from './tenant/deployment.mjs';
import {withoutHidden} from '../public/hosted-text.js';
import {canonicalHash,validateInput,validateCapability,prepareRequest,prepareVerification} from './compiler.mjs';
import {safeRequest} from './network.mjs';
import {credentialValues,secretContext,scrubString,scrubValue} from './redaction.mjs';
import {credentialLocations} from './openapi-security.mjs';
import {PermissionManager,sameRoute,capabilityPermissionHash,permissionEffect,ACTION_WORDS} from './permissions.mjs';
import {validateDeviceCapability} from './device-driver.mjs';
import {checkedClock} from '../contracts/repository.mts';
import {validatePrincipal} from '../contracts/identity.mts';
import {validateExecutionRequest,hashExecutionRequest,bindingForRequest,validateApproval,assertDispatchable} from '../contracts/execution.mts';
import {ProxyPolicy} from './proxy-policy.mjs';
import {routedWords} from './row-locks.mjs';
import {prepareProxyJob,proxyAuthority,assertProxyAuthorization,executeProxy,proxyResponseBody,uncertainRows,sweepBodies} from './proxy-runtime.mjs';
import {sweepResults} from './retention.mjs';
import {checkDistribution} from './slack-limits.mjs';

/** An error carrying a stable code beside its words; the words stay exactly as before. */
const coded=(code,message,extra={})=>Object.assign(new Error(message),{code,...extra});
// Provider answers that mean the request was refused and changed nothing (as in the governed proxy's outcome table).
const CLIENT_ERRORS=new Set([400,401,403,404,405,406,410,411,412,413,414,415,416,417,422,428,431]);

function pointer(value,p) {
  if(p==='') return value;
  if(typeof p!=='string'||!p.startsWith('/')) throw new Error('Invalid verification pointer.');
  return p.slice(1).split('/').reduce((v,k)=>Object.hasOwn(v??{},k.replace(/~1/g,'/').replace(/~0/g,'~'))?v[k.replace(/~1/g,'/').replace(/~0/g,'~')]:undefined,value);
}

/** An agent's optional task title: one line of plain text, at most 120 characters. */
export function taskTitle(task) {
  if(task===undefined||task===null) return null;
  if(typeof task!=='object'||Array.isArray(task)||Object.keys(task).join()!=='title'||typeof task.title!=='string') {const error=new Error('A task is {title} with a short plain-text title.');error.code='invalid_request';throw error;}
  const title=withoutHidden(task.title.replace(/[\t\n\r]/g,' ')).replace(/\s+/g,' ').trim();
  if(!title||title.length>120) {const error=new Error('A task title is 1 to 120 characters.');error.code='invalid_request';throw error;}
  return title;
}

// F10.17: the wait seam of write spacing (lib/write-spacing.mjs): a real timer here; tests pass one that moves their fake clock.
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));

/** F10.21 (lib/retention.mjs): deletes what an app with a shorter retention returned once it expired: proxied bodies and action results. */
export function sweepRetention(store,now) {sweepBodies(store,now);sweepResults(store,now);}

export class Runtime {
  constructor({store,connections,local,browser,persistentBrowser,device,request=safeRequest,permissions=new PermissionManager({store,scopesOf:connection=>connections?.effectiveScopes?.(connection)}),proxyPolicy,actions,authorizeSource,ownerPrincipal,clock=Date.now,wait=sleep,slackDistribution='internal',deployment=LOCAL_DEPLOYMENT,certification=false}) {
    // F10.21 (lib/slack-limits.mjs): how Fabric's Slack app is installed, read once by the server; under distributed Slack paces history and
    // replies, and the minute each workspace's method last went is kept here, in memory, as the write locks are.
    this.slackDistribution=checkDistribution(slackDistribution);this.slackPace=new Map();
    Object.assign(this,{store,connections,local,browser,persistentBrowser,device,request,permissions,authorizeSource,deployment,wait});
    this.proxyPolicy=proxyPolicy||new ProxyPolicy({store,permissions,rowFloor:deployment?.kind==='tenant'});this.clock=checkedClock(clock);this.running=new Set();this.writeLocks=new Set();
    // F10.11 part e: the action catalog is injected, never imported (part p loads it). Every action decision reads it and the proxy's rows,
    // so the permission manager holds both; with no catalog every action is unsupported and never runs.
    this.actions=actions??permissions.actions??null;permissions.actions=this.actions;permissions.proxy=this.proxyPolicy;
    // F10.12: only a certification Fabric (server.mjs createApp() with its guard) runs a placed, pinned candidate action, at Ask only.
    permissions.certification=certification===true;
    this.ownerPrincipal=store.authorityEnabled?validatePrincipal(ownerPrincipal):null;
    if(this.ownerPrincipal&&this.ownerPrincipal.kind!=='local_owner') throw new Error('A trusted local deployment owner is required.');
    if(store.authorityEnabled&&store.scope&&canonicalHash(store.scope)!==canonicalHash(this.ownerPrincipal.scope)) throw new Error('Deployment owner and repository scope differ.');
    this.authorizeSource=authorizeSource||((job)=>{if(store.authorityEnabled&&(job.source?.kind==='client'||job.source?.heartbeatId))throw new Error('Delegated or scheduled execution requires a current authorization resolver.');});
  }
  now() {return new Date(this.clock()).toISOString();}
  /** F03.2: in a developer environment every job belongs to one end user, given as {kind:'product_user',subjectId,userRecordId}. */
  tenantOwner(principal) {
    if(this.deployment.kind!=='tenant') return null;
    if(principal?.kind!=='product_user') throw Object.assign(new Error('An end user is required in a developer environment.'),{code:'invalid_request'});
    return endUser(principal);
  }
  /** A refusal's words, with a stable code beside them in a developer environment; the single-owner runtime's errors are unchanged (section 4.4). */
  refusal(code,message) {const error=new Error(message);if(this.deployment.kind==='tenant')error.code=code;return error;}
  /** Another user's job or account looks exactly like one that does not exist. */
  notFound() {return Object.assign(new Error('Nothing with that id exists here.'),{code:'not_found',httpStatus:404});}
  /** The caller's own jobs in a developer environment; every job in the single-owner runtime. */
  jobsOf(owner) {return this.store.list('jobs').filter(job=>ownedBy(job,owner,this.deployment));}
  recover() {
    for(const job of this.store.list('jobs')) if(['running','queued'].includes(job.status)) {
      job.status='uncertain';job.error='Runtime restarted before completion was recorded. No automatic replay was attempted.';job.updatedAt=this.now();
      if(job.kind==='proxy') {job.errorCode='outcome_uncertain';job.reason='restarted';}
      // F10.11 part i: an action job knows whether it sent a write: with none sent it failed, with one sent it is uncertain.
      if(job.kind==='action') {
        const sent=Array.isArray(job.action?.writesSent)&&job.action.writesSent.length>0;
        Object.assign(job,sent?{status:'uncertain',errorCode:'outcome_uncertain',error:'Fabric restarted after a change was sent. Its outcome is uncertain: check it before trying again.'}
          :{status:'failed',errorCode:'fabric_failed',error:'Fabric restarted before this finished. Nothing was sent.'},{reason:'restarted',result:null});
      }
      this.store.put('jobs',job);
    }
    this.sweepPrepared();
    this.sweepRetention();
    // F10.7 (decision 6): saved settings from before a row split keep their Never (lib/permissions.mjs migrateSplitRows()).
    this.permissions.migrateSplitRows();
  }
  /** F10.11 part h: prepared action bytes live only while their job waits for an approval that can still be given, or is queued or running
   *  on one. Swept at start (when no job is queued or running any more) and whenever an action job is accepted, so a stop nobody decided
   *  in time keeps nothing; there is no timer. */
  sweepPrepared() {
    for(const row of this.store.list('actionPrepared')) {
      const job=this.store.get('jobs',row.id),live=job?.status==='awaiting_approval'?Date.parse(job.approvalExpiresAt)>this.clock():['queued','running'].includes(job?.status);
      if(!live) this.store.delete('actionPrepared',row.id);
    }
  }
  /** F10.21: run at start, on every job acceptance and every minute while a Fabric runs (server.mjs, developer-server.mjs). */
  sweepRetention() {sweepRetention(this.store,this.clock());}
  effectOf(cap) {
    if(cap.driver==='http') return ['GET','HEAD'].includes(cap.request?.method?.toUpperCase())?'read':'write';
    if(cap.driver==='workspace') return cap.action?.op==='write'?'write':'read';
    if(cap.driver==='browser') return ['observe','read'].includes(cap.action?.op)?'read':'write';
    if(cap.driver==='device') return 'read';
    // F10.11 part h: an action's effect is its validated entry's, never a method; a delete takes the write lock like a write.
    if(cap.driver==='action') {
      const entry=this.actions?.entryOf?.(cap)?.entry;
      if(!entry) throw coded('capability_changed',this.actions?ACTION_WORDS.changed:ACTION_WORDS.unsupported);
      if(entry.unplaced) throw coded('capability_changed',ACTION_WORDS.unplaced);
      if(entry.effect!==cap.effect) throw coded('capability_changed',ACTION_WORDS.changed);
      return entry.effect;
    }
    throw new Error('Unsupported execution driver.');
  }
  /** F10.11 part h: an action's catalog item, only while it is current, placed and its transforms still have their pinned code. */
  actionItem(cap) {
    const item=this.actions?.entryOf?.(cap);
    if(!item) throw coded('capability_changed',this.actions?ACTION_WORDS.changed:ACTION_WORDS.unsupported);
    if(item.entry.unplaced) throw coded('capability_changed',ACTION_WORDS.unplaced);
    if(!this.actions.pinned(item)) throw coded('capability_changed','The code of a transform this action runs changed since it was pinned, so it cannot run.');
    return item;
  }
  /** F09.1: a capability stored before the credential guards must not take the account's API key as an input. Its
   *  source document (the import surface, or the discovery source of the map that lists it) names those locations. */
  assertNoDeclaredCredentialInputs(cap) {
    if(cap.provenance?.kind!=='openapi') return;
    // Sources are content-addressed, so a cached answer never goes stale; the cache is checked before any store read.
    const cache=this.credentialLocationCache||=new Map(),remember=(key,value)=>{if(cache.size>=64)cache.delete(cache.keys().next().value);cache.set(key,value);return value;};
    const surfaceKey=`surface:${cap.appId}:${cap.provenance.fingerprint}`;
    let locations=cache.get(surfaceKey);
    if(locations===undefined) {const surface=this.store.get('surfaces',`${cap.appId}:${cap.provenance.fingerprint}`);locations=remember(surfaceKey,surface?credentialLocations(surface.document):null);}
    if(locations===null) {
      const map=this.store.get('applicationMaps',cap.appId);
      if(!Array.isArray(map?.operations)||!map.operations.some(op=>op&&op.capabilityId===cap.id)||typeof map.fingerprint!=='string') return;
      const sourceKey=`source:${cap.appId}:${map.fingerprint}`;
      locations=cache.get(sourceKey)??remember(sourceKey,credentialLocations(this.store.get('discoverySources',`${cap.appId}:${map.fingerprint}`)?.document));
    }
    for(const [where,names] of [['path',cap.request.pathParameters||[]],['query',cap.request.queryParameters||[]]]) for(const name of names) {
      if(locations.has(`${where}:${String(name).toLowerCase()}`)) throw new Error(`This operation takes the account's API key (${where} parameter ${name}) as an input; credentials come only from the connection. Import or discover the description again.`);
    }
  }
  validateJob(input,{uncertainRows:c7=null}={}) {
    const {connectionId,capabilityId,args={}}=input;
    const cap=this.store.get('capabilities',capabilityId);const connection=this.store.get('connections',connectionId);
    // A stored job is re-checked against its account's owner at every dispatch; in a developer environment a stored job
    // without both owner ids fails closed.
    if(this.deployment.kind==='tenant'&&(input.id!==undefined||input.userRecordId!==undefined)) {
      let stored;try {stored=ownershipOf(input,this.deployment);} catch {throw this.notFound();}
      if(!ownedBy(connection,stored,this.deployment)) throw this.notFound();
    }
    if(!cap||(cap.status!=='active'&&!this.permissions.certifying(cap))) throw this.refusal('capability_changed','Select a reviewed, active capability.');
    if(this.store.authorityEnabled&&cap.driver==='browser') throw new Error('Browser authority provenance is not implemented in this isolated execution mode.');
    if(!connection||!['ready','session_ready'].includes(connection.status)) throw this.refusal('connection_required','Connection is not ready. Check or reconnect it first.');
    if(!sameRoute(connection,cap)) throw new Error('Capability does not belong to this application and connection route.');
    // F10.11 part h: an action runs only from its current, placed catalog entry; its inputs that depend on a resource are checked once read.
    const item=cap.driver==='action'?this.actionItem(cap):null;
    try {if(item) this.actions.staticInputs(item.entry,args);else validateInput(cap.inputSchema,args);} catch(error) {if(this.deployment.kind==='tenant')error.code??='invalid_arguments';throw error;}
    if(cap.driver==='http') {
      // A capability made before F09.1 can take a credential as input; say how to replace it rather than only refusing.
      try {validateCapability(cap);} catch(error) {if(/credential/.test(error.message)) throw new Error(`This operation was made by older rules and takes a credential as an input; discover or import the app again. (${error.message})`);throw error;}
      this.assertNoDeclaredCredentialInputs(cap);
    }
    if(cap.driver==='workspace'&&!['list','read','write'].includes(cap.action?.op)) throw new Error('Unsupported workspace operation.');
    if(cap.driver==='browser'&&!['observe','read','click','fill'].includes(cap.action?.op)) throw new Error('Unsupported browser operation.');
    if(connection.transport==='persistent'&&!['observe','read'].includes(cap.action?.op)) throw new Error('Saved browser sessions currently support approved reads only.');
    if(cap.driver==='device') validateDeviceCapability(cap);
    // F10.3: a typed body that a route of its operation sends to a stricter row is refused in every deployment, never moved there:
    // the owner set this operation, not that row. Checked before any preview or request, and again before every send.
    const routed=this.permissions.routedBody(cap,args);
    if(routed) throw coded('invalid_request',routedWords(routed),{details:{routedTo:{groupId:routed.groupId,label:routed.label}}});
    const permission=this.permissions.decision(connection,cap,undefined,item&&c7?{uncertainRows:c7}:{});
    // T4: a lock's refusal keeps its code in every deployment, so each surface can say why (F10.3); so does a member that can never
    // work through a sign-in (F10.6, T3).
    if(!permission.executable) throw permission.locked?coded('permission_denied',permission.reason,{locked:true}):permission.providerAccess==='unavailable'?coded('permission_denied',permission.reason,{unavailable:true}):this.refusal('permission_denied',permission.reason);
    return {cap,connection,effect:this.effectOf(cap),permission};
  }
  assertOwner(principal) {
    const actor=validatePrincipal(principal);
    if(!this.ownerPrincipal||canonicalHash(actor)!==canonicalHash(this.ownerPrincipal)) throw new Error('The exact configured local owner is required.');
    return actor;
  }
  acceptedPrincipal(principal,source) {
    const actor=validatePrincipal(principal);
    if(actor.kind==='local_owner') {
      this.assertOwner(actor);
      if(source.kind==='client') throw new Error('A client request cannot impersonate the local owner.');
    } else if(actor.kind!=='local_client'||canonicalHash(actor.scope)!==canonicalHash(this.ownerPrincipal.scope)||actor.delegatedBy.id!==this.ownerPrincipal.id||source.kind!=='client'||source.clientId!==actor.id) {
      throw new Error('A current local owner or authenticated delegated client is required.');
    }
    return actor;
  }
  capabilityReference(cap) {return {appId:cap.appId,id:cap.id,version:cap.version,definitionHash:capabilityPermissionHash(cap),effect:permissionEffect(cap)};}
  /** A governed proxy request (F08.0): decided per row, approved like any job, and sent exactly as previewed. */
  async createProxyJob(data,principal,{task}={}) {
    const job=this.prepareProxy(data,principal,{task});
    return job.status==='queued'?this.execute(job.id):job;
  }
  /** A proxy job's stored response body while it is kept ({body} or {text}), or null. */
  proxyResponse(job) {return proxyResponseBody(this,job);}
  /** Accepts a proxy request as a job without sending it (the protocol links its reservation first). */
  prepareProxy(data,principal,{task}={}) {
    // F03.7: in a developer environment the end user must own the account before anything is decided (N2, N3).
    const owner=this.tenantOwner(principal);
    if(owner&&!ownedBy(this.store.get('connections',data?.connectionId),owner,this.deployment)) throw this.notFound();
    this.sweepRetention();
    return prepareProxyJob(this,data,principal,{title:taskTitle(task),owner});
  }
  /** Accepts a job and runs it when it may run now. `accepted(job)`, trusted in-process input only, runs once the job is stored and before
   *  anything is sent: fabric/0.1 links its request's reservation there (F10.11 part l), so a crash mid-sequence replays the job's real status. */
  async createJob(data,principal,{accepted,...options}={}) {
    const job=await this.prepareJob(data,principal,options);
    accepted?.(job);
    return job.status==='queued'?this.execute(job.id):job;
  }
  // Builds and persists an accepted job without dispatching it. The third argument is
  // trusted in-process input only (the continuation service pre-generates the id so its
  // authorization can name exactly one job); no HTTP or protocol path can supply it.
  async prepareJob(data,principal,{jobId,task}={}) {
    const title=taskTitle(task);
    if(jobId!==undefined&&(typeof jobId!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(jobId)||this.store.get('jobs',jobId))) throw new Error('A fresh trusted job id is required.');
    // Validate and detach before an awaited preview can let a caller change input.
    if(this.store.authorityEnabled) {
      canonicalHash(data);
      if(Object.keys(data).some(key=>!['connectionId','capabilityId','args','source'].includes(key))) throw new Error('Unexpected execution input fields.');
    }
    const owner=this.tenantOwner(principal);
    // F10.21 (lib/retention.mjs): every acceptance first deletes what an app with a shorter retention returned, once it expired.
    this.sweepRetention();
    const {connectionId,capabilityId,args={},source={kind:'user'}}=structuredClone(data);
    if(owner&&!ownedBy(this.store.get('connections',connectionId),owner,this.deployment)) throw this.notFound();
    // F10.11 part h: c7 for an action is read once, here, from every proxy and action job of the account.
    const isAction=this.store.get('capabilities',capabilityId)?.driver==='action';
    const {cap,connection,effect,permission}=this.validateJob({connectionId,capabilityId,args},isAction?{uncertainRows:uncertainRows(this.store,connectionId,this.clock())}:{});
    if(cap.driver==='browser'&&effect==='write'&&
       (!['user','client'].includes(source.kind)||!permission.requiresApproval)) throw new Error('Browser interactions require an interactive, exact-action approval.');
    const job={id:jobId??randomUUID(),...(cap.driver==='action'?{kind:'action'}:{}),connectionId,capabilityId,args:structuredClone(args),source,effect,capabilityHash:canonicalHash(cap),identityHash:canonicalHash(connection.identity||{}),connectionBindingHash:permission.bindingHash,permissionHash:permission.policyHash,permissionMode:permission.mode,status:permission.requiresApproval?'awaiting_approval':'queued',createdAt:this.now(),updatedAt:this.now(),result:null,error:null};
    if(this.store.authorityEnabled) {
      const actor=this.acceptedPrincipal(principal,source);
      job.executionRequest=validateExecutionRequest({schemaVersion:1,id:job.id,scope:actor.scope,principal:actor,
        access:{kind:'connection',id:connectionId,generation:permission.connectionGeneration},capability:this.capabilityReference(cap),args:job.args,
        // F10.11 part h (open question 5): an action job may stop twice, so its deadline is 25 minutes; each stop's window is 10.
        policyRevision:permission.policyRevision,idempotencyKey:source.requestId||job.id,createdAt:job.createdAt,deadline:new Date(Date.parse(job.createdAt)+(cap.driver==='action'?25:10)*60_000).toISOString()});
      job.executionRequestHash=hashExecutionRequest(job.executionRequest);
    }
    // What the agent says this call is for, shown in the owner's activity. Display only: never authority.
    if(title) job.task={title};
    job.preview={application:cap.appId,account:connection.identity||{displayName:connection.label},operation:cap.name,effect,arguments:job.args,permissionMode:permission.mode,providerAccess:permission.providerAccess};
    // F10.3 (T4): Fabric's fixed warning on a call that reaches other people. The preview is not in the digest.
    if(permission.audience) job.preview.warnings=['reaches_people'];
    if(cap.driver==='browser'&&effect==='write') job.preview.browserTarget=this.browserTarget(job,connection,cap);
    if(cap.driver==='http') {
      // A path value the request builder refuses (such as '..' or one holding '/') is the caller's input, coded in tenants.
      let req;try{req=prepareRequest(cap,args);}catch(error){if(this.deployment.kind==='tenant') throw this.refusal('invalid_arguments','The arguments did not match the operation.');throw error;}
      job.preview.request={method:req.method,url:req.url,body:req.body};
    }
    if(cap.driver==='workspace'&&effect==='write') {job.precondition=await this.local.snapshot(args.path);job.preview.existingFile=job.precondition;}
    // F10.11 part h: the job carries its end user before anything is prepared for it, so an action's prepared row is stamped with them too.
    if(owner) Object.assign(job,stampOwner({},owner));
    // F10.11 part h: an action is decided with no network call; a job that waits for its reads keeps them beside it, never in itself.
    // Accepting one first sweeps the prepared bytes of stops nobody decided in time.
    let prepared=null;
    if(cap.driver==='action') {this.sweepPrepared();prepared=this.actions.acceptAction(this,{job,cap,connection,permission,owner});}
    else if(effect!=='read'||permission.requiresApproval) {
      job.approvalExpiresAt=job.executionRequest?.deadline||new Date(this.clock()+10*60_000).toISOString();job.approvalDigest=this.digest(job);
      if(permission.mode==='allow') {job.approvedAt=this.now();job.approvedBy='standing-policy';}
    }
    if(this.store.authorityEnabled) this.assertAcceptedAuthority(job);else this.authorizeSource(job);
    this.store.put('jobs',job);if(prepared) this.store.put('actionPrepared',prepared);
    this.store.audit({type:'job.created',jobId:job.id,capabilityId,connectionId,status:job.status,...this.attribution(job)});
    return job;
  }
  /** N3 and N13: in a developer environment an activity row names the end user's usr_ id and the key behind the call. */
  attribution(job) {
    if(this.deployment.kind!=='tenant') return {};
    return {userRecordId:job.userRecordId??null,...(job.source?.kind==='service'?{serviceClientId:job.source.serviceClientId,keyId:job.source.keyId}:{}),...(job.source?.kind==='client'?{agentId:job.source.clientId,keyId:job.source.keyId??null}:{})};
  }
  // Only successful, approved observations may describe an action for its owner.
  // An agent may not invent a friendly label or reuse another client's snapshot.
  browserTarget(job,connection,cap) {
    const client=job.source?.kind==='client',time=this.clock();
    const observed=this.store.list('jobs').findLast(read=>read.connectionId===connection.id&&read.status==='succeeded'&&
      read.effect==='read'&&read.result?.verification?.kind==='paired-browser-dom'&&read.result?.verification?.status==='observed'&&
      read.result?.data?.snapshotId===job.args.snapshotId&&
      (!client||read.source?.kind==='client'&&read.source.clientId===job.source.clientId));
    const data=observed?.result?.data;
    const target=Array.isArray(data?.controls)?data.controls.find(control=>control.targetId===job.args.targetId):null;
    const expires=Date.parse(data?.expiresAt),observedAt=Date.parse(observed?.updatedAt);
    let page;try{page=new URL(data?.url);}catch{}
    const permitted=cap.action.op==='click'?target?.canClick===true:target?.canFill===true;
    if(!data||!target||!permitted||!page||page.protocol!=='https:'||page.origin!==data.origin||
       !connection.allowedOrigins?.includes(data.origin)||!Number.isFinite(expires)||!Number.isFinite(observedAt)||
       expires<=time||observedAt>time||expires>observedAt+120000||time-observedAt>120000) {
      throw new Error('Inspect this page again through this client before requesting an action on a supported control.');
    }
    const clean=(value,max)=>typeof value==='string'?value.replace(/[\u0000-\u001f\u007f]/g,' ').slice(0,max):'';
    return {origin:data.origin,url:page.href,title:clean(data.title,160),label:clean(target.label,120)||clean(target.role,40)||'Unlabelled control',
      role:clean(target.role,40),operation:cap.action.op,snapshotExpiresAt:new Date(expires).toISOString()};
  }
  digest(job) {if(job?.kind==='action') return this.actions?this.actions.actionDigest(job):null;return canonicalHash({id:job.id,connectionId:job.connectionId,capabilityHash:job.capabilityHash,identityHash:job.identityHash,connectionBindingHash:job.connectionBindingHash,permissionHash:job.permissionHash,args:job.args,precondition:job.precondition||null,...(job.executionRequestHash?{executionRequestHash:job.executionRequestHash}:{}),...(job.preview?.browserTarget?{browserTarget:job.preview.browserTarget}:{}),expires:job.approvalExpiresAt});}
  async approve(id,digest,principal) {
    // Ownership first: another user's job answers like a missing one, whatever its status, expiry or digest.
    const owner=this.tenantOwner(principal);
    const job=this.store.get('jobs',id);
    if(owner&&!ownedBy(job,owner,this.deployment)) throw this.notFound();
    // N13: in a developer environment every decision says where it was made and which key made it possible, so only the
    // relay (decideWaiting) or Fabric's own page decides; this undescribed path is closed there.
    if(this.deployment.kind==='tenant') throw this.refusal('unsupported_route','Decide through the approval relay or Fabric\'s page.');
    if(!job||job.status!=='awaiting_approval') throw this.refusal('not_awaiting_approval','This job is not awaiting approval.');
    // F10.11 part h: a lapsed stop of an action keeps no prepared bytes.
    if(Date.parse(job.approvalExpiresAt)<=this.clock()) {if(job.kind==='action') this.store.delete('actionPrepared',id);throw this.refusal('approval_expired','Approval expired. Create a new job.');}
    if(typeof digest!=='string'||digest!==job.approvalDigest||digest!==this.digest(job)) throw this.refusal('digest_mismatch','Approval does not match the exact action.');
    if(this.store.authorityEnabled) {
      const approver=this.assertOwner(principal);
      try {this.assertAcceptedAuthority(job);}
      catch(error) {
        // A request continued from an account handoff is bound to the owner's earlier choice of account and policy.
        // Only a change to that bound authority is reported as authority_changed; a connection that is merely
        // not ready right now (same generation, not revoked) and programming errors keep their own answer.
        if(!job.source?.continuationId||!(error instanceof Error)||error instanceof TypeError||error instanceof RangeError||error instanceof ReferenceError) throw error;
        const connection=this.store.get('connections',job.connectionId);
        let generation=null;try {generation=connection?this.store.connectionGeneration(connection.id):null;} catch {}
        if(connection&&!['ready','revoked'].includes(connection.status)&&generation===job.executionRequest?.access?.generation) throw error;
        const changed=new Error('The account, its permissions or the request changed after it was chosen. Nothing was run; the agent must ask again.');
        changed.code='authority_changed';changed.httpStatus=409;throw changed;
      }
      job.executionApproval=validateApproval({schemaVersion:1,id:randomUUID(),...bindingForRequest(job.executionRequest),approver,decision:'approved',createdAt:this.now(),expiresAt:job.executionRequest.deadline},{request:job.executionRequest,now:this.now()});
      // F10.11 part j: each stop of an action job has its own approval record under the job's deadline.
      if(job.kind==='action') job.action.approvals.push(job.executionApproval);
    }
    if(job.kind==='action') this.decidePhase(job,'approved');
    job.status='queued';job.approvedAt=this.now();job.approvedBy='single-action';this.store.put('jobs',job);
    return this.execute(id);
  }
  /** F10.11 part j: a decision covers the stop it was made on, and only that one; every decision stays on the job. */
  decidePhase(job,decision) {
    job.action.decisions.push({phase:job.action.phase,decision,at:this.now()});
    if(decision==='approved') job.action.approvedPhase=job.action.phase;
    else this.store.delete('actionPrepared',job.id);
  }
  /**
   * Developer environments (the approval relay, docs/F03-DEVELOPER-LAYER.md section 5.11): a decision on a waiting call,
   * checked like approve() (owner first, then state, expiry and the exact digest) and recorded with where it was made
   * and which key made it possible. An approval only queues the call: the caller dispatches it detached, and execute()
   * decides it again. A rejection never runs.
   */
  decideWaiting(id,digest,principal,decision) {
    const owner=this.tenantOwner(principal),job=this.store.get('jobs',id);
    if(this.deployment.kind!=='tenant'||!owner||!ownedBy(job,owner,this.deployment)) throw this.notFound();
    if(!job||job.status!=='awaiting_approval') throw this.refusal('not_awaiting_approval','This call is not waiting for a decision.');
    if(Date.parse(job.approvalExpiresAt)<=this.clock()) {if(job.kind==='action') this.store.delete('actionPrepared',id);throw this.refusal('approval_expired','Nobody approved this in time. Nothing was run.');}
    if(typeof digest!=='string'||digest!==job.approvalDigest||digest!==this.digest(job)) throw this.refusal('digest_mismatch','The decision does not match the exact call shown.');
    const approved=decision.decision==='approved';
    // F10.3: a typed call is checked again before it is queued, so one that can no longer run (its operation locked, its body
    // routed elsewhere, its setting changed) ends failed with its own code and is never approved. A proxied call has no typed
    // capability; execute() decides it again.
    if(approved&&job.kind!=='proxy') {
      try {this.validateJob(job);}
      catch(error) {
        Object.assign(job,{status:'failed',result:null,errorCode:error?.code||'fabric_failed',error:String(error?.message).slice(0,600),updatedAt:this.now()});
        this.store.put('jobs',job);this.store.audit({type:'job.completed',jobId:id,status:job.status,capabilityId:job.capabilityId,connectionId:job.connectionId,...this.attribution(job)});
        throw error;
      }
    }
    if(job.kind==='action') this.decidePhase(job,approved?'approved':'rejected');
    job.status=approved?'queued':'cancelled';job.decision=decision;job.updatedAt=this.now();
    if(approved) {job.approvedAt=this.now();job.approvedBy='single-action';}
    this.store.put('jobs',job);
    this.store.audit({type:approved?'job.approved':'job.rejected',jobId:id,...this.attribution(job),decidedIn:decision.decidedIn,decidedByKey:decision.keyId,decidedByServiceClient:decision.serviceClientId});
    return job;
  }
  cancel(id,principal,actor=null) {
    const owner=this.tenantOwner(principal),job=this.store.get('jobs',id);
    if(owner&&!ownedBy(job,owner,this.deployment)) throw this.notFound();
    if(!job||!['awaiting_approval','queued'].includes(job.status)) throw this.refusal('not_cancellable','Only pending jobs can be cancelled.');
    // An approval nobody gave in time already reads as failed (approval_expired); it never turns into cancelled after.
    if(this.deployment.kind==='tenant'&&job.status==='awaiting_approval'&&Date.parse(job.approvalExpiresAt)<=this.clock()) throw this.refusal('not_cancellable','This approval already expired; nothing ran.');
    job.status='cancelled';job.updatedAt=this.now();this.store.put('jobs',job);
    if(job.kind==='action') this.store.delete('actionPrepared',id);
    // The key that cancelled is recorded beside the key that created the call.
    if(this.deployment.kind==='tenant') this.store.audit({type:'job.cancelled',jobId:id,...this.attribution(job),...(actor?{cancelledByKey:actor.keyId,cancelledByServiceClient:actor.serviceClientId}:{})});
    return job;
  }
  assertAcceptedAuthority(job) {
    if(job?.kind==='proxy') return proxyAuthority(this,job);
    if(!this.store.authorityEnabled) return this.validateJob(job);
    const request=validateExecutionRequest(job.executionRequest);
    if(hashExecutionRequest(request)!==job.executionRequestHash||request.id!==job.id||request.access.kind!=='connection'||request.access.id!==job.connectionId||request.capability.id!==job.capabilityId||canonicalHash(request.args)!==canonicalHash(job.args)) throw new Error('The immutable accepted request no longer matches this job.');
    this.acceptedPrincipal(request.principal,job.source||{});
    if(request.principal.kind==='local_client'&&job.source.requestId!==request.idempotencyKey) throw new Error('The accepted client request identity changed.');
    this.authorizeSource(job);
    const decision=this.validateJob(job),{cap,connection,permission}=decision;
    if(canonicalHash(cap)!==job.capabilityHash||canonicalHash(connection.identity||{})!==job.identityHash||permission.bindingHash!==job.connectionBindingHash||permission.policyHash!==job.permissionHash)throw new Error('Connection authorization or permission setting changed. Create a new request.');
    const current={scope:this.ownerPrincipal.scope,principal:request.principal,ownerPrincipal:this.ownerPrincipal,
      connection:{id:connection.id,generation:permission.connectionGeneration,appId:connection.appId,status:'active',ownership:{schemaVersion:1,scope:this.ownerPrincipal.scope,owner:{kind:'local_owner',id:this.ownerPrincipal.id}}},
      capability:{reference:this.capabilityReference(cap),status:'active'},policy:{revision:permission.policyRevision,decision:permission.mode}};
    // An approval_required result still validates all earlier current-authority
    // checks. It allows pending proposals to be displayed, never dispatched.
    try {assertDispatchable({request,now:this.now(),current});}
    catch(error) {if(error.code!=='approval_required')throw error;}
    return {...decision,request,current};
  }
  assertAuthorization(job) {
    if(job?.kind==='proxy') return assertProxyAuthorization(this,job);
    if(job?.kind==='action') {if(!this.actions) throw coded('capability_changed',ACTION_WORDS.unsupported);return this.actions.assertActionAuthorization(this,job);}
    if(!this.store.authorityEnabled)this.authorizeSource(job);
    const decision=this.store.authorityEnabled?this.assertAcceptedAuthority(job):this.validateJob(job);
    const {cap,connection,effect,permission}=decision;
    if(canonicalHash(cap)!==job.capabilityHash||canonicalHash(connection.identity||{})!==job.identityHash) throw new Error('Capability or account changed since this job was prepared.');
    if(permission.bindingHash!==job.connectionBindingHash||permission.policyHash!==job.permissionHash) throw new Error('Connection authorization or permission setting changed. Create a new request.');
    if(cap.driver==='browser'&&effect==='write'&&canonicalHash(this.browserTarget(job,connection,cap))!==canonicalHash(job.preview?.browserTarget)) throw new Error('The inspected browser target changed. Inspect and request the action again.');
    if(effect!=='read'||permission.requiresApproval) {
      if(!job.approvedAt||job.approvalDigest!==this.digest(job)||Date.parse(job.approvalExpiresAt)<=this.clock()) throw new Error('The exact action has no current approval.');
      if(permission.requiresApproval&&job.approvedBy!=='single-action') throw new Error('This operation requires an explicit single-action approval.');
      if(!permission.requiresApproval&&job.approvedBy!=='standing-policy') throw new Error('Standing permission was not bound to this exact action.');
    }
    if(this.store.authorityEnabled) assertDispatchable({request:decision.request,now:this.now(),current:decision.current,...(job.executionApproval?{approval:job.executionApproval}:{})});
    return decision;
  }
  async execute(id) {
    if(this.running.has(id)) throw new Error('Job already executing.');
    const job=this.store.get('jobs',id);if(!job||job.status!=='queued') throw new Error('Job is not queued.');
    if(job.kind==='proxy') return executeProxy(this,job);
    if(job.kind==='action') {
      if(this.actions) return this.actions.runAction(this,job);
      Object.assign(job,{status:'failed',errorCode:'capability_changed',error:ACTION_WORDS.unsupported,updatedAt:this.now()});this.store.put('jobs',job);return job;
    }
    this.running.add(id);let dispatched=false;let secrets=secretContext([]);let lockKey;const tenant=this.deployment.kind==='tenant';
    try {
      const {cap,connection,effect}=this.assertAuthorization(job);
      if(effect!=='read') {lockKey=cap.driver==='workspace'?`workspace:${job.args.path}`:`account:${connection.id}`;if(this.writeLocks.has(lockKey)){lockKey=null;throw new Error('Another write is in progress for this resource. No action was dispatched.');}this.writeLocks.add(lockKey);}
      job.status='running';job.updatedAt=this.now();this.store.put('jobs',job);
      let outcome;
      if(cap.driver==='workspace') {dispatched=true;outcome=await this.local.execute(cap.action,job.args,job.precondition,()=>this.assertAuthorization(job));}
      else if(cap.driver==='browser') {const executor=connection.transport==='persistent'?this.persistentBrowser:this.browser;if(!executor)throw new Error('Browser session runtime unavailable.');dispatched=true;outcome=await executor.execute(connection.id,cap.action,job.args,()=>this.assertAuthorization(job));}
      else if(cap.driver==='device') {if(!this.device) throw new Error('Local device adapter unavailable.');outcome=await this.device.execute(cap,job.args,()=>this.assertAuthorization(job));}
      else {
        const request=prepareRequest(cap,job.args);const authority=await this.connections.credentials(connection.id);
        secrets=secretContext(credentialValues(authority.headers));
        const current=this.store.get('connections',connection.id);if(!current||current.status==='revoked'||canonicalHash(current.identity||{})!==job.identityHash) throw new Error('Connection authority changed before dispatch.');
        // Credential refresh can shrink provider scopes; local permission can also be revoked while it awaits.
        this.assertAuthorization(job);
        dispatched=true;
        let response;
        try {response=await this.request({...request,headers:{...request.headers,...authority.headers},allowedOrigins:authority.allowedOrigins});}
        catch(error) {
          // In a developer environment a request that never left the machine is a failure, not an uncertain write.
          if(tenant&&error?.sent===false) {dispatched=false;throw coded('fabric_failed',String(error.message));}
          throw tenant?coded(job.effect!=='read'?'outcome_uncertain':'provider_failed',String(error?.message||'The provider could not be reached.')):error;
        }
        if(response.status<200||response.status>=300) {
          if(tenant) job.providerStatus=response.status;
          // A definite refusal changed nothing: failed, even for a write. Anything else on a write stays uncertain.
          throw coded(tenant&&(CLIENT_ERRORS.has(response.status)||job.effect==='read')?'provider_failed':'outcome_uncertain',`Provider returned HTTP ${response.status}. No successful outcome recorded.`,{definite:tenant&&CLIENT_ERRORS.has(response.status)});
        }
        outcome={data:response.data,verification:{status:effect==='read'?'observed':'unverified',kind:'provider-response',httpStatus:response.status,checkedAt:this.now()}};
        if(effect==='write'&&cap.verification?.kind==='http-readback') outcome.verification=await this.verifyHttp(cap,job.args,response.data,connection.id,job.identityHash,job);
      }
      // In-flight responses cannot restore a permission or account which changed
      // away and back. Withhold stale output; dispatched writes stay uncertain.
      if(this.store.authorityEnabled||tenant) {try {this.assertAuthorization(job);} catch(error) {throw Object.assign(error,{code:'authority_changed'});}}
      job.result=scrubValue(outcome,secrets);
      job.status=effect==='read'&&outcome.verification.status==='observed'||outcome.verification.status==='verified'?'succeeded':'uncertain';
      if(job.status==='uncertain') job.error='The action returned, but its persistent effect was not independently verified. Do not repeat it blindly.';
      if(tenant) job.errorCode=job.status==='uncertain'?'outcome_uncertain':null;
    } catch(error) {
      job.status=dispatched&&job.effect!=='read'&&!error?.definite?'uncertain':'failed';
      // Drivers must sanitize provider errors. Never persist request headers or credentials.
      job.error=scrubString(String(error.message),secrets).slice(0,600);
      if(tenant) {job.result=null;job.errorCode=job.status==='uncertain'&&!['authority_changed'].includes(error?.code)?'outcome_uncertain':error?.code||(job.status==='uncertain'?'outcome_uncertain':'fabric_failed');}
    } finally {
      // A job whose end user was deleted while it ran is not written back: the delete stands (F03.5).
      const gone=tenant&&!this.store.get('jobs',id);
      if(!gone) {job.updatedAt=this.now();this.store.put('jobs',job);}
      this.running.delete(id);
      if(lockKey) this.writeLocks.delete(lockKey);
      if(!gone) {
        this.store.audit({type:'job.completed',jobId:id,status:job.status,capabilityId:job.capabilityId,connectionId:job.connectionId,...this.attribution(job)});
        const cap=this.store.get('capabilities',job.capabilityId);
        if(cap){const stats=this.store.get('capabilityStats',cap.id)||{id:cap.id,runs:0,succeeded:0,failed:0,uncertain:0};stats.runs++;stats[job.status]=(stats[job.status]||0)+1;stats.lastRunAt=job.updatedAt;this.store.put('capabilityStats',stats);}
      }
    }
    return job;
  }
  async verifyHttp(cap,args,response,connectionId,identityHash,job) {
    if(this.store.authorityEnabled){if(!job)throw new Error('Readback requires the bound execution authorization.');this.assertAuthorization(job);}
    const prepared=prepareVerification(cap,args,response);
    const req=prepared.request;
    if(req.method!=='GET') throw new Error('Readback must be read-only GET.');
    const authority=await this.connections.credentials(connectionId);
    const current=this.store.get('connections',connectionId);if(!current||current.status==='revoked'||canonicalHash(current.identity||{})!==identityHash) throw new Error('Connection changed or was revoked before readback.');
    if(!job) throw new Error('Readback requires the bound execution authorization.');
    this.assertAuthorization(job);
    const result=await this.request({...req,headers:{...req.headers,...authority.headers},allowedOrigins:authority.allowedOrigins});
    if(this.store.authorityEnabled)this.assertAuthorization(job);
    if(result.status!==200) return {status:'unverified',kind:'http-readback',httpStatus:result.status};
    const checks=prepared.assertions.map(a=>{const actual=pointer(result.data,a.pointer);const expected=a.equals;return {pointer:a.pointer,passed:actual!==undefined&&expected!==undefined&&canonicalHash(actual)===canonicalHash(expected)};});
    return {status:checks.every(c=>c.passed)?'verified':'failed',kind:'http-readback',checks,checkedAt:this.now()};
  }
}

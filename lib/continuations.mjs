import {randomUUID,createHash} from 'node:crypto';
import {canonicalHash,validateInput} from './compiler.mjs';
import {scopeSetsOf,leastPrivilegedExtra,sameRoute,resourceDependent,actionStepScopes,ACTION_WORDS} from './permissions.mjs';
import {PERMISSION_GROUPS,groupFor,memberOf,memberData,UNAVAILABLE_REASONS} from './permission-groups.mjs';
import {usableScopes} from './providers/oauth2.mjs';
import {taskTitle} from './runtime.mjs';
import {AGENT_LOCK_WORDS,routedWords,rowMemberOf} from './row-locks.mjs';
import {PROXY_CONFIGS} from './proxy-config.mjs';
import {validateExecutionRequest,hashExecutionRequest,bindingForRequest,validateContinuation,assertDerivedRequest} from '../contracts/execution.mts';

// Missing-access continuation (F02.3, docs/F02.3-MISSING-ACCESS-SPEC.md). A client that the
// owner allowed to *request* an application can ask for an operation on an app it has no
// account for. Fabric records an immutable missing-access request, the owner chooses the
// exact account, and Fabric derives one new connection-bound request under current policy.
// Designated authority mode only. Every transition below is a synchronous read, integrity
// check, guard and put with no await in between, so one handoff yields at most one job
// within this process. Acceptance, job creation and enqueue are not atomic (I04).
export const CONTINUATIONS='continuations';
const TTL_MS=30*60_000,MAX_PER_CLIENT=10,MAX_GLOBAL=50,MAX_ATTEMPTS=5;
const sha256=value=>createHash('sha256').update(value).digest('hex');
const PRE_BIND=new Set(['awaiting_owner','signing_in','awaiting_confirmation']);
const TERMINAL=new Set(['resumed','declined','cancelled','expired','failed']);
const CLOSED=new Set(['declined','cancelled','expired','failed']);
const HEX64=/^[0-9a-f]{64}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CLIENT_STATUS={declined:'cancelled',cancelled:'cancelled',expired:'expired',failed:'failed'};
const OWNER_CLOSED={client_revoked:'The agent no longer has access, so this request was closed.',capability_retired:'This operation is no longer available, so this request was closed.',
  authority_changed:'The operation or the agent\'s permission changed, so this request was closed. Nothing was run.'};

/** What the owner sees of an account: name, email and, where the provider has one, the workspace,
 *  so two workspaces of the same integration are never indistinguishable. */
function shownIdentity(identity,withId=true) {
  return {...(withId?{id:identity.id}:{}),displayName:identity.displayName,...(identity.email?{email:identity.email}:{}),
    ...(identity.workspaceName?{workspaceName:identity.workspaceName}:{}),...(identity.workspaceId?{workspaceId:identity.workspaceId}:{})};
}
function fail(code,message,extra) {const error=new Error(message);error.code=code;if(extra)Object.assign(error,extra);throw error;}
const same=(a,b)=>canonicalHash(a)===canonicalHash(b);
// An account the owner confirmed through this handoff is the owner's. It keeps its origin, through renewals too (F10.4),
// so its later health (an expired grant waiting for a sign-in) never makes it a held account again. One still in
// quarantine is never the owner's, whatever the handoff says: a crash before promotion leaves it to be revoked.
const confirmedThrough=(record,connection)=>record?.binding?.via==='confirm'&&record.binding.connectionId===connection.id&&connection.status!=='pending_confirmation';
/** F10.7: the access a request's sign-in asks for, in words the page reads: 'full', 'pages' (Notion), or a version 1 app's 'read_write'. */
function accessKind(provider,appId) {
  try {const reading=provider.access(provider.app(appId));return reading.schemaVersion!==2?'read_write':reading.grant==='pages'?'pages':'full';}
  catch {return 'read_write';}
}

/** What a sign-in for one operation asks for by name, beyond its level: nothing when the level's required scopes cover the
 *  operation, else the least-privileged documented alternative it needs. Never the union of alternatives, and never request
 *  input: scopes come from the server only. A scope asked for by name is required (F10.5 correction 1), so a needed optional
 *  scope declined at the provider activates nothing. grantable is false when no requestable alternative exists, so signing in
 *  could never let this operation run. Version 1 levels require their whole read-and-write set, so it plans as before.
 *  F10.6: `groups` are the reviewed rows. A member its row marks unavailable is never grantable; the row's scope sets apply where
 *  Discovery is silent; and a version 2 app asks only for scopes usable on the member's own row. Given the `capability`, one with
 *  no map entry sits in the row its request does, as its decision reads it (correction 3; `configs` place it).
 *  F10.11 part l: `actions` is the action catalog, passed explicitly. An action asks for the union of what each step it cannot skip
 *  needs, each with the scopes usable on its member's row, and is not grantable when such a step can never work through a sign-in, or
 *  when no catalog holds it: never "no scopes, grantable". */
export function operationScopes(provider,appId,map,capabilityId,level='full',groups=PERMISSION_GROUPS,{capability=null,configs=PROXY_CONFIGS,actions=null}={}) {
  const app=provider.app(appId),reading=provider.access(app),operations=Array.isArray(map?.operations)?map.operations:[],operation=operations.find(op=>op.capabilityId===capabilityId);
  const documented=new Set(operations.flatMap(op=>Array.isArray(op.requiredScopes)?op.requiredScopes:[]));
  const base=new Set((level==='read'&&reading.levels.read?reading.levels.read:reading.levels.full).required);
  if(capability?.driver==='action') {
    const steps=actionStepScopes(groups,actions,capability,map),scopes=new Set();
    if(!steps) return {scopes:[],grantable:false};
    for(const step of steps) {
      if(step.optional) continue;
      if(step.unavailable) return {scopes:[],grantable:false};
      if(!step.scopeSets.length||step.scopeSets.some(group=>!group.length)) continue;
      const extra=leastPrivilegedExtra(step.scopeSets,base,usableScopes(reading,step.groupId)??(scope=>provider.belongsToApp(app,scope)&&documented.has(scope)));
      if(extra===null) return {scopes:[],grantable:false};
      for(const scope of extra) scopes.add(scope);
    }
    return {scopes:[...scopes].sort(),grantable:true};
  }
  const placed=(capability?rowMemberOf(groups,configs,capability,operation??null,map,actions):null)??(group=>group&&{group,member:memberOf(group,operation)})(groupFor(groups,appId,operation));
  const row=placed?.group??null,data=placed?memberData(placed.group,placed.member):null;
  if(data?.unavailable) return {scopes:[],grantable:false};
  const {scopeSets,invalid}=scopeSetsOf(operation,data);
  if(invalid) return {scopes:[],grantable:false};
  if(!scopeSets.length||scopeSets.some(group=>!group.length)) return {scopes:[],grantable:true};
  const extra=leastPrivilegedExtra(scopeSets,base,usableScopes(reading,row?.id)??(scope=>provider.belongsToApp(app,scope)&&documented.has(scope)));
  return extra===null?{scopes:[],grantable:false}:{scopes:extra,grantable:true};
}

/** The single definition of where a handoff is, shared by the owner view and the client view. */
export function continuationPhase(record,derivedJob=null) {
  if(record.status==='awaiting_owner'||record.status==='signing_in') return {phase:record.status,clientState:record.status,actions:['select','sign_in','decline']};
  if(record.status==='awaiting_confirmation') return {phase:'awaiting_confirmation',clientState:'awaiting_confirmation',actions:['confirm','reject_account','decline']};
  if(record.status==='binding') return {phase:'continuing',clientState:'continuing',actions:[]};
  if(record.status==='resumed') return {phase:derivedJob?.status==='awaiting_approval'?'awaiting_approval':'connected',clientState:'connected',actions:[]};
  return {phase:'closed',clientState:'closed',actions:[]};
}

export class ContinuationService {
  constructor({store,runtime,protocol,connections=null,signInProvider=()=>null,clock=Date.now,origin,oauthRoute=()=>null,appName=appId=>appId}) {
    Object.assign(this,{store,runtime,protocol,connections,signInProvider,clock,origin,oauthRoute,appName});this.dispatches=new Map();
  }
  get enabled() {return this.store.authorityEnabled===true;}
  assertEnabled() {if(!this.enabled) fail('unsupported_route','Missing-access handoffs require a designated authority store.');}
  iso(ms=this.clock()) {return new Date(ms).toISOString();}
  url(id) {return `${new URL(this.origin).origin}/continue/${id}`;}

  /** Server-derived request-only grant entry for one reviewed HTTP capability, or (F10.11 part l) one active action, which runs on its
   *  app's http account; never an action this Fabric does not run now, nor one described by the resource it acts on. */
  grantEntryFor(capabilityId) {
    const cap=this.store.get('capabilities',capabilityId);
    if(!cap||cap.status!=='active'||!sameRoute({appId:cap.appId,driver:'http'},cap)||(cap.driver==='action'&&this.runtime.permissions.actions?.entryOf?.(cap)?.status!=='active')) fail('invalid_request','Only reviewed, active API operations can be requested before an account exists.');
    if(resourceDependent(cap)) fail('invalid_request',ACTION_WORDS.describe);
    // T4 (F10.3): an operation Fabric locks is never requested, so no handoff waits for an account it could never use; nor is one no
    // sign-in can ever run (F10.6).
    if(this.runtime.permissions.lockOf(cap)) fail('permission_denied',AGENT_LOCK_WORDS);
    const route=this.oauthRoute(cap.appId);
    const unavailable=this.runtime.permissions.unavailableOf(cap);
    if(unavailable) fail('permission_denied',UNAVAILABLE_REASONS[unavailable]);
    if(!route) fail('invalid_request','This application has no reviewed sign-in route.');
    const reference=this.runtime.capabilityReference(cap);
    return {appId:cap.appId,capabilityId:cap.id,capabilityVersion:reference.version,definitionHash:reference.definitionHash,effect:reference.effect,providerId:route.providerId};
  }

  // ---- integrity and lazy transitions ------------------------------------------------
  /** Loads a record and re-checks every binding and its state shape; a tampered record never yields a job. */
  load(id,now=this.clock()) {
    if(typeof id!=='string'||!UUID.test(id)) return null;
    const record=this.store.get(CONTINUATIONS,id);
    if(!record) return null;
    try {
      const request=validateExecutionRequest(record.request);
      if(record.schemaVersion!==1||record.id!==id||request.id!==id||hashExecutionRequest(request)!==record.requestHash||
         request.principal.id!==record.clientId||request.idempotencyKey!==record.requestId||request.access.kind!=='missing'||
         canonicalHash(record.grantEntry)!==record.grantEntryHash||!same(record.contract,{schemaVersion:1,id,kind:'connection',createdAt:record.createdAt,expiresAt:record.expiresAt,...bindingForRequest(request)})||
         !Number.isSafeInteger(record.revision)||record.revision<1||!this.shapeOk(record)) throw new Error();
      // Time is context, not integrity: a wall clock stepped back behind createdAt must not read as tampering.
      if(PRE_BIND.has(record.status)&&now<Date.parse(record.expiresAt)) validateContinuation(record.contract,{request,now:this.iso(Math.max(now,Date.parse(record.createdAt)))});
    } catch {fail('tampered','This handoff record failed its integrity check.');}
    return record;
  }
  /** Status and state fields must agree: a rolled-back or half-written record is treated as tampered. */
  shapeOk(record) {
    const binding=record.binding;
    const bound=Boolean(binding&&typeof binding==='object'&&['select','confirm'].includes(binding.via)&&typeof binding.connectionId==='string'&&Number.isSafeInteger(binding.generation)&&
      typeof binding.identityHash==='string'&&typeof binding.jobId==='string'&&UUID.test(binding.jobId)&&typeof binding.decidedAt==='string');
    if(PRE_BIND.has(record.status)) return binding===null&&record.outcome===null&&(record.status!=='signing_in'||typeof record.signIn?.flowIdHash==='string')&&
      (record.status!=='awaiting_confirmation'||typeof record.pendingConnection?.connectionId==='string');
    if(record.status==='binding') return bound&&binding.derivedRequestHash===null&&record.outcome===null;
    if(record.status==='resumed') return bound&&HEX64.test(binding.derivedRequestHash??'')&&record.outcome===null;
    return CLOSED.has(record.status)&&typeof record.outcome?.code==='string';
  }
  write(record,changes,event,meta={}) {
    const next={...record,...changes,revision:record.revision+1,updatedAt:this.iso()};
    this.store.put(CONTINUATIONS,next);
    if(event) this.store.audit({type:`continuation.${event}`,continuationId:record.id,clientId:record.clientId,...(changes.outcome?{code:changes.outcome.code}:{}),...meta});
    return next;
  }
  /** Closing a pre-bind handoff discards its sign-in flow and revokes a quarantined account locally.
   *  An owner-initiated exit keeps the credential for a moment so the provider grant can be revoked too. */
  close(record,status,code,event,{keepForRemoteRevoke=false}={}) {
    const held=this.heldAccounts(record).length>0;
    const next=this.write(record,{status,outcome:{code,at:this.iso(),...(held?{connectionDisposition:'revoked',providerGrantMayRemain:true}:{})}},event);
    this.cleanup(record,{keepQuarantined:keepForRemoteRevoke});
    return next;
  }
  /** Accounts this handoff signed in that the owner never confirmed, found by their origin rather than by the
   *  record's pointer, so an edited pointer cannot strand one: quarantined, or drifted out of quarantine. */
  heldAccounts(record) {return this.store.list('connections').filter(connection=>connection.origin?.kind==='continuation'&&connection.origin.continuationId===record.id&&!['ready','revoked'].includes(connection.status)&&!confirmedThrough(record,connection));}
  quarantined(record) {const id=record.pendingConnection?.connectionId;return this.heldAccounts(record).find(connection=>connection.id===id&&connection.status==='pending_confirmation')||null;}
  cleanup(record,{keepQuarantined=false}={}) {
    if(record.signIn) try {this.signInProvider(record.grantEntry.appId)?.discardFlow(record.signIn.flowIdHash);} catch {}
    const kept=keepQuarantined?this.quarantined(record)?.id:null;
    for(const stored of this.heldAccounts(record)) {
      if(stored.id===kept) continue;
      try {this.connections.revoke(stored.id);this.store.audit({type:'connection.quarantine_revoked',connectionId:stored.id,continuationId:record.id});} catch {}
    }
  }
  /** Applies expiry, grant revocation and capability drift before any read or transition. */
  touch(record,now=this.clock()) {
    if(!PRE_BIND.has(record.status)) return record;
    if(now>=Date.parse(record.expiresAt)) return this.close(record,'expired','continuation_expired','expired');
    const client=this.store.get('clientGrants',record.clientId);
    if(!client||client.status!=='active'||!(Date.parse(client.expiresAt)>now)) return this.close(record,'cancelled','client_revoked','cancelled');
    const cap=this.store.get('capabilities',record.grantEntry.capabilityId);
    if(!cap||cap.status!=='active') return this.close(record,'failed','capability_retired','failed');
    if(this.runtime.permissions.lockOf(cap)) return this.close(record,'failed','policy_denied','failed');
    if(this.runtime.permissions.unavailableOf(cap)) return this.close(record,'failed','policy_denied','failed');
    if(!(client.requestable||[]).some(entry=>same(entry,record.grantEntry))||!same(this.runtime.capabilityReference(cap),record.request.capability)) return this.close(record,'failed','authority_changed','failed');
    return record;
  }
  current(id) {const now=this.clock(),record=this.load(id,now);return record?this.touch(record,now):null;}
  /** Handoffs still open after their lazy transitions; the one predicate behind the pending limits and the owner badge. */
  openRecords() {
    const open=[];
    for(const stored of this.store.list(CONTINUATIONS)) {
      if(!PRE_BIND.has(stored.status)&&stored.status!=='binding') continue;
      let record;try {record=this.current(stored.id);} catch {continue;}
      if(record&&(PRE_BIND.has(record.status)||record.status==='binding')) open.push(record);
    }
    return open;
  }

  // ---- client side --------------------------------------------------------------------
  /** Validates a handoff request. Writes nothing for this call, so a rejected call leaves no reservation;
   *  counting the open handoffs applies other records' lazy transitions (an overdue request frees its slot). */
  prepare(client,params) {
    this.assertEnabled();
    const entry=(client.requestable||[]).find(item=>item.appId===params.appId&&item.capabilityId===params.capabilityId);
    if(!entry) fail('permission_denied','This application operation was not granted to this client for access requests.');
    const cap=this.store.get('capabilities',entry.capabilityId);
    if(!cap||cap.status!=='active'||!same(this.runtime.capabilityReference(cap),{appId:entry.appId,id:entry.capabilityId,version:entry.capabilityVersion,definitionHash:entry.definitionHash,effect:entry.effect})||params.definitionHash!==entry.definitionHash) fail('grant_changed','The operation changed; the owner must review a new client grant.');
    if(this.runtime.permissions.lockOf(cap)) fail('permission_denied',AGENT_LOCK_WORDS);
    const unavailable=this.runtime.permissions.unavailableOf(cap);
    if(unavailable) fail('permission_denied',UNAVAILABLE_REASONS[unavailable]);
    try {validateInput(cap.inputSchema,params.args??{});} catch {fail('invalid_request','The arguments do not match this operation.');}
    // A body a route sends to another row is refused before any handoff, in the words a typed call gets (F10.3).
    const routed=this.runtime.permissions.routedBody(cap,params.args??{});
    if(routed) fail('invalid_request',routedWords(routed),{details:{routedTo:{groupId:routed.groupId,label:routed.label}}});
    const open=this.openRecords();
    if(open.filter(record=>record.clientId===client.id).length>=MAX_PER_CLIENT||open.length>=MAX_GLOBAL) fail('pending_limit','Too many account requests are waiting for the owner. Try again after they are handled.');
    return {entry,cap};
  }
  /** Writes the immutable handoff after the protocol has reserved the request id. Synchronous by design. */
  create(client,principal,requestId,params,{protocolRequestKey,wireRequestHash},{entry,cap}) {
    const id=randomUUID(),created=this.clock(),expires=Math.min(created+TTL_MS,Date.parse(client.expiresAt));
    const request=validateExecutionRequest({schemaVersion:1,id,scope:principal.scope,principal,access:{kind:'missing',appId:entry.appId,accountSelection:{kind:'owner_required'}},
      capability:this.runtime.capabilityReference(cap),args:structuredClone(params.args??{}),
      // Sentinel: a missing-access request never dispatches; the derived request carries current policy.
      policyRevision:1,idempotencyKey:requestId,createdAt:this.iso(created),deadline:this.iso(expires)});
    const contract={schemaVersion:1,id,kind:'connection',createdAt:request.createdAt,expiresAt:request.deadline,...bindingForRequest(request)};
    validateContinuation(contract,{request,now:request.createdAt});
    const record={schemaVersion:1,id,revision:1,status:'awaiting_owner',clientId:client.id,requestId,protocolRequestKey,wireRequestHash,
      request,requestHash:hashExecutionRequest(request),contract,grantEntry:structuredClone(entry),grantEntryHash:canonicalHash(entry),
      createdAt:request.createdAt,updatedAt:request.createdAt,expiresAt:request.deadline,taskTitle:taskTitle(params.task),attempts:0,signIn:null,superseded:[],lastAttempt:null,pendingConnection:null,binding:null,outcome:null};
    this.store.put(CONTINUATIONS,record);
    this.store.audit({type:'continuation.created',continuationId:id,clientId:client.id,appId:entry.appId,capabilityId:entry.capabilityId});
    return record;
  }
  byProtocolKey(key) {return this.store.list(CONTINUATIONS).find(record=>record.protocolRequestKey===key)||null;}

  /** The caller's own record. Ownership is checked on the stored row before integrity and lazy transitions
   *  run, so another client cannot tell a tampered id from an unknown one or trigger its transitions. */
  clientRecord(clientId,id) {
    const stored=typeof id==='string'&&UUID.test(id)?this.store.get(CONTINUATIONS,id):null;
    if(!stored||stored.clientId!==clientId) fail('not_found','Call not found.');
    let record;
    try {record=this.current(id);} catch(error) {if(error.code==='tampered') fail('outcome_unknown','The account request cannot be read safely. Review its activity before issuing a new request.');throw error;}
    if(!record||record.clientId!==clientId) fail('not_found','Call not found.');
    return record;
  }
  /** The client projection: no account identity, scopes, digests or flow data. */
  clientView(clientId,id) {
    const record=this.clientRecord(clientId,id);
    const job=record.binding?.jobId?this.store.get('jobs',record.binding.jobId):null;
    const {clientState}=continuationPhase(record,job);
    const base={id:record.id,capabilityId:record.grantEntry.capabilityId,createdAt:record.createdAt,updatedAt:record.updatedAt,
      handoff:{appId:record.grantEntry.appId,appName:this.appName(record.grantEntry.appId),url:PRE_BIND.has(record.status)?this.url(record.id):null,expiresAt:record.expiresAt,state:clientState,outcome:record.outcome?.code??null}};
    if(record.status==='resumed') {
      if(!job) fail('outcome_unknown','The continued request cannot be read safely.');
      const derived=this.protocol.resultForClient(clientId,job);
      // The card for a resumed request follows the derived call, so its time is the later of the two.
      return {...base,updatedAt:job.updatedAt>record.updatedAt?job.updatedAt:record.updatedAt,status:derived.status,connectionId:record.binding.connectionId,result:derived.result,error:derived.error,approvalRequired:derived.approvalRequired,...(derived.approval?{approval:derived.approval}:{}),resumedCallId:job.id};
    }
    const status=PRE_BIND.has(record.status)||record.status==='binding'?'awaiting_connection':CLIENT_STATUS[record.status];
    return {...base,status,connectionId:null,result:null,error:record.outcome?`The account request closed: ${record.outcome.code}.`:null,approvalRequired:false,resumedCallId:null};
  }
  clientCancel(clientId,id) {
    const record=this.clientRecord(clientId,id);
    if(!PRE_BIND.has(record.status)) fail('invalid_transition','Only an account request still waiting for the owner can be withdrawn.');
    this.close(record,'cancelled','client_cancelled','cancelled');
    return this.clientView(clientId,id);
  }
  /** Eager cancellation when the owner revokes the requesting client. */
  cancelForClient(clientId) {
    for(const stored of this.store.list(CONTINUATIONS)) {
      if(stored.clientId!==clientId||!PRE_BIND.has(stored.status)) continue;
      let record;try {record=this.load(stored.id);} catch {continue;}
      if(record&&PRE_BIND.has(record.status)) this.close(record,'cancelled','client_revoked','cancelled');
    }
  }

  // ---- owner side ---------------------------------------------------------------------
  eligibleAccounts(record,cap) {
    return this.store.list('connections').filter(connection=>connection.appId===record.grantEntry.appId&&(cap?sameRoute(connection,cap):connection.driver==='http')&&['oauth','token'].includes(connection.authMethod)&&
      !connection.transport&&!['revoked','pending_confirmation'].includes(connection.status)).map(connection=>{
      let decision=null;
      try {decision=cap?this.runtime.permissions.decision(connection,cap):null;} catch {decision=null;}
      const eligible=connection.status==='ready'&&Boolean(decision?.executable);
      return {connectionId:connection.id,label:connection.label,identity:shownIdentity(connection.identity||{},false),authMethod:connection.authMethod,
        generation:decision?.connectionGeneration??null,identityHash:canonicalHash(connection.identity||{}),eligible,
        ...(eligible?{}:{reason:connection.status!=='ready'?'reconnect_required':decision?.reason||'not_permitted'}),
        policy:{mode:decision?.mode??null,revision:decision?.policyRevision??null},
        afterSelection:!eligible?'blocked':decision.requiresApproval?'asks_approval':'runs_now'};
    });
  }
  /** Sign-in grants the app's default access (its reviewed read-and-write set) plus what this operation needs (operationScopes). */
  signInPlan(record,provider) {
    const {appId,capabilityId}=record.grantEntry,permissions=this.runtime?.permissions;
    return operationScopes(provider,appId,this.store.get('applicationMaps',appId),capabilityId,'full',permissions?.groups,{capability:this.store.get('capabilities',capabilityId),configs:permissions?.configs,actions:permissions?.actions});
  }
  /** F10.7 (decision 9): the app scopes this handoff's sign-in asked the provider for, read again from the plan signIn() started it
   *  with. A plan that cannot be read again confirms nothing, so whatever the sign-in granted at a default Allow then starts at Ask. */
  plannedScopes(record) {
    try {
      const appId=record.grantEntry.appId,provider=this.signInProvider(appId),scopes=record.signIn?.scopes||[],identity=provider.definition.authorization.identityScopes;
      const plan=provider.plan({appId,writeAccess:record.signIn.writeAccess,...(scopes.length?{scopes}:{})});
      return [...new Set([...plan.scopes.filter(scope=>!identity.includes(scope)),...plan.userScopes])].sort();
    } catch {return [];}
  }
  signInSummary(record) {
    const route=this.oauthRoute(record.grantEntry.appId);
    if(!route) return null;
    // Connecting grants the app's default access, read and write, whatever this one request needs.
    const provider=this.signInProvider(record.grantEntry.appId),writeAccess=true,attemptsLeft=Math.max(0,MAX_ATTEMPTS-record.attempts);
    const plan=provider?this.signInPlan(record,provider):{scopes:[],grantable:true};
    const available=Boolean(route.available&&provider&&attemptsLeft>0&&plan.grantable);
    const reason=available?null:attemptsLeft===0?'No sign-in attempts remain for this request.':!plan.grantable?'Signing in cannot grant the permission this operation needs. Ask the developer to review it.':route.reason||'Sign-in is not available for this application here.';
    // T1 (F10.5 correction 10): where the owner removes Fabric at the provider, when the reviewed definition names it.
    const settingsUrl=provider?.definition?.revocation?.settingsUrl;
    return {providerId:route.providerId,providerName:route.name,available,reason,scopes:plan.scopes,writeAccess,access:accessKind(provider,record.grantEntry.appId),attemptsLeft,afterSignIn:record.grantEntry.effect!=='read'?'asks_approval':'runs_now',...(settingsUrl?{settingsUrl}:{})};
  }
  viewDigest(record,accounts,signIn) {
    return canonicalHash({kind:'continuation-view',id:record.id,revision:record.revision,requestHash:record.requestHash,grantEntryHash:record.grantEntryHash,expiresAt:record.expiresAt,
      signIn:signIn?{providerId:signIn.providerId,available:signIn.available,scopes:signIn.scopes,writeAccess:signIn.writeAccess,access:signIn.access}:null,
      accounts:accounts.filter(account=>account.eligible).map(account=>({connectionId:account.connectionId,generation:account.generation,identityHash:account.identityHash,policyRevision:account.policy.revision,mode:account.policy.mode}))});
  }
  ownerView(id) {
    this.assertEnabled();
    let record;
    try {record=this.current(id);} catch(error) {if(error.code==='tampered') fail('authority_changed','This handoff record failed its integrity check. No action is possible.');throw error;}
    if(!record) fail('not_found','Handoff not found.');
    const cap=this.store.get('capabilities',record.grantEntry.capabilityId),client=this.store.get('clientGrants',record.clientId);
    const job=record.binding?.jobId?this.store.get('jobs',record.binding.jobId):null;
    const {phase,actions:base}=continuationPhase(record,job),pre=PRE_BIND.has(record.status);
    const choosing=record.status==='awaiting_owner'||record.status==='signing_in';
    const accounts=choosing?this.eligibleAccounts(record,cap):[],signIn=choosing?this.signInSummary(record):null;
    const actions=base.filter(action=>action!=='sign_in'||signIn?.available);
    const pending=record.status==='awaiting_confirmation'?this.pendingView(record,cap):null;
    return {id:record.id,status:record.status,phase,revision:record.revision,createdAt:record.createdAt,updatedAt:record.updatedAt,expiresAt:record.expiresAt,
      client:{id:record.clientId,name:client?.name??null,status:client?.status??'missing'},
      app:{id:record.grantEntry.appId,name:this.appName(record.grantEntry.appId),iconUrl:`/api/icons/${encodeURIComponent(record.grantEntry.appId)}`},
      operation:{capabilityId:record.grantEntry.capabilityId,name:cap?.name??null,description:cap?.description??'',effect:record.grantEntry.effect,version:record.grantEntry.capabilityVersion,definitionHash:record.grantEntry.definitionHash},
      arguments:structuredClone(record.request.args),accounts,signIn,pendingConnection:pending,lastAttempt:record.lastAttempt,outcome:record.outcome,
      derived:job?{jobId:job.id,status:job.status,approval:job.status==='awaiting_approval'?{digest:job.approvalDigest,expiresAt:job.approvalExpiresAt,preview:job.preview}:null,result:job.result??null,error:job.error??null}:null,
      viewDigest:choosing?this.viewDigest(record,accounts,signIn):null,confirmDigest:pending?this.confirmDigest(record,pending):null,actions};
  }
  /** The verified identity of the quarantined account and what confirming it would do. */
  pendingView(record,cap) {
    const pending=record.pendingConnection,stored=pending&&this.store.get('connections',pending.connectionId);
    if(!pending) return null;
    let decision=null;
    try {decision=stored&&cap?this.runtime.permissions.decision(stored,cap):null;} catch {decision=null;}
    const onceReady=Boolean(decision&&decision.status==='active'&&decision.providerAccess!=='missing'&&decision.providerAccess!=='unavailable'&&decision.mode!=='deny');
    return {connectionId:pending.connectionId,identity:shownIdentity(pending.identity,false),scopes:pending.scopes,duplicateOf:pending.duplicateOf,
      policy:{mode:decision?.mode??null,revision:decision?.policyRevision??null},afterConfirm:!onceReady?'blocked':decision.mode==='ask'?'asks_approval':'runs_now'};
  }
  confirmDigest(record,view) {
    const pending=record.pendingConnection;
    return canonicalHash({kind:'continuation-confirm',id:record.id,revision:record.revision,requestHash:record.requestHash,
      connection:{id:pending.connectionId,generation:pending.generation,identityHash:pending.identityHash,scopes:pending.scopes},policy:view.policy});
  }
  ownerList() {
    this.assertEnabled();
    const rows=[];
    for(const stored of this.store.list(CONTINUATIONS)) {
      let record;
      // An unreadable record stays visible to the owner as closed, rather than silently disappearing.
      try {record=this.current(stored.id);}
      catch {rows.push({id:String(stored.id),phase:'closed',status:'failed',integrity:'failed',outcome:{code:'fabric_failed'},client:{id:null,name:null},app:{id:null,name:null},operation:{capabilityId:null,name:null,effect:null},createdAt:String(stored.createdAt??''),expiresAt:null});continue;}
      if(!record) continue;
      const job=record.binding?.jobId?this.store.get('jobs',record.binding.jobId):null;
      rows.push({id:record.id,phase:continuationPhase(record,job).phase,status:record.status,client:{id:record.clientId,name:this.store.get('clientGrants',record.clientId)?.name??null},
        app:{id:record.grantEntry.appId,name:this.appName(record.grantEntry.appId)},operation:{capabilityId:record.grantEntry.capabilityId,name:this.store.get('capabilities',record.grantEntry.capabilityId)?.name??null,effect:record.grantEntry.effect},createdAt:record.createdAt,expiresAt:record.expiresAt});
    }
    const open=rows.filter(row=>!TERMINAL.has(row.status)),done=rows.filter(row=>TERMINAL.has(row.status)).sort((a,b)=>b.createdAt.localeCompare(a.createdAt)).slice(0,50);
    return [...open,...done];
  }
  pendingCount() {return this.enabled?this.openRecords().filter(record=>PRE_BIND.has(record.status)).length:0;}

  ownerRecord(id,principal) {
    this.assertEnabled();this.runtime.assertOwner(principal);
    let record;
    try {record=this.current(id);} catch(error) {if(error.code==='tampered') fail('authority_changed','This handoff record failed its integrity check. No action is possible.');throw error;}
    if(!record) fail('not_found','Handoff not found.');
    if(record.status==='expired') fail('continuation_expired','This account request has expired. The client must make a new request.');
    // A closure Fabric applied (revoked grant, retired or edited operation) is reported as itself, whoever
    // read the record first; "already handled" is kept for requests that were actually handled.
    if(CLOSED.has(record.status)&&OWNER_CLOSED[record.outcome?.code]) fail(record.outcome.code,OWNER_CLOSED[record.outcome.code],{view:this.ownerView(id)});
    if(!PRE_BIND.has(record.status)) fail('invalid_transition','This account request was already handled.');
    return record;
  }
  /** One handoff yields at most one job, independent of the status field: a rolled-back record cannot bind twice. */
  assertNoJob(record) {
    if(!this.store.list('jobs').some(job=>job.source?.continuationId===record.id)) return;
    this.close(record,'failed','fabric_failed','failed');
    fail('authority_changed','This account request already produced a request. No second request is created.');
  }
  /** The decision time, read once; a decision at or after expiry is refused rather than mislabelled later. */
  decisionTime(record) {
    const now=this.clock();
    // A wall clock stepped back behind the request is a retryable condition, never a reason to close it.
    if(now<Date.parse(record.createdAt)) fail('clock_behind','Fabric\'s clock moved back since this request was made. Nothing was changed; try again shortly.');
    if(now>=Date.parse(record.expiresAt)) {this.close(record,'expired','continuation_expired','expired');fail('continuation_expired','This account request has expired. The client must make a new request.');}
    return this.iso(now);
  }
  /** Owner chooses one exact, eligible existing account, bound to the view they saw. */
  async select(id,body,principal) {
    this.assertEnabled();
    if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).some(key=>!['connectionId','viewDigest'].includes(key))) fail('invalid_request','Only the selected account and the view digest are accepted.');
    let record=this.ownerRecord(id,principal);
    const view=this.ownerView(id);
    if(typeof body.viewDigest!=='string'||body.viewDigest!==view.viewDigest) fail('view_changed','The accounts or permissions changed. Review the request again.',{view});
    const account=view.accounts.find(item=>item.connectionId===body.connectionId);
    if(!account||!account.eligible) fail('account_ineligible','Choose a ready account that this operation is permitted to use.');
    // Re-check the grant, caller and capability synchronously before recording the decision.
    const client=this.protocol.activeClient(record.clientId),actor=this.protocol.principalForClient(client);
    if(!same(actor,record.request.principal)||!(client.requestable||[]).some(entry=>same(entry,record.grantEntry))) fail('authority_changed','The requesting client changed. No account was bound.');
    this.assertNoJob(record);
    const decidedAt=this.decisionTime(record);
    // Choosing an existing account ends any sign-in in progress for this request.
    if(record.signIn) try {this.signInProvider(record.grantEntry.appId)?.discardFlow(record.signIn.flowIdHash);} catch {}
    record=this.write(record,{status:'binding',binding:{via:'select',connectionId:account.connectionId,generation:account.generation,identityHash:account.identityHash,
      policyRevision:account.policy.revision,mode:account.policy.mode,decidedAt,jobId:randomUUID(),derivedRequestHash:null}},'selected');
    return this.derive(record,actor);
  }
  async derive(record,actor) {
    const {binding}=record;
    let job;
    try {
      job=await this.runtime.prepareJob({connectionId:binding.connectionId,capabilityId:record.grantEntry.capabilityId,args:structuredClone(record.request.args),
        source:{kind:'client',clientId:record.clientId,requestId:`${record.id}@continuation`,continuationId:record.id}},actor,{jobId:binding.jobId,...(record.taskTitle?{task:{title:record.taskTitle}}:{})});
    } catch(error) {
      const fresh=this.load(record.id);
      // A lock, a route or an operation no sign-in can run (F10.6) refuses with words that name no permission, so each is read by its
      // own mark, never as a changed authority.
      const code=['policy_denied','authority_changed','capability_retired'].includes(error.code)?error.code:error.locked===true||error.details?.routedTo||error.unavailable===true||/permission|denied|not currently permitted/i.test(error.message)?'policy_denied':'authority_changed';
      this.close(fresh,'failed',code,'failed');
      fail(code,'The account could not be bound to this request. No request was submitted.');
    }
    try {
      assertDerivedRequest({original:record.request,continuation:record.contract,derived:job.executionRequest,
        binding:{connectionId:binding.connectionId,generation:binding.generation,policyRevision:binding.policyRevision,decidedAt:binding.decidedAt}});
      // The persisted job must still match the live account and policy, not only the snapshots it was built from.
      const connection=this.store.get('connections',binding.connectionId),cap=this.store.get('capabilities',record.grantEntry.capabilityId);
      const decision=connection&&cap?this.runtime.permissions.decision(connection,cap):null;
      if(!decision?.executable||decision.connectionGeneration!==binding.generation||decision.policyRevision!==job.executionRequest.policyRevision) throw new Error();
    } catch {
      try {this.runtime.cancel(job.id);} catch {}
      this.close(this.load(record.id),'failed','authority_changed','failed');
      fail('authority_changed','Permissions changed while the account was being bound. The prepared request was cancelled.');
    }
    const resumed=this.write(this.load(record.id),{status:'resumed',binding:{...binding,derivedRequestHash:job.executionRequestHash}},'resumed',{jobId:job.id});
    // Allow runs now under current standing policy; Ask waits for the owner's approval of this job's own digest.
    if(job.status==='queued') this.dispatch(record.id,job.id);
    return this.ownerView(resumed.id);
  }
  /** Runs a derived job detached from the owner's request. Never rejects; shutdown waits for it (drain). */
  dispatch(id,jobId) {
    const running=this.runtime.execute(jobId).then(()=>undefined,()=>{try {this.store.audit({type:'continuation.dispatch_failed',continuationId:id,jobId});} catch {}})
      .finally(()=>{if(this.dispatches.get(id)===running) this.dispatches.delete(id);});
    this.dispatches.set(id,running);
  }
  /** Test and shutdown seam: resolves when a dispatched derived job settles. */
  settled(id) {return this.dispatches.get(id)??Promise.resolve();}
  drain() {return Promise.allSettled([...this.dispatches.values()]);}
  async decline(id,body,principal) {
    this.assertEnabled();
    if(body&&(typeof body!=='object'||Array.isArray(body)||Object.keys(body).length)) fail('invalid_request','Declining accepts no fields.');
    const record=this.ownerRecord(id,principal),quarantined=this.quarantined(record);
    // The credential stays (unusable, quarantined) only until the provider revocation below.
    this.close(record,'declined','owner_declined','declined',{keepForRemoteRevoke:Boolean(quarantined)});
    if(quarantined) await this.recordRevocation(id,await this.revokeRemotely(record,quarantined.id));
    return this.ownerView(id);
  }
  /** Revokes a quarantined account locally and, where the revocation covers only its token, at the provider. A provider
   *  whose revocation removes the whole grant (Google) is never asked (T1): that would sign the same account out of every
   *  app on this sign-in client. The outcome says whether a live account here, in any app, still holds that grant. */
  async revokeRemotely(record,connectionId) {
    const provider=this.signInProvider(record.grantEntry.appId),stored=this.store.get('connections',connectionId);
    if(!stored) return {remoteRevoked:false,providerGrant:'unknown'};
    const grant=provider?.revocationCovers?.()==='grant';
    const shared=grant&&this.store.list('connections').some(other=>other.id!==stored.id&&this.connections.providerOf(other)===this.connections.providerOf(stored)&&!['revoked','pending_confirmation'].includes(other.status)&&other.identity?.id===stored.identity?.id);
    if(!provider||grant||stored.status==='revoked') {try {if(stored.status!=='revoked') this.connections.revoke(connectionId);} catch {} return {remoteRevoked:false,providerGrant:shared?'shared':'may_remain'};}
    try {const result=await provider.revoke(connectionId);return {remoteRevoked:Boolean(result?.remoteRevoked),providerGrant:result?.remoteRevoked?'revoked':'may_remain'};}
    catch {try {this.connections.revoke(connectionId);} catch {} return {remoteRevoked:false,providerGrant:'may_remain'};}
  }
  recordRevocation(id,{providerGrant}) {
    let record;try {record=this.load(id);} catch {return;}
    if(!record?.outcome) return;
    this.write(record,{outcome:{...record.outcome,connectionDisposition:'revoked',providerGrantMayRemain:providerGrant==='may_remain',providerGrant}},'quarantine_revoked');
  }

  // ---- sign-in to a new account (quarantined until confirmed) -------------------------
  /** Starts a provider sign-in bound to this handoff. Synchronous: no await between check and write. */
  signIn(id,body,principal) {
    this.assertEnabled();
    if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).some(key=>key!=='viewDigest')) fail('invalid_request','Only the view digest is accepted.');
    const record=this.ownerRecord(id,principal);
    if(record.status==='awaiting_confirmation') fail('invalid_transition','Confirm or reject the signed-in account first.');
    const view=this.ownerView(id);
    if(typeof body.viewDigest!=='string'||body.viewDigest!==view.viewDigest) fail('view_changed','The request changed. Review it again.',{view});
    if(record.attempts>=MAX_ATTEMPTS) fail('attempts_exhausted','No sign-in attempts remain for this request.');
    if(!view.signIn?.available) fail('signin_unavailable',view.signIn?.reason||'Sign-in is not available for this application here.');
    const provider=this.signInProvider(record.grantEntry.appId);
    if(record.signIn) provider.discardFlow(record.signIn.flowIdHash);
    const flow=provider.start({appId:record.grantEntry.appId,writeAccess:view.signIn.writeAccess,...(view.signIn.scopes.length?{scopes:view.signIn.scopes}:{})},{continuation:{id,notAfter:record.expiresAt}});
    this.write(this.load(id),{status:'signing_in',attempts:record.attempts+1,superseded:record.signIn?[record.signIn.flowIdHash,...(record.superseded||[])].slice(0,5):record.superseded||[],
      signIn:{providerId:provider.providerId,flowIdHash:sha256(flow.flowId),scopes:view.signIn.scopes,writeAccess:view.signIn.writeAccess,startedAt:this.iso(),expiresAt:flow.expiresAt}},'signin_started');
    return {authorizationUrl:flow.authorizationUrl,expiresAt:flow.expiresAt,flowId:flow.flowId,providerId:provider.providerId};
  }
  /** Finds the handoff a returning browser belongs to by its flow cookie, including superseded flows. */
  byFlowIdHash(flowIdHash) {
    if(typeof flowIdHash!=='string') return null;
    return this.store.list(CONTINUATIONS).find(record=>record.signIn?.flowIdHash===flowIdHash||(record.superseded||[]).includes(flowIdHash))||null;
  }
  /** Synchronous admission check run before the token exchange and again before credentials persist. */
  admitCallback(flow) {
    let record;
    try {record=this.current(flow.continuationId);} catch {record=null;}
    if(!record||record.status!=='signing_in'||record.signIn?.flowIdHash!==flow.flowIdHash||record.signIn.providerId!==flow.providerId) fail('continuation_closed','This account request is no longer waiting for this sign-in.');
  }
  /** Records the outcome of a provider callback for the handoff that owns the browser's flow. */
  completeSignIn(id,flowIdHash,{connection,error}={}) {
    let record;try {record=this.current(id);} catch {record=null;}
    const ours=Boolean(record&&record.status==='signing_in'&&record.signIn?.flowIdHash===flowIdHash);
    if(connection) {
      const stored=this.store.get('connections',connection.id);
      if(!ours||!stored||stored.status!=='pending_confirmation'||stored.origin?.continuationId!==id) {
        // The handoff moved on while sign-in finished: never leave an unbound account behind.
        if(stored?.status==='pending_confirmation') {try {this.connections.revoke(stored.id);this.store.audit({type:'connection.quarantine_revoked',connectionId:stored.id,continuationId:id});} catch {}}
        return record;
      }
      const identity=stored.identity||{};
      const duplicate=this.store.list('connections').find(other=>other.id!==stored.id&&other.appId===stored.appId&&other.status==='ready'&&other.identity?.id===identity.id);
      return this.write(record,{status:'awaiting_confirmation',pendingConnection:{connectionId:stored.id,generation:this.store.connectionGeneration(stored.id),identityHash:canonicalHash(identity),
        identity:shownIdentity(identity),scopes:stored.scopes||[],duplicateOf:duplicate?.id??null,at:this.iso()}},'signed_in');
    }
    // Tokens issued after the handoff closed were dropped; say what happened to the provider grant, in the
    // audit and, when the handoff is closed, in its outcome where the owner and the agent read it.
    if(error?.code==='continuation_closed'&&error.providerGrant) {
      this.store.audit({type:'continuation.late_signin_discarded',continuationId:id,providerGrant:error.providerGrant});
      if(record&&CLOSED.has(record.status)) this.recordRevocation(id,{providerGrant:error.providerGrant});
    }
    // T1: the provider granted a permission Fabric never holds; nothing was connected, and the audit says what became of the grant.
    if(error?.code==='never_requested') this.store.audit({type:'continuation.scope_refused',continuationId:id,providerGrant:error.providerGrant??'may_remain'});
    // A wrong-browser or replayed callback never consumed this flow; the real one may still arrive.
    if(!ours||error?.code==='invalid_state') return record;
    const outcome=error?.code==='consent_denied'?'declined_at_provider':error?.code==='insufficient_scope'?'insufficient_scope':error?.code==='never_requested'?'scope_refused':'sign_in_failed';
    return this.write(record,{status:'awaiting_owner',signIn:null,superseded:[record.signIn.flowIdHash,...(record.superseded||[])].slice(0,5),lastAttempt:{outcome,at:this.iso()}},'signin_failed');
  }
  /** Owner confirms the verified identity of the quarantined account; Fabric then derives the request. */
  async confirm(id,body,principal) {
    this.assertEnabled();
    if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).some(key=>key!=='confirmDigest')) fail('invalid_request','Only the confirmation digest is accepted.');
    let record=this.ownerRecord(id,principal);
    if(record.status!=='awaiting_confirmation') fail('invalid_transition','There is no signed-in account to confirm.');
    const view=this.ownerView(id);
    if(typeof body.confirmDigest!=='string'||body.confirmDigest!==view.confirmDigest) fail('view_changed','The signed-in account or its permissions changed. Review it again.',{view});
    const pending=record.pendingConnection,stored=this.quarantined(record);
    let generation=null;try {generation=stored?this.store.connectionGeneration(stored.id):null;} catch {}
    if(!stored||generation!==pending.generation||canonicalHash(stored.identity||{})!==pending.identityHash) {
      this.close(record,'failed','authority_changed','failed');
      fail('authority_changed','The signed-in account changed before confirmation. It was disconnected.');
    }
    const client=this.protocol.activeClient(record.clientId),actor=this.protocol.principalForClient(client);
    if(!same(actor,record.request.principal)||!(client.requestable||[]).some(entry=>same(entry,record.grantEntry))) fail('authority_changed','The requesting client changed. No account was bound.');
    this.assertNoJob(record);
    const decidedAt=this.decisionTime(record);
    record=this.write(record,{status:'binding',binding:{via:'confirm',connectionId:stored.id,generation:pending.generation,identityHash:pending.identityHash,
      policyRevision:view.pendingConnection.policy.revision,mode:view.pendingConnection.policy.mode,decidedAt,jobId:randomUUID(),derivedRequestHash:null}},'confirmed');
    // Promotion changes only a health field, so the account's authority generation is unchanged.
    this.store.put('connections',{...this.store.get('connections',stored.id),status:'ready',updatedAt:this.iso()});
    if(this.store.connectionGeneration(stored.id)!==pending.generation) {this.close(this.load(id),'failed','authority_changed','failed');fail('authority_changed','The account changed while it was being confirmed.');}
    // F10.7 (decision 9): a first sign-in has no card, so what its sign-in asked for stands in for one, and whatever else the provider
    // granted starts at Ask, typed and raw, before the request is derived. Saved settings leave the authority generation as it is.
    this.connections?.upgradeGuard?.(null,this.store.get('connections',stored.id),this.plannedScopes(record));
    return this.derive(record,actor);
  }
  /** Owner says the signed-in account is the wrong one: revoke it and let them try again. */
  async rejectAccount(id,body,principal) {
    this.assertEnabled();
    if(body&&(typeof body!=='object'||Array.isArray(body)||Object.keys(body).length)) fail('invalid_request','Rejecting an account accepts no fields.');
    const record=this.ownerRecord(id,principal);
    if(record.status!=='awaiting_confirmation') fail('invalid_transition','There is no signed-in account to reject.');
    const quarantined=this.quarantined(record);
    if(!quarantined) {this.close(record,'failed','authority_changed','failed');fail('authority_changed','The signed-in account changed. Nothing was revoked; the agent must ask again.');}
    this.write(record,{status:'awaiting_owner',pendingConnection:null,signIn:null,superseded:record.signIn?[record.signIn.flowIdHash,...(record.superseded||[])].slice(0,5):record.superseded||[],lastAttempt:{outcome:'wrong_account',at:this.iso()}},'account_rejected');
    await this.revokeRemotely(record,quarantined.id);
    return this.ownerView(id);
  }

  // ---- authorization branch for derived jobs ------------------------------------------
  /** The only authority a derived job has: its handoff, for exactly one job id. Never grant bindings. */
  assertJobAuthority(job) {
    if(!this.enabled) fail('permission_denied','Continued requests require designated authority mode.');
    const source=job.source;
    if(!source||Object.keys(source).sort().join()!=='clientId,continuationId,kind,requestId'||source.kind!=='client') fail('permission_denied','The continued request source is malformed.');
    let record;
    try {record=this.load(source.continuationId);} catch {fail('permission_denied','The account request failed its integrity check.');}
    if(!record||record.clientId!==source.clientId||source.requestId!==`${record.id}@continuation`||!['binding','resumed'].includes(record.status)||record.binding?.jobId!==job.id) fail('permission_denied','This request is not the one the owner bound.');
    const client=this.protocol.activeClient(record.clientId),actor=this.protocol.principalForClient(client);
    if(!(client.requestable||[]).some(entry=>same(entry,record.grantEntry))) fail('permission_denied','The client is no longer allowed to request this operation.');
    const request=job.executionRequest;
    if(!request||!same(actor,record.request.principal)||!same(actor,request.principal)) fail('permission_denied','The requesting client changed.');
    const {binding}=record;
    let generation;try {generation=this.store.connectionGeneration(job.connectionId);} catch {fail('permission_denied','The selected account changed.');}
    if(job.connectionId!==binding.connectionId||request.access?.generation!==binding.generation||generation!==binding.generation) fail('permission_denied','The selected account changed.');
    if(record.status==='resumed'&&job.executionRequestHash!==binding.derivedRequestHash) fail('permission_denied','The continued request was replaced.');
    const cap=this.store.get('capabilities',job.capabilityId);
    if(!cap||!same(this.runtime.capabilityReference(cap),record.request.capability)) fail('permission_denied','The operation changed.');
    try {assertDerivedRequest({original:record.request,continuation:record.contract,derived:request,binding:{connectionId:binding.connectionId,generation:binding.generation,policyRevision:binding.policyRevision,decidedAt:binding.decidedAt}});}
    catch {fail('permission_denied','The continued request no longer matches the owner decision.');}
  }

  /** Restart recovery. Never creates or dispatches a job. */
  recover() {
    if(!this.enabled) return;
    this.recoverRecords();
    // A quarantined account not held by a handoff awaiting confirmation is an orphan: revoke it.
    for(const connection of this.store.list('connections')) {
      if(['ready','revoked'].includes(connection.status)||connection.origin?.kind!=='continuation') continue;
      const owner=this.store.get(CONTINUATIONS,connection.origin.continuationId);
      if(confirmedThrough(owner,connection)) continue;
      if(owner?.status!=='awaiting_confirmation'||owner.pendingConnection?.connectionId!==connection.id) {try {this.connections?.revoke(connection.id);} catch {}}
    }
  }
  /** One bad record never aborts startup: each is recovered on its own, and an unreadable one is closed failed. */
  recoverRecords() {
    for(const stored of this.store.list(CONTINUATIONS)) {
      try {this.recoverRecord(stored);} catch {this.failUnreadable(stored,'recovery_failed');}
    }
  }
  /** An unreadable or unrecoverable record never yields a job: it is closed failed with an audit entry saying
   *  which (integrity or recovery_failed), and a pending job it names is cancelled. Its clientId may itself be
   *  tampered, so it is not recorded. */
  failUnreadable(stored,reason='integrity') {
    if(TERMINAL.has(stored?.status)) return;
    try {
      const jobId=stored.binding?.jobId,job=typeof jobId==='string'?this.store.get('jobs',jobId):null;
      if(job?.source?.continuationId===stored.id) try {this.runtime.cancel(job.id);} catch {}
      this.store.put(CONTINUATIONS,{...stored,status:'failed',outcome:{code:'fabric_failed',at:this.iso()},revision:(Number.isSafeInteger(stored.revision)?stored.revision:0)+1,updatedAt:this.iso()});
      this.store.audit({type:'continuation.failed',continuationId:String(stored.id),code:'fabric_failed',reason});
    } catch {}
  }
  recoverRecord(stored) {
    let record;
    try {record=this.load(stored.id);} catch {return this.failUnreadable(stored);}
    if(!record) return;
    if(PRE_BIND.has(record.status)) {
      const current=this.touch(record);
      // A flow consumed without a recorded outcome (crash during callback) returns the owner to the choice.
      if(current.status==='signing_in'&&!this.store.list('oauthFlows').some(flow=>flow.flowIdHash===current.signIn?.flowIdHash)) this.write(current,{status:'awaiting_owner',signIn:null,superseded:[current.signIn.flowIdHash,...(current.superseded||[])].slice(0,5),lastAttempt:{outcome:'sign_in_interrupted',at:this.iso()}},'signin_failed');
      return;
    }
    if(record.status!=='binding') return;
    const job=this.store.get('jobs',record.binding.jobId);
    if(!job) return this.close(record,'failed','fabric_failed','failed');
    // A binding that names a job this handoff did not create is never trusted, and that job is left alone.
    if(job.source?.continuationId!==record.id) return this.close(record,'failed','authority_changed','failed');
    try {
      assertDerivedRequest({original:record.request,continuation:record.contract,derived:job.executionRequest,binding:{connectionId:record.binding.connectionId,generation:record.binding.generation,policyRevision:record.binding.policyRevision,decidedAt:record.binding.decidedAt}});
      this.write(record,{status:'resumed',binding:{...record.binding,derivedRequestHash:job.executionRequestHash}},'resumed',{jobId:job.id});
    } catch {
      try {this.runtime.cancel(job.id);} catch {}
      this.close(record,'failed','authority_changed','failed');
    }
  }
}

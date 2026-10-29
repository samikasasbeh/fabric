import {randomBytes,randomUUID,createHash,timingSafeEqual} from 'node:crypto';
import {canonicalHash} from './compiler.mjs';
import {validatePrincipal} from '../contracts/identity.mts';
import {assertConnectionAuthority,captureConnectionAuthority} from './authority-guard.mjs';
import {validateExecutionRequest,hashExecutionRequest} from '../contracts/execution.mts';
const digest=value=>createHash('sha256').update(value).digest('hex');
const timestamp=()=>new Date().toISOString();
const HEARTBEAT_MAX_AGE=90_000;
const OBSERVATION_MAX_AGE=120_000;
const boundedTitle=value=>typeof value==='string'?value.replace(/[\u0000-\u001f\u007f]/g,' ').slice(0,160):null;
const validPastTime=(value,now)=>typeof value==='string'&&Number.isFinite(Date.parse(value))&&Date.parse(value)<=now;
const durable=connection=>connection?.bridgeVersion==='0.3'&&connection?.sessionScope==='browser-profile';
const authError=message=>Object.assign(new Error(message),{code:'browser_revoked'});
export class BrowserBridge {
  constructor({store,catalog,ownerPrincipal}) {
    Object.assign(this,{store,catalog});this.pending=new Map();
    this.ownerPrincipal=store.authorityEnabled&&ownerPrincipal?validatePrincipal(ownerPrincipal):null;
    if(this.ownerPrincipal&&this.ownerPrincipal.kind!=='local_owner')throw authError('The configured local owner is required.');
    // A process restart loses the in-memory exact-job authorization. Never replay queued browser work.
    for(const command of store.list('browserCommands')) if(['queued','dispatched'].includes(command.status)) {
      store.put('browserCommands',{...command,status:'expired',completedAt:timestamp()});
      if(!store.authorityEnabled)this.recordReadAttempt(command,'cancelled');
    }
  }
  assertOwner(principal=this.ownerPrincipal) {
    if(!this.store.authorityEnabled)return;
    const actor=validatePrincipal(principal);
    if(!this.ownerPrincipal||actor.kind!=='local_owner'||canonicalHash(actor)!==canonicalHash(this.ownerPrincipal))throw authError('The exact configured local owner is required.');
    const saved=this.store.get('localDeployment','owner');
    if(saved&&canonicalHash(saved.ownerPrincipal)!==canonicalHash(actor))throw authError('The saved deployment owner changed.');
  }
  deviceBinding(device,connection) {
    return canonicalHash({id:device.id,appId:connection.appId,origin:device.origin,tokenHash:device.tokenHash,bridgeVersion:device.bridgeVersion,sessionScope:device.sessionScope??null,createdAt:device.createdAt,consentId:device.consentId});
  }
  helperAuthority(device) {
    if(!this.store.authorityEnabled)return null;
    this.assertOwner();
    const consent=device&&this.store.get('browserHelperConsents',device.consentId);
    if(!consent||consent.schemaVersion!==1||consent.id!==device.consentId||canonicalHash(consent.ownerPrincipal)!==canonicalHash(this.ownerPrincipal))throw authError('Browser consent provenance is missing. Reconnect the application.');
    const connection=assertConnectionAuthority(this.store,consent.connectionAuthority);
    if(connection.id!==device.id||connection.driver!=='browser'||connection.status==='revoked'||connection.transport==='persistent'||connection.consentId!==device.consentId||
       connection.bridgeVersion!==device.bridgeVersion||connection.sessionScope!==device.sessionScope||!connection.allowedOrigins?.includes(device.origin)||consent.deviceBinding!==this.deviceBinding(device,connection))throw authError('Browser consent no longer matches this helper.');
    return {schemaVersion:1,consentId:consent.id,connectionAuthority:consent.connectionAuthority};
  }
  commandHash(command) {
    return canonicalHash({id:command.id,connectionId:command.connectionId,action:command.action,args:command.args,createdAt:command.createdAt,expiresAt:command.expiresAt,authority:command.authority,executionRequest:command.executionRequest});
  }
  authorizeRequest(connectionId,action,args,authorize,accepted) {
    const decision=authorize();
    if(!this.store.authorityEnabled)return null;
    if(decision instanceof Promise){decision.catch(()=>{});throw authError('Browser runtime authorization must be synchronous.');}
    const request=validateExecutionRequest(decision?.request),connection=this.store.get('connections',connectionId),cap=decision?.cap;
    const actor=request.principal,owner=this.ownerPrincipal;
    if(!owner||canonicalHash(request.scope)!==canonicalHash(owner.scope)||
       (actor.kind==='local_owner'?canonicalHash(actor)!==canonicalHash(owner):actor.kind!=='local_client'||actor.delegatedBy.id!==owner.id)||
       request.access.kind!=='connection'||request.access.id!==connectionId||request.access.generation!==this.store.connectionGeneration(connectionId)||
       request.capability.appId!==connection?.appId||canonicalHash(request.args)!==canonicalHash(args)||
       cap?.driver!=='browser'||cap.appId!==connection?.appId||canonicalHash(cap.action)!==canonicalHash(action)||
       request.capability.id!==cap.id||request.capability.version!==cap.version||request.capability.definitionHash!==canonicalHash(cap)||
       request.capability.effect!==(['click','fill'].includes(action.op)?'write':'read')||Date.parse(request.deadline)<=Date.now()||Date.parse(request.createdAt)>Date.now()||
       (accepted&&hashExecutionRequest(request)!==hashExecutionRequest(accepted)))throw authError('Browser execution request no longer matches its accepted authority.');
    return request;
  }
  assertCommand(command,pending,status) {
    if(!this.store.authorityEnabled)return;
    if(!pending?.accepted||!command||!['queued','dispatched'].includes(command.status)||(status&&command.status!==status)||this.commandHash(command)!==this.commandHash(pending.accepted))throw authError('Browser command no longer matches its accepted request.');
    if(status&&(!Number.isFinite(Date.parse(command.expiresAt))||Date.parse(command.expiresAt)<=Date.now()))throw authError('Browser command expired during authorization. Any dispatched action effect is unknown.');
    const device=this.store.get('browserDevices',command.connectionId),authority=this.helperAuthority(device);
    if(canonicalHash(command.authority)!==canonicalHash(authority))throw authError('Browser command authority changed.');
  }
  // Public evidence is computed from current persisted authority, never a caller's
  // stale connection snapshot. A paired tab, heartbeat, or DOM read is not login.
  getConnectionEvidence(connection) {
    if(connection?.driver!=='browser')return null;
    const current=this.store.get('connections',connection.id),device=this.store.get('browserDevices',connection.id),now=Date.now();
    if(this.store.authorityEnabled)try{this.helperAuthority(device);}catch{return {bridge:{status:current?.status==='revoked'?'revoked':'unavailable',origin:null,lastHeartbeatAt:null},account:{status:'unverified',verified:false},page:{status:'not_observed',lastAttempt:null},observedPage:null};}
    const lastHeartbeatAt=validPastTime(device?.lastHeartbeatAt,now)?device.lastHeartbeatAt:null;
    const status=current?.status==='revoked'?'revoked':!current||!device?'unavailable':!lastHeartbeatAt?'waiting':now-Date.parse(lastHeartbeatAt)<HEARTBEAT_MAX_AGE?'alive':'stale';
    const saved=device?.observedPage;
    const observedPage=saved&&saved.origin===device.origin&&validPastTime(saved.observedAt,now)?{observedAt:saved.observedAt,origin:device.origin,title:boundedTitle(saved.title)}:null;
    const attempt=device?.lastReadAttempt;
    const lastAttempt=attempt&&['succeeded','failed','timed_out','cancelled'].includes(attempt.status)&&validPastTime(attempt.at,now)?{status:attempt.status,at:attempt.at}:null;
    const latestFailed=lastAttempt&&lastAttempt.status!=='succeeded'&&(!observedPage||Date.parse(lastAttempt.at)>=Date.parse(observedPage.observedAt));
    const executionState=durable(current)&&['idle','open'].includes(device?.executionState)?device.executionState:'unknown';
    const pageStatus=!observedPage?'not_observed':status==='alive'&&!latestFailed&&(!durable(current)||(executionState==='open'&&!device.observationInvalidated))&&now-Date.parse(observedPage.observedAt)<OBSERVATION_MAX_AGE?'observed':'stale';
    return {bridge:{status,origin:device?.origin||null,lastHeartbeatAt,...(durable(current)?{scope:'browser-profile',executionState}:{})},account:{status:'unverified',verified:false},page:{status:pageStatus,lastAttempt},observedPage};
  }
  recordReadAttempt(command,status,data) {
    if(!['observe','read'].includes(command?.action?.op))return;
    const device=this.store.get('browserDevices',command.connectionId);
    if(!device)return;
    if(this.store.authorityEnabled)try{if(canonicalHash(command.authority)!==canonicalHash(this.helperAuthority(device)))return;}catch{return;}
    const at=timestamp();
    device.lastReadAttempt={status,at};
    if(status==='succeeded'&&data?.origin===device.origin) {
      device.observedPage={observedAt:at,origin:device.origin,title:boundedTitle(data.title)};
      if(device.sessionScope==='browser-profile'){device.executionState='open';device.observationInvalidated=false;}
    }
    this.store.put('browserDevices',device);
  }
  createPair(appId,principal) {
    if(this.store.authorityEnabled){if(!principal)throw authError('Trusted owner approval is required.');this.assertOwner(principal);}
    const app=this.catalog().find(a=>a.id===appId);const origins=app?.webOrigins||[];
    if(!origins.length) throw new Error('This application has no declared browser origin. Add its manifest first.');
    const code=randomBytes(6).toString('hex').toUpperCase(),pairingId=randomUUID(),expiresAt=Date.now()+5*60_000;
    const authority=this.store.authorityEnabled?{schemaVersion:1,consentId:randomUUID(),ownerPrincipal:this.ownerPrincipal,appId,origins:[...origins],expiresAt,pairingId}:null;
    this.store.put('pairings',{id:digest(code),pairingId,appId,origins,expiresAt,...(authority?{authority}:{})});
    this.store.put('pairingSessions',{id:pairingId,appId,status:'pending',expiresAt,createdAt:timestamp(),...(authority?{authority}:{})});
    return {pairingId,code,appId,appName:app.name||appId,bridgeVersion:'0.3',sessionScope:'browser-profile',launchUrl:origins[0],expiresAt:new Date(expiresAt).toISOString(),origins,instructions:'Approve saved app access in the Fabric browser helper. Approved reads can open a temporary tab in this browser profile until you disconnect. Sign-in remains managed by the website; cookies stay in the browser.'};
  }
  // Expose this only through the product's same-origin session API. The random ID
  // locates a setup attempt; it is never a substitute for the secret pairing code.
  status(pairingId) {
    if(typeof pairingId!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(pairingId)) throw new Error('Unknown browser pairing session.');
    const session=this.store.get('pairingSessions',pairingId);
    if(!session) throw new Error('Unknown browser pairing session.');
    if(session.status==='pending'&&session.expiresAt<=Date.now()) {session.status='expired';this.store.put('pairingSessions',session);}
    let status=session.status,connectionStatus;
    if(status==='paired') {
      const connection=this.store.get('connections',session.connectionId);
      if(!connection||connection.appId!==session.appId||connection.driver!=='browser'||connection.status==='revoked') status='revoked';
      else if(this.store.authorityEnabled)try{const a=this.helperAuthority(this.store.get('browserDevices',connection.id));if(a.consentId!==session.authority?.consentId)throw authError('Stale pairing.');connectionStatus=connection.status;}catch{status='revoked';}
      else connectionStatus=connection.status;
    }
    return {pairingId,appId:session.appId,status,expiresAt:new Date(session.expiresAt).toISOString(),...(session.connectionId?{connectionId:session.connectionId}:{}),...(connectionStatus?{connectionStatus}:{}),...(session.pairedAt?{pairedAt:session.pairedAt}:{})};
  }
  pair(input) {
    if(this.store.authorityEnabled){canonicalHash(input);if(Object.keys(input).some(key=>!['code','origin','label','bridgeVersion','sessionScope'].includes(key)))throw authError('Unexpected browser pairing fields.');}
    const {code,origin,label,bridgeVersion,sessionScope}=input;
    if((bridgeVersion==='0.3'&&sessionScope!=='browser-profile')||(sessionScope!==undefined&&(bridgeVersion!=='0.3'||sessionScope!=='browser-profile'))) throw new Error('Saved browser access requires helper v0.3 and explicit browser-profile scope approval.');
    if(typeof code!=='string'||code.length>30) throw new Error('Invalid pairing code.');
    const pair=this.store.get('pairings',digest(code.trim().toUpperCase()));
    if(!pair||pair.expiresAt<=Date.now()) throw new Error('Pairing code expired or already used.');
    if(!pair.origins.includes(origin)) throw new Error('The selected tab does not match the requested application origin.');
    const session=pair.pairingId?this.store.get('pairingSessions',pair.pairingId):null;
    if(pair.pairingId&&(!session||session.status!=='pending'||session.expiresAt<=Date.now())) throw new Error('Pairing code expired or already used.');
    if(this.store.authorityEnabled){
      this.assertOwner();
      const authority=pair.authority;
      if(!authority||authority.schemaVersion!==1||typeof authority.consentId!=='string'||!authority.consentId||canonicalHash(authority)!==canonicalHash(session?.authority)||canonicalHash(authority.ownerPrincipal)!==canonicalHash(this.ownerPrincipal)||
         authority.appId!==pair.appId||session.appId!==pair.appId||authority.pairingId!==pair.pairingId||authority.expiresAt!==pair.expiresAt||session.expiresAt!==pair.expiresAt||canonicalHash(authority.origins)!==canonicalHash(pair.origins))throw authError('Browser pairing consent changed or is missing. Start a new connection.');
    }
    const token=randomBytes(32).toString('base64url');const id=randomUUID();
    this.store.delete('pairings',pair.id);
    const version=['0.2','0.3'].includes(bridgeVersion)?bridgeVersion:'0.1',saved=version==='0.3';
    const consentId=pair.authority?.consentId;
    const device={id,tokenHash:digest(token),origin,bridgeVersion:version,...(saved?{sessionScope,executionState:'idle',observationInvalidated:true}:{}),createdAt:timestamp(),...(this.store.authorityEnabled?{consentId}:{})};
    const connection={id,appId:pair.appId,driver:'browser',authMethod:'browser',bridgeVersion:version,...(saved?{sessionScope}:{}),label:String(label||origin).slice(0,100),status:'session_ready',identity:{id:`browser:${id}`,displayName:`${saved?'Saved app access':'Paired browser'}: ${origin}`,binding:saved?'origin-and-browser-profile; provider account not independently verified':'origin-and-tab; provider account not independently verified',...(saved?{verified:false}:{})},allowedOrigins:[origin],createdAt:timestamp(),updatedAt:timestamp(),lastCheckedAt:timestamp()};
    if(this.store.authorityEnabled){
      connection.consentId=consentId;
      // Persist parent, then side authority, then bind the FINAL generation in a
      // separate grant. A partial save has no usable token; never stamp a side
      // document with the generation that its own write would invalidate.
      this.store.put('connections',connection);this.store.put('browserDevices',device);
      this.store.put('browserHelperConsents',{id:consentId,schemaVersion:1,ownerPrincipal:this.ownerPrincipal,connectionAuthority:captureConnectionAuthority(this.store,id),deviceBinding:this.deviceBinding(device,connection)});
    }else{this.store.put('browserDevices',device);this.store.put('connections',connection);}
    this.store.audit({type:'browser.paired',connectionId:id,appId:pair.appId});
    this.seedCapabilities(pair.appId,version);
    if(session) this.store.put('pairingSessions',{...session,status:'paired',connectionId:id,pairedAt:timestamp()});
    return {connection,token,pairingId:pair.pairingId};
  }
  seedCapabilities(appId,version='0.1') {
    for(const op of ['observe','read']) {
      const cap={id:`${appId}.browser.${op}.v1`,specVersion:'fabric/0.1',version:1,appId,driver:'browser',name:op==='observe'?'Inspect app page':'Read a page element',description:'Read access bounded by the selected browser connection and its approval. No cookies or credentials are exported.',status:'active',effect:'read',action:{op},inputSchema:{type:'object',properties:op==='read'?{selector:{type:'string',minLength:1,maxLength:500}}:{},required:op==='read'?['selector']:[],additionalProperties:false},provenance:{kind:'builtin',source:'read-only browser bridge v1'},verification:{kind:'observed-browser-state'}};
      if(!this.store.get('capabilities',cap.id)) this.store.put('capabilities',cap);
    }
    if(['0.2','0.3'].includes(version)) for(const op of ['click','fill']) {
      const properties={snapshotId:{type:'string',minLength:1,maxLength:100},targetId:{type:'string',minLength:1,maxLength:100},...(op==='fill'?{value:{type:'string',maxLength:10000}}:{})};
      const cap={id:`${appId}.browser.${op}.v2`,specVersion:'fabric/0.1',version:2,appId,driver:'browser',name:op==='click'?'Click an inspected control':'Fill an inspected field',description:'Requires a recent page inspection and exact-action approval. Credentials and sensitive fields are excluded. A dispatched action is not proof of a saved provider change.',status:'active',effect:'write',action:{op},inputSchema:{type:'object',properties,required:Object.keys(properties),additionalProperties:false},provenance:{kind:'builtin',source:'browser bridge v0.2; observed targets only'},verification:{kind:'browser-dispatch-unverified'}};
      if(!this.store.get('capabilities',cap.id)) this.store.put('capabilities',cap);
    }
  }
  authenticate(token) {
    if(typeof token!=='string'||token.length>256) throw authError('Browser pairing authorization required.');
    const computed=digest(token);
    for(const device of this.store.list('browserDevices')) if(typeof device.tokenHash==='string'&&/^[a-f0-9]{64}$/.test(device.tokenHash)&&timingSafeEqual(Buffer.from(device.tokenHash),Buffer.from(computed))) {
      const c=this.store.get('connections',device.id);if(c&&c.status!=='revoked'){this.helperAuthority(device);return device;}
    }
    throw authError('Browser pairing revoked or unknown.');
  }
  poll(token,data={}) {
    if(this.store.authorityEnabled){canonicalHash(data);data=JSON.parse(JSON.stringify(data));}
    const device=this.authenticate(token);const connection=this.store.get('connections',device.id);
    if(durable(connection)) {
      // A heartbeat means the helper is reachable, not that a site or login is.
      device.executionState=['idle','open'].includes(data?.execution?.state)?data.execution.state:'unknown';
      if(device.executionState!=='open')device.observationInvalidated=true;
    }
    device.lastHeartbeatAt=timestamp();this.store.put('browserDevices',device);
    connection.lastCheckedAt=timestamp();connection.updatedAt=timestamp();connection.status='session_ready';this.store.put('connections',connection);
    const command=this.store.list('browserCommands').find(c=>c.connectionId===device.id&&c.status==='queued');
    if(!command) return {command:null};
    const pending=this.pending.get(command.id);
    if(!pending) {this.store.put('browserCommands',{...command,status:'expired',completedAt:timestamp()});if(!this.store.authorityEnabled)this.recordReadAttempt(command,'cancelled');return {command:null};}
    if(command.expiresAt&&Date.parse(command.expiresAt)<=Date.now()) {
      this.recordPendingAttempt(command,pending,'timed_out');this.terminalCommand(command,pending,'expired');
      this.pending.delete(command.id);clearTimeout(pending.timer);pending.reject(new Error('Browser request expired before dispatch. Inspect the page and create a new request.'));
      return {command:null};
    }
    try {this.assertCommand(command,pending,'queued');this.authorizeRequest(command.connectionId,command.action,command.args,pending.authorize,pending.accepted?.executionRequest);this.assertCommand(this.store.get('browserCommands',command.id),pending,'queued');}
    catch(error) {
      this.recordPendingAttempt(command,pending,'cancelled');
      this.terminalCommand(command,pending,'cancelled');
      this.pending.delete(command.id);clearTimeout(pending.timer);pending.reject(error);
      return {command:null};
    }
    command.status='dispatched';command.dispatchedAt=timestamp();this.store.put('browserCommands',command);
    return {command:{id:command.id,origin:device.origin,action:command.action,args:command.args,...(command.expiresAt?{expiresAt:command.expiresAt}:{})}};
  }
  result(token,input) {
    if(this.store.authorityEnabled){canonicalHash(input);input=JSON.parse(JSON.stringify(input));}
    const {id,ok,data,error}=input;
    const device=this.authenticate(token);const command=this.store.get('browserCommands',id);
    if(!command||command.connectionId!==device.id||command.status!=='dispatched') throw new Error('No matching outstanding browser command.');
    if(this.store.authorityEnabled)canonicalHash(data??null);
    if(JSON.stringify(data??null).length>65000) throw new Error('Browser result exceeds size limit.');
    const pending=this.pending.get(id);
    if(!pending) {this.store.put('browserCommands',{...command,status:'expired',completedAt:timestamp()});if(!this.store.authorityEnabled)this.recordReadAttempt(command,'cancelled');throw new Error('The browser command no longer has an active execution authorization.');}
    if(command.expiresAt&&Date.parse(command.expiresAt)<=Date.now()) {
      this.recordPendingAttempt(command,pending,'timed_out');this.terminalCommand(command,pending,'expired');
      this.pending.delete(id);clearTimeout(pending.timer);pending.reject(new Error('Browser request expired before its response arrived. Any action effect is unknown; inspect the application before requesting another action.'));
      return {accepted:false};
    }
    try {this.assertCommand(command,pending,'dispatched');this.authorizeRequest(command.connectionId,command.action,command.args,pending.authorize,pending.accepted?.executionRequest);this.assertCommand(this.store.get('browserCommands',id),pending,'dispatched');}
    catch(error) {
      this.recordPendingAttempt(command,pending,'cancelled');
      this.terminalCommand(command,pending,'cancelled');
      this.pending.delete(id);clearTimeout(pending.timer);pending.reject(error);
      return {accepted:false};
    }
    const write=['click','fill'].includes(command.action.op);
    device.lastHeartbeatAt=timestamp();this.store.put('browserDevices',device);
    // Even an authenticated helper must bind read evidence to the exact paired
    // origin. Missing or unrelated page data cannot become a successful read.
    if(ok===true&&!write&&(!data||typeof data!=='object'||Array.isArray(data)||data.origin!==device.origin)) {
      this.store.put('browserCommands',{...command,status:'failed',completedAt:timestamp()});
      this.recordReadAttempt(command,'failed');
      this.pending.delete(id);clearTimeout(pending.timer);pending.reject(new Error('Browser read result did not match the paired origin.'));
      return {accepted:false};
    }
    if(ok===true&&write&&(!data||typeof data!=='object'||Array.isArray(data)||data.origin!==device.origin||
       data.operation!==command.action.op||data.targetId!==command.args.targetId||data.dispatchStatus!=='dispatched'||data.persistentEffect!=='unverified')) {
      this.store.put('browserCommands',{...command,status:'failed',completedAt:timestamp()});
      this.pending.delete(id);clearTimeout(pending.timer);pending.reject(new Error('Browser action receipt did not match the approved origin, operation and target. Its effect is unknown; inspect before requesting another action.'));
      return {accepted:false};
    }
    command.status=ok===true?'done':'failed';command.completedAt=timestamp();this.store.put('browserCommands',command);
    this.recordReadAttempt(command,ok===true?'succeeded':'failed',data);
    this.pending.delete(id);clearTimeout(pending.timer);if(ok===true) pending.resolve({data,verification:{status:write?'unverified':'observed',kind:write?'paired-browser-dispatch':'paired-browser-dom',origin:device.origin,checkedAt:timestamp()}});else pending.reject(new Error(`Browser operation failed: ${String(error||'Unknown error').slice(0,180)}`));
    return {accepted:true};
  }
  async execute(connectionId,action,args,authorize) {
    if(this.store.authorityEnabled){canonicalHash({connectionId,action,args});action=JSON.parse(JSON.stringify(action));args=JSON.parse(JSON.stringify(args));if(typeof authorize!=='function')throw authError('Browser requests require exact-job runtime authorization.');}
    if(!['observe','read','click','fill'].includes(action.op)) throw new Error('Unsupported browser operation. No JavaScript or shell execution is supported.');
    const c=this.store.get('connections',connectionId);if(!c||c.status==='revoked') throw new Error('Browser connection revoked.');
    const write=['click','fill'].includes(action.op);
    if(write) {
      if(c.bridgeVersion!=='0.2'&&!durable(c)) throw new Error('Reconnect with browser helper v0.2 or later before requesting an action.');
      if(typeof authorize!=='function') throw new Error('Browser actions require exact-job runtime authorization.');
      const keys=action.op==='fill'?['snapshotId','targetId','value']:['snapshotId','targetId'];
      if(!args||typeof args!=='object'||Object.keys(args).some(key=>!keys.includes(key))||keys.some(key=>typeof args[key]!=='string')||!args.snapshotId||!args.targetId||args.snapshotId.length>100||args.targetId.length>100||(args.value?.length||0)>10000) throw new Error('Browser actions require observed snapshot and target identifiers, and only the declared action arguments.');
    }
    authorize=typeof authorize==='function'?authorize:()=>{};
    const authority=this.helperAuthority(this.store.get('browserDevices',connectionId));
    const executionRequest=this.authorizeRequest(connectionId,action,args,authorize);
    if(this.store.authorityEnabled&&canonicalHash(authority)!==canonicalHash(this.helperAuthority(this.store.get('browserDevices',connectionId))))throw authError('Browser consent changed before queueing.');
    // Account for the 30-second MV3 poll interval plus bounded page startup.
    const timeoutMs=durable(c)?75_000:40_000;
    const id=randomUUID();const command=this.store.put('browserCommands',{id,connectionId,action,args,status:'queued',createdAt:timestamp(),expiresAt:new Date(Date.now()+timeoutMs).toISOString(),...(this.store.authorityEnabled?{authority,executionRequest}:{})});
    const accepted=this.store.authorityEnabled?JSON.parse(JSON.stringify(command)):null;
    return new Promise((resolve,reject)=> {
      const timer=setTimeout(()=>{const item=this.pending.get(id);this.pending.delete(id);const current=this.store.get('browserCommands',id);if(current){this.recordPendingAttempt(current,item,'timed_out');this.terminalCommand(current,item,'expired');}reject(new Error(write?'Browser action response was not received. Its effect is unknown; inspect the application before requesting another action.':durable(c)?'Browser helper did not respond. Open its Chrome or Edge profile and request the read again. No job will be replayed automatically.':'Paired browser did not respond. Open the extension on its paired tab and retry this read.'));},timeoutMs);
      this.pending.set(id,{resolve,reject,timer,authorize,accepted});
    });
  }
  recordPendingAttempt(command,pending,status) {
    if(this.store.authorityEnabled){try{this.assertCommand(this.store.get('browserCommands',command.id),pending);}catch{return;}this.recordReadAttempt(pending.accepted,status);}
    else this.recordReadAttempt(command,status);
  }
  terminalCommand(command,pending,status) {
    const current=this.store.get('browserCommands',command.id);
    if(this.store.authorityEnabled){try{if(!pending?.accepted||!current||!['queued','dispatched'].includes(current.status)||this.commandHash(current)!==this.commandHash(pending.accepted))return;}catch{return;}}
    if(current)this.store.put('browserCommands',{...current,status,completedAt:timestamp()});
  }
  check(id) {const c=this.store.get('connections',id);if(!c) throw new Error('Connection not found.');if(c.status==='revoked') return c;if(this.store.authorityEnabled)this.helperAuthority(this.store.get('browserDevices',id));c.status=this.getConnectionEvidence(c)?.bridge.status==='alive'?'session_ready':'unavailable';c.updatedAt=timestamp();this.store.put('connections',c);return c;}
  close() {for(const [id,item] of this.pending){clearTimeout(item.timer);const command=this.store.get('browserCommands',id);if(command){this.recordPendingAttempt(command,item,'cancelled');this.terminalCommand(command,item,'expired');}item.reject(new Error('Browser bridge stopped.'));}this.pending.clear();}
}

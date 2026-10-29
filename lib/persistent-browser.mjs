import {randomUUID} from 'node:crypto';
import {constants} from 'node:fs';
import {access,chmod,lstat,mkdir,realpath,rm} from 'node:fs/promises';
import path from 'node:path';
import {isIP} from 'node:net';
import {observeBrowserPage} from './browser-observation.mjs';
import {canonicalHash} from './compiler.mjs';
import {validatePrincipal} from '../contracts/identity.mts';
import {validateExecutionRequest,hashExecutionRequest} from '../contracts/execution.mts';
import {captureConnectionAuthority,assertConnectionAuthority} from './authority-guard.mjs';

const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const now=()=>new Date().toISOString();
const boundedTitle=value=>typeof value==='string'?value.replace(/[\u0000-\u001f\u007f]/g,' ').slice(0,160):null;
function approvedOrigin(value){
  let url;try{url=new URL(value);}catch{throw new Error('A declared HTTPS application origin is required.');}
  if(url.protocol!=='https:'||url.username||url.password||url.pathname!=='/'||url.search||url.hash||(url.port&&url.port!=='443')||isIP(url.hostname.replace(/^\[|\]$/g,''))||url.hostname==='localhost'||/\.(?:localhost|local|internal)$/.test(url.hostname))throw new Error('A declared public HTTPS application origin is required.');
  return url.origin;
}
function originOf(page){try{return new URL(page.url()).origin;}catch{return null;}}

// A profile is durable local session storage, not proof of a provider login.
// This module never exports that storage or reads it to guess authentication.
export class PersistentBrowser {
  constructor({store,catalog,dataDir,launch,ownerPrincipal}){
    if(typeof dataDir!=='string'||!path.isAbsolute(dataDir)||dataDir.length>4096||/[\u0000-\u001f\u007f]/.test(dataDir))throw new Error('An absolute local data directory is required.');
    Object.assign(this,{store,catalog,dataDir:path.resolve(dataDir),launch});
    this.contexts=new Map();this.openings=new Map();this.queues=new Map();this.pages=new Map();this.crashedPages=new WeakSet();this.stopped=false;
    this.ownerPrincipal=store.authorityEnabled&&ownerPrincipal?validatePrincipal(ownerPrincipal):null;
    if(this.ownerPrincipal&&this.ownerPrincipal.kind!=='local_owner')throw new Error('The configured local owner is required.');
    this.contextAuthorities=new WeakMap();this.pageAuthorities=new WeakMap();this.openingAuthorities=new Map();this.orphanContexts=new Set();
    for(const session of store.list('persistentSessions'))if(session.state!=='revoked'){
      if(store.authorityEnabled){try{this.profileAuthority(session.id);}catch{continue;}}
      store.put('persistentSessions',{...session,state:'dormant',updatedAt:now(),observationCurrent:false});
    }
  }
  assertOwner(principal=this.ownerPrincipal){
    const actor=validatePrincipal(principal);
    if(!this.ownerPrincipal||actor.kind!=='local_owner'||canonicalHash(actor)!==canonicalHash(this.ownerPrincipal))throw new Error('The exact configured local owner is required.');
    const saved=this.store.get('localDeployment','owner');
    if(saved&&canonicalHash(saved.ownerPrincipal)!==canonicalHash(actor))throw new Error('The saved deployment owner changed.');
    return actor;
  }
  profileBinding(session){return canonicalHash({id:session.id,connectionId:session.connectionId,profileId:session.profileId,appId:session.appId,origin:session.origin,origins:session.origins,createdAt:session.createdAt,consent:session.consent,consentId:session.consentId});}
  profileAuthority(id,accepted){
    this.assertOwner();
    const session=this.store.get('persistentSessions',id),grant=session&&this.store.get('persistentProfileConsents',session.consentId);
    if(!grant||grant.schemaVersion!==1||grant.id!==session.consentId||canonicalHash(grant.ownerPrincipal)!==canonicalHash(this.ownerPrincipal))throw new Error('Saved-profile consent provenance is missing. Reconnect the application.');
    const connection=assertConnectionAuthority(this.store,grant.connectionAuthority);
    if(connection.id!==id||connection.driver!=='browser'||connection.transport!=='persistent'||connection.status==='revoked'||session.state==='revoked'||connection.consentId!==grant.id||session.consent?.granted!==true||grant.profileBinding!==this.profileBinding(session))throw new Error('Saved-profile consent authority changed.');
    const authority={schemaVersion:1,consentId:grant.id,connectionAuthority:grant.connectionAuthority};
    if(accepted&&canonicalHash(accepted)!==canonicalHash(authority))throw new Error('Saved-profile accepted authority changed.');
    return authority;
  }
  activeAuthority(id,accepted){if(this.stopped)throw new Error('Persistent browser runtime is stopped.');this.profileAuthority(id,accepted);return this.current(id);}
  resourceAuthority(id,accepted,context,page){
    const current=this.activeAuthority(id,accepted);
    if(context&&(this.contexts.get(id)!==context||canonicalHash(this.contextAuthorities.get(context))!==canonicalHash(accepted)||context.browser?.()?.isConnected?.()===false))throw new Error('The accepted browser context changed.');
    if(page&&(this.pages.get(id)!==page||page.isClosed()||this.crashedPages.has(page)||canonicalHash(this.pageAuthorities.get(page))!==canonicalHash(accepted)))throw new Error('The accepted browser page changed.');
    return current;
  }
  updateAuthority(id,accepted,fields){try{this.profileAuthority(id,accepted);this.update(id,fields);return true;}catch{return false;}}
  requestAuthority(id,action,args,authorize,accepted){
    if(typeof authorize!=='function')throw new Error('Browser observations require runtime authorization.');
    const decision=authorize();
    if(decision instanceof Promise){decision.catch(()=>{});throw new Error('Browser runtime authorization must be synchronous.');}
    const request=validateExecutionRequest(decision?.request),cap=decision?.cap,connection=this.store.get('connections',id),owner=this.ownerPrincipal,actor=request.principal;
    if(!owner||canonicalHash(request.scope)!==canonicalHash(owner.scope)||(actor.kind==='local_owner'?canonicalHash(actor)!==canonicalHash(owner):actor.kind!=='local_client'||actor.delegatedBy.id!==owner.id)||
       request.access.kind!=='connection'||request.access.id!==id||request.access.generation!==this.store.connectionGeneration(id)||request.capability.appId!==connection?.appId||canonicalHash(request.args)!==canonicalHash(args)||
       cap?.driver!=='browser'||cap.transport!=='persistent'||canonicalHash(cap.action)!==canonicalHash({...action,transport:'persistent'})||cap.appId!==connection?.appId||request.capability.id!==cap.id||request.capability.version!==cap.version||request.capability.definitionHash!==canonicalHash(cap)||request.capability.effect!=='read'||Date.parse(request.deadline)<=Date.now()||Date.parse(request.createdAt)>Date.now()||
       (accepted&&hashExecutionRequest(request)!==hashExecutionRequest(accepted)))throw new Error('Saved-profile execution request authority changed.');
    return request;
  }
  async availability(){
    if(this.launch)return {available:true};
    try{
      const {chromium}=await import('playwright');
      await access(chromium.executablePath(),constants.X_OK);
      return {available:true};
    }catch{return {available:false,error:'The dedicated Fabric browser is not installed. Install the Playwright dependency and its Chromium browser before connecting.'};}
  }
  current(id){
    if(typeof id!=='string'||!UUID.test(id))throw new Error('Unknown persistent browser connection.');
    const connection=this.store.get('connections',id),session=this.store.get('persistentSessions',id);
    if(!connection||connection.driver!=='browser'||connection.transport!=='persistent'||!session)throw new Error('Unknown persistent browser connection.');
    if(connection.status==='revoked'||session.state==='revoked')throw new Error('Persistent browser connection revoked.');
    const origins=session.origins||[session.origin];
    if(session.profileId!==id||session.connectionId!==id||session.appId!==connection.appId||!Array.isArray(origins)||!origins.length||origins.length>5||new Set(origins).size!==origins.length||session.origin!==origins[0]||!Array.isArray(connection.allowedOrigins)||connection.allowedOrigins.length!==origins.length||origins.some((origin,index)=>origin!==connection.allowedOrigins[index]||approvedOrigin(origin)!==origin))throw new Error('Persistent browser profile metadata is invalid.');
    if(this.store.authorityEnabled)this.profileAuthority(id);
    return {connection,session:{...session,origins}};
  }
  async guard(id,authorize){
    if(this.store.authorityEnabled)throw new Error('Legacy browser lifecycle is unavailable in authority mode.');
    if(this.stopped)throw new Error('Persistent browser runtime is stopped.');
    this.current(id);
    if(authorize)await authorize();
    if(this.stopped)throw new Error('Persistent browser runtime is stopped.');
    return this.current(id);
  }
  update(id,fields){
    const session=this.store.get('persistentSessions',id);
    if(session&&session.state!=='revoked')this.store.put('persistentSessions',{...session,...fields,updatedAt:now()});
  }
  async profileDirectory(id,{create=false}={}){
    const accepted=this.store.authorityEnabled?this.profileAuthority(id):null;
    if(!UUID.test(id)||this.store.get('persistentSessions',id)?.profileId!==id)throw new Error('Persistent browser profile metadata is invalid.');
    // Reject symlinks at each owned boundary. realpath only canonicalizes a
    // trusted parent (e.g. /var -> /private/var), never a profile redirect.
    const data=await lstat(this.dataDir);
    if(!data.isDirectory()||data.isSymbolicLink())throw new Error('The browser profile data directory must be a real directory.');
    const root=path.join(this.dataDir,'browser-profiles');
    if(create)try{await mkdir(root,{mode:0o700});}catch(error){if(error.code!=='EEXIST')throw new Error('Could not create the browser profile directory.');}
    const rootInfo=await lstat(root);
    if(!rootInfo.isDirectory()||rootInfo.isSymbolicLink()||await realpath(root)!==path.join(await realpath(this.dataDir),'browser-profiles'))throw new Error('Unsafe browser profile directory or symlink.');
    const directory=path.join(root,id);
    if(create)try{await mkdir(directory,{mode:0o700});}catch(error){if(error.code!=='EEXIST')throw new Error('Could not create the dedicated browser profile.');}
    const info=await lstat(directory);
    if(!info.isDirectory()||info.isSymbolicLink()||await realpath(directory)!==path.join(await realpath(root),id))throw new Error('Unsafe browser profile directory or symlink.');
    if(create){await chmod(root,0o700);await chmod(directory,0o700);}
    if(accepted)this.profileAuthority(id,accepted);
    return directory;
  }
  seedCapabilities(appId){
    for(const op of ['observe','read']){
      const capability={id:`${appId}.session.${op}.v1`,specVersion:'fabric/0.1',version:1,appId,driver:'browser',transport:'persistent',name:op==='observe'?'Inspect the connected application':'Read an application element',description:'Read-only observation in the dedicated Fabric browser profile. Reuses valid website sessions; account identity remains unverified. No cookies, credentials, or form values are exported.',status:'active',effect:'read',action:{op,transport:'persistent'},inputSchema:{type:'object',properties:op==='read'?{selector:{type:'string',minLength:1,maxLength:500}}:{},required:op==='read'?['selector']:[],additionalProperties:false},provenance:{kind:'builtin',source:'persistent browser read-only runtime v1'},verification:{kind:'observed-browser-state'}};
      if(!this.store.get('capabilities',capability.id))this.store.put('capabilities',capability);
    }
  }
  async connect(input,principal){
    if(this.store.authorityEnabled){canonicalHash(input);input=JSON.parse(JSON.stringify(input));if(!principal)throw new Error('Trusted owner approval is required.');principal=this.assertOwner(principal);}
    if(!input||typeof input!=='object'||Array.isArray(input)||Object.keys(input).some(key=>!['appId','consent'].includes(key))||input.consent!==true)throw new Error('Explicit browser-profile consent is required.');
    if(this.stopped)throw new Error('Persistent browser runtime is stopped.');
    let app=this.catalog().find(item=>item.id===input.appId);
    if(this.store.authorityEnabled&&app){canonicalHash(app);app=JSON.parse(JSON.stringify(app));}
    if(!app||!Array.isArray(app.webOrigins)||!app.webOrigins.length||app.webOrigins.length>5)throw new Error('This application needs one to five declared browser origins.');
    const origins=[...new Set(app.webOrigins.map(approvedOrigin))],origin=origins[0],availability=await this.availability();
    if(!availability.available)throw new Error(availability.error);
    if(this.stopped)throw new Error('Persistent browser runtime is stopped.');
    if(this.store.authorityEnabled)this.assertOwner(principal);
    const id=randomUUID(),at=now();
    const connection={id,appId:app.id,driver:'browser',authMethod:'browser',transport:'persistent',persistentSession:true,label:`${String(app.name||app.id).slice(0,80)} — dedicated browser`,status:'session_ready',identity:{id:`persistent-browser:${id}`,displayName:'Dedicated browser profile — account unverified',status:'unverified',verified:false,binding:'profile-and-origin; provider account not independently verified'},allowedOrigins:origins,expiresAt:null,grantExpiresAt:null,createdAt:at,updatedAt:at,lastCheckedAt:null};
    const consentId=this.store.authorityEnabled?randomUUID():null;
    if(consentId)connection.consentId=consentId;
    this.store.put('connections',connection);
    const session={id,connectionId:id,profileId:id,appId:app.id,origin,origins,state:'dormant',consent:{granted:true,grantedAt:at,scope:'read-only browser observation; reuse profile until disconnect',expiresAt:null},sessionEpoch:0,observationCurrent:false,createdAt:at,updatedAt:at,...(consentId?{consentId}:{})};
    this.store.put('persistentSessions',session);
    if(consentId)this.store.put('persistentProfileConsents',{id:consentId,schemaVersion:1,ownerPrincipal:this.ownerPrincipal,connectionAuthority:captureConnectionAuthority(this.store,id),profileBinding:this.profileBinding(session)});
    this.seedCapabilities(app.id);
    this.store.audit({type:'browser.session.consented',connectionId:id,appId:app.id});
    await this.open(id,principal);
    return this.current(id).connection;
  }
  invalidate(id){const session=this.store.get('persistentSessions',id);this.update(id,{observationCurrent:false,documentEpoch:(session?.documentEpoch||0)+1});}
  watchPage(id,page){
    if(this.pages.get(id)===page)return;
    this.pages.set(id,page);
    page.on?.('close',()=>{if(this.pages.get(id)===page){this.pages.delete(id);this.invalidate(id);}});
    page.on?.('crash',()=>{this.crashedPages.add(page);if(this.pages.get(id)===page){this.pages.delete(id);this.invalidate(id);}});
    page.on?.('framenavigated',frame=>{if(!page.mainFrame||frame===page.mainFrame())this.invalidate(id);});
  }
  watchAuthorityPage(id,accepted,context,page){
    if(this.pages.get(id)===page)return;
    this.pages.set(id,page);this.pageAuthorities.set(page,accepted);
    const owns=()=>{try{this.activeAuthority(id,accepted);return this.contexts.get(id)===context&&this.pages.get(id)===page;}catch{return false;}};
    const invalidate=()=>{if(owns()){const session=this.store.get('persistentSessions',id);this.updateAuthority(id,accepted,{observationCurrent:false,documentEpoch:(session.documentEpoch||0)+1});}};
    page.on?.('close',()=>{if(owns()){invalidate();this.pages.delete(id);}});
    page.on?.('crash',()=>{this.crashedPages.add(page);if(owns()){invalidate();this.pages.delete(id);}});
    page.on?.('framenavigated',frame=>{if(!page.mainFrame||frame===page.mainFrame())invalidate();});
    invalidate();
  }
  async contextAuthority(id,accepted,guard){
    guard();
    if([...this.orphanContexts].some(context=>this.contextAuthorities.get(context)?.connectionAuthority.id===id))throw new Error('An old browser context could not be closed. Close its window before reopening.');
    const current=this.contexts.get(id);
    if(current){
      if(canonicalHash(this.contextAuthorities.get(current))===canonicalHash(accepted)&&current.browser?.()?.isConnected?.()!==false)return current;
      await current.close();guard();
      if(this.contexts.get(id)===current){this.contexts.delete(id);this.pages.delete(id);}
    }
    if(this.openings.has(id)&&canonicalHash(this.openingAuthorities.get(id))!==canonicalHash(accepted))throw new Error('An obsolete browser launch is still closing. Retry after it finishes.');
    if(!this.openings.has(id)){
      const opening=(async()=>{
        let context;
        try{
          guard();this.updateAuthority(id,accepted,{state:'opening',observationCurrent:false});
          const directory=await this.profileDirectory(id,{create:true});guard();
          let launcher=this.launch;
          if(!launcher){const {chromium}=await import('playwright');guard();launcher=chromium.launchPersistentContext.bind(chromium);}
          guard();context=await launcher(directory,{headless:false,acceptDownloads:false,chromiumSandbox:true,timeout:20000});
          this.contextAuthorities.set(context,accepted);guard();
          if(this.contexts.has(id))throw new Error('A different browser context owns this connection.');
          this.contexts.set(id,context);
          context.setDefaultTimeout?.(10000);context.setDefaultNavigationTimeout?.(20000);
          context.on?.('close',()=>{if(this.contexts.get(id)===context){this.contexts.delete(id);this.pages.delete(id);this.updateAuthority(id,accepted,{state:'dormant',observationCurrent:false});}});
          const {session}=this.activeAuthority(id,accepted);
          this.updateAuthority(id,accepted,{state:'available',sessionEpoch:(session.sessionEpoch||0)+1,lastOpenedAt:now(),observationCurrent:false,lastError:null});
          return context;
        }catch{
          if(context){try{await context.close();}catch{this.orphanContexts.add(context);}}
          if(context&&this.contexts.get(id)===context){this.contexts.delete(id);this.pages.delete(id);}
          if(!this.contexts.has(id))this.updateAuthority(id,accepted,{state:'dormant',observationCurrent:false,lastError:'The dedicated browser could not be opened or closed. Check its window before retrying.'});
          throw new Error('The accepted saved-profile launch failed or its authority changed. No account access was restored.');
        }
      })();
      this.openings.set(id,opening);this.openingAuthorities.set(id,accepted);
      opening.finally(()=>{if(this.openings.get(id)===opening){this.openings.delete(id);this.openingAuthorities.delete(id);}}).catch(()=>{});
    }
    const context=await this.openings.get(id);guard();this.resourceAuthority(id,accepted,context);return context;
  }
  async pageAuthority(id,accepted,context,guard,{interactive=false}={}){
    guard();const {session}=this.resourceAuthority(id,accepted,context);
    let page=this.pages.get(id);
    if(page&&(page.isClosed()||this.crashedPages.has(page)||canonicalHash(this.pageAuthorities.get(page))!==canonicalHash(accepted)))page=null;
    if(!page){
      const usable=candidate=>!candidate.isClosed()&&!this.crashedPages.has(candidate);
      page=context.pages().find(candidate=>usable(candidate)&&session.origins.includes(originOf(candidate)))||context.pages().find(candidate=>usable(candidate)&&candidate.url()==='about:blank');
      if(!page){page=await context.newPage();try{guard();this.resourceAuthority(id,accepted,context);}catch(error){try{await page.close();}catch{}throw error;}}
      guard();this.resourceAuthority(id,accepted,context);this.watchAuthorityPage(id,accepted,context,page);
      if(page.url()==='about:blank'){guard();await page.goto(session.origin,{waitUntil:'domcontentloaded',timeout:20000});guard();this.resourceAuthority(id,accepted,context,page);}
    }
    this.resourceAuthority(id,accepted,context,page);
    if(interactive){guard();await page.bringToFront();guard();this.resourceAuthority(id,accepted,context,page);}
    return page;
  }
  async openAuthority(id,principal){
    if(!principal)throw new Error('Trusted owner approval is required.');this.assertOwner(principal);
    const accepted=this.profileAuthority(id);
    return this.enqueue(id,async()=>{
      const guard=()=>this.activeAuthority(id,accepted);
      let context;
      try{guard();context=await this.contextAuthority(id,accepted,guard);guard();await this.pageAuthority(id,accepted,context,guard,{interactive:true});guard();return this.current(id).connection;}
      catch{if(!this.contexts.has(id)||this.contexts.get(id)===context)this.updateAuthority(id,accepted,{observationCurrent:false,lastError:'The approved browser could not be opened. Its connection or page may have changed.'});throw new Error('The approved saved-profile browser could not be opened or its authority changed.');}
    });
  }
  async executeAuthority(id,action,args,authorize){
    canonicalHash({action,args});action=JSON.parse(JSON.stringify(action));args=JSON.parse(JSON.stringify(args));
    if(!['observe','read'].includes(action?.op)||Object.keys(action).some(key=>!['op','transport'].includes(key))||(action.transport&&action.transport!=='persistent'))throw new Error('Only read-only browser operations are supported.');
    if(!args||typeof args!=='object'||Array.isArray(args)||Object.keys(args).some(key=>action.op!=='read'||key!=='selector')||(action.op==='read'&&(typeof args.selector!=='string'||!args.selector.trim()||args.selector.length>500||/[\u0000-\u001f\u007f]/.test(args.selector))))throw new Error('Unsupported browser observation arguments.');
    const accepted=this.profileAuthority(id),request=this.requestAuthority(id,action,args,authorize);
    this.activeAuthority(id,accepted);
    return this.enqueue(id,async()=>{
      let context,page;
      const guard=()=>{this.activeAuthority(id,accepted);this.requestAuthority(id,action,args,authorize,request);return this.activeAuthority(id,accepted);};
      try{
        guard();context=await this.contextAuthority(id,accepted,guard);guard();page=await this.pageAuthority(id,accepted,context,guard);guard();
        const {session}=this.resourceAuthority(id,accepted,context,page),origin=originOf(page);
        if(!session.origins.includes(origin))throw new Error('The browser is outside its approved origin.');
        const beforeUrl=page.url(),documentEpoch=session.documentEpoch||0;
        const input={op:action.op,...(action.op==='read'?{selector:args.selector}:{}),expectedOrigin:origin};
        let data=await page.evaluate(observeBrowserPage,input);guard();
        const after=this.resourceAuthority(id,accepted,context,page);
        if(page.url()!==beforeUrl||originOf(page)!==origin||(after.session.documentEpoch||0)!==documentEpoch)throw new Error('The browser page changed during this read.');
        canonicalHash(data);data=JSON.parse(JSON.stringify(data));
        if(!data||typeof data!=='object'||Array.isArray(data)||data.origin!==origin||JSON.stringify(data).length>65000)throw new Error('The browser result did not match the accepted origin or size limit.');
        guard();const final=this.resourceAuthority(id,accepted,context,page);
        if(page.url()!==beforeUrl||originOf(page)!==origin||(final.session.documentEpoch||0)!==documentEpoch)throw new Error('The browser page changed before accepting this read.');
        const at=now();if(!this.updateAuthority(id,accepted,{observationCurrent:true,observedPage:{origin,title:boundedTitle(data.title),observedAt:at},lastAttempt:{status:'succeeded',at},lastError:null}))throw new Error('The browser observation could not be committed.');
        guard();const committed=this.resourceAuthority(id,accepted,context,page);
        if(page.url()!==beforeUrl||originOf(page)!==origin||(committed.session.documentEpoch||0)!==documentEpoch)throw new Error('The browser page changed before returning this read.');
        return {data,verification:{status:'observed',kind:'persistent-browser-dom',origin,checkedAt:at,accountVerified:false}};
      }catch{
        // A previous context/page callback must not write evidence on a later
        // resource even when both resources share the same consent generation.
        if((context?this.contexts.get(id)===context:!this.contexts.has(id))&&(!page||this.pages.get(id)===page))this.updateAuthority(id,accepted,{observationCurrent:false,lastAttempt:{status:'failed',at:now()}});
        throw new Error('The approved browser observation failed, expired, or its authority/page changed. No result was accepted.');
      }
    });
  }
  async revokeAuthority(id,principal){
    if(!principal)throw new Error('Trusted owner approval is required.');this.assertOwner(principal);
    const {connection,session}=this.current(id),accepted=this.profileAuthority(id),context=this.contexts.get(id),opening=this.openings.get(id);
    this.store.put('connections',{...connection,status:'revoked',updatedAt:now()});
    this.store.put('persistentSessions',{...session,state:'revoked',observationCurrent:false,revokedAt:now(),updatedAt:now()});
    const revoked=captureConnectionAuthority(this.store,id);
    if(context&&canonicalHash(this.contextAuthorities.get(context))===canonicalHash(accepted)){
      try{await context.close();this.orphanContexts.delete(context);}catch{this.orphanContexts.add(context);throw new Error('Connection revoked, but its old browser could not be closed. The profile was retained; close its window manually.');}
      if(this.contexts.get(id)===context){this.contexts.delete(id);this.pages.delete(id);}
    }
    if(opening)try{await opening;}catch{}
    if([...this.orphanContexts].some(old=>canonicalHash(this.contextAuthorities.get(old))===canonicalHash(accepted)))throw new Error('Connection revoked, but its old browser could not be closed. The profile was retained; close its window manually.');
    assertConnectionAuthority(this.store,revoked);this.assertOwner(principal);
    const profileCleanup={status:'retained',cleanupRequired:true,reason:'Physical profile erasure requires a separately reviewed cleanup operation. Retained bytes do not authorize account access.'};
    this.store.audit({type:'browser.session.revoked',connectionId:id,appId:connection.appId,profileCleanup});
    return {...this.store.get('connections',id),profileCleanup};
  }
  async shutdownAuthority(){
    this.stopped=true;
    const contexts=new Set([...this.contexts.values(),...this.orphanContexts]);
    await Promise.allSettled([...contexts].map(async context=>{
      const accepted=this.contextAuthorities.get(context),id=accepted?.connectionAuthority.id;
      try{await context.close();this.orphanContexts.delete(context);}catch{this.orphanContexts.add(context);}
      if(id&&this.contexts.get(id)===context){this.contexts.delete(id);this.pages.delete(id);this.updateAuthority(id,accepted,{state:'dormant',observationCurrent:false});}
    }));
    await Promise.allSettled([...this.openings.values()]);await Promise.allSettled([...this.queues.values()]);
  }
  async context(id,authorize){
    await this.guard(id,authorize);
    const current=this.contexts.get(id);
    if(current&&current.browser?.()?.isConnected?.()!==false)return current;
    if(current)this.contexts.delete(id);
    if(!this.openings.has(id)){
      const opening=(async()=>{
        this.update(id,{state:'opening',observationCurrent:false});
        let context;
        try{
          const directory=await this.profileDirectory(id,{create:true});await this.guard(id,authorize);
          let launcher=this.launch;
          if(!launcher){const {chromium}=await import('playwright');launcher=chromium.launchPersistentContext.bind(chromium);}
          await this.guard(id,authorize);
          context=await launcher(directory,{headless:false,acceptDownloads:false,chromiumSandbox:true,timeout:20000});await this.guard(id,authorize);
          this.contexts.set(id,context);
          context.setDefaultTimeout?.(10000);context.setDefaultNavigationTimeout?.(20000);
          context.on?.('close',()=>{if(this.contexts.get(id)===context){this.contexts.delete(id);this.pages.delete(id);this.update(id,{state:'dormant',observationCurrent:false});}});
          const {session}=this.current(id);this.update(id,{state:'available',sessionEpoch:(session.sessionEpoch||0)+1,lastOpenedAt:now(),observationCurrent:false,lastError:null});
          return context;
        }catch(error){
          let closed=true;
          if(context)try{await context.close();}catch{closed=false;this.contexts.set(id,context);}
          if(closed)this.contexts.delete(id);
          this.pages.delete(id);this.update(id,{state:'dormant',observationCurrent:false,lastError:closed?'The dedicated browser could not be opened. Try opening the connection again.':'The browser could not be closed. Close its window before retrying.'});
          if(this.stopped||this.store.get('connections',id)?.status==='revoked')throw new Error(this.stopped?'Persistent browser runtime is stopped.':'Persistent browser connection revoked.');
          if(/profile|directory|symlink/i.test(error.message))throw new Error('The dedicated browser profile directory is unsafe or unavailable.');
          throw new Error('The dedicated browser could not be opened. Try opening the connection again.');
        }
      })();
      this.openings.set(id,opening);opening.finally(()=>{if(this.openings.get(id)===opening)this.openings.delete(id);}).catch(()=>{});
    }
    const context=await this.openings.get(id);await this.guard(id,authorize);return context;
  }
  enqueue(id,operation){
    const previous=this.queues.get(id)||Promise.resolve();
    const job=previous.catch(()=>{}).then(operation);this.queues.set(id,job);
    job.finally(()=>{if(this.queues.get(id)===job)this.queues.delete(id);}).catch(()=>{});
    return job;
  }
  async page(id,context,authorize,{interactive=false}={}){
    const {session}=await this.guard(id,authorize);
    let page=this.pages.get(id);
    if(!page||page.isClosed()||this.crashedPages.has(page)){
      const usable=candidate=>!candidate.isClosed()&&!this.crashedPages.has(candidate);
      page=context.pages().find(candidate=>usable(candidate)&&session.origins.includes(originOf(candidate)))||context.pages().find(candidate=>usable(candidate)&&candidate.url()==='about:blank');
      if(!page){page=await context.newPage();await this.guard(id,authorize);}
      this.watchPage(id,page);this.invalidate(id);
      if(page.url()==='about:blank'){
        await this.guard(id,authorize);await page.goto(session.origin,{waitUntil:'domcontentloaded',timeout:20000});await this.guard(id,authorize);
      }
    }
    if(interactive){await page.bringToFront();await this.guard(id,authorize);}
    return page;
  }
  open(id,principal){
    if(this.store.authorityEnabled)return this.openAuthority(id,principal);
    return this.enqueue(id,async()=>{
      await this.guard(id);const context=await this.context(id);await this.guard(id);
      try{await this.page(id,context,null,{interactive:true});await this.guard(id);}catch(error){
        if(this.stopped||this.store.get('connections',id)?.status==='revoked')throw error;
        this.update(id,{observationCurrent:false,lastError:'The browser opened, but the application did not finish loading. Complete sign-in in its browser window.'});
        throw new Error('The browser opened, but the application did not finish loading. Complete sign-in in its browser window.');
      }
      return this.current(id).connection;
    });
  }
  evidence(connection){
    if(connection?.transport!=='persistent')return null;
    let accepted;
    if(this.store.authorityEnabled)try{accepted=this.profileAuthority(connection.id);}catch{
      const revoked=this.store.get('connections',connection.id)?.status==='revoked'||this.store.get('persistentSessions',connection.id)?.state==='revoked';
      return {bridge:{status:revoked?'revoked':'unavailable',origin:null,lastHeartbeatAt:null},account:{status:'unverified',verified:false},page:{status:'not_observed',lastAttempt:null},observedPage:null,session:{state:revoked?'revoked':'unavailable',persistent:true,expiresAt:null,...(revoked?{profileCleanup:{status:'retained',cleanupRequired:true}}:{})}};
    }
    const current=this.store.get('connections',connection.id),session=this.store.get('persistentSessions',connection.id);
    let context=this.contexts.get(connection.id);
    if(accepted&&context&&canonicalHash(this.contextAuthorities.get(context)??null)!==canonicalHash(accepted))context=null;
    const state=current?.status==='revoked'||session?.state==='revoked'?'revoked':!current||!session?'unavailable':context&&context.browser?.()?.isConnected?.()!==false?'available':session.state==='opening'?'opening':'dormant';
    const observed=session?.observedPage;
    const observedPage=observed&&(session.origins||[session.origin]).includes(observed.origin)?{origin:observed.origin,title:boundedTitle(observed.title),observedAt:observed.observedAt}:null;
    const pageCurrent=observedPage&&session.observationCurrent&&state==='available'&&Date.now()-Date.parse(observedPage.observedAt)<120000;
    return {bridge:{status:state==='available'?'alive':state==='revoked'?'revoked':state==='unavailable'?'unavailable':'waiting',origin:session?.origin||null,lastHeartbeatAt:null},account:{status:'unverified',verified:false},page:{status:!observedPage?'not_observed':pageCurrent?'observed':'stale',lastAttempt:session?.lastAttempt||null},observedPage,session:{state,persistent:true,expiresAt:null,lastOpenedAt:session?.lastOpenedAt||null,sessionEpoch:session?.sessionEpoch||0,lastError:session?.lastError||null}};
  }
  check(id){const {connection}=this.current(id);return connection;}
  execute(id,action,args,authorize){
    if(this.store.authorityEnabled)return this.executeAuthority(id,action,args,authorize);
    return this.enqueue(id,async()=>{
      if(!action||!['observe','read'].includes(action.op)||Object.keys(action).some(key=>!['op','transport'].includes(key))||(action.transport&&action.transport!=='persistent'))throw new Error('Only read-only browser operations are supported. JavaScript, shell, click and fill are unavailable.');
      if(typeof authorize!=='function')throw new Error('Browser observations require runtime authorization.');
      if(!args||typeof args!=='object'||Array.isArray(args)||Object.keys(args).some(key=>action.op!=='read'||key!=='selector'))throw new Error('Unsupported browser observation arguments.');
      if(action.op==='read'&&(typeof args.selector!=='string'||!args.selector.trim()||args.selector.length>500||/[\u0000-\u001f\u007f]/.test(args.selector)))throw new Error('A bounded element selector is required.');
      const input={op:action.op,...(action.op==='read'?{selector:args.selector}:{})};
      try{
        const {session}=await this.guard(id,authorize),context=await this.context(id,authorize);await this.guard(id,authorize);
        const page=await this.page(id,context,authorize);await this.guard(id,authorize);
        const origin=originOf(page);
        if(!session.origins.includes(origin))throw new Error('The browser is outside the approved origin. Complete sign-in interactively before reading.');
        const beforeUrl=page.url(),documentEpoch=this.current(id).session.documentEpoch||0;
        const data=await page.evaluate(observeBrowserPage,{...input,expectedOrigin:origin});await this.guard(id,authorize);
        if(page.isClosed()||this.crashedPages.has(page)||originOf(page)!==origin||page.url()!==beforeUrl||(this.current(id).session.documentEpoch||0)!==documentEpoch)throw new Error('The browser page or origin changed during this read. Inspect again.');
        if(!data||typeof data!=='object'||Array.isArray(data)||data.origin!==origin)throw new Error('Browser read result did not match the approved origin.');
        if(JSON.stringify(data).length>65000)throw new Error('Browser observation exceeded the result limit.');
        const at=now();this.update(id,{observationCurrent:true,observedPage:{origin,title:boundedTitle(data.title),observedAt:at},lastAttempt:{status:'succeeded',at},lastError:null});
        return {data,verification:{status:'observed',kind:'persistent-browser-dom',origin,checkedAt:at,accountVerified:false}};
      }catch(error){
        this.update(id,{observationCurrent:false,lastAttempt:{status:'failed',at:now()}});
        // Never surface Playwright's call log, page URL, content or credentials.
        if(this.stopped)throw new Error('Persistent browser runtime is stopped.');
        if(this.store.get('connections',id)?.status==='revoked')throw new Error('Persistent browser connection revoked.');
        if(/permission revoked/i.test(error.message))throw new Error('Permission revoked during browser observation.');
        if(/origin|sign.in|changed during|profile|result limit/i.test(error.message))throw new Error('The browser page is unavailable, changed, or outside its approved origin. Open the connection to check sign-in, then retry.');
        throw new Error('Browser observation was not completed. The page may have closed or permission may have changed.');
      }
    });
  }
  async revoke(id,principal){
    if(this.store.authorityEnabled)return this.revokeAuthority(id,principal);
    if(typeof id!=='string'||!UUID.test(id))throw new Error('Unknown persistent browser connection.');
    const connection=this.store.get('connections',id),session=this.store.get('persistentSessions',id);
    if(!connection||connection.transport!=='persistent'||!session)throw new Error('Unknown persistent browser connection.');
    // Revoke before the first await. In-flight and queued jobs must fail closed.
    this.store.put('connections',{...connection,status:'revoked',updatedAt:now()});
    this.store.put('persistentSessions',{...session,state:'revoked',observationCurrent:false,revokedAt:now(),updatedAt:now()});
    const context=this.contexts.get(id);this.pages.delete(id);
    if(context)try{await context.close();this.contexts.delete(id);}catch{throw new Error('Connection revoked, but the browser could not be closed. Close its window before removing the profile.');}
    if(this.openings.has(id))try{await this.openings.get(id);}catch{/* Late launches close themselves after seeing revocation. */}
    const lateContext=this.contexts.get(id);
    if(lateContext)try{await lateContext.close();this.contexts.delete(id);}catch{throw new Error('Connection revoked, but the browser could not be closed. Its profile was retained; close the browser and retry disconnect.');}
    try{const directory=await this.profileDirectory(id);await rm(directory,{recursive:true,force:false});}catch(error){if(error.code!=='ENOENT')throw new Error('Connection revoked, but its browser profile could not be safely removed.');}
    this.store.audit({type:'browser.session.revoked',connectionId:id,appId:connection.appId});
    return this.store.get('connections',id);
  }
  async shutdown(){
    if(this.store.authorityEnabled)return this.shutdownAuthority();
    this.stopped=true;
    const contexts=[...this.contexts.entries()];this.pages.clear();
    await Promise.allSettled(contexts.map(async([id,context])=>{try{await context.close();this.contexts.delete(id);}finally{this.update(id,{state:'dormant',observationCurrent:false});}}));
    await Promise.allSettled([...this.openings.values()]);
    // Closing real contexts settles pending reads. Drain jobs before the caller
    // closes the Store, so late cancellation cannot write to a closed database.
    await Promise.allSettled([...this.queues.values()]);
  }
}

import {randomUUID} from 'node:crypto';
import {canonicalHash} from './compiler.mjs';
import {PERMISSION_GROUPS,groupFor,reviewedRead,memberData,memberKey,UNAVAILABLE_REASONS,SPLIT_ROWS} from './permission-groups.mjs';
import {sensitivity as classify,SENSITIVITY_VERSION} from './sensitivity.mjs';
import {resolveInternal} from './compiler.mjs';
import {PROXY_CONFIGS} from './proxy-config.mjs';
import {LOCK_WORDS,lockedRowOf as lockedRow,bodyRouteOf as bodyRoute,memberRoutes,rowMemberOf,actionSteps} from './row-locks.mjs';
import {fitsTemplate} from './proxy-match.mjs';

const MODES=new Set(['allow','ask','deny']);
const activeConnection=c=>c&&['ready','session_ready'].includes(c.status);
const strings=value=>Array.isArray(value)&&value.every(item=>typeof item==='string'&&item.length>0&&item.length<=1000);
const unique=value=>[...new Set(value)].sort();
const STRICT={allow:0,ask:1,deny:2},VERDICT={'suspected-write':1,secrets:2};
const strictest=(...modes)=>modes.reduce((a,b)=>STRICT[b]>STRICT[a]?b:a,'allow');
/** F10.11 part e: the fixed words of an action that cannot run for a reason its settings do not decide. */
export const ACTION_WORDS=Object.freeze({
  unsupported:'Actions are not loaded in this Fabric, so this action cannot run.',
  changed:'This action no longer matches its reviewed file, so it cannot run. Fabric reads the file again at its next start.',
  unplaced:'A step of this action cannot be placed: its app is reviewed by method id and Fabric has no map of it yet.',
  unreachable:'This account was not connected for the app\'s reviewed API address, so its actions cannot run.',
  removed:'This action is no longer in Fabric\'s reviewed actions.',
  superseded:'This action was replaced by a newer version. Use the action it names instead.',
  candidate:'This action is a candidate: only a reviewed file with live evidence makes it active (I8).',
  // F10.11 part l: an action whose inputs depend on the resource it acts on is described once an account exists, never before.
  describe:'Connect the account first, then describe it.',
  // F10.12: a candidate in a certification Fabric, run for its live tests.
  certifying:'Certification run: this action runs at Ask only, for its live tests. Only a reviewed file with live evidence makes it active (I8).',
});
/** A step's own request ("METHOD /path") as the segments matchRequest() reads: a parameter segment as its own text, which only a
 *  parameter or rest segment fits (lib/action-placement.mjs). Null when there is none. */
const ownRequest=request=>{
  if(typeof request!=='string'||!request.includes(' /')) return null;
  const [method,path]=request.split(' ');
  return {method,segments:path==='/'?[]:path.slice(1).split('/')};
};

/** Iteration 9 (docs/I07-BUILD-MAP.md section 2.5): the phases a trigger reads in. A register or teardown step lands in a row Fabric locks and
 *  Fabric runs none, so neither says anything about what a watch may read. */
const TRIGGER_READS=['poll','seed','enrich'];
/** A trigger's reads: each poll, seed and enrich placement beside the step the file writes. */
function triggerReads(entry) {
  const {poll}=entry.trigger,written=new Map([...(poll.source?.steps??[]),...(poll.seed?[poll.seed.step]:[]),...(poll.enrich?.steps??[])].map(step=>[step.id,step]));
  return entry.placements.filter(placement=>TRIGGER_READS.includes(placement.phase)).map(placement=>({placement,step:written.get(placement.stepId)}));
}

/** F10.11 part l: a capability's four hints, under the name the developer catalog gives them (annotations): an action's reviewed hints,
 *  an operation's derived from its effect, as lib/tenant/views.mjs capabilityView() derives them. */
export function annotationsOf(capability) {
  const hints=capability?.driver==='action'?capability.action?.hints:null;
  if(hints&&typeof hints==='object') return {readOnly:hints.readOnly===true,destructive:hints.destructive===true,idempotent:hints.idempotent===true,openWorld:hints.openWorld===true};
  const effect=permissionEffect(capability);
  return {readOnly:effect==='read',destructive:effect==='delete',idempotent:effect==='read',openWorld:true};
}
/** F10.11 part l: whether an action has an input whose fields come from the resource it acts on (F10.9 section 9). */
export const resourceDependent=capability=>capability?.driver==='action'&&Array.isArray(capability.action?.resolvedInputs)&&capability.action.resolvedInputs.length>0;
/** F10.11 part l: which inputs of an action a reviewed choice list can fill, each with the inputs its list depends on; never the source. */
export const actionChoices=capability=>(Array.isArray(capability?.action?.choices)?capability.action.choices:[]).map(choice=>({input:choice.input,dependsOn:[...(choice.dependsOn??[])]}));
/** F10.11 parts e, l and m: the rows an action touches: its own row first, then every other row a step lands in or a body route moved a
 *  step from, in step order, at most 16. One reading for its decision and every listing; actionRowLabels() gives their labels. */
export function actionRowGroups(definition,entry) {
  const group=id=>definition?.groups.find(item=>item.id===id);
  return [...new Set([group(entry.row),...entry.placements.flatMap(placement=>[group(placement.groupId),group(placement.routedFrom?.groupId)])].filter(Boolean))].slice(0,16);
}
export const actionRowLabels=(definition,entry)=>actionRowGroups(definition,entry).map(group=>group.label);
/**
 * F10.11 parts k and l: what each step of an action needs from a sign-in, without an account: per placement its step id, the row its member
 * lives in (for a routed step, the row a body route moved it from), whether it is optional, why it can never work through a sign-in, and
 * its scope alternatives, read as ProxyPolicy.memberAccess() reads the member (Discovery's by the member's map id, else its row's sets;
 * malformed ones name nothing, as the proxy reads them unknown). The one reading behind the upgrade card, the callback wall, the
 * not-granted notice, Add access, rowsNeeding() and a continuation's sign-in. `catalog` is the action catalog, passed explicitly (none
 * means no step is known). Null when it holds no current, placed entry for the action.
 */
export function actionStepScopes(groups,catalog,capability,map) {
  const entry=capability?.driver==='action'?catalog?.entryOf?.(capability)?.entry:null;
  if(!entry||entry.unplaced) return null;
  const rows=groups?.get(capability.appId)?.groups??[],operations=Array.isArray(map?.operations)?map.operations:[];
  return actionSteps(entry,map).map(({placement,optional})=>{
    const groupId=placement.routedFrom?.groupId??placement.groupId,data=memberData(rows.find(group=>group.id===groupId),placement.member);
    const {scopeSets,invalid}=scopeSetsOf(operations.find(op=>op&&typeof op==='object'&&op.id===placement.member)??null,data);
    return {stepId:placement.stepId,groupId,optional,unavailable:data.unavailable??null,scopeSets:invalid?[]:scopeSets};
  });
}

/** F10.9 (R5): the account identity a binding hashes. Slack's userId repeats the second part of its reviewed id (team_id:user_id, and
 *  contracts/auth-definition.mts keeps userId on an id pointer), so leaving it out loses nothing, and an account that records it at its
 *  next sign-in or refresh keeps every saved setting. */
export function bindingIdentity(identity) {
  if(!identity||typeof identity!=='object'||Array.isArray(identity)) return identity??{};
  const {userId,...rest}=identity;void userId;
  return rest;
}

// A shared "browser" driver must not make a helper pairing interchangeable
// with a dedicated saved profile. Legacy capabilities are helper-only.
export function matchingBrowserTransport(connection,capability) {
  if(connection.driver!=='browser'||capability.driver!=='browser')return true;
  const route=connection.transport||'helper',target=capability.transport||'helper';
  return ['helper','persistent'].includes(route)&&route===target;
}
/** F10.11 part e (A8): the one route check every driver comparison reads. The same app; an action runs on its app's http connection; any
 *  other capability keeps driver equality and the browser transport rule. */
export function sameRoute(connection,capability) {
  if(!connection||!capability||connection.appId!==capability.appId) return false;
  if(capability.driver==='action') return connection.driver==='http';
  return connection.driver===capability.driver&&matchingBrowserTransport(connection,capability);
}

// Promotion is review state, not part of the immutable operation definition.
/** The one reading of an operation's scope metadata: OR between alternatives, AND within each group.
 *  An empty conjunction is valid (bearer auth may name no scopes; OpenAPI may offer anonymous access).
 *  requiredScopes alone means each scope is its own alternative. Sign-in and permission checks share it. */
export function scopeAlternatives(operation) {
  let requiredScopes=[],scopeSets=[],invalid=false;
  if(operation?.requiredScopes!==undefined) {
    if(strings(operation.requiredScopes)) requiredScopes=unique(operation.requiredScopes);
    else invalid=true;
  }
  if(operation?.scopeSets!==undefined) {
    if(Array.isArray(operation.scopeSets)&&operation.scopeSets.every(group=>strings(group))) scopeSets=operation.scopeSets.map(unique);
    else invalid=true;
  }
  if(!scopeSets.length&&requiredScopes.length) scopeSets=requiredScopes.map(scope=>[scope]);
  return {requiredScopes,scopeSets,invalid};
}
/** F10.6: a member's scope alternatives. Discovery's wherever the map operation has any, or is malformed (never read around);
 *  else the reviewed row's sets for the member (lib/permission-groups.mjs memberData()), copied; else none. Row data only ever
 *  speaks where Discovery is silent, so it never makes a member more runnable than Discovery does. */
export function scopeSetsOf(operation,data) {
  const discovered=scopeAlternatives(operation);
  if(discovered.invalid||discovered.scopeSets.length||!Array.isArray(data?.scopeSets)) return discovered;
  return {requiredScopes:[],scopeSets:data.scopeSets.map(set=>[...set]),invalid:false};
}
/** The one reading of an account's provider access to a member, typed or proxied: 'granted' when a named alternative is held,
 *  'unknown' when a zero-scope alternative exists, else 'missing'. Only an OAuth grant says anything; any other account, or a
 *  member with no alternatives, is 'unknown'. `granted` is the account's held scopes as every decision reads them
 *  (PermissionManager.grantedScopes(), with what a granted parent grants), or a function that reads them only when they matter. */
export function providerAccessOf(connection,scopeSets,granted) {
  if(connection?.authMethod!=='oauth'||!Array.isArray(scopeSets)||!scopeSets.length) return 'unknown';
  const have=new Set(typeof granted==='function'?granted():granted);
  // A zero-scope branch removes this local named-scope requirement, not the
  // credential/connection checks. It is not evidence of provider consent.
  return scopeSets.some(group=>group.length>0&&group.every(scope=>have.has(scope)))?'granted':scopeSets.some(group=>group.length===0)?'unknown':'missing';
}
/** The fewest extra scopes that satisfy one alternative, read-only first (suffix forms like gmail.readonly or
 *  channels:read and prefix forms like GitHub read:org). null when no usable alternative exists. */
export function leastPrivilegedExtra(scopeSets,granted,usable=()=>true) {
  const have=new Set(granted);
  if(scopeSets.some(group=>group.every(scope=>have.has(scope)))) return [];
  const extra=group=>group.filter(scope=>!have.has(scope)),broad=scope=>!/(readonly|[.:]read)$|^read:/.test(scope);
  const options=scopeSets.filter(group=>group.every(scope=>have.has(scope)||usable(scope))).map(extra);
  if(!options.length) return null;
  return options.sort((a,b)=>a.length-b.length||a.filter(broad).length-b.filter(broad).length||a.join(' ').localeCompare(b.join(' ')))[0];
}
export function capabilityPermissionHash(capability) {return canonicalHash({...capability,status:'review-state'});}
export function permissionEffect(capability) {
  if(capability.driver==='http') {
    const method=capability.request?.method?.toUpperCase();
    if(method==='DELETE') return 'delete';
    return ['GET','HEAD'].includes(method)?'read':'write';
  }
  if(capability.driver==='workspace') return capability.action?.op==='delete'?'delete':capability.action?.op==='write'?'write':'read';
  if(capability.driver==='browser') return ['observe','read'].includes(capability.action?.op)?'read':'write';
  if(capability.driver==='device') return 'read';
  // F10.11 part e: an action's effect is the one its steps compute, which the validator checked against what it declares.
  if(capability.driver==='action') return ['read','write','delete'].includes(capability.effect)?capability.effect:'write';
  return 'write';
}

/** A group's declared default, never looser than the operation's own effect allows: a member that deletes, or
 *  writes where the group is not a reversible in-account write, falls back to Ask. Browser routes always ask, and so
 *  does an operation that returns credentials or a GET whose name says it changes something (F09.1, I9). A row Fabric
 *  locks is Never for every member, and a row that reaches other people never defaults to Allow (F10.3, T4). */
export function groupDefault(group,capability,effect,{reviewedAsRead=false,sensitive=null}={}) {
  if(group?.locked==='fabric') return 'deny';
  if(group?.audience===true&&group.defaultMode==='allow') return 'ask';
  if(capability.driver==='browser') return group?.defaultMode==='deny'?'deny':'ask';
  if(sensitive) return group?.defaultMode==='deny'?'deny':'ask';
  if(!group) return effect==='read'?'allow':'ask';
  if(group.defaultMode!=='allow') return group.defaultMode;
  if(effect==='read'||reviewedAsRead&&group.effect==='read') return 'allow';
  return effect==='write'&&group.effect==='write'&&group.stayInAccount===true?'allow':'ask';
}

/** Why an operation is sensitive (lib/sensitivity.mjs). Discovery's recorded verdict is used only when the map was
 *  classified by the current rules; an unknown recorded value counts as "secrets". */
export function operationSensitivity(capability,operation,map) {
  if(capability?.driver!=='http') return null;
  if(operation&&Object.hasOwn(operation,'sensitive')&&map?.classifierVersion===SENSITIVITY_VERSION) return operation.sensitive===null||operation.sensitive==='suspected-write'?operation.sensitive:'secrets';
  return classify(capability,operation);
}
/** The default mode of one operation with no saved setting, before account clamps. Used by decisions and the coverage harness. */
export function operationDefault(groups,capability,operation,sensitive=operationSensitivity(capability,operation)) {
  const group=groupFor(groups,capability.appId,operation);
  return groupDefault(group,capability,permissionEffect(capability),{reviewedAsRead:reviewedRead(group,operation),sensitive});
}
/** One read of an application map for a batch of decisions: its operations by capability id. */
export function mapIndex(map) {
  const list=Array.isArray(map?.operations)?map.operations:[];
  // A malformed map fails every decision closed rather than being read around.
  if(list.some(op=>op===null||typeof op!=='object'||Array.isArray(op))) throw new Error('The application map is malformed; decisions fail closed.');
  return {map,operations:new Map(list.filter(op=>op.capabilityId).map(op=>[op.capabilityId,op]))};
}

const CEILING_RANK={ask:1,deny:2};
/** The record in the store's `migrations` collection that says the split-row migration (decision 6) has run. */
const SPLIT_MIGRATION='f10.7-split-rows';
/** F10.7 (decision 6): a developer's ceiling on a row also covers the rows split out of it (SPLIT_ROWS); the stricter of the two applies.
 *  Every reader of a ceiling (typed decisions, proxy rows, the app pages) reads it through this one function. */
export function splitCeiling(ceilingOf) {
  return (appId,groupId)=>{
    const own=ceilingOf(appId,groupId),from=SPLIT_ROWS[appId]?.[groupId],inherited=from?ceilingOf(appId,from):null;
    return (CEILING_RANK[inherited]||0)>(CEILING_RANK[own]||0)?inherited:own;
  };
}

export class PermissionManager {
  /** ceilingOf(appId, groupId) is the developer's cap on a row in one environment (F03.3): 'ask', 'deny' or null. A ceiling only lowers.
   *  configs: the apps' proxy settings, whose bases place a capability with no map operation by its request (F10.3).
   *  scopesOf(connection) is what an account's grant holds (F10.5): its scopes and every scope a granted parent grants. */
  constructor({store,groups=PERMISSION_GROUPS,configs=PROXY_CONFIGS,ceilingOf=null,scopesOf=null}) {this.store=store;this.groups=groups;this.configs=configs;this.imports=new Map();this.ceilingOf=ceilingOf?splitCeiling(ceilingOf):null;this.scopesOf=scopesOf;
    // F10.11 part e: the action catalog and the proxy's rows, injected by the Runtime (never imported). With no catalog an action is unsupported.
    // F10.12: `certification` is set by the Runtime only, true in a certification Fabric.
    this.actions=null;this.proxy=null;this.certification=false;}
  /** The scopes an account holds, as every access decision reads them: through scopesOf, else as stored. Anything but a list of
   *  scope strings holds nothing. */
  grantedScopes(connection) {const value=this.scopesOf?.(connection)??connection?.scopes;return strings(value)?[...value]:[];}
  /** T4 (F10.3): the row Fabric locks that this capability is a member of, or null (lib/row-locks.mjs). An action answers from its steps
   *  through the injected catalog (F10.11 part f), and every lookup below does the same. */
  lockedRowOf(capability,operation,map=this.store.get('applicationMaps',capability.appId)) {return lockedRow(this.groups,this.configs,capability,operation===undefined?this.operationOf(capability,map):operation,map,this.actions);}
  /** The strictest row this capability's body routes send a parsed body to, as {groupId, label, locked}, or null. */
  bodyRouteOf(capability,body,operation,map=this.store.get('applicationMaps',capability.appId)) {return bodyRoute(this.groups,this.configs,capability,operation===undefined?this.operationOf(capability,map):operation,body,map,this.actions);}
  /** The same for a typed call's arguments: its body parameter, when it was sent. */
  routedBody(capability,args) {const name=capability?.driver==='http'?capability.request?.bodyParameter:undefined;return name&&args&&typeof args==='object'&&Object.hasOwn(args,name)?this.bodyRouteOf(capability,args[name]):null;}
  /** 'fabric' when a row Fabric locks holds the capability, else null. It needs no account, so grants and holds can ask before
   *  one exists. */
  lockOf(capability) {
    const map=this.store.get('applicationMaps',capability.appId);
    return lockedRow(this.groups,this.configs,capability,this.operationOf(capability,map),map,this.actions)?'fabric':null;
  }
  /** F10.6 (T3): the reason code when the capability's reviewed member can never work through a sign-in, else null. Like
   *  lockOf(), it needs no account. */
  unavailableOf(capability) {
    const map=this.store.get('applicationMaps',capability.appId);
    // F10.11 part f: an action is unavailable when the member of a step that is not optional is.
    if(capability?.driver==='action') {
      const entry=this.actions?.entryOf?.(capability)?.entry,groups=this.groups.get(capability.appId)?.groups??[];
      for(const {placement,optional} of entry?actionSteps(entry,map):[]) {
        const code=optional?null:memberData(groups.find(group=>group.id===(placement.routedFrom?.groupId??placement.groupId)),placement.member).unavailable;
        if(code) return code;
      }
      return null;
    }
    return this.memberDataOf(capability,this.operationOf(capability,map),map)?.unavailable??null;
  }
  /** F10.6: the row data of the reviewed member a capability is (lib/permission-groups.mjs memberData()): by its map operation's
   *  row, else by its request (correction 3). Null when it is in no row. */
  memberDataOf(capability,operation,map) {const placed=rowMemberOf(this.groups,this.configs,capability,operation,map,this.actions);return placed?memberData(placed.group,placed.member):null;}
  /** An operation's sensitivity. A direct import has no map entry, so its stored description's documented response
   *  decides. Each stored description is read once and kept for a few imports; it is content-addressed, so never stale. */
  sensitivityOf(capability,operation,map) {
    if(capability?.driver==='action') return this.actionSensitivity(capability,map??this.store.get('applicationMaps',capability.appId));
    if(capability?.driver!=='http') return null;
    if(operation||capability.provenance?.kind!=='openapi') return operationSensitivity(capability,operation,map);
    const surfaceId=`${capability.appId}:${capability.provenance.fingerprint}`;
    let entry=this.imports.get(surfaceId);
    if(!entry) {
      entry={document:this.store.get('surfaces',surfaceId)?.document??null,verdicts:new Map()};
      if(this.imports.size>=8) this.imports.delete(this.imports.keys().next().value);
      this.imports.set(surfaceId,entry);
    }
    const key=`${capability.provenance.method} ${capability.provenance.path}`;
    if(!entry.verdicts.has(key)) entry.verdicts.set(key,this.importedVerdict(capability,entry.document));
    return entry.verdicts.get(key);
  }
  importedVerdict(capability,document) {
    if(!document) return classify(capability,null);
    // Path items and operations may be references, exactly as the compiler resolved them; if they cannot be read, Ask.
    try {
      const item=resolveInternal(document,document.paths?.[capability.provenance.path]);
      const raw=item&&typeof item==='object'?item[String(capability.provenance.method).toLowerCase()]:undefined;
      const responses=raw===undefined?undefined:resolveInternal(document,raw)?.responses;
      return classify(capability,responses&&typeof responses==='object'?{responseSchema:{dialect:'openapi',responses,components:document.components||{}}}:null);
    } catch {return 'secrets';}
  }
  policyId(connectionId,capabilityId) {return canonicalHash({connectionId,capabilityId});}
  /** A sensitive operation's classification is part of what a saved setting was made for: one saved before the operation
   *  was classified sensitive is stale (Ask), never a standing Allow. So are the member's own body routes (F10.3): a member
   *  that gains or changes routes needs fresh consent. Each is absent when empty, so other bindings do not change. */
  binding(connection,capability,sensitivity=null,routes=memberRoutes(this.groups,this.configs,capability,this.operationOf(capability),this.store.get('applicationMaps',capability.appId))) {
    return canonicalHash({...(sensitivity?{sensitivity}:{}),...(routes.length?{bodyRoutes:routes}:{}),connectionId:connection.id,appId:connection.appId,driver:connection.driver,...(connection.transport?{transport:connection.transport}:{}),...(connection.driver==='browser'?{sessionScope:connection.sessionScope||'browser-tab',bridgeVersion:connection.bridgeVersion||null,allowedOrigins:connection.allowedOrigins||[]}:{}),authRevision:connection.authRevision??null,identity:bindingIdentity(connection.identity),createdAt:connection.createdAt??null,capabilityId:capability.id,capabilityHash:capabilityPermissionHash(capability)});
  }
  /** `index` (from mapIndex) lets a batch read the application map once; it must be this capability's app map. `options` reach an
   *  action's decision only (actionDecision()). */
  decision(connection,capability,index,options={}) {
    if(!connection||!capability) throw new Error('Connection and capability are required for a permission decision.');
    // API projections intentionally omit authRevision. Always resolve the persisted binding.
    const persisted=this.store.get('connections',connection.id);
    if(this.store.authorityEnabled&&!persisted) throw new Error('Current connection authority is unavailable. Prepare a new connection.');
    if(persisted) connection=persisted;
    // F10.11 part e (T8): an action is decided from every step it runs, never as one operation.
    if(capability.driver==='action') return this.actionDecision(connection,capability,options);
    const effect=permissionEffect(capability);
    const {map,operations}=index&&index.map?.appId===capability.appId?index:mapIndex(this.store.get('applicationMaps',capability.appId));
    const operation=operations.get(capability.id)||null;
    // The plain-language row this operation sits in, and that row's reviewed default.
    const group=groupFor(this.groups,capability.appId,operation),data=this.memberDataOf(capability,operation,map);
    // T4 (F10.3): a member of a row Fabric locks is Never for every caller, whatever was saved before the lock.
    const lockedGroup=lockedRow(this.groups,this.configs,capability,operation,map),fabricLocked=Boolean(lockedGroup);
    const sensitivity=this.sensitivityOf(capability,operation,map);
    const defaultMode=fabricLocked?'deny':groupDefault(group,capability,effect,{reviewedAsRead:reviewedRead(group,operation),sensitive:sensitivity});
    const bindingHash=this.binding(connection,capability,sensitivity,memberRoutes(this.groups,this.configs,capability,operation,map));
    const policy=this.store.get('permissions',this.policyId(connection.id,capability.id));
    const stale=Boolean(policy&&policy.bindingHash!==bindingHash);
    // A record that follows the default still exists, so every change gets a fresh revision (no ABA).
    const follows=policy?.followsDefault===true;
    const saved=Boolean(policy&&!follows&&!stale&&MODES.has(policy.mode));
    // Binding drift must never broaden an old restriction or silently renew standing consent.
    let mode=follows?defaultMode:saved?policy.mode:stale?(policy.mode==='deny'?'deny':'ask'):defaultMode;
    // Generic UI controls have unknown effects. A standing Allow cannot authorize
    // arbitrary site actions: the exact observed target and input need approval.
    if(capability.driver==='browser'&&effect!=='read'&&mode==='allow') mode='ask';
    // Saved profile availability does not establish which provider account is
    // signed in. No unattended reads under a user-asserted account identity.
    if((connection.transport==='persistent'||connection.sessionScope==='browser-profile')&&connection.identity?.verified!==true&&mode==='allow') mode='ask';
    // F03.3: the developer's ceiling on this row in this environment caps the mode; it never raises one.
    const ceiling=group&&this.ceilingOf?this.ceilingOf(capability.appId,group.id):null;
    if(ceiling==='deny') mode='deny';else if(ceiling==='ask'&&mode==='allow') mode='ask';
    // T4, after every saved mode and clamp: an operation that gives access to other people or services stays Never.
    if(fabricLocked) mode='deny';
    const previouslyMapped=Array.isArray(map?.historicalCapabilityIds)&&map.historicalCapabilityIds.includes(capability.id);
    const removed=previouslyMapped&&!operation;
    // F10.6: a row may mark a compiled member unsupported, as a map can; its bytes and id stay as they are (I1).
    let status=removed?'removed':operation?.support==='unsupported'||data?.unsupported?'unsupported':capability.status==='active'?'active':'candidate';
    // Discovery's scopes where the map has any; the row's only where it is silent.
    const {requiredScopes,scopeSets,invalid:metadataInvalid}=scopeSetsOf(operation,data);
    if(metadataInvalid) status='unsupported';
    // A member that can never work through a sign-in is unavailable before anything Discovery says, for every auth method.
    const providerAccess=capability.driver==='workspace'||capability.driver==='device'?'local':data?.unavailable?'unavailable':metadataInvalid?'unknown':providerAccessOf(connection,scopeSets,()=>this.grantedScopes(connection));
    let reason;
    if(!sameRoute(connection,capability)) reason='The capability belongs to a different application or connection route.';
    else if(fabricLocked) reason=LOCK_WORDS;
    else if(providerAccess==='unavailable') reason=UNAVAILABLE_REASONS[data.unavailable];
    else if(!activeConnection(connection)) reason='The connection is not ready. Check or reconnect it first.';
    else if(removed) reason='This previously discovered operation is absent from the current application map. Rediscover and review its replacement.';
    else if(metadataInvalid) reason='The discovered provider scope requirements are malformed; execution is blocked.';
    else if(status==='unsupported') reason=data?.unsupported??'The current application map marks this operation unsupported.';
    else if(status==='candidate') reason='This capability is a candidate and must be explicitly reviewed and activated before execution.';
    else if(providerAccess==='missing') reason='The account does not have a required provider scope. Local Allow cannot grant provider permission; reconnect with the required consent.';
    else if(mode==='deny') reason='Execution is denied by your setting for this account and operation.';
    else if(stale) reason='The previous setting no longer matches this account authorization or operation definition. Review the new authorization; each request requires approval until then.';
    else if(mode==='ask') reason='Each exact request must be approved before execution.';
    else if(providerAccess==='unknown') reason='Allowed locally; provider scopes are unknown or provider-enforced. This is not proof of provider access.';
    else reason=effect==='read'?'Allowed for this account and operation.':'Standing consent allows new requests for this exact account and operation without another prompt. Jobs are never automatically replayed.';
    const executable=activeConnection(connection)&&sameRoute(connection,capability)&&status==='active'&&providerAccess!=='missing'&&providerAccess!=='unavailable'&&mode!=='deny';
    const policySource=follows?'default':saved?'saved':stale?'stale':'default';
    const policyRevision=saved||follows?policy.revision:'default';
    const policyHash=canonicalHash({bindingHash,mode,policyRevision,providerAccess,scopeSets,status});
    // Numeric authority is available only in explicitly designated local stores.
    // Do not fold it into legacy hashes or invent snapshots for historical jobs.
    const authority=this.store.authorityEnabled?{
      connectionGeneration:this.store.connectionGeneration(connection.id),
      policyRevision:this.store.policyRevision(this.policyId(connection.id,capability.id)),
    }:{};
    return {connectionId:connection.id,capabilityId:capability.id,name:capability.name,effect,mode,defaultMode,...(fabricLocked?{locked:true}:{}),...((lockedGroup||group)?.audience===true?{audience:true}:{}),sensitivity,groupId:group?.id??null,groupLabel:group?.label??null,providerAccess,...(data?.unavailable?{unavailable:data.unavailable}:{}),...(data?.conditions?{conditions:[...data.conditions]}:{}),requiredScopes,scopeSets,status,reason,executable,requiresApproval:mode==='ask',policySource,stale,bindingHash,policyHash,...authority};
  }
  list(connectionId) {
    const connection=this.store.get('connections',connectionId);
    if(!connection) throw new Error('Connection not found.');
    const index=mapIndex(this.store.get('applicationMaps',connection.appId)),memo=new Map();
    return this.store.list('capabilities').filter(cap=>sameRoute(connection,cap)).map(cap=>this.decision(connection,cap,index,{memo}));
  }
  set({connectionId,capabilityId,mode}) {
    if(!MODES.has(mode)) throw new Error('Permission mode must be allow, ask, or deny.');
    const connection=this.store.get('connections',connectionId),capability=this.store.get('capabilities',capabilityId);
    if(!activeConnection(connection)) throw new Error('Choose a ready connection before changing its permissions.');
    if(!capability||!sameRoute(connection,capability)) throw new Error('Capability does not belong to this application and connection route.');
    // F10.11 part e: an action's record is bound to its steps, and only a current, placed action takes one.
    if(capability.driver==='action') return this.setAction(connection,capability,mode);
    // T4 (F10.3): nothing but Never is saved on a member Fabric locks, so no record can wait for the lock to lift.
    const map=this.store.get('applicationMaps',capability.appId),operation=this.operationOf(capability,map);
    if(mode!=='deny'&&lockedRow(this.groups,this.configs,capability,operation,map)) throw Object.assign(new Error(LOCK_WORDS),{code:'mode_not_allowed',locked:true});
    const id=this.policyId(connectionId,capabilityId);
    // Choosing the row's default keeps following its reviewed default. It is still a new record with a fresh
    // revision, never a deletion: removing the record would restore the original revision and let an approval
    // made before a Deny become valid again.
    const follows=mode===this.decisionWithout(connection,capability).mode;
    this.store.put('permissions',{id,connectionId,capabilityId,mode,...(follows?{followsDefault:true}:{}),bindingHash:this.binding(connection,capability,this.sensitivityOf(capability,operation,map),memberRoutes(this.groups,this.configs,capability,operation,map)),revision:randomUUID(),updatedAt:new Date().toISOString()});
    this.store.audit({type:'permission.updated',connectionId,capabilityId,mode,...(follows?{source:'default'}:{})});
    return this.decision(connection,capability);
  }
  // ---- actions (F10.11 parts e and f; spec lines 869-879) ----------------------------------------------------------------------------
  /** F10.12: true only in a certification Fabric, for an action whose current entry is placed, still has its pinned code, and both the
   *  catalog and the stored record call a candidate. A changed, unplaced, repinned, superseded or refused-app action never qualifies. */
  certifying(capability) {
    if(this.certification!==true||capability?.driver!=='action') return false;
    const item=this.actions?.entryOf?.(capability);
    if(!item||item.entry.unplaced||!this.actions.pinned(item)) return false;
    return item.status==='candidate'&&capability.status==='candidate';
  }
  /** One read per listing call: the memo holds the proxy's view of the account, its rows, its typed templates and decisions, and each
   *  row's base(), so a page of actions reads each once. */
  memoized(memo,key,read) {if(!memo.has(key)) memo.set(key,read());return memo.get(key);}
  /**
   * What an action's decision is made of, before its own record: the catalog entry, each step's contribution (its row's saved or stale
   * proxy setting, Never when the row's default is Never, the developer's ceiling, and c4, the mode of every typed operation whose template
   * fits the step's own template), its sensitivity, its own default, the row Fabric locks that it meets and its binding. `blocked` says why
   * there is nothing to decide: no catalog, a removed or superseded id, a record that is not the reviewed definition, an unplaced step or an
   * account that cannot reach the app's reviewed API address.
   */
  actionFacts(connection,capability,memo) {
    const catalog=this.actions,effect=permissionEffect(capability),appId=capability.appId,definition=this.groups.get(appId);
    const stop=(status,reason,extra={})=>({effect,blocked:{status,reason,...extra}});
    if(!catalog) return stop('unsupported',ACTION_WORDS.unsupported);
    const replaced=catalog.superseded?.get?.(capability.id);
    if(replaced) return stop('removed',ACTION_WORDS.superseded,{replacedBy:replaced.replacedBy});
    if(capability.status==='disabled'||!catalog.entries?.has?.(capability.id)) return stop('removed',ACTION_WORDS.removed);
    const item=catalog.entryOf(capability),entry=item?.entry;
    if(!entry) return stop('unsupported',ACTION_WORDS.changed);
    if(entry.unplaced) return stop('unsupported',ACTION_WORDS.unplaced);
    const at=`${connection.id}:`,context=definition&&this.proxy?this.memoized(memo,`${at}context`,()=>this.proxy.display(connection,definition)):null;
    if(!context) return stop('unsupported',ACTION_WORDS.unreachable);
    const {config,map}=context,rows=this.memoized(memo,`${at}rows`,()=>new Map(this.proxy.rows(context).map(row=>[row.row,row])));
    const stateOf=row=>this.memoized(memo,`${at}base:${row.row}`,()=>this.proxy.base(context,row));
    const typedList=this.memoized(memo,`${at}typed`,()=>this.proxy.typedTemplates(context));
    const typedOf=typed=>this.memoized(memo,`${at}typed:${typed.id}`,()=>({...this.proxy.typed(connection,typed),sensitivity:this.sensitivityOf(typed,this.operationOf(typed,map),map)}));
    const related=new Set(),ceilings=new Set();
    const steps=actionSteps(entry,map).map(({placement,request,optional,resolves})=>{
      const target=rows.get(`group:${placement.groupId}`),source=placement.routedFrom?rows.get(`group:${placement.routedFrom.groupId}`):null,own=ownRequest(request);
      let mode=target&&own?'allow':'deny',verdict=null;
      // The step's rows: its own, and the row a body route moved it from, each with its proxy setting when one is saved or stale.
      for(const row of [target,source].filter(Boolean)) {
        const state=stateOf(row),ceiling=this.ceilingOf?this.ceilingOf(appId,row.group.id):null;
        related.add(`${row.row}:${state.revision}`);ceilings.add(`${row.group.id}:${ceiling??'none'}`);
        if(state.source==='saved'||state.source==='stale') mode=strictest(mode,state.mode);
        if(row.defaultMode==='deny') mode=strictest(mode,'deny');
        if(ceiling) mode=strictest(mode,ceiling);
      }
      // c4: every typed operation that routes the step's own template caps it by its mode, never its status.
      for(const {capability:typed,template} of own?typedList:[]) {
        if(!fitsTemplate(template,own,{style:config.style})) continue;
        const state=typedOf(typed);related.add(state.revision);mode=strictest(mode,state.mode);
        if((VERDICT[state.sensitivity]||0)>(VERDICT[verdict]||0)) verdict=state.sensitivity;
      }
      const home=source??target,data=home?memberData(home.group,placement.member):{};
      const access=home?this.proxy.memberAccess(connection,map,home.group,placement.member):{providerAccess:'unknown',scopeSets:[]};
      return {placement,optional,resolves,rows:[target,source].filter(Boolean),mode,sensitive:data.sensitive==='secrets'?'secrets':verdict,unavailable:data.unavailable??null,
        providerAccess:access.providerAccess,scopeSets:access.scopeSets};
    });
    // Sensitivity: a step on a member its row marks secrets, or a typed verdict on any step, secrets above suspected-write.
    const sensitivity=entry.sensitive===true?'secrets':steps.reduce((most,step)=>(VERDICT[step.sensitive]||0)>(VERDICT[most]||0)?step.sensitive:most,null);
    // The own default: the strictest groupDefault() over the action's row, with its effect and sensitivity, and over the row of every perform
    // and verify step with that step's own effect, so a step that reaches people or writes outside the account asks (T8).
    const ownGroup=definition.groups.find(group=>group.id===entry.row)??null;
    let defaultMode=groupDefault(ownGroup,capability,effect,{reviewedAsRead:false,sensitive:sensitivity});
    for(const step of steps) if(step.placement.phase==='perform'||step.placement.phase==='verify') for(const row of step.rows) defaultMode=strictest(defaultMode,groupDefault(row.group,capability,step.placement.effect,{reviewedAsRead:false}));
    const locked=lockedRow(this.groups,this.configs,capability,null,map,catalog),routes=memberRoutes(this.groups,this.configs,capability,null,map,catalog);
    return {effect,item,entry,context,ownGroup,steps,sensitivity,defaultMode:locked?'deny':defaultMode,locked,related,ceilings,bindingHash:this.actionBinding(connection,capability,entry,sensitivity,routes)};
  }
  /** What an action's own record is bound to: what a typed binding holds, every placement (step, phase, member, row and the row a body
   *  route moved it from) and its sensitivity, so a moved step or a newly sensitive member makes a saved Allow stale. */
  actionBinding(connection,capability,entry,sensitivity,routes) {
    const identity=bindingIdentity(connection.identity);
    return canonicalHash({kind:'fabric-action',bodyRoutes:routes,connectionId:connection.id,appId:connection.appId,driver:connection.driver,authRevision:connection.authRevision??null,identity,
      createdAt:connection.createdAt??null,capabilityId:capability.id,capabilityHash:capabilityPermissionHash(capability),
      placements:entry.placements.map(placement=>({stepId:placement.stepId,phase:placement.phase,member:placement.member,groupId:placement.groupId,routedFrom:placement.routedFrom?.groupId??null})),
      sensitivity:sensitivity??null});
  }
  /** F10.11 part k: what each step of an action needs from a sign-in, through this manager's rows and catalog (actionStepScopes()). */
  actionScopes(capability,map=this.store.get('applicationMaps',capability.appId)) {return actionStepScopes(this.groups,this.actions,capability,map);}
  /** F10.11 part l: the labels of the rows an action touches, without an account (actionRowLabels()); none when the catalog lacks it. */
  actionRows(capability) {const entry=this.actions?.entryOf?.(capability)?.entry;return entry?actionRowLabels(this.groups.get(capability.appId),entry):[];}
  /** An action's sensitivity without an account: its entry's flag, or the strictest verdict of a typed operation one of its steps reaches. */
  actionSensitivity(capability,map) {
    const entry=this.actions?.entryOf?.(capability)?.entry;
    if(!entry) return null;
    if(entry.sensitive===true) return 'secrets';
    const config=this.configs.get(capability.appId),typed=this.proxy&&config?this.proxy.typedTemplates({connection:{appId:capability.appId},config}):[];
    let most=null;
    for(const {request} of actionSteps(entry,map)) for(const {capability:operation,template} of typed) {
      const own=ownRequest(request),verdict=own&&fitsTemplate(template,own,{style:config.style})?this.sensitivityOf(operation,this.operationOf(operation,map),map):null;
      if((VERDICT[verdict]||0)>(VERDICT[most]||0)) most=verdict;
    }
    return most;
  }
  /**
   * F10.11 part e (T8): an action's decision, in the shape of a typed one, plus prepareMode (its schema, lookup and prepare steps),
   * resolveMode (a two-phase action's resolving write; null otherwise), performMode (its perform and verify steps), steps, the labels of
   * its rows and whether one reaches people. Its own record follows the typed rules; each phase mode is the strictest of its steps'
   * contributions, and of the own mode where the phase needs it: always for perform, for prepare only when a step there is sensitive (no
   * secret is read before the action's own approval), and for the resolving write. `options`: {memo, uncertainRows}. `memo` is one listing
   * call's; `uncertainRows` is c7, the rows with an unresolved uncertain write (lib/proxy-runtime.mjs uncertainRows()), decided once by the
   * caller at acceptance and kept out of the policy hash.
   */
  actionDecision(connection,capability,{memo=new Map(),uncertainRows=null}={}) {
    const facts=this.actionFacts(connection,capability,memo),route=sameRoute(connection,capability),appId=capability.appId,policyId=this.policyId(connection.id,capability.id);
    const authority=this.store.authorityEnabled?{connectionGeneration:this.store.connectionGeneration(connection.id),policyRevision:this.store.policyRevision(policyId)}:{};
    const head={connectionId:connection.id,capabilityId:capability.id,name:capability.name,kind:'action',effect:facts.effect};
    if(facts.blocked) {
      const {status,reason,replacedBy}=facts.blocked,words=route?reason:'The capability belongs to a different application or connection route.';
      return {...head,mode:'deny',defaultMode:'deny',prepareMode:'deny',resolveMode:null,performMode:'deny',sensitivity:null,groupId:null,groupLabel:null,providerAccess:'unknown',requiredScopes:[],scopeSets:[],
        steps:[],rows:[],status,...(replacedBy?{replacedBy}:{}),reason:words,executable:false,requiresApproval:false,policySource:'default',stale:false,bindingHash:null,
        policyHash:canonicalHash({kind:'fabric-action',capabilityId:capability.id,status,reason:words}),...authority};
    }
    const {item,entry,ownGroup,steps,sensitivity,defaultMode,locked,related,ceilings,bindingHash}=facts;
    // The own record, read as a typed one is: drift never broadens an old restriction, and a record that follows the default follows it.
    const policy=this.store.get('permissions',policyId),stale=Boolean(policy&&policy.bindingHash!==bindingHash),follows=policy?.followsDefault===true;
    const saved=Boolean(policy&&!follows&&!stale&&MODES.has(policy.mode)),ownCeiling=ownGroup&&this.ceilingOf?this.ceilingOf(appId,ownGroup.id):null;
    let own=follows?defaultMode:saved?policy.mode:stale?(policy.mode==='deny'?'deny':'ask'):defaultMode;
    if(ownCeiling) {own=strictest(own,ownCeiling);ceilings.add(`${ownGroup.id}:${ownCeiling}`);}
    const fold=list=>list.reduce((mode,step)=>strictest(mode,step.mode),'allow'),phase=(step,...names)=>names.includes(step.placement.phase);
    const reads=steps.filter(step=>phase(step,'schema','lookup','prepare')),resolving=steps.find(step=>step.resolves)??null;
    const perform=steps.filter(step=>(phase(step,'perform')&&!step.resolves)||phase(step,'verify'));
    let prepareMode=strictest(fold(reads),reads.some(step=>step.sensitive)?own:'allow');
    let resolveMode=entry.twoPhase?strictest(resolving?resolving.mode:'deny',own):null;
    let performMode=strictest(own,fold(perform));
    // F10.12: in a certification Fabric every action, candidate or active, asks at least at its final approval (and its resolving write);
    // prepare reads keep their rows' modes, so an Allow read still builds the card before the one approval. A Never anywhere still refuses.
    if(this.certification===true) {performMode=strictest(performMode,'ask');if(resolveMode) resolveMode=strictest(resolveMode,'ask');}
    if(locked) {prepareMode='deny';performMode='deny';if(resolveMode) resolveMode='deny';}
    let mode=strictest(prepareMode,resolveMode??'allow',performMode);
    const hashed={mode,prepareMode,resolveMode,performMode};
    // c7, decided at acceptance and kept out of the policy hash: a write row with an unresolved uncertain write asks again.
    let duplicate=false;
    if(uncertainRows instanceof Set) {
      const hit=step=>step.placement.effect!=='read'&&uncertainRows.has(`group:${step.placement.groupId}`);
      if(resolving&&hit(resolving)) {resolveMode=strictest(resolveMode,'ask');duplicate=true;}
      if(steps.some(step=>phase(step,'perform')&&!step.resolves&&hit(step))) {performMode=strictest(performMode,'ask');duplicate=true;}
      mode=strictest(mode,resolveMode??'allow',performMode);
    }
    // Access: runPlan() over every step, each member read as the proxy reads it (the source row for a routed step).
    const byStep=new Map(steps.map(step=>[step.placement.stepId,step]));
    const plan=this.actions.runPlan(entry,{accessOf:placement=>byStep.get(placement.stepId).providerAccess,modeOf:placement=>byStep.get(placement.stepId).mode});
    const providerAccess=plan.access,unavailable=providerAccess==='unavailable'?steps.find(step=>plan.run.includes(step.placement.stepId)&&step.unavailable)?.unavailable??null:null;
    const status=item.status==='active'&&capability.status==='active'?'active':'candidate';
    const certifying=status==='candidate'&&this.certifying(capability);
    const never=steps.find(step=>step.mode==='deny')?.rows[0];
    let reason;
    if(!route) reason='The capability belongs to a different application or connection route.';
    else if(locked) reason=LOCK_WORDS;
    else if(providerAccess==='unavailable') reason=UNAVAILABLE_REASONS[unavailable];
    else if(!activeConnection(connection)) reason='The connection is not ready. Check or reconnect it first.';
    else if(status==='candidate'&&!certifying) reason=item.reason??ACTION_WORDS.candidate;
    else if(providerAccess==='missing') reason='The account does not have a required provider scope. Local Allow cannot grant provider permission; reconnect with the required consent.';
    else if(mode==='deny') reason=own==='deny'||!never?'Execution is denied by your setting for this account and operation.':`Never: "${never.label}" is set to Never, so this action is refused before any call.`;
    else if(stale) reason='The previous setting no longer matches this account authorization or operation definition. Review the new authorization; each request requires approval until then.';
    else if(certifying) reason=ACTION_WORDS.certifying;
    else if(mode==='ask') reason='Each exact request must be approved before execution.';
    else if(providerAccess==='unknown') reason='Allowed locally; provider scopes are unknown or provider-enforced. This is not proof of provider access.';
    else reason=facts.effect==='read'?'Allowed for this account and operation.':'Standing consent allows new requests for this exact account and operation without another prompt. Jobs are never automatically replayed.';
    const executable=route&&activeConnection(connection)&&(status==='active'||certifying)&&!locked&&!['missing','unavailable'].includes(providerAccess)&&mode!=='deny';
    const policySource=follows?'default':saved?'saved':stale?'stale':'default',policyRevision=saved||follows?policy.revision:'default';
    // The policy hash reads every record revision and ceiling the decision read, so changing one and changing it back still refuses (no ABA).
    const policyHash=canonicalHash({kind:'fabric-action',bindingHash,...hashed,policyRevision,providerAccess,steps:steps.map(step=>({stepId:step.placement.stepId,scopeSets:step.scopeSets})),status,
      ...(certifying?{certifying:true}:{}),related:[...related].sort(),ceilings:[...ceilings].sort()});
    const audience=ownGroup?.audience===true||steps.some(step=>step.rows.some(row=>row.audience===true));
    const labels=actionRowLabels(this.groups.get(appId),entry);
    return {...head,mode,defaultMode,prepareMode,resolveMode,performMode,...(locked?{locked:true}:{}),...(audience?{audience:true}:{}),sensitivity,groupId:ownGroup?.id??null,groupLabel:ownGroup?.label??null,
      providerAccess,...(unavailable?{unavailable}:{}),requiredScopes:[],scopeSets:[],
      steps:steps.map(step=>({stepId:step.placement.stepId,phase:step.placement.phase,groupId:step.placement.groupId,member:step.placement.member,providerAccess:step.providerAccess,scopeSets:step.scopeSets,mode:step.mode})),
      rows:labels,status,...(certifying?{certifying:true}:{}),reason,executable,requiresApproval:mode==='ask',policySource,stale,bindingHash,policyHash,...(duplicate?{duplicateOfUncertain:true}:{}),...authority};
  }
  /**
   * Iteration 9 part 2a (docs/I07-BUILD-MAP.md section 2.5; T8): whether a trigger may read on this account unattended, now. A trigger has no
   * record of its own, so its mode is the strictest over its poll, seed and enrich steps of each row's proxy setting (base(), which folds the
   * default, a saved or stale record and a ceiling, so a read row that defaults to Ask cannot pass), the row a body route moved a step from, and
   * c4, the mode of every typed operation that fits a step's own template. A step on a member marked secrets asks: no watch reads one in the
   * background, and a trigger has no record of its own to allow it. Access is the weakest step's, each member read as the proxy reads it, and
   * display() gives the account's rows without the ready check, since gate steps 3 to 8 run on an account that must reconnect too.
   * `memo` holds the typed template list alone, for one tick: the account, the rows, base() and each typed mode are read on every call, so a
   * change made during a poll is seen at the next gate. It is not a memo of actionFacts(). Returns {mode, executable, access, bindingHash,
   * policyHash, rows: [{row, policyHash}]}, with connectionGeneration and policyRevision on a designated store. Neither hash reads a cursor.
   */
  triggerDecision(connection,entry,{memo=new Map()}={}) {
    const stored=this.store.get('connections',connection?.id),reads=triggerReads(entry),definition=stored?this.groups.get(stored.appId):null;
    const context=definition&&this.proxy?this.proxy.display(stored,definition):null;
    const generation=stored&&this.store.authorityEnabled?{connectionGeneration:this.store.connectionGeneration(stored.id)}:{};
    if(!context||!reads.length) return {mode:'deny',executable:false,access:'unknown',bindingHash:null,policyHash:canonicalHash({kind:'fabric-trigger',triggerId:entry.id,connectionId:connection?.id??null}),rows:[],...generation};
    const {config,map}=context,rows=new Map(this.proxy.rows(context).map(row=>[row.row,row]));
    const templates=this.memoized(memo,`${stored.id}:typedTemplates`,()=>this.proxy.typedTemplates(context));
    const modes=[],policies=new Set(),seen=new Map(),seenIn=row=>{if(!seen.has(row.row)) seen.set(row.row,new Set());return seen.get(row.row);};
    const steps=reads.map(({placement,step})=>{
      const target=rows.get(`group:${placement.groupId}`),source=rows.get(`group:${placement.routedFrom?.groupId}`),path=placement.routedFrom?[target,source]:[target];
      const own=step?ownRequest(`${step.method} ${step.path}`):null;
      if(!own||!path.every(Boolean)) {modes.push('deny');return {stepId:placement.stepId,scopeSets:[],access:'unknown'};}
      for(const row of path) {
        const state=this.proxy.base(context,row);
        modes.push(state.mode);policies.add(state.id);
        seenIn(row).add(`${state.mode}:${state.revision}`);
      }
      for(const {capability} of templates.filter(({template})=>fitsTemplate(template,own,{style:config.style}))) {
        const state=this.proxy.typed(stored,capability);
        modes.push(state.mode);policies.add(this.policyId(stored.id,capability.id));
        for(const row of path) seenIn(row).add(`${state.mode}:${state.revision}`);
      }
      const home=source??target,{providerAccess,scopeSets,data}=this.proxy.memberAccess(stored,map,home.group,placement.member);
      if(data.sensitive==='secrets') modes.push('ask');
      return {stepId:placement.stepId,scopeSets,access:providerAccess};
    });
    const mode=strictest(...modes),states=steps.map(step=>step.access),access=['unavailable','missing','unknown'].find(state=>states.includes(state))??'granted';
    const bindingHash=this.triggerBinding(stored,entry,reads,definition);
    const held=[...seen].sort(([a],[b])=>a<b?-1:1).map(([row,values])=>({row,policyHash:canonicalHash({kind:'fabric-trigger',bindingHash,row,values:[...values].sort()})}));
    const policyHash=canonicalHash({kind:'fabric-trigger',bindingHash,mode,access,steps:steps.map(({stepId,scopeSets})=>({stepId,scopeSets})),rows:held});
    const revision=this.store.authorityEnabled?{policyRevision:canonicalHash([...policies].sort().map(id=>[id,this.store.policyRevision(id)]))}:{};
    return {mode,executable:stored.status==='ready'&&mode==='allow'&&!['missing','unavailable'].includes(access),access,bindingHash,policyHash,rows:held,...generation,...revision};
  }
  /** What a watch's authority is bound to: what an action's binding holds, its reads in place of its steps, and identity.id alone, so a rename moves
   *  nothing here. A row's own binding still holds the display name, so a saved row turns stale on a rename, exactly as for actions. */
  triggerBinding(connection,entry,reads,definition) {
    const routes=reads.flatMap(({placement})=>(definition.groups.find(group=>group.id===(placement.routedFrom?.groupId??placement.groupId))?.bodyRoutes??[]).filter(route=>memberKey(route.member)===memberKey(placement.member)));
    return canonicalHash({kind:'fabric-trigger',bodyRoutes:routes,connectionId:connection.id,appId:connection.appId,driver:connection.driver,authRevision:connection.authRevision??null,identity:connection.identity?.id??null,
      createdAt:connection.createdAt??null,triggerId:entry.id,placements:reads.map(({placement})=>({stepId:placement.stepId,phase:placement.phase,member:placement.member,groupId:placement.groupId,routedFrom:placement.routedFrom?.groupId??null}))});
  }
  /** An action's own record, written as a typed one is, bound to its steps; only a current, placed action takes one, and one that meets a
   *  row Fabric locks takes only Never. */
  setAction(connection,capability,mode) {
    const facts=this.actionFacts(connection,capability,new Map());
    if(facts.blocked) throw Object.assign(new Error(facts.blocked.reason),{code:'capability_changed'});
    if(mode!=='deny'&&facts.locked) throw Object.assign(new Error(LOCK_WORDS),{code:'mode_not_allowed',locked:true});
    // Choosing the default is still a new record with a fresh revision, never a deletion (no ABA).
    const follows=mode===facts.defaultMode;
    this.store.put('permissions',{id:this.policyId(connection.id,capability.id),connectionId:connection.id,capabilityId:capability.id,mode,...(follows?{followsDefault:true}:{}),bindingHash:facts.bindingHash,revision:randomUUID(),updatedAt:new Date().toISOString()});
    this.store.audit({type:'permission.updated',connectionId:connection.id,capabilityId:capability.id,mode,...(follows?{source:'default'}:{})});
    return this.decision(connection,capability);
  }
  operationOf(capability,map=this.store.get('applicationMaps',capability.appId)) {
    return Array.isArray(map?.operations)?map.operations.find(op=>op&&op.capabilityId===capability.id)||null:null;
  }
  /** The mode an operation would have with no saved setting: its default after every clamp. */
  decisionWithout(connection,capability) {
    const persisted=this.store.get('connections',connection.id)||connection;
    if(capability.driver==='action') {const facts=this.actionFacts(persisted,capability,new Map());return {mode:facts.blocked||facts.locked?'deny':facts.defaultMode};}
    const effect=permissionEffect(capability),map=this.store.get('applicationMaps',capability.appId);
    const operation=Array.isArray(map?.operations)?map.operations.find(op=>op.capabilityId===capability.id):null;
    let mode=lockedRow(this.groups,this.configs,capability,operation||null,map)?'deny':operationDefault(this.groups,capability,operation,this.sensitivityOf(capability,operation,map));
    if(capability.driver==='browser'&&effect!=='read'&&mode==='allow') mode='ask';
    if((persisted.transport==='persistent'||persisted.sessionScope==='browser-profile')&&persisted.identity?.verified!==true&&mode==='allow') mode='ask';
    return {mode};
  }
  /** F10.7 (decision 6), at the first start on split rows, once per store: a record that followed a row's Never before its member
   *  moved to a row split out of it (SPLIT_ROWS) becomes a saved Never, marked with the row it came from, so the split loosens no
   *  existing account. A record that follows the default followed the old row's Never then, whatever mode a reset left stored in it.
   *  Once done it never runs again, so a record that follows the new row's default afterwards (a reset after the split) reads Ask. */
  migrateSplitRows() {
    if(this.store.get('migrations',SPLIT_MIGRATION)) return 0;
    let count=0;
    for(const policy of this.store.list('permissions')) {
      if(policy.kind==='proxy-row'||policy.followsDefault!==true||policy.splitFrom) continue;
      const capability=this.store.get('capabilities',policy.capabilityId),split=capability?SPLIT_ROWS[capability.appId]:null;
      const group=split?groupFor(this.groups,capability.appId,this.operationOf(capability)):null;
      if(!group||!Object.hasOwn(split,group.id)) continue;
      const {followsDefault,...saved}=policy;
      this.store.put('permissions',{...saved,mode:'deny',splitFrom:split[group.id],revision:randomUUID(),updatedAt:new Date().toISOString()});
      this.store.audit({type:'permission.updated',connectionId:policy.connectionId,capabilityId:policy.capabilityId,mode:'deny',source:'split'});
      count++;
    }
    this.store.put('migrations',{id:SPLIT_MIGRATION,converted:count,ranAt:new Date().toISOString()});
    return count;
  }
  /** Reset to defaults: removes saved settings for one account (optionally only some operations). */
  reset({connectionId,capabilityIds}) {
    const connection=this.store.get('connections',connectionId);
    if(!activeConnection(connection)) throw new Error('Choose a ready connection before changing its permissions.');
    const only=capabilityIds?new Set(capabilityIds):null;
    // Proxy rows share the collection but have their own reset; a typed reset never touches them.
    const changed=this.store.list('permissions').filter(policy=>policy.kind!=='proxy-row'&&policy.connectionId===connectionId&&policy.followsDefault!==true&&(!only||only.has(policy.capabilityId)));
    for(const policy of changed) this.store.put('permissions',{...policy,followsDefault:true,revision:randomUUID(),updatedAt:new Date().toISOString()});
    this.store.audit({type:'permission.reset',connectionId,count:changed.length});
    return changed.length;
  }
}

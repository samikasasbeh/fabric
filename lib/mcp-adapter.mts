import {Server, fromJsonSchema} from '@modelcontextprotocol/server';
import type {CallToolResult, JsonSchemaType, Tool} from '@modelcontextprotocol/server';
import {FabricClient} from './fabric-client.mjs';
import {canonicalHash} from './compiler.mjs';
import {validateCard,lapsed,toText as cardText} from './cards.mjs';

// This adapter holds one operator-provisioned local client grant. It does not
// authenticate an owner, mint grants, connect accounts, approve or dispatch work.
const INPUT_BYTES=64*1024;
const RESPONSE_BYTES=2*1024*1024;
const DEFAULT_TIMEOUT_MS=90_000;
const MAX_INFLIGHT=8;
const TOKEN=/^fab_client\.[a-f0-9-]{36}\.[A-Za-z0-9_-]{43}$/;
const HASH=/^[a-f0-9]{64}$/;
const STATES=new Set(['awaiting_connection','awaiting_approval','queued','running','succeeded','failed','uncertain','cancelled','expired']);
const HANDOFF_STATES=new Set(['awaiting_owner','signing_in','awaiting_confirmation','continuing','connected','closed']);
const HANDOFF_OUTCOMES=new Set(['owner_declined','client_cancelled','client_revoked','continuation_expired','authority_changed','capability_retired','policy_denied','fabric_failed']);
const APP=/^[a-z][a-z0-9-]{0,63}$/;
const SECRET_KEY=/^(?:authorization|cookie|set-cookie|password|passwd|secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|token|tokenHash|approvalDigest|preview)$/i;
const MESSAGES=Object.freeze({
  invalid_request:'Invalid tool arguments. Use the listed schema and bounded JSON inputs.',
  method_not_found:'This adapter exposes only capability listing, invocation and call lookup.',
  unauthorized:'Fabric client access is missing, expired or revoked. Ask the owner to review access.',
  permission_denied:'The owner has not permitted this account and operation.',
  unsupported_route:'This operation is not supported through the granted route.',
  grant_changed:'Account or capability authority changed. Ask the owner to review a new grant.',
  not_found:'This call is unavailable to the current client.',
  idempotency_conflict:'This request ID already names different inputs. No new request was submitted.',
  outcome_unknown:'The earlier request has no safely recoverable result. Do not replay it blindly.',
  request_failed:'The earlier request failed. No automatic retry was attempted.',
  unsupported_version:'The Fabric runtime does not support this protocol version.',
  request_interrupted:'Request interrupted or timed out. Execution may have started; no retry was attempted. Check the existing call or owner activity before taking further action.',
  invalid_response:'The Fabric runtime returned an invalid or oversized response. No retry was attempted.',
  unavailable:'The Fabric runtime could not be reached safely. No retry was attempted.',
  busy:'The adapter has too many active requests. No request was submitted.',
  pending_limit:'Too many account requests are waiting for the owner. No new request was submitted.',
  invalid_transition:'This account request was already handled. No change was made.',
  invalid_path:'The path is not a single canonical relative path under the app\'s reviewed API address. Nothing was sent.',
  parameter_not_allowed:'A query or body parameter is reserved, not allowed for this app, or not a string value. Fabric adds credentials itself. Nothing was sent.',
  rate_limited:'Too many refused proxied requests. Wait a minute before trying again. Nothing was sent.',
  header_not_allowed:'Only Accept and conditional headers may be sent; Fabric adds credentials and provider headers itself. Nothing was sent.',
  method_not_allowed:'Use GET, POST, PUT, PATCH or DELETE (GET or POST for method-style apps). Nothing was sent.',
  unsupported_body:'The body must be plain JSON, and a GET has none. Nothing was sent.',
  request_too_large:'The request is over the proxy limits. Nothing was sent.',
  row_not_granted:'This client may not send requests that land in that permission row. Nothing was sent.',
  policy_denied:'The account owner set this to Never. Nothing was sent.',
  provider_access_missing:'The account does not have the provider access this needs. The owner must reconnect with it. Nothing was sent.',
  proxy_unavailable:'The proxy is not available for this account or app. Nothing was sent.',
  authority_changed:'The account, its settings or the request changed. Nothing was sent; ask again if still needed.',
  app_disabled:'The app was turned off by the developer. Nothing was sent.',
  // F10.11 part l: an action's own refusals, and the notice on an action a newer version replaced.
  input_schema_changed:'The fields of this resource changed after Fabric read them. Nothing was sent: describe it again and ask again.',
  action_refused:'Fabric refused this action for what it was given or what it read. Nothing was sent.',
  superseded:'This action was replaced by a newer version. Use the action it names in replacedBy.',
});
type ErrorCode=keyof typeof MESSAGES;
type RecordValue=Record<string,unknown>;
type Environment=Readonly<Record<string,string|undefined>>;
type InvokeInput={requestId:string;connectionId?:string;appId?:string;capabilityId:string;definitionHash:string;args:RecordValue;task?:{title:string}};
const record=(value:unknown):value is RecordValue=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const text=(value:unknown,max=256):value is string=>typeof value==='string'&&value.length>0&&value.length<=max&&!/[\u0000-\u001f\u007f]/.test(value);
const timestamp=(value:unknown):value is string=>typeof value==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)&&Number.isFinite(Date.parse(value))&&new Date(value).toISOString()===value;
function fail(code:ErrorCode):never {throw Object.assign(new Error(MESSAGES[code]),{code});}
function errorCode(error:unknown):ErrorCode {
  const code=error&&typeof error==='object'?Object.getOwnPropertyDescriptor(error,'code')?.value:undefined;
  return typeof code==='string'&&Object.hasOwn(MESSAGES,code)?code as ErrorCode:'unavailable';
}
function toolError(code:ErrorCode):CallToolResult {
  const value={error:{code,message:MESSAGES[code]}};
  return {content:[{type:'text',text:JSON.stringify(value)}],structuredContent:value,isError:true};
}

/** Entry-point configuration only. No argument, tool input or .env-file fallback. */
export function readMcpEnvironment(env:Environment=process.env):Readonly<{endpoint:string;token:string}> {
  const endpoint=env.FABRIC_ENDPOINT??'http://127.0.0.1:4188/fabric/v1',token=env.FABRIC_CLIENT_TOKEN;
  const match=/^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/fabric\/v1$/.exec(endpoint);
  if(!match||Number(match[1])>65535||typeof token!=='string'||!TOKEN.test(token))throw new Error('Invalid MCP environment. Set a scoped FABRIC_CLIENT_TOKEN and an explicit http://127.0.0.1:PORT/fabric/v1 endpoint.');
  return Object.freeze({endpoint,token});
}

const identifier={type:'string',minLength:1,maxLength:256,pattern:'^[^\\u0000-\\u001f\\u007f]+$'};
const HINTS=['readOnly','destructive','idempotent','openWorld'] as const;
const DATE=/^\d{4}-\d{2}-\d{2}$/;
/**
 * F10.11 part l: an entry's kind, its four hints (renamed to MCP's own names) and, for an action, the schema of its checked output, the rows
 * it touches and its inputs' choices, each in a closed shape. A missing kind is an operation's (an older Fabric), kept absent; an action
 * always has all of them, an operation none of the action's. Anything else is invalid_response.
 */
function described(item:RecordValue,token:string):RecordValue {
  if(item.kind!==undefined&&item.kind!=='operation'&&item.kind!=='action')fail('invalid_response');
  const action=item.kind==='action',value=item.annotations;
  if((action||value!==undefined)&&!(record(value)&&HINTS.every(name=>typeof value[name]==='boolean')))fail('invalid_response');
  const hints=record(value)?{annotations:{readOnlyHint:value.readOnly,destructiveHint:value.destructive,idempotentHint:value.idempotent,openWorldHint:value.openWorld}}:{};
  const kind=item.kind===undefined?{}:{kind:item.kind};
  if(!action) {
    if(['outputSchema','rows','choices'].some(name=>Object.hasOwn(item,name)))fail('invalid_response');
    return {...kind,...hints};
  }
  const output=item.outputSchema,rows=item.rows,choices=item.choices;
  if(!record(output)||JSON.stringify(output).includes(token)||Buffer.byteLength(JSON.stringify(output))>RESPONSE_BYTES)fail('invalid_response');
  if(!Array.isArray(rows)||rows.length<1||rows.length>16||!rows.every(row=>text(row,200)))fail('invalid_response');
  if(!Array.isArray(choices)||choices.length>100||!choices.every(choice=>record(choice)&&Object.keys(choice).sort().join()==='dependsOn,input'&&text(choice.input,128)&&Array.isArray(choice.dependsOn)&&choice.dependsOn.length<=3&&choice.dependsOn.every(name=>text(name,128))))fail('invalid_response');
  return {...kind,...hints,outputSchema:output,rows:[...rows],choices:(choices as RecordValue[]).map(choice=>({input:choice.input,dependsOn:[...(choice.dependsOn as string[])]}))};
}
/** F10.11 part l: an unavailable entry on an action a newer version replaced names the one that replaced it, in a closed shape. */
function replacement(item:RecordValue):RecordValue {
  if(item.reason!=='superseded')return {};
  if(!text(item.replacedBy)||!(item.stopsAfter===undefined||typeof item.stopsAfter==='string'&&DATE.test(item.stopsAfter)))fail('invalid_response');
  return {replacedBy:item.replacedBy,...(item.stopsAfter===undefined?{}:{stopsAfter:item.stopsAfter})};
}
const definitions:Tool[]=[
  {name:'fabric_list_capabilities',description:'List currently granted Fabric account-operation pairs and their exact definition hashes and input schemas. Actions come first: an action runs several reviewed steps as one call, and lists the rows it touches and the schema of what it returns. Does not connect accounts or grant access.',inputSchema:{type:'object',properties:{},additionalProperties:false},annotations:{readOnlyHint:true}},
  {name:'fabric_invoke',description:'Submit an exact granted Fabric operation. Send connectionId for a granted account, or appId for an operation listed as connection_required; then the owner gets a link to choose or sign in to an account and Fabric continues this exact request (status awaiting_connection). Reuse requestId only for the identical accepted request; never retry an uncertain action blindly. awaiting_approval waits for the owner: relay the approval link to the account owner, who approves or declines in Fabric. An action may ask the owner twice, first for the reads it needs and then for the exact final request; read the call again after each approval. Fabric includes a card describing the call; a returned record is not proof of success.',inputSchema:{type:'object',properties:{requestId:{type:'string',minLength:1,maxLength:128,pattern:'^[A-Za-z0-9_.:-]+$'},connectionId:identifier,appId:{type:'string',minLength:1,maxLength:64,pattern:'^[a-z][a-z0-9-]{0,63}$'},capabilityId:identifier,definitionHash:{type:'string',pattern:'^[a-f0-9]{64}$'},args:{type:'object',maxProperties:1000},task:{type:'object',description:'Optional: a short title for what you are doing, shown to the account owner in Fabric activity (e.g. "Triage billing emails").',properties:{title:{type:'string',minLength:1,maxLength:120}},required:['title'],additionalProperties:false}},required:['requestId','capabilityId','definitionHash','args'],additionalProperties:false},annotations:{readOnlyHint:false,destructiveHint:true,idempotentHint:false}},
  {name:'fabric_proxy_request',description:'Call any endpoint of a granted account through Fabric\'s governed proxy: send method and a relative path (plus optional query, Accept or conditional headers and a JSON body). Fabric places the request in one of the account owner\'s permission rows and applies their Allow/Ask/Never; changes usually wait for the owner (relay the approval link). A change that reached the provider comes back uncertain, never as done: check before trying again, never retry blindly. Reuse requestId only for the identical request.',
    inputSchema:{type:'object',properties:{requestId:{type:'string',minLength:1,maxLength:128,pattern:'^[A-Za-z0-9_.:-]+$'},connectionId:identifier,
      request:{type:'object',properties:{method:{type:'string',enum:['GET','POST','PUT','PATCH','DELETE']},path:{type:'string',minLength:1,maxLength:2048,pattern:'^/'},query:{type:'object',maxProperties:50,additionalProperties:{anyOf:[{type:'string',maxLength:2048},{type:'array',maxItems:20,items:{type:'string',maxLength:2048}}]}},headers:{type:'object',maxProperties:16,additionalProperties:{type:'string',maxLength:1024}},body:{}},required:['method','path'],additionalProperties:false},
      timeoutMs:{type:'integer',minimum:1000,maximum:30000},task:{type:'object',description:'Optional: a short title for what you are doing, shown to the account owner.',properties:{title:{type:'string',minLength:1,maxLength:120}},required:['title'],additionalProperties:false}},
      required:['requestId','connectionId','request'],additionalProperties:false},annotations:{readOnlyHint:false,destructiveHint:true,idempotentHint:false}},
  {name:'fabric_get_call',description:'Read a client-owned Fabric call or a pending account handoff. This does not approve, cancel, replay or retry an operation.',inputSchema:{type:'object',properties:{callId:identifier},required:['callId'],additionalProperties:false},annotations:{readOnlyHint:true}},
];
// These schemas are the fixed definitions above, not caller-supplied schemas.
const schemas=new Map(definitions.map(tool=>[tool.name,fromJsonSchema<RecordValue>(tool.inputSchema as JsonSchemaType)]));
function bounded(value:unknown,limit:number,code:ErrorCode):void {
  try {canonicalHash(value);if(Buffer.byteLength(JSON.stringify(value))>limit)fail(code);}
  catch {fail(code);}
}
function redact(value:unknown,token:string,credentialFields=true):unknown {
  const clean=(value:string)=>value.split(token).join('[redacted]');
  if(typeof value==='string')return clean(value);
  if(Array.isArray(value))return value.map(item=>redact(item,token,credentialFields));
  if(record(value))return Object.fromEntries(Object.entries(value).map(([key,item])=>[clean(key),credentialFields&&SECRET_KEY.test(key)?'[redacted]':redact(item,token,credentialFields)]));
  return value;
}
const HANDOFF_TEXT:Readonly<Record<string,string>>=Object.freeze({
  owner_declined:'The owner declined this account request.',client_cancelled:'This account request was withdrawn.',client_revoked:'Client access was revoked before an account was chosen.',
  continuation_expired:'The account request expired before an account was chosen.',authority_changed:'Permissions or the operation changed. Ask again if still needed.',
  capability_retired:'This operation is no longer available.',policy_denied:'The chosen account is not permitted to run this operation.',fabric_failed:'Fabric could not continue this request.'});
/** The owner link must be exactly this endpoint's /continue/<callId>; nothing else is relayed to a model. */
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
function projectHandoff(value:RecordValue,endpoint:string):RecordValue {
  const handoff=value.handoff;
  // A developer environment (F03.9e): never a link. The request names its Connect session, which the app turns into a link
  // for the person; the model relays the session id to the app, never a URL.
  if(record(handoff)&&Object.keys(handoff).sort().join()==='appId,appName,connectSessionId,expiresAt,outcome,state') {
    if(typeof handoff.appId!=='string'||!APP.test(handoff.appId)||!text(handoff.appName,200)||!timestamp(handoff.expiresAt)||typeof handoff.state!=='string'||!HANDOFF_STATES.has(handoff.state)||
       !(handoff.outcome===null||typeof handoff.outcome==='string'&&HANDOFF_OUTCOMES.has(handoff.outcome))||typeof handoff.connectSessionId!=='string'||!/^cs_[a-z2-7]{26}$/.test(handoff.connectSessionId)||typeof value.id!=='string'||!UUID.test(value.id))fail('invalid_response');
    return {appId:handoff.appId,appName:handoff.appName,url:null,connectSessionId:handoff.connectSessionId,expiresAt:handoff.expiresAt,state:handoff.state,outcome:handoff.outcome};
  }
  if(!record(handoff)||Object.keys(handoff).sort().join()!=='appId,appName,expiresAt,outcome,state,url'||typeof handoff.appId!=='string'||!APP.test(handoff.appId)||!text(handoff.appName,200)||!timestamp(handoff.expiresAt)||
     typeof handoff.state!=='string'||!HANDOFF_STATES.has(handoff.state)||!(handoff.outcome===null||typeof handoff.outcome==='string'&&HANDOFF_OUTCOMES.has(handoff.outcome)))fail('invalid_response');
  // The link is relayed to a person: only Fabric's exact handoff route for a UUID call id, and a canonical expiry.
  if(typeof value.id!=='string'||!UUID.test(value.id)||new Date(handoff.expiresAt as string).toISOString()!==handoff.expiresAt)fail('invalid_response');
  if(handoff.url!==null&&handoff.url!==`${new URL(endpoint).origin}/continue/${value.id}`)fail('invalid_response');
  if(Object.hasOwn(value,'resumedCallId')&&!(value.resumedCallId===null||text(value.resumedCallId)))fail('invalid_response');
  return {appId:handoff.appId,appName:handoff.appName,url:handoff.url,expiresAt:handoff.expiresAt,state:handoff.state,outcome:handoff.outcome};
}
/** A sentence a model can relay to the account owner, with the exact link and call id. */
function handoffText(projected:RecordValue):string {
  const handoff=projected.handoff as RecordValue;
  if(handoff.url===null&&typeof handoff.connectSessionId==='string')return `Account needed: ${handoff.appName} is not connected for this request. Ask the app to send the person a Connect link for session ${handoff.connectSessionId} before ${handoff.expiresAt}; Fabric continues this exact request after they connect an account. Check progress with fabric_get_call using callId "${projected.id}". Do not resubmit.`;
  return `Account needed: ${handoff.appName} is not connected for this request. Ask the account owner to open ${handoff.url} before ${handoff.expiresAt} to choose or sign in to an account. Fabric continues this exact request afterwards. Check progress with fabric_get_call using callId "${projected.id}". Do not resubmit.`;
}
function projectResult(value:unknown,method:string,input:RecordValue,token:string,endpoint:string):RecordValue {
  bounded(value,RESPONSE_BYTES,'invalid_response');
  if(!record(value))fail('invalid_response');
  let projected:RecordValue;
  if(method==='capabilities.list') {
    // A grant holds at most 100 bound operations plus 50 request-only ones.
    if(!Array.isArray(value.capabilities)||value.capabilities.length>150)fail('invalid_response');
    // The proxy section lists only the granted accounts and rows, with each row's current mode.
    let proxy:unknown[]|null=null;
    if(Object.hasOwn(value,'proxy')) {
      if(!Array.isArray(value.proxy)||value.proxy.length>20)fail('invalid_response');
      proxy=value.proxy.map(entry=>{
        if(!record(entry)||!text(entry.connectionId)||typeof entry.appId!=='string'||!APP.test(entry.appId)||!['available','unavailable'].includes(entry.status as string)||!Array.isArray(entry.rows)||entry.rows.length>45)fail('invalid_response');
        return {connectionId:entry.connectionId,appId:entry.appId,status:entry.status,...(text(entry.reason,64)?{reason:entry.reason}:{}),rows:entry.rows.map(row=>{
          if(!record(row)||!text(row.row,200)||!text(row.label,200)||!['read','write','delete'].includes(row.effect as string)||!['allow','ask','deny','unavailable'].includes(row.approval as string))fail('invalid_response');
          return {row:row.row,label:row.label,effect:row.effect,approval:row.approval,...(text(row.reason,64)?{reason:row.reason}:{})};
        })};
      });
    }
    projected={...(proxy?{proxy}:{}),capabilities:value.capabilities.map(item=>{
      // A request-only entry has no account: connectionId is null and appId names the application.
      const requestOnly=record(item)&&item.connectionId===null&&typeof item.appId==='string'&&APP.test(item.appId);
      if(!record(item)||!text(item.id)||!(requestOnly||text(item.connectionId))||typeof item.definitionHash!=='string'||!HASH.test(item.definitionHash))fail('invalid_response');
      const base={id:item.id,connectionId:item.connectionId,definitionHash:item.definitionHash,...(requestOnly?{appId:item.appId}:{})};
      if(item.status==='unavailable') {
        if(item.kind!==undefined&&item.kind!=='operation'&&item.kind!=='action')fail('invalid_response');
        const reason=typeof item.reason==='string'&&Object.hasOwn(MESSAGES,item.reason)?item.reason:'permission_denied';
        return {...base,...(item.kind===undefined?{}:{kind:item.kind}),status:'unavailable',reason,...replacement({...item,reason})};
      }
      if(requestOnly) {
        // F10.11 part l: a request-only action entry carries driver action; any other is an API operation's.
        const driver=item.kind==='action'?'action':'http';
        if(item.status!=='connection_required'||item.approval!=='after_connection'||!['available','unavailable'].includes(item.signIn as string)||!text(item.name,1000)||typeof item.description!=='string'||item.driver!==driver||!record(item.inputSchema)||typeof item.effect!=='string'||!['read','write','delete'].includes(item.effect))fail('invalid_response');
        if(JSON.stringify(item.inputSchema).includes(token))fail('invalid_response');
        return {...base,...described(item,token),status:'connection_required',name:item.name,description:item.description,driver,inputSchema:item.inputSchema,effect:item.effect,approval:'after_connection',signIn:item.signIn};
      }
      if(item.status!=='available'||!text(item.name,1000)||!text(item.appId)||!text(item.driver)||!record(item.inputSchema)||typeof item.effect!=='string'||!['read','write','delete'].includes(item.effect)||typeof item.approval!=='string'||!['ask','allow'].includes(item.approval)||typeof item.description!=='string')fail('invalid_response');
      // Schema properties describe inputs, not credential values. Never corrupt
      // e.g. properties.token by applying result-data field-name redaction.
      // A schema containing the actual configured grant is rejected, not edited
      // into a different schema under the original definition hash.
      if(JSON.stringify(item.inputSchema).includes(token))fail('invalid_response');
      return {...base,...described(item,token),status:'available',name:item.name,description:item.description,appId:item.appId,driver:item.driver,inputSchema:item.inputSchema,effect:item.effect,approval:item.approval};
    })};
  } else {
    const handoff=Object.hasOwn(value,'handoff')?projectHandoff(value,endpoint):null;
    // Only a handoff that has not bound an account may lack one (queued: the held call is resuming on the chosen account).
    const accountless=handoff!==null&&value.connectionId===null&&['awaiting_connection','queued','cancelled','expired','failed'].includes(value.status as string);
    if(!text(value.id)||!(accountless||text(value.connectionId))||!text(value.capabilityId)||typeof value.status!=='string'||!STATES.has(value.status)||!timestamp(value.createdAt)||!timestamp(value.updatedAt)||value.approvalRequired!==(value.status==='awaiting_approval')||!Object.hasOwn(value,'result')||!(value.error===null||typeof value.error==='string'))fail('invalid_response');
    if(value.status==='awaiting_connection'&&!handoff)fail('invalid_response');
    // An account request names its app in its handoff; once it resumed, the same request id replays the call itself
    // (on its own account, no handoff), which must be of the same app.
    const requested=handoff?handoff.appId===input.appId:value.appId===input.appId;
    if(method==='calls.create'&&(value.capabilityId!==input.capabilityId||(input.appId===undefined?value.connectionId!==input.connectionId:!requested))||method==='calls.get'&&value.id!==input.callId)fail('invalid_response');
    // A proxied call: it must be this account's, and what it reports about itself is checked, never passed through raw.
    const proxied=typeof value.capabilityId==='string'&&value.capabilityId.startsWith('proxy:');
    if(method==='proxy.request'&&(!proxied||value.connectionId!==input.connectionId||handoff))fail('invalid_response');
    let proxyFields:RecordValue={};
    if(proxied) {
      const request=value.request,code=(field:unknown)=>field===null||typeof field==='string'&&/^[a-z_]{1,64}$/.test(field);
      if(!record(request)||Object.keys(request).sort().join()!=='effect,method,row,url'||!['GET','POST','PUT','PATCH','DELETE'].includes(request.method as string)||!['read','write','delete'].includes(request.effect as string)
        ||!text(request.row,200)||typeof request.url!=='string'||request.url.length>12000||!request.url.startsWith('https://')||!code(value.errorCode)||!code(value.reason)||(Object.hasOwn(value,'resultWithheld')&&value.resultWithheld!==true))fail('invalid_response');
      proxyFields={errorCode:value.errorCode,reason:value.reason,request:{method:request.method,url:request.url,row:request.row,effect:request.effect},...(value.resultWithheld===true?{resultWithheld:true}:{})};
    }
    if(value.result!==null&&!record(value.result))fail('invalid_response');
    // The approval link is relayed to a person: exactly this endpoint's /approve/<call>, only while approval is pending.
    const callId=handoff&&typeof value.resumedCallId==='string'?value.resumedCallId:value.id;
    let approval:RecordValue|null=null;
    if(Object.hasOwn(value,'approval')&&record(value.approval)&&Object.keys(value.approval).sort().join()==='callRef,expiresAt') {
      // A developer environment: no link; the person approves in the app or on Fabric's page, by this call reference.
      const pointer=value.approval;
      if(value.status!=='awaiting_approval'||!timestamp(pointer.expiresAt)||typeof callId!=='string'||!UUID.test(callId)||pointer.callRef!==callId)fail('invalid_response');
      approval={callRef:pointer.callRef,expiresAt:pointer.expiresAt};
    } else if(Object.hasOwn(value,'approval')) {
      const pointer=value.approval;
      if(value.status!=='awaiting_approval'||!record(pointer)||Object.keys(pointer).sort().join()!=='expiresAt,url'||!timestamp(pointer.expiresAt)||typeof callId!=='string'||!UUID.test(callId)||pointer.url!==`${new URL(endpoint).origin}/approve/${callId}`)fail('invalid_response');
      approval={url:pointer.url,expiresAt:pointer.expiresAt};
    }
    // Fabric's card for this call: re-checked here, and it must describe this call, its state and its one link.
    let card:RecordValue|null=null;
    if(Object.hasOwn(value,'card')) {
      const checked:RecordValue=(()=>{try {return validateCard(value.card,{origin:new URL(endpoint).origin});} catch {return fail('invalid_response');}})();
      const state=handoff&&handoff.state!=='connected'?handoff.state:value.status,link=checked.kind==='account_request'?handoff?.url:approval?.url;
      if(checked.id!==value.id||checked.callId!==callId||checked.state!==state||(checked.actions as RecordValue[]).some(action=>action.url!==link))fail('invalid_response');
      card=checked;
    }
    // Client-visible job errors are intentionally fixed here. Never relay a
    // provider/driver exception, even if a future runtime forgets to redact it.
    const error=value.error===null?null:value.status==='uncertain'?'The external effect is uncertain. Do not repeat the action blindly.':handoff?.outcome?HANDOFF_TEXT[handoff.outcome as string]??'The account request closed.':'The operation did not complete successfully. Review the owner activity.';
    projected={id:value.id,status:value.status,connectionId:value.connectionId,capabilityId:value.capabilityId,createdAt:value.createdAt,updatedAt:value.updatedAt,result:value.result,error,approvalRequired:value.approvalRequired,
      ...(approval?{approval}:{}),...(handoff?{handoff,resumedCallId:value.resumedCallId??null}:{}),...proxyFields,...(card?{card}:{})};
  }
  return redact(projected,token,method!=='capabilities.list') as RecordValue;
}

/** Bound bytes before FabricClient's response.json(), including error bodies. */
async function boundedResponse(response:Response,signal:AbortSignal):Promise<Response> {
  const length=response.headers.get('content-length');
  if(!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type')??'')||(length!==null&&(!/^\d+$/.test(length)||Number(length)>RESPONSE_BYTES))||!response.body) {
    void response.body?.cancel().catch(()=>{});fail('invalid_response');
  }
  const reader=response.body.getReader(),chunks:Uint8Array[]=[];
  let completed=false,cancelled=false;
  const cancel=()=>{if(!completed&&!cancelled){cancelled=true;void reader.cancel().catch(()=>{});}};
  signal.addEventListener('abort',cancel,{once:true});
  let size=0;
  try {
    while(true) {
      signal.throwIfAborted();const chunk=await reader.read();signal.throwIfAborted();
      if(chunk.done){completed=true;break;}
      size+=chunk.value.byteLength;if(size>RESPONSE_BYTES){cancel();fail('invalid_response');}chunks.push(chunk.value);
    }
    return new Response(Buffer.concat(chunks),{status:response.status,headers:{'content-type':'application/json'}});
  } finally {
    // Also cancel when the signal was already aborted before listener setup or
    // body consumption failed; merely releasing the reader leaves it live.
    if(!completed)cancel();signal.removeEventListener('abort',cancel);reader.releaseLock();
  }
}

export function createMcpAdapter({env=process.env,fetch:request=globalThis.fetch,timeoutMs=DEFAULT_TIMEOUT_MS}:{env?:Environment;fetch?:typeof globalThis.fetch;timeoutMs?:number}={}):Server {
  const {endpoint,token}=readMcpEnvironment(env);
  if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>120_000)throw new Error('Invalid MCP request timeout.');
  const server=new Server({name:'fabric-local',version:'0.3.0'},{capabilities:{tools:{listChanged:false}}});
  const closed=new AbortController();let active=0;
  server.onclose=()=>closed.abort();
  server.setRequestHandler('tools/list',()=>({tools:structuredClone(definitions)}));
  server.setRequestHandler('tools/call',async (call,ctx)=>{
    const schema=schemas.get(call.params.name);
    if(!schema)return toolError('method_not_found');
    if(active>=MAX_INFLIGHT)return toolError('busy');
    let input:RecordValue;
    try {
      const args=call.params.arguments??{};bounded(args,INPUT_BYTES,'invalid_request');
      const checked=await schema['~standard'].validate(args);if(checked.issues)return toolError('invalid_request');input=checked.value;
    } catch {return toolError('invalid_request');}
    if(call.params.name==='fabric_invoke'&&(Object.hasOwn(input,'connectionId')===Object.hasOwn(input,'appId')))return toolError('invalid_request');
    // Schema validation may be asynchronous; check the limit again before
    // reserving an upstream slot, without an await between check and increment.
    if(active>=MAX_INFLIGHT)return toolError('busy');
    const timeout=new AbortController(),timer=setTimeout(()=>timeout.abort(),timeoutMs);
    const signal=AbortSignal.any([ctx.mcpReq.signal,closed.signal,timeout.signal]);
    active++;
    try {
      signal.throwIfAborted();
      const client=new FabricClient({endpoint,token,fetch:async (url:Parameters<typeof globalThis.fetch>[0],options?:RequestInit)=>{
        signal.throwIfAborted();
        const response=await request(url,{...options,signal,redirect:'error'});
        return boundedResponse(response,signal);
      }});
      const method=call.params.name==='fabric_list_capabilities'?'capabilities.list':call.params.name==='fabric_get_call'?'calls.get':call.params.name==='fabric_proxy_request'?'proxy.request':'calls.create';
      let value:unknown;
      if(method==='proxy.request') {
        const args=input as {requestId:string;connectionId:string;request:{method:string;path:string}&RecordValue;timeoutMs?:number;task?:{title:string}};
        value=await client.proxy({connectionId:args.connectionId,request:args.request,...(args.timeoutMs===undefined?{}:{timeoutMs:args.timeoutMs}),...(args.task?{task:{title:args.task.title}}:{})},{requestId:args.requestId,signal});
      } else if(method==='calls.create') {
        const args=input as InvokeInput;
        value=await client.invoke({...(args.appId===undefined?{connectionId:args.connectionId as string}:{appId:args.appId}),capabilityId:args.capabilityId,definitionHash:args.definitionHash,args:args.args,...(args.task?{task:{title:args.task.title}}:{})},{requestId:args.requestId,signal});
      } else value=await client.call(method,method==='calls.get'?{callId:input.callId}:{},{signal});
      signal.throwIfAborted();
      const projected=projectResult(value,method,input,token,endpoint);
      // A pending card's sentence, with the exact link, is what a model relays to the account owner.
      // Fabric already dropped an expired link when it built the card, on its own clock.
      const card=record(projected.card)?projected.card:null;
      const relay=card&&card.kind!=='status'?[{type:'text' as const,text:lapsed(card as never)?`${cardText(card as never)} This request will not run. If it is still needed, send a new request.`
          :`${cardText(card as never)} Fabric continues this exact request after the owner acts. Check progress with fabric_get_call using callId "${projected.id}". Do not resubmit.`}]
        :projected.status==='awaiting_connection'&&record(projected.handoff)&&(typeof projected.handoff.url==='string'||typeof projected.handoff.connectSessionId==='string')?[{type:'text' as const,text:handoffText(projected)}]:[];
      return {content:[...relay,{type:'text',text:JSON.stringify(projected)}],structuredContent:projected,isError:['failed','uncertain','expired','cancelled'].includes(projected.status as string)};
    } catch(error) {return toolError(signal.aborted?'request_interrupted':errorCode(error));}
    finally {clearTimeout(timer);active--;}
  });
  return server;
}

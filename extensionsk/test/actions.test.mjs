import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import vm from 'node:vm';

const background=readFileSync(new URL('../background.js',import.meta.url),'utf8');
const origin='https://fixture.example';
function domHarness(){
  const observers=[],listeners=new Map(),timers=new Map();let timerId=0;
  const addListener=(type,listener)=>{if(!listeners.has(type))listeners.set(type,new Set());listeners.get(type).add(listener);};
  const removeListener=(type,listener)=>listeners.get(type)?.delete(listener);
  class MutationObserver {
    constructor(callback){this.callback=callback;this.records=[];this.connected=false;observers.push(this);}
    observe(target,options){this.target=target;this.options=options;this.connected=true;}
    disconnect(){this.connected=false;this.records=[];}
    takeRecords(){return this.records.splice(0);}
  }
  class Element {
    constructor(tag,attrs={}){this.tagName=tag.toUpperCase();this.attrs=attrs;this.id=attrs.id||'';this.type=attrs.type||'text';this.innerText=attrs.label||'';this.labels=[];this.isConnected=true;this.disabled=false;this.readOnly=false;this.hidden=false;this.parentElement=null;this.events=[];this.clicks=0;}
    getAttribute(key){return this.attrs[key]??null;}
    hasAttribute(key){return Object.hasOwn(this.attrs,key);}
    getClientRects(){return this.hidden?[]:[{}];}
    matches(selector){return selector.split(',').some(part=>{part=part.trim();if(part==='input')return this.tagName==='INPUT';if(part==='textarea')return this.tagName==='TEXTAREA';if(part==='button')return this.tagName==='BUTTON';if(part==='a')return this.tagName==='A';const input=part.match(/^input\[type="(.+)"\]$/);if(input)return this.tagName==='INPUT'&&this.type===input[1];const attr=part.match(/^\[([^=]+)="(.+)"\]$/);return Boolean(attr&&this.getAttribute(attr[1])===attr[2]);});}
    closest(selector){if(selector.includes('[data-sensitive]')&&this.attrs['data-sensitive'])return this;if(selector.includes('[inert]')&&this.attrs.inert)return this;return null;}
    click(){this.clicks++;}
    dispatchEvent(event){this.events.push(event.type);}
    get href(){return new URL(this.attrs.href||'/',origin).href;}
    get formAction(){return new URL(this.attrs.formaction||'/page',origin).href;}
    get formTarget(){return this.attrs.formtarget||'';}
  }
  class Input extends Element{constructor(attrs){super('input',attrs);this._value='preexisting private field text';}get value(){return this._value;}set value(v){this._value=v;}}
  class Textarea extends Element{constructor(attrs){super('textarea',attrs);this._value='';}get value(){return this._value;}set value(v){this._value=v;}}
  const button=new Element('button',{id:'save',label:'Save draft'}),field=new Input({id:'summary',name:'summary',label:'Summary'}),password=new Input({id:'password',type:'password'}),link=new Element('a',{id:'more',label:'More',href:'/more'});
  const body=new Element('body');const elements=[button,field,password,link];
  const document={body,title:'Fixture application',querySelectorAll:selector=>selector.startsWith('#')?elements.filter(e=>e.id===selector.slice(1)):elements,querySelector:()=>null,createTreeWalker:()=>({nextNode:()=>null}),addEventListener:addListener,removeEventListener:removeListener};
  const context=vm.createContext({URL,Date,TypeError,Error,Map,MutationObserver,setTimeout:callback=>{timers.set(++timerId,callback);return timerId;},clearTimeout:id=>timers.delete(id),addEventListener:addListener,removeEventListener:removeListener,crypto:{randomUUID},location:{origin,href:origin+'/page'},document,NodeFilter:{SHOW_TEXT:4},CSS:{escape:v=>v},getComputedStyle:()=>({display:'block',visibility:'visible',opacity:'1'}),HTMLInputElement:Input,HTMLTextAreaElement:Textarea,Event:class {constructor(type){this.type=type;}},chrome:{runtime:{onMessage:{addListener(){}},getURL:p=>'chrome-extension://fixture/'+p,id:'fixture'},alarms:{onAlarm:{addListener(){}},create(){}}}});
  vm.runInContext(background,context);
  const run=(op,args={},fields={})=>{context.command={action:{op},args,...fields};return vm.runInContext(`observe(command,${JSON.stringify(origin)})`,context);};
  const inspect=()=>{const result=run('observe');assert.equal(result.ok,true);return result.data;};
  const mutate=(type='childList',{deliver=false}={})=>{for(const observer of observers.filter(item=>item.connected)){observer.records.push({type,target:body});if(deliver)observer.callback(observer.takeRecords());}};
  const emit=type=>{for(const listener of [...(listeners.get(type)||[])])listener({type});};
  const form=(attrs={})=>{const result=new Element('form',attrs);Object.defineProperties(result,{action:{get:()=>new URL(attrs.action||'/page',origin).href},target:{get:()=>attrs.target||''}});result.querySelectorAll=()=>[field];button.form=result;field.form=result;return result;};
  return {context,button,field,password,link,document,run,inspect,mutate,emit,form,observers,listeners,timers};
}
test('inspection emits opaque targets, excludes password controls, and never includes field values',()=>{
  const h=domHarness(),data=h.inspect();assert.equal(data.controls.length,3);assert.ok(data.snapshotId);
  assert.equal(data.controls.find(c=>c.label==='Summary').canFill,true);assert.equal(JSON.stringify(data).includes(h.field.value),false);assert.equal(JSON.stringify(data).includes('password'),false);
});
test('an approved inspected click dispatches once and reports no semantic success',()=>{
  const h=domHarness(),data=h.inspect(),args={snapshotId:data.snapshotId,targetId:data.controls[0].targetId};
  const result=h.run('click',args);assert.equal(result.ok,true);assert.equal(h.button.clicks,1);assert.equal(result.data.dispatchStatus,'dispatched');assert.equal(result.data.persistentEffect,'unverified');
  assert.equal(h.run('click',args).ok,false);assert.equal(h.button.clicks,1);
});
test('fill uses the native value setter and DOM events, never submitted provider success',()=>{
  const h=domHarness(),data=h.inspect(),field=data.controls.find(c=>c.canFill);
  const result=h.run('fill',{snapshotId:data.snapshotId,targetId:field.targetId,value:'Fixture draft'});
  assert.equal(result.ok,true);assert.equal(h.field.value,'Fixture draft');assert.deepEqual(h.field.events,['input','change']);assert.equal(result.data.persistentEffect,'unverified');
});
test('in-page dispatch rejects expired or malformed deadlines while preserving legacy commands',()=>{
  for(const op of ['click','fill'])for(const expiresAt of [new Date(Date.now()-1).toISOString(),'not-a-date',null,0,undefined]) {
    const h=domHarness(),data=h.inspect(),target=op==='fill'?data.controls.find(c=>c.canFill):data.controls[0];
    const result=h.run(op,{snapshotId:data.snapshotId,targetId:target.targetId,value:'New text'},{expiresAt});
    assert.equal(result.ok,false);assert.match(result.error,/expired/i);assert.equal(h.button.clicks,0);assert.equal(h.field.value,'preexisting private field text');
  }
  const h=domHarness(),data=h.inspect();assert.equal(h.run('click',{snapshotId:data.snapshotId,targetId:data.controls[0].targetId}).ok,true);
});
test('deadline is checked again immediately before a validated form click dispatches',()=>{
  const h=domHarness();let clock=Date.now();h.context.Date=class extends Date{static now(){return clock;}};
  const expiresAt=new Date(clock+1000).toISOString(),form=h.form({action:'/save'}),data=h.inspect();
  form.querySelectorAll=()=>{clock+=1001;return[];};
  const result=h.run('click',{snapshotId:data.snapshotId,targetId:data.controls[0].targetId},{expiresAt});
  assert.equal(result.ok,false);assert.match(result.error,/expired/i);assert.equal(h.button.clicks,0);
});
test('navigation, document replacement, expiration, detached controls and changed fingerprint fail closed',()=>{
  const cases=[h=>{h.context.location.href=origin+'/different';},h=>{h.context.document={...h.document};},h=>vm.runInContext('__fabricSnapshotV2.at=0',h.context),h=>{h.button.isConnected=false;},h=>{h.button.innerText='Delete everything';},h=>{h.button.disabled=true;}];
  for(const mutate of cases){const h=domHarness(),data=h.inspect();mutate(h);const result=h.run('click',{snapshotId:data.snapshotId,targetId:data.controls[0].targetId});assert.equal(result.ok,false);assert.equal(h.button.clicks,0);}
});
test('unknown targets, arbitrary JS/shell operations, and wrong origin cannot execute',()=>{
  const h=domHarness(),data=h.inspect();
  assert.equal(h.run('click',{snapshotId:data.snapshotId,targetId:'not-observed'}).ok,false);
  for(const op of ['eval','javascript','shell','submit'])assert.equal(h.run(op,{script:'document.cookie'}).ok,false);
  h.context.location.origin='https://other.example';assert.equal(h.run('click',{snapshotId:data.snapshotId,targetId:data.controls[0].targetId}).ok,false);assert.equal(h.button.clicks,0);
});
test('sensitive fields and cross-origin or native navigation are unavailable even with a valid snapshot',()=>{
  const h=domHarness(),data=h.inspect(),field=data.controls.find(c=>c.canFill);
  h.field.attrs.name='access_token';assert.equal(h.run('fill',{snapshotId:data.snapshotId,targetId:field.targetId,value:'not allowed'}).ok,false);assert.equal(h.field.value,'preexisting private field text');
  for(const href of ['https://other.example/action','notion://open','javascript:alert(1)']){h.link.attrs.href=href;const fresh=h.inspect(),target=fresh.controls.find(c=>c.label==='More');assert.equal(h.run('click',{snapshotId:fresh.snapshotId,targetId:target.targetId}).ok,false);assert.equal(h.link.clicks,0);}
});

test('form clicks reject off-origin and native destinations, including submitter overrides',()=>{
  for(const destination of ['https://other.example/save','notion://save','javascript:alert(1)','http://fixture.example/save','https://account:secret@fixture.example/save']) {
    for(const override of [false,true]) {
      const h=domHarness();h.form({action:override?'/save':destination});if(override)h.button.attrs.formaction=destination;
      const data=h.inspect(),result=h.run('click',{snapshotId:data.snapshotId,targetId:data.controls[0].targetId});
      assert.equal(result.ok,false,`${override?'submitter':'form'} destination ${destination}`);assert.equal(h.button.clicks,0);
    }
  }
});

test('same-origin form approval never permits submitting existing credentials',()=>{
  const h=domHarness(),form=h.form({action:'/save'});form.querySelectorAll=()=>[h.field,h.password];
  const data=h.inspect(),result=h.run('click',{snapshotId:data.snapshotId,targetId:data.controls[0].targetId});
  assert.equal(result.ok,false);assert.match(result.error,/credentials or sensitive/);assert.equal(h.button.clicks,0);
});

test('form clicks stay in the paired tab and respect form, submitter, and base targets',()=>{
  for(const target of ['_blank','another-window','_top','_parent']) {
    for(const source of ['form','submitter','base']) {
      const h=domHarness();h.form({action:'/save',...(source==='form'?{target}:{})});
      if(source==='submitter')h.button.attrs.formtarget=target;
      if(source==='base')h.document.querySelector=()=>({target});
      const data=h.inspect(),result=h.run('click',{snapshotId:data.snapshotId,targetId:data.controls[0].targetId});
      assert.equal(result.ok,false,`${source} target ${target}`);assert.equal(h.button.clicks,0);
    }
  }
  for(const override of [false,true]) {
    const h=domHarness();h.form({action:override?'https://other.example/save':'/save',target:override?'_blank':'_self'});
    if(override)Object.assign(h.button.attrs,{formaction:'/approved-save',formtarget:'_self'});
    const data=h.inspect();assert.equal(h.run('click',{snapshotId:data.snapshotId,targetId:data.controls[0].targetId}).ok,true);assert.equal(h.button.clicks,1);
  }
});

test('context mutations invalidate an unchanged target, including records awaiting observer delivery',()=>{
  for(const type of ['childList','characterData','attributes']) {
    for(const deliver of [false,true]) {
      const h=domHarness(),data=h.inspect();h.mutate(type,{deliver});
      const result=h.run('click',{snapshotId:data.snapshotId,targetId:data.controls[0].targetId});
      assert.equal(result.ok,false,`${type}, delivered=${deliver}`);assert.equal(h.button.clicks,0);
      assert.equal(h.observers.filter(observer=>observer.connected).length,0);
    }
  }
});

test('input and change events invalidate targets even when form attributes are unchanged',()=>{
  for(const event of ['input','change']) {
    const h=domHarness();h.form({action:'/save'});const data=h.inspect();h.field.value='Different record';h.emit(event);
    assert.equal(h.run('click',{snapshotId:data.snapshotId,targetId:data.controls[0].targetId}).ok,false);assert.equal(h.button.clicks,0);
    assert.equal(h.observers.filter(observer=>observer.connected).length,0);
  }
});

test('snapshot observers and listeners are replaced and released after dispatch, expiry, and page exit',()=>{
  const h=domHarness(),first=h.inspect(),second=h.inspect();
  assert.notEqual(first.snapshotId,second.snapshotId);assert.equal(h.observers.filter(observer=>observer.connected).length,1);
  assert.equal(h.listeners.get('input')?.size,1);assert.equal(h.listeners.get('change')?.size,1);assert.equal(h.timers.size,1);
  assert.equal(h.run('click',{snapshotId:second.snapshotId,targetId:second.controls[0].targetId}).ok,true);
  assert.equal(h.observers.filter(observer=>observer.connected).length,0);assert.equal(h.listeners.get('input')?.size,0);assert.equal(h.timers.size,0);
  for(const end of ['expiry','pagehide']) {
    const data=h.inspect();if(end==='expiry')[...h.timers.values()][0]();else h.emit('pagehide');
    assert.equal(h.run('click',{snapshotId:data.snapshotId,targetId:data.controls[0].targetId}).ok,false);
    assert.equal(h.observers.filter(observer=>observer.connected).length,0);assert.equal(h.listeners.get('input')?.size,0);assert.equal(h.listeners.get('change')?.size,0);assert.equal(h.listeners.get('pagehide')?.size,0);assert.equal(h.timers.size,0);
  }
});

function setupHarness(){
  const stored={},session={},calls=[];const id='extension-fixture';const extensionUrl=path=>`chrome-extension://${id}/${path}`;
  const area=values=>({get:async key=>({[key]:structuredClone(values[key])}),set:async value=>Object.assign(values,structuredClone(value)),setAccessLevel:async()=>{}});
  const context=vm.createContext({URL,Date,Error,TypeError,crypto:{randomUUID},setTimeout,chrome:{runtime:{id,getURL:extensionUrl,onMessage:{addListener(){}}},storage:{local:area(stored),session:area(session)},tabs:{create:async options=>{calls.push(options);return {id:99};}},permissions:{contains:async()=>false},alarms:{onAlarm:{addListener(){}},create(){}}}});
  vm.runInContext(background,context);
  const call=(message,sender)=>{context.message=message;context.sender=sender;return vm.runInContext('connectMessage(message,sender)',context);};
  const pairing={pairingId:randomUUID(),code:'ABCDEF123456',appName:'Fixture',appId:'fixture',origins:[origin],launchUrl:origin,expiresAt:new Date(Date.now()+5*60000).toISOString(),bridgeVersion:'0.3',sessionScope:'browser-profile'};
  const sender={id,url:'http://127.0.0.1:4188/#connectors',frameId:0,tab:{id:1}};
  return {stored,session,calls,context,call,pairing,sender,extensionUrl,id};
}
test('connect handoff accepts only top-level localhost Fabric and opens an extension confirmation, not the app',async()=>{
  const h=setupHarness();const result=await h.call({type:'fabric-connect-request',pairing:h.pairing},h.sender);
  assert.equal(result.ok,true);assert.equal(result.pairingId,h.pairing.pairingId);assert.equal(result.confirmationOpened,true);assert.equal(h.calls.length,1);assert.ok(h.calls[0].url.startsWith(h.extensionUrl('connect.html')+'?request='));
  for(const sender of [{...h.sender,url:'https://attacker.example'},{...h.sender,frameId:1},{...h.sender,id:'different'}])await assert.rejects(h.call({type:'fabric-connect-request',pairing:h.pairing},sender),/Only the local/);
});
test('page cannot approve its own request; extension requires exact request page and website consent',async()=>{
  const h=setupHarness();await h.call({type:'fabric-connect-request',pairing:h.pairing},h.sender);const requestId=Object.keys(h.stored.fabricConnectRequests)[0];
  await assert.rejects(h.call({type:'fabric-connect-approve',requestId},h.sender),/extension setup page/);
  await assert.rejects(h.call({type:'fabric-connect-approve',requestId},{id:h.id,url:h.extensionUrl('connect.html')+'?request='+randomUUID()}),/does not match/);
  await assert.rejects(h.call({type:'fabric-connect-approve',requestId},{id:h.id,url:h.extensionUrl('connect.html')+'?request='+requestId}),/Website access/);assert.equal(h.calls.length,1);
});
test('handoff rejects expired pairing, non-HTTPS or undeclared targets, and does not leak secret code in details',async()=>{
  const h=setupHarness();for(const change of [{launchUrl:'notion://open'},{launchUrl:'https://other.example'},{expiresAt:new Date(0).toISOString()},{launchUrl:origin+'/unsafe'}])await assert.rejects(h.call({type:'fabric-connect-request',pairing:{...h.pairing,...change}},h.sender));
  await h.call({type:'fabric-connect-request',pairing:h.pairing},h.sender);const requestId=Object.keys(h.stored.fabricConnectRequests)[0];
  const details=await h.call({type:'fabric-connect-details',requestId},{id:h.id,url:h.extensionUrl('connect.html')+'?request='+requestId});assert.equal(JSON.stringify(details).includes(h.pairing.code),false);
});
test('approved handoff opens HTTPS app in browser, pairs exact id, then deletes setup secret',async()=>{
  const h=setupHarness();await h.call({type:'fabric-connect-request',pairing:h.pairing},h.sender);const requestId=Object.keys(h.stored.fabricConnectRequests)[0];
  h.context.chrome.permissions.contains=async()=>true;
  h.context.chrome.tabs.get=async()=>({id:99,url:origin+'/home',status:'complete',title:'Fixture app'});
  let pairedBody;
  h.context.fetch=async(url,options)=>{assert.equal(url,'http://127.0.0.1:4188/api/browser/pair');pairedBody=JSON.parse(options.body);return {ok:true,json:async()=>({connection:{id:'real-fixture-connection',bridgeVersion:'0.3',sessionScope:'browser-profile'},token:'fixture-secret',pairingId:h.pairing.pairingId})};};
  const response=await h.call({type:'fabric-connect-approve',requestId},{id:h.id,url:h.extensionUrl('connect.html')+'?request='+requestId});
  assert.equal(response.ok,true);assert.equal(response.pairingId,h.pairing.pairingId);assert.equal(h.calls[1].url,origin);assert.equal(pairedBody.code,h.pairing.code);assert.equal(pairedBody.bridgeVersion,'0.3');assert.equal(pairedBody.sessionScope,'browser-profile');
  assert.equal(h.stored.fabricConnections['real-fixture-connection'].token,'fixture-secret');assert.equal(h.stored.fabricConnections['real-fixture-connection'].tabId,undefined);assert.equal(h.session.fabricLeases['real-fixture-connection'].tabId,99);assert.equal(h.session.fabricLeases['real-fixture-connection'].owned,false);assert.equal(JSON.stringify(response).includes('fixture-secret'),false);assert.deepEqual(Object.keys(h.stored.fabricConnectRequests),[]);
  await assert.rejects(h.call({type:'fabric-connect-approve',requestId},{id:h.id,url:h.extensionUrl('connect.html')+'?request='+requestId}),/expired or already used/);
});
test('wrong exact pairing id cannot be stored as a successful browser connection',async()=>{
  const h=setupHarness();await h.call({type:'fabric-connect-request',pairing:h.pairing},h.sender);const requestId=Object.keys(h.stored.fabricConnectRequests)[0];
  h.context.chrome.permissions.contains=async()=>true;h.context.chrome.tabs.get=async()=>({id:99,url:origin,status:'complete'});
  h.context.fetch=async()=>({ok:true,json:async()=>({connection:{id:'wrong'},token:'fixture-secret',pairingId:randomUUID()})});
  await assert.rejects(h.call({type:'fabric-connect-approve',requestId},{id:h.id,url:h.extensionUrl('connect.html')+'?request='+requestId}),/exact setup request/);assert.equal(h.stored.fabricPair,undefined);
});
test('approval saves durable consent before opening sign-in and survives a tab opening failure',async()=>{
  const h=setupHarness();await h.call({type:'fabric-connect-request',pairing:h.pairing},h.sender);const requestId=Object.keys(h.stored.fabricConnectRequests)[0];
  h.context.chrome.permissions.contains=async()=>true;
  h.context.fetch=async()=>({ok:true,json:async()=>({connection:{id:'saved',bridgeVersion:'0.3',sessionScope:'browser-profile'},token:'fixture-secret',pairingId:h.pairing.pairingId})});
  h.context.chrome.tabs.create=async()=>{assert.equal(h.stored.fabricConnections.saved.sessionScope,'browser-profile');throw new Error('No window available');};
  h.context.chrome.tabs.get=async()=>{assert.fail('Saving consent must not wait for provider login');};
  const result=await h.call({type:'fabric-connect-approve',requestId},{id:h.id,url:h.extensionUrl('connect.html')+'?request='+requestId});
  assert.equal(result.ok,true);assert.equal(result.signInOpened,false);assert.ok(h.stored.fabricConnections.saved);assert.deepEqual(Object.keys(h.stored.fabricConnectRequests),[]);
});
test('concurrent approvals preserve each saved app and do not broaden an existing tab-only pair',async()=>{
  const h=setupHarness(),second={...h.pairing,pairingId:randomUUID(),code:'FEDCBA654321',appName:'Second fixture',origins:['https://other.example.com'],launchUrl:'https://other.example.com'};
  h.stored.fabricPair={connectionId:'legacy',token:'fixture-legacy',tabId:42,origin,bridgeVersion:'0.2'};
  await Promise.all([h.call({type:'fabric-connect-request',pairing:h.pairing},h.sender),h.call({type:'fabric-connect-request',pairing:second},h.sender)]);
  assert.equal(Object.keys(h.stored.fabricConnectRequests).length,2);h.context.chrome.permissions.contains=async()=>true;
  h.context.fetch=async(url,options)=>{const body=JSON.parse(options.body),first=body.code===h.pairing.code;return {ok:true,json:async()=>({connection:{id:first?'first':'second',bridgeVersion:'0.3',sessionScope:'browser-profile'},token:first?'fixture-one':'fixture-two',pairingId:first?h.pairing.pairingId:second.pairingId})};};
  await Promise.all(Object.keys(h.stored.fabricConnectRequests).map(requestId=>h.call({type:'fabric-connect-approve',requestId},{id:h.id,url:h.extensionUrl('connect.html')+'?request='+requestId})));
  assert.deepEqual(Object.keys(h.stored.fabricConnections).sort(),['first','second']);assert.equal(h.stored.fabricPair.tabId,42);assert.equal(h.stored.fabricPair.bridgeVersion,'0.2');assert.deepEqual(Object.keys(h.stored.fabricConnectRequests),[]);
});
test('a v0.2 handoff cannot silently acquire browser-profile consent',async()=>{
  const h=setupHarness();await assert.rejects(h.call({type:'fabric-connect-request',pairing:{...h.pairing,bridgeVersion:'0.2',sessionScope:undefined}},h.sender),/Existing tab-only pairings are unchanged/);
  assert.equal(h.calls.length,0);assert.equal(h.stored.fabricConnections,undefined);
});
test('extension surface has no cookie/debugger/native-messaging authority and handoff is exact loopback only',()=>{
  const manifest=JSON.parse(readFileSync(new URL('../manifest.json',import.meta.url),'utf8'));
  for(const permission of ['tabs','cookies','debugger','nativeMessaging','webRequest'])assert.equal(manifest.permissions.includes(permission),false);
  assert.deepEqual(manifest.content_scripts[0].matches,['http://127.0.0.1:4188/*']);assert.equal(manifest.content_scripts[0].all_frames,false);assert.equal(manifest.web_accessible_resources,undefined);
});
test('content handoff refuses cross-origin/window messages and never forwards operation commands',async()=>{
  const source=readFileSync(new URL('../fabric-handoff.js',import.meta.url),'utf8'),posts=[],requests=[];let listener;
  const window={addEventListener:(type,fn)=>{listener=fn;},postMessage:(value,target)=>posts.push({value,target})};window.top=window;
  const context=vm.createContext({window,location:{origin:'http://127.0.0.1:4188'},chrome:{runtime:{sendMessage:async value=>{requests.push(value);return {ok:true,confirmationOpened:true};}}}});vm.runInContext(source,context);
  const data={source:'fabric-page',type:'fabric:bridge:ping',requestId:randomUUID()};
  for(const event of [{source:{},origin:'http://127.0.0.1:4188',data},{source:window,origin:'http://evil.example',data},{source:window,origin:'http://127.0.0.1:4188',data:{...data,type:'fabric:execute'}}])await listener(event);
  assert.equal(posts.length,0);assert.equal(requests.length,0);
  await listener({source:window,origin:'http://127.0.0.1:4188',data});assert.equal(posts[0].value.version,'0.3');assert.equal(posts[0].value.requestId,data.requestId);assert.equal(requests.length,0);
});

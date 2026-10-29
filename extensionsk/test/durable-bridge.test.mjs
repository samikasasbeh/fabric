import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import vm from 'node:vm';

const source=readFileSync(new URL('../background.js',import.meta.url),'utf8');
const plain=value=>JSON.parse(JSON.stringify(value));
const grant=(id='notes',origin=`https://${id}.fixture.test`)=>({connectionId:id,token:`fixture-token-${id}`,origin,bridgeVersion:'0.3',sessionScope:'browser-profile',label:id});
function harness(options={}) {
  const local=options.local||{fabricConnections:{notes:grant()}},session=options.session||{},tabs=options.tabs||new Map();
  const calls=[],commands=new Map(),receipts=[],listeners={},removedPermissions=[];let sequence=100,clock=1000000;
  const event=name=>({addListener:fn=>{listeners[name]=fn;}});
  const area=(values,name)=>({get:async key=>typeof key==='string'?{[key]:structuredClone(values[key])}:Object.fromEntries((key||Object.keys(values)).map(k=>[k,structuredClone(values[k])])),set:async value=>Object.assign(values,structuredClone(value)),remove:async keys=>{for(const key of [].concat(keys))delete values[key];},setAccessLevel:async value=>calls.push({kind:'access',name,...value})});
  const chrome={storage:{local:area(local,'local'),session:area(session,'session')},runtime:{id:'fixture-extension',getURL:path=>`chrome-extension://fixture-extension/${path}`,onMessage:event('message')},
    tabs:{get:async id=>{if(!tabs.has(id))throw new Error('Tab closed');if(options.onGet)options.onGet({id,tabs,listeners,context:()=>context});return {...tabs.get(id)};},create:async input=>{const tab={id:++sequence,url:input.url,active:input.active,status:'complete'};tabs.set(tab.id,tab);calls.push({kind:'create',...input,tabId:tab.id});if(options.afterCreate)await options.afterCreate({local,session,tabs,tab,listeners,tick:ms=>{clock+=ms;}});return {...tab};},remove:async id=>{calls.push({kind:'remove',tabId:id});tabs.delete(id);},onActivated:event('activated'),onUpdated:event('updated'),onRemoved:event('removed')},
    permissions:{contains:async()=>options.permission!==false,remove:async input=>{removedPermissions.push(input);return true;}},
    scripting:{executeScript:async input=>{calls.push({kind:'execute',tabId:input.target.tabId,operation:input.args[0].action.op});if(options.duringExecute)await options.duringExecute({local,session,tabs});return [{result:{ok:true,data:{origin:input.args[1],text:'Synthetic fixture'}}}];}},
    alarms:{onAlarm:event('alarm'),get:async()=>options.existingAlarm?{name:'fabric-poll',periodInMinutes:0.5}:undefined,create:async(name,value)=>calls.push({kind:'alarm-create',name,...value})}};
  const fetch=async(url,input)=>{
    const id=Object.values(local.fabricConnections||{}).find(item=>`Bearer ${item.token}`===input.headers?.Authorization)?.connectionId||'removed';
    const body=JSON.parse(input.body),kind=url.endsWith('/poll')?'poll':'result';calls.push({kind,id,body});
    if(options.unauthorized)return {ok:false,status:401,json:async()=>({error:'Revoked',code:'browser_revoked'})};
    if(options.responseError)return {ok:false,status:options.responseError.status,json:async()=>options.responseError.body};
    if(kind==='poll'){const command=commands.get(id);commands.delete(id);if(options.afterPoll)await options.afterPoll({local,session,tabs,command});return {ok:true,status:200,json:async()=>({command:command||null})};}
    receipts.push(body);return {ok:true,status:200,json:async()=>({accepted:true})};
  };
  const Clock=class extends Date{constructor(...args){super(...(args.length?args:[clock]));}static now(){return clock;}};
  const context=vm.createContext({URL,Date:Clock,Error,TypeError,Map,Set,Promise,AbortController,crypto:{randomUUID},chrome,fetch,setTimeout,clearTimeout});
  vm.runInContext(source,context);
  const invoke=(name,...args)=>{context.testArgs=args;return vm.runInContext(`${name}(...testArgs)`,context);};
  const enqueue=(id='notes',op='observe')=>commands.set(id,{id:randomUUID(),origin:local.fabricConnections[id].origin,expiresAt:new Date(clock+75000).toISOString(),action:{op},args:['click','fill'].includes(op)?{snapshotId:'snapshot',targetId:'target',...(op==='fill'?{value:'Fixture'}:{})}:op==='read'?{selector:'#saved'}:{}});
  return {local,session,tabs,calls,commands,receipts,listeners,removedPermissions,context,invoke,enqueue,tick:ms=>{clock+=ms;},poll:id=>invoke('poll',...(id?[id]:[]))};
}

test('durable idle heartbeats need no app tab and restrict token storage to trusted extension contexts',async()=>{
  const h=harness();assert.equal((await h.poll()).state,'idle');
  assert.deepEqual(h.calls.filter(c=>c.kind==='poll').map(c=>c.body),[{execution:{state:'idle'}}]);
  assert.equal(h.calls.some(c=>['create','execute'].includes(c.kind)),false);
  assert.ok(h.calls.some(c=>c.kind==='access'&&c.name==='local'&&c.accessLevel==='TRUSTED_CONTEXTS'));
});

test('approved reads create a bounded inactive lease and recover after the tab closes',async()=>{
  const h=harness();h.enqueue();assert.equal((await h.poll()).state,'completed');
  const first=h.session.fabricLeases.notes;assert.equal(first.owned,true);assert.equal(h.tabs.get(first.tabId).active,false);
  assert.equal('tabId' in h.local.fabricConnections.notes,false);
  h.tabs.delete(first.tabId);h.enqueue('notes','read');assert.equal((await h.poll()).state,'completed');
  assert.notEqual(h.session.fabricLeases.notes.tabId,first.tabId);assert.equal(h.receipts.length,2);
});

test('closed or lost execution tabs never reopen for a queued click or fill',async()=>{
  for(const op of ['click','fill']) {
    const h=harness({session:{fabricLeases:{notes:{tabId:7,owned:true,lastUsedAt:0}}}});h.enqueue('notes',op);
    assert.equal((await h.poll()).state,'failed');assert.equal(h.calls.some(c=>c.kind==='create'||c.kind==='execute'),false);
    assert.equal(h.receipts[0].ok,false);assert.match(h.receipts[0].error,/inspect/i);
  }
});

test('multiple apps keep independent grants and workers reuse only session-owned matching leases',async()=>{
  const local={fabricConnections:{notes:grant(),tasks:grant('tasks')}},session={},tabs=new Map();
  const first=harness({local,session,tabs});first.enqueue('notes');first.enqueue('tasks');await first.poll();
  assert.equal(Object.keys(session.fabricLeases).length,2);assert.equal(first.calls.filter(c=>c.kind==='create').length,2);
  const restarted=harness({local,session,tabs});restarted.enqueue('notes');await restarted.poll();
  assert.equal(restarted.calls.filter(c=>c.kind==='create').length,0);assert.equal(Object.keys(local.fabricConnections).length,2);
});

test('browser restart discards tab IDs and never takes over a recycled or matching existing tab',async()=>{
  const local={fabricConnections:{notes:grant()}},tabs=new Map([[7,{id:7,url:grant().origin,active:false,status:'complete'}]]);
  const h=harness({local,session:{},tabs});h.enqueue('notes','click');await h.poll();
  assert.equal(h.calls.some(c=>c.kind==='execute'||c.kind==='create'),false);
  h.enqueue();await h.poll();assert.notEqual(h.session.fabricLeases.notes.tabId,7);assert.ok(tabs.has(7));
});

test('three helper-owned tabs is a hard ceiling and idle polls never create more',async()=>{
  const connections=Object.fromEntries(['notes','tasks','settings','fourth'].map(id=>[id,grant(id)]));
  const h=harness({local:{fabricConnections:connections}});for(const id of Object.keys(connections))h.enqueue(id);await h.poll();
  assert.equal(h.calls.filter(c=>c.kind==='create').length,3);assert.equal(h.receipts.filter(r=>r.ok===false).length,1);
  await h.poll();assert.equal(h.calls.filter(c=>c.kind==='create').length,3);
});

test('idle cleanup closes only old helper-owned inactive unchanged-origin tabs',async()=>{
  const ids=['owned','user','active','navigated'],connections=Object.fromEntries(ids.map(id=>[id,grant(id)]));
  const leases=Object.fromEntries(ids.map((id,i)=>[id,{tabId:i+1,owned:id!=='user',lastUsedAt:1}]));
  const tabs=new Map(ids.map((id,i)=>[i+1,{id:i+1,url:id==='navigated'?'https://elsewhere.fixture.test':connections[id].origin,active:id==='active',status:'complete'}]));
  const h=harness({local:{fabricConnections:connections},session:{fabricLeases:leases},tabs});await h.poll();
  assert.deepEqual(h.calls.filter(c=>c.kind==='remove').map(c=>c.tabId),[1]);assert.ok(tabs.has(2)&&tabs.has(3)&&tabs.has(4));
  assert.equal(h.calls.some(c=>c.kind==='create'),false);
});

test('activation, navigation, or same-URL reload permanently relinquishes helper cleanup ownership',async()=>{
  for(const event of ['activated','updated','reload']) {
    const h=harness();h.enqueue();await h.poll();const lease=h.session.fabricLeases.notes;
    if(event==='activated')await h.listeners.activated({tabId:lease.tabId});
    else await h.listeners.updated(lease.tabId,event==='reload'?{status:'loading'}:{url:grant().origin+'/different'},{...h.tabs.get(lease.tabId),url:grant().origin+'/different'});
    h.tick(180001);await h.poll();assert.ok(h.tabs.has(lease.tabId));assert.equal(h.session.fabricLeases.notes.owned,false);
  }
});

test('an initial same-origin redirect retains cleanup ownership unless the user activates the tab',async()=>{
  for(const activated of [false,true]) {
    const h=harness({afterCreate:({tab,listeners})=>{if(activated)listeners.activated({tabId:tab.id});tab.url+='/workspace';listeners.updated(tab.id,{url:tab.url,status:'loading'});}});
    h.enqueue();assert.equal((await h.poll()).state,'completed');const {tabId,owned}=h.session.fabricLeases.notes;
    assert.equal(owned,!activated);h.tick(180001);await h.poll();assert.equal(h.tabs.has(tabId),activated);
  }
});

test('runtime revocation removes a durable grant and only its safe helper-owned tab',async()=>{
  const other=grant('other'),notes=grant();const h=harness({unauthorized:true,local:{fabricConnections:{notes,other}},session:{fabricLeases:{notes:{tabId:7,owned:true,lastUsedAt:1}}},tabs:new Map([[7,{id:7,url:notes.origin,active:false,status:'complete'}]])});
  await h.poll('notes');assert.equal(h.local.fabricConnections.notes,undefined);assert.ok(h.local.fabricConnections.other);
  assert.equal(h.session.fabricLeases.notes,undefined);assert.equal(h.tabs.has(7),false);
  await h.poll('notes');assert.equal(h.calls.some(c=>c.kind==='create'),false);
});

test('queued initial loading and completion preserve ownership without suppressing real user navigation',async()=>{
  for(const event of ['initial','activation','reload','off-origin']) {
    const h=harness({session:{fabricLeases:{notes:{tabId:7,owned:true,lastUsedAt:1000000}}}});
    await vm.runInContext('storageReady',h.context);
    vm.runInContext("openingTabs.set(7, 'https://notes.fixture.test/'); storageTask(() => new Promise(resolve => { globalThis.releaseStorage = resolve; }));",h.context);
    await Promise.resolve();
    const url=event==='off-origin'?'https://elsewhere.fixture.test/':'https://notes.fixture.test/';
    h.listeners.updated(7,{url,status:'loading'},{url,status:'loading'});
    if(event==='activation'){h.listeners.activated({tabId:7});assert.equal(vm.runInContext('protectedTabs.has(7)',h.context),true,'activation protects before queued storage work drains');}
    h.listeners.updated(7,{status:'complete'},{url,status:'complete'});
    if(event==='reload')h.listeners.updated(7,{status:'loading'},{url,status:'loading'});
    vm.runInContext('releaseStorage()',h.context);await vm.runInContext('storageWrites',h.context);
    assert.equal(h.session.fabricLeases.notes.owned,event==='initial',event);
    assert.equal(vm.runInContext('openingTabs.has(7)',h.context),false);
  }
});

test('loading and completion before tabs.create resolves still retain the helper-owned lease',async()=>{
  const h=harness({afterCreate:({tab,listeners})=>{
    listeners.updated(tab.id,{url:tab.url,status:'loading'},{...tab,status:'loading'});
    listeners.updated(tab.id,{status:'complete'},tab);
  }});
  h.enqueue();assert.equal((await h.poll()).state,'completed');
  assert.equal(h.session.fabricLeases.notes.owned,true);
  assert.equal(vm.runInContext('openingTabs.size',h.context),0);
});

test('execution cleanup waits behind queued initial loading observed during app-tab polling',async()=>{
  let fired=false;
  const h=harness({onGet:({id,tabs,listeners,context})=>{
    if(fired)return;fired=true;const tab=tabs.get(id);
    vm.runInContext("storageTask(() => new Promise(resolve => { globalThis.releaseUnrelated = resolve; }));",context());
    listeners.updated(id,{url:tab.url,status:'loading'},{...tab,status:'loading'});
    listeners.updated(id,{status:'complete'},tab);
    setTimeout(()=>vm.runInContext('releaseUnrelated()',context()),20);
  }});
  h.enqueue();assert.equal((await h.poll()).state,'completed');
  await vm.runInContext('storageWrites',h.context);
  assert.equal(h.session.fabricLeases.notes.owned,true,'helper-created tab must stay helper-owned');
  assert.equal(vm.runInContext('openingTabs.size',h.context),0);
});

test('removing local consent before dispatch or receipt prevents the next boundary',async()=>{
  const before=harness({afterPoll:({local,command})=>{if(command)delete local.fabricConnections.notes;}});before.enqueue();await before.poll();
  assert.equal(before.calls.some(c=>['create','execute','result'].includes(c.kind)),false);
  const after=harness({duringExecute:({local})=>{delete local.fabricConnections.notes;}});after.enqueue();await after.poll();
  assert.equal(after.calls.some(c=>c.kind==='execute'),true);assert.equal(after.receipts.length,0);
});

test('disconnecting one grant keeps shared website permission and user-owned tabs',async()=>{
  const notes=grant(),other=grant('other',notes.origin),tabs=new Map([[7,{id:7,url:notes.origin,active:false,status:'complete'}]]);
  const h=harness({local:{fabricConnections:{notes,other}},session:{fabricLeases:{notes:{tabId:7,owned:false,lastUsedAt:1}}},tabs});
  await h.invoke('disconnectConnection','notes');assert.equal(h.local.fabricConnections.notes,undefined);assert.ok(h.local.fabricConnections.other);
  assert.equal(h.removedPermissions.length,0);assert.ok(tabs.has(7));
  await h.invoke('disconnectConnection','other');assert.deepEqual(plain(h.removedPermissions),[{origins:[`${notes.origin}/*`]}]);
});

test('expired commands cannot open a tab or dispatch after a slow opening',async()=>{
  const before=harness();before.enqueue();before.tick(75001);await before.poll();
  assert.equal(before.calls.some(c=>['create','execute'].includes(c.kind)),false);assert.match(before.receipts[0].error,/expired/);
  const after=harness({afterCreate:({tick})=>tick(75001)});after.enqueue();await after.poll();
  assert.equal(after.calls.filter(c=>c.kind==='create').length,1);assert.equal(after.calls.some(c=>c.kind==='execute'),false);assert.match(after.receipts[0].error,/expired/);
});

test('unrelated HTTP failures retain the saved grant and never open a tab',async()=>{
  for(const responseError of [{status:403,body:{error:'Origin not permitted',code:'browser_revoked'}},{status:401,body:{error:'Authentication unavailable',code:'different_error'}}]) {
    const h=harness({responseError});h.enqueue();await h.poll();assert.ok(h.local.fabricConnections.notes);
    assert.equal(h.calls.some(c=>['create','execute'].includes(c.kind)),false);
  }
});

test('lost website permission blocks new tabs and existing execution',async()=>{
  for(const existing of [false,true]) {
    const h=harness({permission:false,...(existing?{session:{fabricLeases:{notes:{tabId:7,owned:false,lastUsedAt:1000000}}},tabs:new Map([[7,{id:7,url:grant().origin,active:false,status:'complete'}]])}:{})});
    h.enqueue();await h.poll();assert.equal(h.calls.some(c=>['create','execute'].includes(c.kind)),false);assert.match(h.receipts[0].error,/access is no longer approved/);
  }
});

test('closing a leased tab promptly reports idle without opening a replacement',async()=>{
  const h=harness();h.enqueue();await h.poll();const {tabId}=h.session.fabricLeases.notes;h.tabs.delete(tabId);
  await h.listeners.removed(tabId);assert.equal(h.session.fabricLeases.notes,undefined);
  assert.deepEqual(h.calls.filter(c=>c.kind==='poll').at(-1).body,{execution:{state:'idle'}});
  assert.equal(h.calls.filter(c=>c.kind==='create').length,1);
});

test('a tab navigating away during poll is not reused for a queued write',async()=>{
  const h=harness({session:{fabricLeases:{notes:{tabId:7,owned:false,lastUsedAt:1000000}}},tabs:new Map([[7,{id:7,url:grant().origin,active:false,status:'complete'}]]),afterPoll:({tabs})=>{tabs.get(7).url='https://elsewhere.fixture.test';}});
  h.enqueue('notes','click');await h.poll();assert.equal(h.calls.some(c=>['create','execute'].includes(c.kind)),false);assert.match(h.receipts[0].error,/Inspect the page again/);
});

test('worker startup preserves an existing polling alarm and recreates a missing one',async()=>{
  for(const existingAlarm of [true,false]) {
    const h=harness({existingAlarm});await h.poll();const created=h.calls.filter(c=>c.kind==='alarm-create');
    assert.equal(created.length,existingAlarm?0:1);if(!existingAlarm)assert.deepEqual(created[0],{kind:'alarm-create',name:'fabric-poll',periodInMinutes:0.5});
  }
});

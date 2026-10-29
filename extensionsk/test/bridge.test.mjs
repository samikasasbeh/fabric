import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const background = readFileSync(new URL('../background.js', import.meta.url), 'utf8');
const popup = readFileSync(new URL('../popup.js', import.meta.url), 'utf8');
const pair = {connectionId:'fixture-connection',token:'fixture-local-pairing',tabId:17,origin:'https://app.example.com'};
const command = {id:'fixture-read',origin:pair.origin,action:{op:'observe'},args:{}};
const plain = value => JSON.parse(JSON.stringify(value));

function backgroundHarness(options = {}) {
  const stored = options.unpaired ? {} : {fabricPair:{...pair}};
  const calls = [];
  const context = vm.createContext({URL,Date,TypeError,Error,chrome:{
    storage:{local:{get:async key=>typeof key==='string'?{[key]:stored[key]}:stored,set:async value=>Object.assign(stored,value),setAccessLevel:async()=>{}},session:{get:async()=>({}),set:async()=>{},setAccessLevel:async()=>{}}},
    tabs:{get:async()=>{if(options.closed)throw new Error('No tab');return {url:options.url || pair.origin+'/home'};}},
    scripting:{executeScript:async()=>{calls.push('observe');if(options.stopDuringRead)delete stored.fabricPair;return [{result:{ok:true,data:{text:'Synthetic fixture text'}}}];}},
    runtime:{onMessage:{addListener:()=>{}}},alarms:{onAlarm:{addListener:()=>{}},create:()=>{}}
  },fetch:async(url,request)=>{
    calls.push(url.endsWith('/poll')?'poll':'result');
    if(url.endsWith('/poll'))return {ok:true,json:async()=>({command:options.command ?? null})};
    return {ok:options.rejectResult?false:true,json:async()=>options.rejectResult?{error:'Request expired'}:{accepted:true}};
  }});
  vm.runInContext(background,context);
  return {stored,calls,context,poll:()=>vm.runInContext('poll()',context)};
}

test('unpaired bridge does not claim a successful check or fetch data',async()=>{
  const harness=backgroundHarness({unpaired:true});
  assert.deepEqual(plain(await harness.poll()),{state:'not_paired'});
  assert.deepEqual(harness.calls,[]);
});
test('idle is an observed runtime check without a page read',async()=>{
  const harness=backgroundHarness();
  assert.deepEqual(plain(await harness.poll()),{state:'idle'});
  assert.deepEqual(harness.calls,['poll']);
  assert.equal(harness.stored.fabricBridgeStatus.state,'idle');
  assert.equal(harness.stored.fabricBridgeStatus.connectionId,pair.connectionId);
});
test('completed is reported only after the runtime accepts a requested result',async()=>{
  const harness=backgroundHarness({command});
  assert.deepEqual(plain(await harness.poll()),{state:'completed'});
  assert.deepEqual(harness.calls,['poll','observe','result']);
  assert.equal('data' in harness.stored.fabricBridgeStatus,false);
});
test('rejected result is an error, never a completed read',async()=>{
  const harness=backgroundHarness({command,rejectResult:true});
  assert.deepEqual(plain(await harness.poll()),{state:'failed',error:'Request expired'});
  assert.equal(harness.stored.fabricBridgeStatus.state,'failed');
});
test('stop sharing during observation suppresses sending page data',async()=>{
  const harness=backgroundHarness({command,stopDuringRead:true});
  const result=await harness.poll();
  assert.equal(result.state,'failed');
  assert.match(result.error,/not sent/);
  assert.deepEqual(harness.calls,['poll','observe']);
});
test('changed origin and closed tab fail before contacting the runtime',async()=>{
  for(const options of [{url:'https://different.example.com'}, {closed:true}]) {
    const harness=backgroundHarness(options);
    assert.equal((await harness.poll()).state,'failed');
    assert.deepEqual(harness.calls,[]);
  }
});
test('DOM actions require inspected targets before touching the document',()=>{
  const harness=backgroundHarness();
  harness.context.location={origin:pair.origin};
  const result=vm.runInContext("observe({action:{op:'click'},args:{}},'https://app.example.com')",harness.context);
  assert.equal(result.ok,false);
  assert.match(result.error,/snapshot and target/);
});

test('popup validates code before any permission request or pairing attempt',async()=>{
  const elements=new Map(),calls=[];
  function element(id){if(!elements.has(id))elements.set(id,{value:'',textContent:'',disabled:false,hidden:false,classList:{toggle:()=>{}},listeners:{},replaceChildren(){},addEventListener(type,listener){this.listeners[type]=listener;}});return elements.get(id);}
  const chrome={
    tabs:{query:async()=>[{id:17,url:pair.origin,title:'Synthetic application'}]},
    storage:{local:{get:async()=>({})}},
    permissions:{contains:async()=>{calls.push('contains');return false;},request:async()=>{calls.push('request');return false;}},
    runtime:{sendMessage:async()=>({state:'idle'})}
  };
  const context=vm.createContext({URL,Date,TypeError,Error,chrome,document:{querySelector:element},fetch:async()=>{calls.push('fetch');throw new Error('Unexpected fetch');}});
  vm.runInContext(popup,context);
  await new Promise(resolve=>setImmediate(resolve));
  element('#code').value='not-a-code';
  await element('#pair-form').listeners.submit({preventDefault(){}});
  assert.deepEqual(calls,[]);
  assert.match(element('#status').textContent,/not an API key/);
  assert.equal(element('#tab-origin').textContent,pair.origin);
});

test('popup primary action opens Fabric without codes, website access or claiming an account connection',async()=>{
  const elements=new Map(),opened=[];
  function element(id){if(!elements.has(id))elements.set(id,{value:'',textContent:'',disabled:false,hidden:false,classList:{toggle(){}},listeners:{},replaceChildren(){},addEventListener(type,fn){this.listeners[type]=fn;}});return elements.get(id);}
  const chrome={tabs:{query:async()=>[{id:17,url:pair.origin,title:'Fixture'}],create:async options=>opened.push(options)},storage:{local:{get:async()=>({})}},runtime:{sendMessage:async()=>({state:'idle'})}};
  vm.runInNewContext(popup,{URL,Date,Error,chrome,document:{querySelector:element}});
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(typeof element('#open-fabric').listeners.click,'function');
  await element('#open-fabric').listeners.click();
  assert.deepEqual(plain(opened),[{url:'http://127.0.0.1:4188/#connectors',active:true}]);
  const html=readFileSync(new URL('../popup.html',import.meta.url),'utf8');
  assert.match(html,/<details[^>]*>\s*<summary>Advanced recovery<\/summary>\s*<form id="pair-form">/);
});

test('popup lists saved apps independently and checks or removes only the chosen grant',async()=>{
  const stored={fabricConnections:Object.fromEntries(['notes','tasks'].map(id=>[id,{connectionId:id,token:`fixture-${id}-secret`,origin:`https://${id}.fixture.test`,label:id,bridgeVersion:'0.3',sessionScope:'browser-profile'}]))},elements=new Map(),messages=[];
  function node(){return {value:'',textContent:'',disabled:false,hidden:false,classList:{toggle(){}},listeners:{},children:[],append(...children){this.children.push(...children);},replaceChildren(...children){this.children=children;},addEventListener(type,fn){this.listeners[type]=fn;}};}
  function element(id){if(!elements.has(id))elements.set(id,node());return elements.get(id);}
  const chrome={tabs:{query:async()=>[{id:17,url:pair.origin,title:'Fixture'}]},storage:{local:{get:async()=>structuredClone(stored)}},runtime:{sendMessage:async message=>{messages.push(message);if(message.type==='fabric-disconnect')delete stored.fabricConnections[message.connectionId];return message.type==='fabric-disconnect'?{ok:true}:{state:'idle'};}}};
  vm.runInNewContext(popup,{URL,Date,Error,chrome,document:{querySelector:element,createElement:node}});
  await new Promise(resolve=>setImmediate(resolve));
  const list=element('#saved-connections');assert.equal(list.children.length,2);assert.equal(element('#saved-section').hidden,false);
  assert.equal(JSON.stringify(list).includes('fixture-notes-secret'),false);
  await list.children[0].children[3].children[0].listeners.click();assert.deepEqual(plain(messages[0]),{type:'fabric-poll',connectionId:'notes'});
  await list.children[1].children[3].children[1].listeners.click();assert.deepEqual(plain(messages[1]),{type:'fabric-disconnect',connectionId:'tasks'});
  assert.deepEqual(Object.keys(stored.fabricConnections),['notes']);assert.equal(list.children.length,1);assert.equal(list.children[0].children[0].textContent,'notes');
});

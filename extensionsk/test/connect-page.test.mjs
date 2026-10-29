import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const source=readFileSync(new URL('../connect.js',import.meta.url),'utf8');
const flush=()=>new Promise(resolve=>setImmediate(resolve));
function harness({grant=true,pending=false}={}) {
  const elements=new Map(),messages=[];let closeCount=0,finish;
  function element(id) {if(!elements.has(id))elements.set(id,{textContent:'',disabled:false,classList:{toggle(){}},listeners:{},addEventListener(event,fn){this.listeners[event]=fn;}});return elements.get(id);}
  const chrome={permissions:{request:async()=>grant},runtime:{sendMessage:async message=>{
    messages.push(message.type);
    if(message.type==='fabric-connect-details')return {ok:true,request:{appName:'Slack',origin:'https://app.slack.com'}};
    if(message.type==='fabric-connect-approve'&&pending)return new Promise(resolve=>{finish=resolve;});
    return {ok:true};
  }}};
  vm.runInNewContext(source,{URL,Error,chrome,location:{href:'chrome-extension://fixture/connect.html?request=fixture'},document:{querySelector:element},window:{close(){closeCount++;}}});
  return {element,messages,closed:()=>closeCount,finish:()=>finish({ok:true})};
}
test('approved page saves browser-profile consent without claiming sign-in and closes without cancelling it',async()=>{
  const h=harness();await flush();await h.element('#approve').listeners.click();
  assert.equal(h.element('#approve').textContent,'Connection saved');
  assert.match(h.element('#status').textContent,/sign-in.*not verified/i);
  assert.match(h.element('#status').textContent,/close app tabs.*approved read/i);
  assert.equal(h.element('#cancel').textContent,'Close this setup page');
  await h.element('#cancel').listeners.click();
  assert.equal(h.messages.includes('fabric-connect-cancel'),false);
  assert.equal(h.closed(),1);
});
test('in-flight setup cannot be presented as cancelled while pairing completes',async()=>{
  const h=harness({pending:true});await flush();const approval=h.element('#approve').listeners.click();await flush();
  assert.equal(h.element('#cancel').disabled,true);
  await h.element('#cancel').listeners.click();
  assert.equal(h.closed(),0);assert.equal(h.messages.includes('fabric-connect-cancel'),false);
  h.finish();await approval;
  assert.equal(h.element('#cancel').disabled,false);
});
test('denied website approval does not dispatch pairing and leaves cancellation available',async()=>{
  const h=harness({grant:false});await flush();await h.element('#approve').listeners.click();
  assert.equal(h.messages.includes('fabric-connect-approve'),false);
  assert.equal(h.element('#approve').disabled,false);
  assert.equal(h.element('#cancel').disabled,false);
  await h.element('#cancel').listeners.click();
  assert.equal(h.messages.includes('fabric-connect-cancel'),true);
});

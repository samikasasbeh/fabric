const base='http://127.0.0.1:4188';let polling=false,pollAgain=false,storageWrites=Promise.resolve();
const MAX_OWNED_TABS=3,IDLE_LEASE_MS=180000,protectedTabs=new Set(),openingTabs=new Map();
// Content scripts never receive the saved bearer credentials. Session storage
// holds tab IDs only for this browser session, including across worker restarts.
const storageReady=Promise.resolve().then(async()=>{
  await chrome.storage.local.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'});
  await chrome.storage.session.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'});
  return true;
}).catch(()=>false);
const originOf=tab=>{try{return new URL(tab?.url).origin;}catch{return null;}};
const durable=p=>p?.bridgeVersion==='0.3'&&p.sessionScope==='browser-profile';
function storageTask(operation){const next=storageWrites.then(operation,operation);storageWrites=next.catch(()=>{});return next;}
function changeMap(area,key,change){return storageTask(async()=>{const values=(await area.get(key))[key]||{};const result=change(values);await area.set({[key]:values});return result;});}
async function currentConnection(pair){
  await storageWrites;const {fabricConnections={}}=await chrome.storage.local.get('fabricConnections'),current=fabricConnections[pair.connectionId];
  return durable(current)&&current.token===pair.token&&current.origin===pair.origin;
}
async function currentPair(pair) {
  if(durable(pair))return currentConnection(pair);
  const {fabricPair:current}=await chrome.storage.local.get('fabricPair');
  return current?.connectionId===pair.connectionId&&current?.token===pair.token&&current?.tabId===pair.tabId;
}
async function record(pair,result) {
  try {
    if(pair&&await currentPair(pair)) {
      const status={connectionId:pair.connectionId,at:new Date().toISOString(),state:result.state,error:result.error||null};
      if(durable(pair))await changeMap(chrome.storage.local,'fabricConnectionStatus',values=>{values[pair.connectionId]=status;});
      else await chrome.storage.local.set({fabricBridgeStatus:status});
    }
  } catch { /* Losing optional check history must not replay a read or mask its observed result. */ }
  return result;
}
async function pollLegacy(){
  let pair;
  try {
    const {fabricPair:p}=await chrome.storage.local.get('fabricPair');pair=p;if(!p) return {state:'not_paired'};
    let tab;
    try {tab=await chrome.tabs.get(p.tabId);} catch {throw new Error('The paired tab is no longer open. Open the application tab and create a new pairing in Fabric.');}
    if(new URL(tab.url).origin!==p.origin) throw new Error('The paired tab changed application. Reopen the intended app and pair it again.');
    const headers={'Content-Type':'application/json',Authorization:`Bearer ${p.token}`};
    const response=await fetch(`${base}/api/browser/poll`,{method:'POST',headers,body:'{}'});const payload=await response.json();if(!response.ok) throw new Error(typeof payload.error==='string'?payload.error:'Fabric refused this browser connection.');if(!payload.command) return await record(p,{state:'idle'});
    const command=payload.command;if(command.origin!==p.origin) throw new Error('Command origin does not match pairing.');
    if(!await currentPair(p)) throw new Error('Browser sharing stopped or changed before this read.');
    let result;
    try {
      const injected=await chrome.scripting.executeScript({target:{tabId:p.tabId},world:'ISOLATED',func:observe,args:[command,p.origin]});
      result=injected[0]?.result;if(!result) throw new Error('No page result.');
    }catch(error){result={ok:false,error:error.message};}
    if(!await currentPair(p)) throw new Error('Browser sharing stopped or changed. This read result was not sent.');
    const returned=await fetch(`${base}/api/browser/result`,{method:'POST',headers,body:JSON.stringify({id:command.id,...result})});
    const acknowledgement=await returned.json();
    if(!returned.ok||acknowledgement.accepted!==true) throw new Error(typeof acknowledgement.error==='string'?acknowledgement.error:'Fabric did not accept this read result. Check the action in Fabric.');
    return await record(p,result.ok?{state:'completed'}:{state:'failed',error:result.error||'The page could not be read.'});
  }catch(error){return await record(pair,{state:'failed',error:error instanceof TypeError?'Cannot reach local Fabric at 127.0.0.1:4188. Keep Fabric running and try again.':error.message});}
}
async function releaseLease(pair,{idle=false}={}) {
  return storageTask(async()=>{
    const {fabricLeases={}}=await chrome.storage.session.get('fabricLeases'),lease=fabricLeases[pair.connectionId];
    if(!lease)return;
    if(idle&&Date.now()-lease.lastUsedAt<IDLE_LEASE_MS)return;
    let tab;try{tab=await chrome.tabs.get(lease.tabId);}catch{}
    if(lease.owned&&!protectedTabs.has(lease.tabId)&&tab?.active===false&&originOf(tab)===pair.origin&&(!tab.pendingUrl||new URL(tab.pendingUrl).origin===pair.origin)) {
      await chrome.tabs.remove(lease.tabId).catch(()=>{});
    } else if(idle&&tab&&originOf(tab)===pair.origin) {
      // Once a person uses a tab, Fabric never reclaims cleanup ownership.
      lease.owned=false;await chrome.storage.session.set({fabricLeases});return;
    }
    delete fabricLeases[pair.connectionId];await chrome.storage.session.set({fabricLeases});
  });
}
async function disconnectConnection(id) {
  if(!await storageReady)throw new Error('Update this browser before managing Fabric connections.');
  if(typeof id!=='string'||!/^[A-Za-z0-9-]{1,100}$/.test(id))throw new Error('Choose a saved browser connection.');
  const pair=await changeMap(chrome.storage.local,'fabricConnections',values=>{const previous=values[id];delete values[id];return previous;});
  if(!pair)return {ok:true};
  await releaseLease(pair);await changeMap(chrome.storage.local,'fabricConnectionStatus',values=>{delete values[id];});
  const {fabricConnections={},fabricPair}=await chrome.storage.local.get(['fabricConnections','fabricPair']);
  if(!Object.values(fabricConnections).some(other=>other.origin===pair.origin)&&fabricPair?.origin!==pair.origin)await chrome.permissions.remove({origins:[`${pair.origin}/*`]}).catch(()=>{});
  return {ok:true};
}
async function leaseFor(pair) {
  await storageWrites;const {fabricLeases={}}=await chrome.storage.session.get('fabricLeases'),lease=fabricLeases[pair.connectionId];
  if(!lease||!Number.isInteger(lease.tabId))return null;
  let tab;try{tab=await chrome.tabs.get(lease.tabId);}catch{}
  if(!tab||originOf(tab)!==pair.origin||tab.pendingUrl&&new URL(tab.pendingUrl).origin!==pair.origin) {
    await changeMap(chrome.storage.session,'fabricLeases',values=>{if(values[pair.connectionId]?.tabId===lease.tabId)delete values[pair.connectionId];});return null;
  }
  if(tab.active||protectedTabs.has(lease.tabId)) {
    lease.owned=false;await changeMap(chrome.storage.session,'fabricLeases',values=>{if(values[pair.connectionId]?.tabId===lease.tabId)values[pair.connectionId].owned=false;});
  }
  return {lease,tab};
}
async function cleanupLeases() {
  const {fabricConnections={}}=await chrome.storage.local.get('fabricConnections');
  for(const pair of Object.values(fabricConnections))if(durable(pair))await releaseLease(pair,{idle:true});
}
function assertCommandCurrent(command){if(typeof command.expiresAt!=='string'||!Number.isFinite(Date.parse(command.expiresAt))||Date.parse(command.expiresAt)<=Date.now())throw new Error('The requested operation expired. Inspect the page again and make a new request. No action was replayed.');}
async function executionTab(pair,command) {
  assertCommandCurrent(command);
  if(!await chrome.permissions.contains({origins:[`${pair.origin}/*`]}))throw new Error('Website access is no longer approved. Reconnect this app in Fabric before requesting page access.');
  let current=await leaseFor(pair);
  if(current)return current.tab;
  if(!['observe','read'].includes(command.action.op))throw new Error('The inspected tab is no longer available. Inspect the page again before requesting a click or fill. No action was replayed.');
  if(!await currentConnection(pair))throw new Error('Browser sharing stopped before opening the requested page.');
  await cleanupLeases();
  const tab=await storageTask(async()=>{
    const {fabricLeases={}}=await chrome.storage.session.get('fabricLeases');
    const {fabricConnections={}}=await chrome.storage.local.get('fabricConnections');
    if(fabricConnections[pair.connectionId]?.token!==pair.token)throw new Error('Browser sharing stopped before opening this page.');
    if(Object.values(fabricLeases).filter(lease=>lease.owned).length>=MAX_OWNED_TABS)throw new Error('Fabric already has three execution tabs. Close an unused Fabric tab or wait for idle cleanup, then request the read again.');
    assertCommandCurrent(command);
    const opened=await chrome.tabs.create({url:pair.origin,active:false});openingTabs.set(opened.id,new URL(pair.origin).href);
    fabricLeases[pair.connectionId]={tabId:opened.id,owned:!protectedTabs.has(opened.id)&&opened.active!==true,lastUsedAt:Date.now()};
    await chrome.storage.session.set({fabricLeases});return opened;
  });
  try {
    if(!await currentConnection(pair)) {await releaseLease(pair);throw new Error('Browser sharing stopped before this read.');}
    return await awaitAppTab(tab.id,pair.origin);
  } finally {await storageTask(()=>openingTabs.delete(tab.id));}
}
async function runtimeRequest(pair,path,body) {
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),7000);
  try {
    const response=await fetch(`${base}${path}`,{method:'POST',headers:{'Content-Type':'application/json',Authorization:`Bearer ${pair.token}`},body:JSON.stringify(body),signal:controller.signal});
    const payload=await response.json();
    if(!response.ok){if(response.status===401&&payload.code==='browser_revoked')await disconnectConnection(pair.connectionId);throw new Error(typeof payload.error==='string'?payload.error:'Fabric refused this browser connection.');}
    return payload;
  }finally{clearTimeout(timer);}
}
async function pollConnection(pair) {
  try {
    if(!await currentConnection(pair))return {state:'not_paired'};
    const current=await leaseFor(pair);
    const payload=await runtimeRequest(pair,'/api/browser/poll',{execution:{state:current?'open':'idle'}});
    if(!payload.command)return await record(pair,{state:'idle'});
    const command=payload.command;
    if(command.origin!==pair.origin||!['observe','read','click','fill'].includes(command.action?.op))throw new Error('Command does not match this browser connection.');
    if(!await currentConnection(pair))throw new Error('Browser sharing stopped or changed before this operation.');
    let result;
    try {
      const tab=await executionTab(pair,command);
      if(!await currentConnection(pair))throw new Error('Browser sharing stopped before this operation.');
      const confirmed=await leaseFor(pair);
      if(!confirmed||confirmed.tab.id!==tab.id)throw new Error('The execution tab changed. Inspect the page again.');
      await changeMap(chrome.storage.session,'fabricLeases',values=>{if(values[pair.connectionId]?.tabId===tab.id)values[pair.connectionId].lastUsedAt=Date.now();});
      if(!await currentConnection(pair))throw new Error('Browser sharing stopped before this operation.');
      assertCommandCurrent(command);
      const injected=await chrome.scripting.executeScript({target:{tabId:tab.id},world:'ISOLATED',func:observe,args:[command,pair.origin]});
      result=injected[0]?.result;if(!result)throw new Error('No page result.');
    }catch(error){result={ok:false,error:error.message};}
    if(!await currentConnection(pair))throw new Error('Browser sharing stopped or changed. This operation result was not sent.');
    const acknowledgement=await runtimeRequest(pair,'/api/browser/result',{id:command.id,...result});
    if(acknowledgement.accepted!==true)throw new Error('Fabric did not accept this operation result. Check its status in Fabric.');
    return await record(pair,result.ok?{state:'completed'}:{state:'failed',error:result.error||'The requested operation was not completed.'});
  }catch(error){return await record(pair,{state:'failed',error:error instanceof TypeError?'Cannot reach local Fabric at 127.0.0.1:4188. Keep Fabric running and try again.':error.message});}
}
async function poll(connectionId) {
  if(polling)return {state:'busy'};polling=true;
  try {
    if(!await storageReady)throw new Error('Update this browser to use Fabric’s protected connection storage.');
    await cleanupLeases();
    const {fabricConnections={},fabricPair}=await chrome.storage.local.get(['fabricConnections','fabricPair']);
    const pairs=Object.values(fabricConnections).filter(pair=>durable(pair)&&(!connectionId||pair.connectionId===connectionId)),results=[];
    let index=0;
    await Promise.all(pairs.slice(0,2).map(async()=>{while(index<pairs.length){const position=index++,pair=pairs[position];results[position]={connectionId:pair.connectionId,...await pollConnection(pair)};}}));
    if(fabricPair&&(!connectionId||fabricPair.connectionId===connectionId))results.push({connectionId:fabricPair.connectionId,...await pollLegacy()});
    if(!results.length)return {state:'not_paired'};
    if(results.length===1){const {connectionId:ignored,...result}=results[0];return result;}
    const failed=results.find(result=>result.state==='failed');return {state:failed?'failed':results.some(result=>result.state==='completed')?'completed':'idle',...(failed?{error:failed.error}:{}),connections:results};
  }catch(error){return {state:'failed',error:error.message};}finally{polling=false;if(pollAgain){pollAgain=false;Promise.resolve().then(()=>poll());}}
}
function observe(command,expectedOrigin){
  try {
    if(location.origin!==expectedOrigin) throw new Error('Origin changed.');
    if(!['observe','read','click','fill'].includes(command.action?.op)) throw new Error('Unsupported browser operation; JavaScript and shell execution are not supported.');
    const write=['click','fill'].includes(command.action.op);
    // Keep this check inside the injected function: a busy renderer may run it
    // after the worker's deadline check. Legacy tab-only commands omit expiry.
    const assertUnexpired=()=>{if(Object.prototype.hasOwnProperty.call(command,'expiresAt')&&(typeof command.expiresAt!=='string'||!Number.isFinite(Date.parse(command.expiresAt))||Date.parse(command.expiresAt)<=Date.now())){if(write)globalThis.__fabricSnapshotV2?.dispose?.();throw new Error('The requested operation expired or its deadline is invalid. Inspect again and make a new request. No action was replayed.');}};
    assertUnexpired();
    if(write&&(!command.args?.snapshotId||!command.args?.targetId)) throw new Error('An observed snapshot and target are required.');
    const visible=e=>{if(!e.isConnected||!e.getClientRects().length)return false;for(let p=e;p;p=p.parentElement){const s=getComputedStyle(p);if(s.display==='none'||['hidden','collapse'].includes(s.visibility)||s.opacity==='0'||p.hidden||p.getAttribute('aria-hidden')==='true')return false;}return true;};
    const label=e=>(e.getAttribute('aria-label')||[...(e.labels||[])].map(n=>n.textContent).join(' ')||e.getAttribute('placeholder')||e.innerText||e.getAttribute('title')||'').trim().slice(0,120);
    const sensitive=e=>Boolean(e.closest('[data-sensitive]'))||e.matches('input[type="password"],input[type="file"],input[type="hidden"],[contenteditable="true"]')||/password|passwd|secret|(?:access|refresh|auth)[-_ ]?token|api[-_ ]?key|private[-_ ]?key|credit|card.?number|cc-|cvc|cvv|security.?code|one.?time|otp|ssn|social.?security|bank.?account|routing.?number|recovery.?code|verification.?code/i.test([e.getAttribute('autocomplete'),e.getAttribute('name'),e.id,e.getAttribute('type'),label(e)].join(' '));
    const privateText=e=>e.matches('input,textarea,[contenteditable="true"]')||Boolean(e.closest('input,textarea,[contenteditable="true"],[data-sensitive]'));
    const text=e=>{const walker=document.createTreeWalker(e,NodeFilter.SHOW_TEXT);let output='',visits=0,node;while((node=walker.nextNode())&&visits++<5000&&output.length<24000){const parent=node.parentElement;if(!parent||privateText(parent)||parent.closest('script,style,[hidden],[aria-hidden="true"]'))continue;if(visible(parent))output+=`${node.textContent.trim()} `;}return output.trim().slice(0,24000);};
    const disabled=e=>Boolean(e.disabled||e.readOnly||e.getAttribute('aria-disabled')==='true'||e.closest('[inert]'));
    const canFill=e=>!sensitive(e)&&!disabled(e)&&(e.tagName==='TEXTAREA'||e.tagName==='INPUT'&&['text','search','email','tel','url','number'].includes((e.type||'text').toLowerCase()));
    const canClick=e=>!sensitive(e)&&!disabled(e)&&e.matches('button,a,[role="button"],[role="tab"],input[type="checkbox"],input[type="radio"]');
    const fingerprint=e=>JSON.stringify({tag:e.tagName,role:e.getAttribute('role'),id:e.id,name:e.getAttribute('name'),type:e.getAttribute('type'),label:label(e),text:(e.innerText||'').slice(0,500),href:e.getAttribute('href'),form:e.form?.action||null,disabled:disabled(e),sensitive:sensitive(e)});
    if(command.action.op==='read') {
      if(typeof command.args?.selector!=='string'||!command.args.selector||command.args.selector.length>500)throw new Error('A bounded element selector is required.');
      const nodes=document.querySelectorAll(command.args.selector);if(nodes.length!==1||!visible(nodes[0])||privateText(nodes[0])||sensitive(nodes[0])) throw new Error('Selector must identify one visible, non-sensitive element.');
      return {ok:true,data:{origin:location.origin,title:document.title,text:text(nodes[0]),selector:command.args.selector}};
    }
    if(write) {
      const state=globalThis.__fabricSnapshotV2,args=command.args;
      // Drain records too: a same-task mutation may precede observer delivery.
      if(state?.observer?.takeRecords().length)state.dispose();
      if(!state||state.disposed||state.document!==document||state.snapshotId!==args.snapshotId||state.origin!==location.origin||state.url!==location.href||Date.now()-state.at>120000) {state?.dispose?.();throw new Error('Page inspection is stale. Inspect the current page before requesting this action.');}
      const target=state.targets.get(args.targetId),element=target?.element;
      if(!element||!visible(element)||sensitive(element)||disabled(element)||fingerprint(element)!==target.fingerprint) throw new Error('The inspected control changed or is no longer available. Inspect again.');
      if(command.action.op==='click') {
        if(!canClick(element)) throw new Error('This inspected control is not clickable.');
        if(element.tagName==='A') {const destination=new URL(element.href,location.href);if(destination.protocol!=='https:'||destination.origin!==expectedOrigin)throw new Error('Cross-origin and native-app navigation are not allowed by this paired action.');}
        if(element.form) {
          const destination=new URL(element.hasAttribute('formaction')?element.formAction:element.form.action,location.href);
          const target=(element.hasAttribute('formtarget')?element.formTarget:element.form.target)||document.querySelector('base[target]')?.target||'';
          if(destination.protocol!=='https:'||destination.origin!==expectedOrigin||destination.username||destination.password)throw new Error('Cross-origin and native-app form submission are not allowed by this paired action.');
          if(target&&target.toLowerCase()!=='_self')throw new Error('Form submission must stay in the paired tab.');
          if([...element.form.querySelectorAll('input,textarea')].some(field=>sensitive(field)&&field.value))throw new Error('Submitting a form containing credentials or sensitive values is not supported.');
        }
        // Consume the snapshot before dispatch: a response lost on navigation must
        // never permit replay of the same prepared action.
        state.dispose();
        assertUnexpired();
        element.click();
      } else {
        if(!canFill(element)||typeof args.value!=='string'||args.value.length>10000) throw new Error('Only bounded text in non-sensitive inspected fields can be filled.');
        const prototype=element.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;
        const setter=Object.getOwnPropertyDescriptor(prototype,'value')?.set;
        if(!setter)throw new Error('This field does not expose a supported text setter.');
        state.dispose();
        assertUnexpired();
        setter.call(element,args.value);
        element.dispatchEvent(new Event('input',{bubbles:true}));element.dispatchEvent(new Event('change',{bubbles:true}));
      }
      return {ok:true,data:{origin:expectedOrigin,operation:command.action.op,targetId:args.targetId,dispatchStatus:'dispatched',persistentEffect:'unverified',note:'Inspect the application again. DOM dispatch does not establish a saved provider result.'}};
    }
    globalThis.__fabricSnapshotV2?.dispose?.();
    const state={snapshotId:crypto.randomUUID(),document,origin:location.origin,url:location.href,at:Date.now(),targets:new Map(),disposed:false};
    const controls=[...document.querySelectorAll('button,a,[role="button"],[role="tab"],input,textarea')].filter(e=>visible(e)&&!sensitive(e)).slice(0,100).map(e=>{const targetId=crypto.randomUUID();state.targets.set(targetId,{element:e,fingerprint:fingerprint(e)});return {targetId,role:e.getAttribute('role')||e.tagName.toLowerCase(),label:label(e),kind:canFill(e)?'field':'control',canClick:canClick(e),canFill:canFill(e),selector:e.id?`#${CSS.escape(e.id)}`:null};});
    globalThis.__fabricSnapshotV2=state;
    // A control's label can stay unchanged while its record or form changes.
    // Observe the full document conservatively; a new inspection restores access.
    state.dispose=()=>{
      state.disposed=true;state.observer.disconnect();state.targets.clear();clearTimeout(state.timer);
      document.removeEventListener('input',state.dispose,true);document.removeEventListener('change',state.dispose,true);globalThis.removeEventListener('pagehide',state.dispose);
      if(globalThis.__fabricSnapshotV2===state)globalThis.__fabricSnapshotV2=null;
    };
    state.observer=new MutationObserver(state.dispose);
    state.observer.observe(document,{subtree:true,childList:true,characterData:true,attributes:true});
    document.addEventListener('input',state.dispose,true);document.addEventListener('change',state.dispose,true);globalThis.addEventListener('pagehide',state.dispose);
    state.timer=setTimeout(state.dispose,120000);
    return {ok:true,data:{snapshotId:state.snapshotId,origin:location.origin,url:location.href,title:document.title,text:text(document.body),controls,expiresAt:new Date(state.at+120000).toISOString(),accountBinding:'Browser session only; no provider identity verification.'}};
  }catch(error){return {ok:false,error:error.message};}
}
function extensionPage(sender,page){return sender.id===chrome.runtime.id&&sender.url===chrome.runtime.getURL(page);}
function localFabricPage(sender){try{return sender.id===chrome.runtime.id&&sender.frameId===0&&Number.isInteger(sender.tab?.id)&&new URL(sender.url).origin===base;}catch{return false;}}
function validatePairing(pairing){
  if(!pairing||typeof pairing.pairingId!=='string'||!/^[a-f0-9-]{36}$/.test(pairing.pairingId)||typeof pairing.code!=='string'||!/^[A-F0-9]{12}$/.test(pairing.code)||typeof pairing.appName!=='string'||pairing.appName.length>150||!Array.isArray(pairing.origins)||pairing.origins.length<1||pairing.origins.length>5||Date.parse(pairing.expiresAt)<=Date.now()||!Number.isFinite(Date.parse(pairing.expiresAt))||Date.parse(pairing.expiresAt)>Date.now()+6*60000)throw new Error('Invalid or expired Fabric connection request. Start again in Fabric.');
  const url=new URL(pairing.launchUrl);
  if(url.protocol!=='https:'||url.username||url.password||url.pathname!=='/'||url.search||url.hash||!pairing.origins.includes(url.origin)||url.hostname==='localhost'||/^\d+\.\d+\.\d+\.\d+$/.test(url.hostname)||url.hostname.includes(':'))throw new Error('The connection must open a declared HTTPS application origin.');
  if(pairing.bridgeVersion!=='0.3'||pairing.sessionScope!=='browser-profile')throw new Error('Update Fabric before approving a saved browser connection. Existing tab-only pairings are unchanged.');
  return {pairingId:pairing.pairingId,code:pairing.code,appName:pairing.appName,origin:url.origin,expiresAt:pairing.expiresAt,sessionScope:'browser-profile'};
}
async function getRequest(requestId){
  if(typeof requestId!=='string'||!/^[a-f0-9-]{36}$/.test(requestId))throw new Error('Unknown setup request.');
  const {fabricConnectRequests:requests={}}=await chrome.storage.local.get('fabricConnectRequests');
  const request=requests[requestId];
  if(!request||request.state!=='pending'||Date.parse(request.expiresAt)<=Date.now())throw new Error('Connection request expired or already used. Return to Fabric and connect again.');
  return {request,requests};
}
async function awaitAppTab(tabId,origin){
  const deadline=Date.now()+20000;
  while(Date.now()<deadline){const tab=await chrome.tabs.get(tabId);if(tab.url&&new URL(tab.url).origin===origin&&tab.status==='complete')return tab;await new Promise(resolve=>setTimeout(resolve,250));}
  throw new Error('The app did not finish opening on the approved website. Complete sign-in in this browser, then request page access again. Your connection is still saved.');
}
async function connectMessage(message,sender){
  if(!await storageReady)throw new Error('Update this browser to use Fabric’s protected connection storage.');
  if(message.type==='fabric-connect-request'){
    if(!localFabricPage(sender))throw new Error('Only the local Fabric page can request a connection.');
    const pairing=validatePairing(message.pairing),requestId=crypto.randomUUID();
    await changeMap(chrome.storage.local,'fabricConnectRequests',requests=>{
      for(const [id,request] of Object.entries(requests))if(Date.parse(request.expiresAt)<=Date.now())delete requests[id];
      if(Object.keys(requests).length>=5)throw new Error('Finish or cancel an open connection request first.');
      requests[requestId]={...pairing,requestId,state:'pending'};
    });
    await chrome.tabs.create({url:`${chrome.runtime.getURL('connect.html')}?request=${requestId}`,active:true});
    return {ok:true,pairingId:pairing.pairingId,confirmationOpened:true};
  }
  if(!sender.url?.startsWith(chrome.runtime.getURL('connect.html')+'?')||sender.id!==chrome.runtime.id)throw new Error('Connection approval must come from the Fabric extension setup page.');
  const {request}=await getRequest(message.requestId);
  if(new URL(sender.url).searchParams.get('request')!==message.requestId)throw new Error('Connection request does not match this approval page.');
  if(message.type==='fabric-connect-details')return {ok:true,request:{appName:request.appName,origin:request.origin,pairingId:request.pairingId,sessionScope:'browser-profile'}};
  if(message.type==='fabric-connect-cancel'){await changeMap(chrome.storage.local,'fabricConnectRequests',requests=>{delete requests[message.requestId];});return {ok:true};}
  if(message.type!=='fabric-connect-approve')throw new Error('Unknown browser setup action.');
  if(!await chrome.permissions.contains({origins:[`${request.origin}/*`]}))throw new Error('Website access must be approved before connecting.');
  await changeMap(chrome.storage.local,'fabricConnectRequests',requests=>{
    if(requests[message.requestId]?.state!=='pending')throw new Error('This connection request is already being used.');
    requests[message.requestId]={...request,state:'connecting'};
  });
  try {
    const response=await fetch(`${base}/api/browser/pair`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:request.code,origin:request.origin,label:request.appName,bridgeVersion:'0.3',sessionScope:'browser-profile'})});
    const data=await response.json();
    if(!response.ok)throw new Error(typeof data.error==='string'?data.error:'Fabric refused the connection.');
    if(typeof data.connection?.id!=='string'||!/^[A-Za-z0-9-]{1,100}$/.test(data.connection.id)||data.connection.sessionScope!=='browser-profile'||data.connection.bridgeVersion!=='0.3'||typeof data.token!=='string'||!data.token||data.token.length>256||data.pairingId!==request.pairingId)throw new Error('The returned connection did not match this exact setup request.');
    const pair={connectionId:data.connection.id,token:data.token,origin:request.origin,label:request.appName,bridgeVersion:'0.3',sessionScope:'browser-profile',pairingId:data.pairingId};
    await changeMap(chrome.storage.local,'fabricConnections',values=>{values[pair.connectionId]=pair;});
    let signInOpened=false;
    if(await currentConnection(pair))try {
      const tab=await chrome.tabs.create({url:request.origin,active:true});
      if(await currentConnection(pair))await changeMap(chrome.storage.session,'fabricLeases',values=>{values[pair.connectionId]={tabId:tab.id,owned:false,lastUsedAt:Date.now()};});
      signInOpened=true;
    }catch{ /* Consent remains saved even if a sign-in tab cannot open. */ }
    return {ok:true,pairingId:data.pairingId,connectionId:pair.connectionId,sessionScope:'browser-profile',signInOpened};
  }finally{
    await changeMap(chrome.storage.local,'fabricConnectRequests',requests=>{delete requests[message.requestId];});
  }
}
chrome.runtime.onMessage.addListener((message,sender,sendResponse)=>{
  if(message?.type==='fabric-poll'){if(!extensionPage(sender,'popup.html'))return false;poll(message.connectionId).then(sendResponse);return true;}
  if(message?.type==='fabric-disconnect'){if(!extensionPage(sender,'popup.html'))return false;disconnectConnection(message.connectionId).then(sendResponse,error=>sendResponse({ok:false,error:error.message}));return true;}
  if(!['fabric-connect-request','fabric-connect-details','fabric-connect-approve','fabric-connect-cancel'].includes(message?.type))return false;
  connectMessage(message,sender).then(sendResponse,error=>sendResponse({ok:false,error:error.message}));return true;
});
chrome.alarms.onAlarm.addListener(alarm=>{if(alarm.name==='fabric-poll') poll();});
async function ensurePollAlarm(){if(!await chrome.alarms.get('fabric-poll'))await chrome.alarms.create('fabric-poll',{periodInMinutes:0.5});}
ensurePollAlarm().catch(()=>{});
function protectTab(tabId,navigationUrl,loading=false){
  // Activation relinquishes ownership immediately, even while a storage update
  // is queued. A same-URL reload has no change.url but is still user navigation.
  if(!navigationUrl&&!loading)protectedTabs.add(tabId);
  return changeMap(chrome.storage.session,'fabricLeases',leases=>{
    const opening=openingTabs.get(tabId);
    // Only the helper's initial load may redirect within its approved origin.
    // User activation, off-origin redirects, and post-load navigation remain
    // permanently user-owned; completion closes this narrow startup window.
    if(loading&&opening&&!protectedTabs.has(tabId)&&(!navigationUrl||originOf({url:navigationUrl})===originOf({url:opening})))return;
    for(const lease of Object.values(leases))if(lease.tabId===tabId){protectedTabs.add(tabId);lease.owned=false;}
  });
}
chrome.tabs?.onActivated?.addListener(({tabId})=>protectTab(tabId).catch(()=>{}));
chrome.tabs?.onUpdated?.addListener((tabId,change,tab)=>{
  // Keep completion behind earlier queued loading events. Removing this marker
  // synchronously can turn an initial load into apparent user navigation.
  if(change.status==='complete')storageTask(()=>openingTabs.delete(tabId)).catch(()=>{});
  if(change.url||change.status==='loading')return protectTab(tabId,change.url,change.status==='loading'||Boolean(change.url&&tab?.status==='loading')).catch(()=>{});
});
chrome.tabs?.onRemoved?.addListener(tabId=>{
  protectedTabs.delete(tabId);openingTabs.delete(tabId);
  return changeMap(chrome.storage.session,'fabricLeases',leases=>{let removed=false;for(const [id,lease] of Object.entries(leases))if(lease.tabId===tabId){delete leases[id];removed=true;}return removed;}).then(removed=>{if(removed){if(polling)pollAgain=true;else return poll();}}).catch(()=>{});
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm, access, readFile, writeFile, cp} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import {randomInt,createHash,X509Certificate} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
import {createApp} from '../server.mjs';
import {resolveHelperDirectory} from '../lib/helper-directory.mjs';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const APPS = ['notes', 'tasks'].map(name=>({id:`durable-${name}-fixture`, name:`Synthetic durable ${name}`, origin:`https://durable-${name}.fabric.test`}));
const sleep = ms=>new Promise(resolve=>setTimeout(resolve, ms));
async function until(check, message, timeout=15000) {
  const deadline=Date.now()+timeout;
  do {const result=await check();if(result)return result;await sleep(30);} while(Date.now()<deadline);
  throw new Error(message);
}
const escapeHTML = value=>String(value).replace(/[&<>"']/g, character=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
function fixtureHTML(app, state) {
  return `<!doctype html><meta charset="utf-8"><title>${escapeHTML(app.name)}</title>
    <h1>${escapeHTML(app.name)}</h1><main id="stored">${escapeHTML(state.value || 'No saved content')}</main>
    <p id="identity">Synthetic signed-out state</p><form action="/save" method="post"><label for="content">Content</label><input id="content" name="value" value="${escapeHTML(state.value)}"><button type="submit">Save content</button></form><p id="status">Ready</p>
    <script>document.querySelector('#identity').textContent=localStorage.getItem('fixture-account')||'Synthetic signed-out state';document.querySelector('form').addEventListener('submit',async e=>{e.preventDefault();const response=await fetch('/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({value:document.querySelector('#content').value})});const state=await response.json();document.querySelector('#stored').textContent=state.value;document.querySelector('#status').textContent='Saved '+state.writes;});</script>`;
}

async function applications(directory) {
  const states=new Map(APPS.map(app=>[app.id,{value:'',writes:0}]));
  const handle=async(req,res)=>{
    const pieces=new URL(req.url,'http://fixture.invalid').pathname.split('/').filter(Boolean);
    const hostApp=APPS.find(app=>new URL(app.origin).hostname===String(req.headers.host).split(':')[0]);
    const id=hostApp?.id||pieces.shift(),operation=pieces[0]||'',app=APPS.find(app=>app.id===id),state=states.get(id);
    const reply=(status,type,body)=>{res.writeHead(status,{'Content-Type':type,'Cache-Control':'no-store'});res.end(body);};
    if(!app)return reply(404,'text/plain','Unknown synthetic app');
    if(req.method==='GET'&&!operation)return reply(200,'text/html',fixtureHTML(app,state));
    if(req.method==='GET'&&operation==='state')return reply(200,'application/json',JSON.stringify(state));
    if(req.method!=='POST'||operation!=='save')return reply(404,'text/plain','Unknown operation');
    try {
      const chunks=[];let length=0;
      for await(const chunk of req){length+=chunk.length;if(length>2000)throw new Error('Too large');chunks.push(chunk);}
      const body=JSON.parse(Buffer.concat(chunks).toString());
      if(Object.keys(body).length!==1||typeof body.value!=='string'||body.value.length>500)throw new Error('Invalid input');
      state.value=body.value;state.writes++;
      return reply(200,'application/json',JSON.stringify(state));
    }catch{return reply(400,'text/plain','Invalid fixture input');}
  };
  const keyPath=path.join(directory,'fixture-tls-key.pem'),certPath=path.join(directory,'fixture-tls-cert.pem');
  // A new test-only certificate, never a real provider credential. Chromium is
  // allowed to trust only this certificate's public key, not arbitrary TLS.
  await promisify(execFile)('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=fabric-isolated-fixture.test','-keyout',keyPath,'-out',certPath],{timeout:15000,maxBuffer:16000});
  const key=await readFile(keyPath),cert=await readFile(certPath);
  const server=http.createServer(handle),tlsServer=https.createServer({key,cert},handle);
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  try {await new Promise((resolve,reject)=>{tlsServer.once('error',reject);tlsServer.listen(0,'127.0.0.1',resolve);});}
  catch(error){await new Promise(resolve=>server.close(resolve));throw error;}
  for(const app of APPS)app.origin=`https://${new URL(app.origin).hostname}:${tlsServer.address().port}`;
  const origin=`http://127.0.0.1:${server.address().port}`;
  return {
    spki:createHash('sha256').update(new X509Certificate(cert).publicKey.export({type:'spki',format:'der'})).digest('base64'),
    close:async()=>{server.closeAllConnections();tlsServer.closeAllConnections();await Promise.all([new Promise(resolve=>server.close(resolve)),new Promise(resolve=>tlsServer.close(resolve))]);},
    read:async app=>{const response=await fetch(`${origin}/${app.id}/state`);assert.equal(response.status,200);return response.json();},
  };
}

async function isolatedFabric(dataDir) {
  for(let attempt=0;attempt<15;attempt++) {
    const app=await createApp({dataDir,port:randomInt(54000,56000),request:async()=>{throw new Error('No provider API or external account in this proof.');}});
    try {await app.start();return app;}
    catch(error){await app.close();if(error.code!=='EADDRINUSE')throw error;}
  }
  throw new Error('No isolated Fabric test port available.');
}

// This test loads the actual MV3 extension, not an in-process transport relay.
// Only the test environment differs: a TEMPORARY copy targets a random isolated
// Fabric port, and the manifest pregrants two synthetic hosts (no native consent
// dialog is automated). All helper JS functions, real extension message handling,
// Chrome storage, fetch polling/results and isolated-world injection are intact.
// Synthetic HTTPS reaches a real loopback server, with exact host resolver rules
// and a freshly generated test-only certificate SPKI exception. It is NOT page
// interception: Chrome's inactive extension-created tabs may be invisible to
// Playwright. Native tab metadata and closure assertions use Chrome's APIs.
// Deterministic manual worker ticks replace waiting for the 30-second alarm;
// lease timestamps are aged in the isolated profile to exercise actual cleanup.
// A scripted scoped Fabric client is used, not an LLM. There are no user accounts.
test('real installed helper: durable multi-app delegation, tab leases, rejected stale writes and full browser restart', {timeout:180000}, async t=>{
  let chromium;
  try {({chromium}=await import('playwright'));await access(chromium.executablePath());}
  catch(error){if(process.env.FABRIC_REQUIRE_BROWSER_TEST==='1')throw error;t.skip('Chromium required for installed-extension durability proof; FABRIC_REQUIRE_BROWSER_TEST=1 forbids this skip.');return;}
  const directory=await mkdtemp(path.join(tmpdir(),'fabric-durable-helper-live-'));
  let fabric, fixtures, context, worker, control, extensionId;
  const pageErrors=[],pageRequests=[];
  t.after(async()=>{
    await context?.close().catch(()=>{});
    await fabric?.close();await fixtures?.close();
    await rm(directory,{recursive:true,force:true});
  });
  fabric=await isolatedFabric(path.join(directory,'runtime'));
  fixtures=await applications(directory);
  for(const app of APPS)fabric.store.put('applications',{id:app.id,name:app.name,webOrigins:[app.origin],apiOrigins:[]});
  const helper=await resolveHelperDirectory({root:ROOT});assert.equal(helper.status,'ready');
  const extension=path.join(directory,'staged-helper'),profile=path.join(directory,'fresh-browser-profile');
  await cp(helper.directory,extension,{recursive:true});
  for(const name of ['background.js','fabric-handoff.js']) {
    const original=await readFile(path.join(extension,name),'utf8');
    assert.ok(original.includes('http://127.0.0.1:4188'),`Explicit isolated endpoint substitution in ${name}`);
    await writeFile(path.join(extension,name),original.replaceAll('http://127.0.0.1:4188',fabric.origin));
  }
  const manifest=JSON.parse(await readFile(path.join(extension,'manifest.json'),'utf8'));
  assert.match(manifest.version,/^0\.3\./,'The actual durable helper is required, not a simulated v0.3 implementation');
  manifest.host_permissions=[`${fabric.origin}/*`,...APPS.map(app=>`${app.origin}/*`)];
  manifest.content_scripts=manifest.content_scripts.map(script=>({...script,matches:script.matches.map(match=>match.replace('http://127.0.0.1:4188',fabric.origin))}));
  await writeFile(path.join(extension,'manifest.json'),JSON.stringify(manifest));

  async function launch() {
    context=await chromium.launchPersistentContext(profile,{channel:'chromium',headless:true,chromiumSandbox:true,serviceWorkers:'allow',args:[`--disable-extensions-except=${extension}`,`--load-extension=${extension}`,`--host-resolver-rules=${APPS.map(app=>`MAP ${new URL(app.origin).hostname} 127.0.0.1`).join(',')}`,`--ignore-certificate-errors-spki-list=${fixtures.spki}`,'--no-proxy-server']});
    context.on('page',page=>page.on('pageerror',error=>{if(pageErrors.length<8)pageErrors.push(error.message.slice(0,300));}));
    context.on('request',request=>{if(APPS.some(app=>request.url().startsWith(app.origin)))pageRequests.push({event:'request',url:request.url(),kind:request.resourceType()});});
    context.on('requestfailed',request=>{if(APPS.some(app=>request.url().startsWith(app.origin)))pageRequests.push({event:'failed',url:request.url(),error:request.failure()?.errorText});});
    context.on('response',response=>{if(APPS.some(app=>response.url().startsWith(app.origin)))pageRequests.push({event:'response',url:response.url(),status:response.status()});});
    // Real local Fabric requests are NOT intercepted. No request can reach the
    // user's 4188 runtime. All non-fixture external page requests are blocked.
    await context.route('**/*',route=>{
      const url=new URL(route.request().url());
      if(url.origin===fabric.origin)return route.continue();
      if(url.protocol==='chrome-extension:'&&url.hostname===extensionId)return route.continue();
      if(APPS.some(app=>app.origin===url.origin))return route.continue();
      return route.abort();
    });
    worker=context.serviceWorkers().find(worker=>worker.url().startsWith('chrome-extension://'))||await context.waitForEvent('serviceworker',{predicate:worker=>worker.url().startsWith('chrome-extension://'),timeout:15000});
    extensionId=new URL(worker.url()).hostname;
    await worker.evaluate(async()=>{await chrome.alarms.clearAll();});
    control=await context.newPage();await control.goto(fabric.origin);await control.bringToFront();
  }
  await launch();
  const tick=connectionId=>until(async()=>{
    const result=await worker.evaluate(id=>poll(id),connectionId);
    return result.state==='busy'?null:result;
  },'Real extension poll remained busy',30000);
  const storage=()=>worker.evaluate(async()=>({local:await chrome.storage.local.get(['fabricConnections']),session:await chrome.storage.session.get(['fabricLeases'])}));
  const appTabs=()=>worker.evaluate(async origins=>(await chrome.tabs.query({})).filter(tab=>origins.some(origin=>tab.url?.startsWith(`${origin}/`))).map(tab=>({id:tab.id,url:tab.url,status:tab.status,active:tab.active})),APPS.map(app=>app.origin));
  const closeTab=tabId=>worker.evaluate(id=>chrome.tabs.remove(id),tabId);
  const inputValue=tabId=>worker.evaluate(async id=>(await chrome.scripting.executeScript({target:{tabId:id},func:()=>document.querySelector('#content')?.value}))[0]?.result,tabId);
  const failureDetails=async(link,job)=>`${link.definition.id}: ${job.error}; requests=${JSON.stringify(pageRequests.slice(-20))}; errors=${JSON.stringify(pageErrors)}; tabs=${JSON.stringify(await appTabs())}`;
  const linked=[];
  for(const definition of APPS) {
    const pairing=fabric.browser.createPair(definition.id);
    assert.equal(pairing.bridgeVersion,'0.3');
    const handoff=await control.evaluate(pairing=>new Promise((resolve,reject)=>{
      const requestId=crypto.randomUUID();
      const timer=setTimeout(()=>{window.removeEventListener('message',listener);reject(new Error('Fabric content-script handoff did not respond'));},10000);
      const listener=event=>{if(event.source===window&&event.data?.source==='fabric-extension'&&event.data.requestId===requestId){clearTimeout(timer);window.removeEventListener('message',listener);resolve(event.data);}};
      window.addEventListener('message',listener);window.postMessage({source:'fabric-page',type:'fabric:bridge:connect',requestId,pairing},location.origin);
    }),pairing);
    assert.equal(handoff.ok,true,handoff.error);assert.equal(handoff.confirmationOpened,true);
    const setup=await until(()=>context.pages().find(page=>page.url().startsWith(worker.url().replace('/background.js','/connect.html?'))),'Actual extension setup page did not open');
    try {await until(()=>setup.locator('#approve').isEnabled(),'Extension approval button remained disabled',5000);}
    catch(error){throw new Error(`${error.message}. Setup status: ${(await setup.locator('#status').textContent()).slice(0,500)}. Page errors: ${JSON.stringify(pageErrors)}`);}
    await setup.locator('#approve').click({timeout:5000});
    await until(()=>fabric.browser.status(pairing.pairingId).status==='paired','Actual extension approval did not pair to isolated Fabric');
    const {connectionId}=fabric.browser.status(pairing.pairingId),connection=fabric.store.get('connections',connectionId);
    assert.equal(connection.bridgeVersion,'0.3');assert.equal(connection.sessionScope,'browser-profile');
    const page=await until(()=>context.pages().find(page=>page.url().startsWith(definition.origin)),'Approval did not open synthetic app');
    await page.waitForLoadState('domcontentloaded');
    await page.evaluate(identity=>localStorage.setItem('fixture-account',identity),`Fixture session: ${definition.id}`);
    await page.reload();
    linked.push({definition,connection});
    await setup.close();await control.bringToFront();
  }
  const saved=await storage();
  assert.equal(Object.keys(saved.local.fabricConnections).length,2,'Second app must not replace the first durable grant');
  for(const {connection} of linked) {
    const grant=saved.local.fabricConnections[connection.id];
    assert.equal(grant.connectionId,connection.id);assert.equal(grant.sessionScope,'browser-profile');
    assert.equal(Object.hasOwn(grant,'tabId'),false,'Durable authority cannot use a session-scoped Chrome tab ID');
    assert.equal(fabric.browser.getConnectionEvidence(connection).account.verified,false);
  }
  for(const tab of await appTabs())await closeTab(tab.id);
  await tick();
  assert.equal((await appTabs()).length,0,'An idle connection must not manufacture a permanent app tab');
  for(const {connection} of linked) {
    const evidence=fabric.browser.getConnectionEvidence(connection);
    assert.equal(evidence.bridge.status,'alive');assert.equal(evidence.bridge.scope,'browser-profile');assert.equal(evidence.bridge.executionState,'idle');
    assert.equal(evidence.account.verified,false);
  }
  const bindings=linked.flatMap(({definition,connection})=>['observe.v1','read.v1','fill.v2','click.v2'].map(operation=>({connectionId:connection.id,capabilityId:`${definition.id}.browser.${operation}`})));
  const client=fabric.protocol.createClient({name:'Synthetic durable browser test agent',bindings});let sequence=0;
  const invoke=(method,params={},id=`durable-${++sequence}`)=>fabric.protocol.handle(`Bearer ${client.token}`,{protocol:'fabric/0.1',id,method,params});
  const request=async(link,operation,args={},id=`durable-${++sequence}`)=>{
    const capabilityId=`${link.definition.id}.browser.${operation}`,binding=client.client.bindings.find(binding=>binding.connectionId===link.connection.id&&binding.capabilityId===capabilityId);
    const response=await invoke('calls.create',{connectionId:link.connection.id,capabilityId,definitionHash:binding.definitionHash,args},id);
    assert.equal(response.error,undefined,response.error?.message);assert.equal(response.result.status,'awaiting_approval');
    return response.result;
  };
  const approve=async(link,pending)=>{
    const job=fabric.store.get('jobs',pending.id),completion=fabric.runtime.approve(job.id,job.approvalDigest);completion.catch(()=>{});
    await until(async()=>{
      const current=fabric.store.get('jobs',job.id);
      if(['succeeded','failed','uncertain'].includes(current.status))return true;
      await tick(link.connection.id);return ['succeeded','failed','uncertain'].includes(fabric.store.get('jobs',job.id).status);
    },'Real extension did not finish the approved command',35000);
    return completion;
  };
  const read=async(link,selector)=>{
    const pending=await request(link,'read.v1',{selector});const complete=await approve(link,pending);
    assert.equal(complete.status,'succeeded',complete.error);return complete.result.data;
  };
  const observe=async link=>{
    const complete=await approve(link,await request(link,'observe.v1'));
    assert.equal(complete.status,'succeeded',complete.error);return complete.result.data;
  };
  for(const link of linked) {
    const pending=await request(link,'read.v1',{selector:'#identity'});
    await tick(link.connection.id);assert.equal((await appTabs()).some(tab=>tab.url.startsWith(link.definition.origin)),false,'No execution lease before owner approval');
    const selfApproval=await invoke('calls.approve',{callId:pending.id});assert.equal(selfApproval.error.code,'method_not_found');
    const complete=await approve(link,pending);
    assert.equal(complete.status,'succeeded',complete.status==='succeeded'?undefined:await failureDetails(link,complete));assert.equal(complete.result.data.text,`Fixture session: ${link.definition.id}`);
    assert.equal(fabric.browser.getConnectionEvidence(link.connection).account.verified,false);
  }
  assert.equal((await appTabs()).length,2,'Independent approved reads reopen one temporary execution tab per app');
  const first=linked[0];
  const inspection=await observe(first),field=inspection.controls.find(control=>control.canFill&&control.label==='Content');assert.ok(field);
  const writeId='closed-tab-write',writeArgs={snapshotId:inspection.snapshotId,targetId:field.targetId,value:'Must not be replayed'};
  const pendingWrite=await request(first,'fill.v2',writeArgs,writeId);
  await closeTab((await appTabs()).find(tab=>tab.url.startsWith(first.definition.origin)).id);
  const closedWrite=await approve(first,pendingWrite);
  assert.notEqual(closedWrite.status,'succeeded');assert.match(closedWrite.error,/inspect|inspection|tab|lease|page/i);
  assert.equal((await appTabs()).some(tab=>tab.url.startsWith(first.definition.origin)),false,'Missing write lease must not open a new target');
  assert.deepEqual(await fixtures.read(first.definition),{value:'',writes:0});
  await tick(first.connection.id);assert.equal((await appTabs()).some(tab=>tab.url.startsWith(first.definition.origin)),false,'Rejected write is not replayed by polling');
  await read(first,'#stored');
  const replay=await invoke('calls.create',{connectionId:first.connection.id,capabilityId:`${first.definition.id}.browser.fill.v2`,definitionHash:client.client.bindings.find(binding=>binding.capabilityId===`${first.definition.id}.browser.fill.v2`).definitionHash,args:writeArgs},writeId);
  assert.equal(replay.result.id,closedWrite.id);assert.equal(replay.result.status,closedWrite.status);
  assert.equal(await inputValue((await appTabs()).find(tab=>tab.url.startsWith(first.definition.origin)).id),'');

  // A fresh inspection and separate owner approvals can act through the actual
  // installed extension. Independent HTTP state, not DOM dispatch, proves save.
  const fresh=await observe(first),freshField=fresh.controls.find(control=>control.canFill&&control.label==='Content');
  const fill=await approve(first,await request(first,'fill.v2',{snapshotId:fresh.snapshotId,targetId:freshField.targetId,value:'Saved through the durable helper'}));
  assert.equal(fill.status,'uncertain');assert.equal(fill.result.data.persistentEffect,'unverified');
  const beforeClick=await observe(first),button=beforeClick.controls.find(control=>control.canClick&&control.label==='Save content');assert.ok(button);
  const click=await approve(first,await request(first,'click.v2',{snapshotId:beforeClick.snapshotId,targetId:button.targetId}));
  assert.equal(click.status,'uncertain');
  await until(async()=>(await fixtures.read(first.definition)).writes===1,'Independent app server did not save');
  assert.deepEqual(await fixtures.read(first.definition),{value:'Saved through the durable helper',writes:1});

  const beforeRestart=await observe(first),restartField=beforeRestart.controls.find(control=>control.canFill&&control.label==='Content');
  const restartWrite=await request(first,'fill.v2',{snapshotId:beforeRestart.snapshotId,targetId:restartField.targetId,value:'Must not target a new browser session'});
  await control.bringToFront();
  const leasesBefore=(await storage()).session.fabricLeases;
  for(const link of linked)assert.equal(leasesBefore[link.connection.id]?.owned,true,'Reopened execution tabs are helper-owned, not user sign-in tabs');
  await worker.evaluate(async()=>{
    const {fabricLeases={}}=await chrome.storage.session.get('fabricLeases');
    for(const lease of Object.values(fabricLeases))lease.lastUsedAt=Date.now()-181000;
    await chrome.storage.session.set({fabricLeases});
  });
  await tick();
  assert.equal((await appTabs()).length,0,'Real idle cleanup retires temporary tabs while retaining connection grants');
  assert.equal(Object.keys((await storage()).local.fabricConnections).length,2);
  await context.close();context=null;
  await launch();
  const restored=await storage();
  assert.deepEqual(Object.keys(restored.local.fabricConnections).sort(),linked.map(link=>link.connection.id).sort());
  assert.equal(Object.keys(restored.session.fabricLeases||{}).length,0,'Whole browser restart drops transient tab leases');
  await tick();assert.equal((await appTabs()).length,0,'Restart recovery reconnects grants, not stale tab IDs or permanent pages');
  const stale=await approve(first,restartWrite);
  assert.notEqual(stale.status,'succeeded');assert.match(stale.error,/inspect|inspection|tab|lease|page/i);
  assert.equal((await appTabs()).length,0,'Pre-restart write must not silently create and act on a replacement tab');
  for(const link of linked) {
    const identity=await read(link,'#identity');assert.equal(identity.text,`Fixture session: ${link.definition.id}`,'Same isolated profile retains only its synthetic app session');
    assert.equal(fabric.browser.getConnectionEvidence(link.connection).account.verified,false);
  }
  assert.equal((await read(first,'#stored')).text,'Saved through the durable helper');
  assert.deepEqual(await fixtures.read(first.definition),{value:'Saved through the durable helper',writes:1});
  assert.equal(fabric.store.get('jobs',click.id).status,'uncertain','Independent fixture proof must not rewrite a generic dispatch into verified provider success');
  t.diagnostic('Actual MV3 extension in isolated Chromium; two real loopback HTTPS apps using exact host-resolver rules and a generated test-only certificate SPKI exception; real Fabric HTTP pair/poll/result; app save independently verified after browser restart. Temporary manifest/base-URL substitutions and pregranted fixture hosts only. Manual poll ticks and aged fixture-only leases exercise cleanup, not alarm scheduling. No real providers, user browser profile, account verification or LLM used.');
});

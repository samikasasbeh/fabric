import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,access} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {Store} from '../lib/store.mjs';
import {PersistentBrowser} from '../lib/persistent-browser.mjs';

// Real Chromium + on-disk profiles, but synthetic apps only. Every request is
// intercepted; these tests never use a person's account, browser, or cookies.
// Fixture logins test storage continuity, NOT real-provider compatibility.
test('real Chromium preserves three isolated app sessions through tab and runtime closure', {timeout:90000}, async t=>{
  let chromium;
  try {({chromium}=await import('playwright'));await access(chromium.executablePath());}
  catch(error){if(process.env.FABRIC_REQUIRE_BROWSER_TEST==='1')throw error;t.skip('Install the Fabric browser with npm run browser:install to run the real-browser lifecycle test.');return;}
  const dataDir=await mkdtemp(path.join(tmpdir(),'fabric-real-session-'));
  const store=new Store({dataDir}),contexts=[],profiles=[];
  const apps=['mail-fixture','notes-fixture','music-fixture'].map(id=>({id,name:id,webOrigins:[`https://${id}.fabric.test`]}));
  const html='<!doctype html><title>Fabric lifecycle fixture</title><main id="identity"></main><button id="inspect">Public control</button><input type="password" value="never-export-this"><textarea>never-export-textarea</textarea><div contenteditable>never-export-editor</div><div data-sensitive>never-export-sensitive</div><div hidden>never-export-hidden</div><script>/* never-export-script */ document.querySelector("main").textContent=localStorage.getItem("fixture-identity")||"Sign in required";</script>';
  const launch=async(profile,options)=>{
    const context=await chromium.launchPersistentContext(profile,{...options,headless:true,serviceWorkers:'block'});
    await context.route('**/*',route=>{
      const url=new URL(route.request().url());
      if(apps.some(app=>app.webOrigins.includes(url.origin)))return route.fulfill({status:200,contentType:'text/html',body:html});
      return route.abort();
    });
    contexts.push(context);profiles.push(profile);return context;
  };
  let manager=new PersistentBrowser({store,catalog:()=>apps,dataDir,launch});
  t.after(async()=>{await manager.shutdown();store.close();await rm(dataDir,{recursive:true,force:true});});
  const connections=[];
  for(const [index,app] of apps.entries()) {
    const connection=await manager.connect({appId:app.id,consent:true});connections.push(connection);
    assert.equal(connection.transport,'persistent');assert.equal(connection.expiresAt,null);
    const page=contexts.at(-1).pages().find(p=>p.url().startsWith(app.webOrigins[0]));
    assert.ok(page,'Connect opened only the dedicated fixture page');
    await contexts.at(-1).addCookies([{name:'fabric-fixture-login',value:`fixture-${index+1}`,url:app.webOrigins[0],httpOnly:true,secure:true,sameSite:'Lax',expires:Math.floor(Date.now()/1000)+3600}]);
    await page.evaluate(identity=>localStorage.setItem('fixture-identity',identity),`Fixture account ${index+1}`);
    await page.reload();
    await page.close();
    const outcome=await manager.execute(connection.id,{op:'observe'},{},()=>{});
    assert.match(JSON.stringify(outcome.data),new RegExp(`Fixture account ${index+1}`));
    assert.equal(JSON.stringify(outcome.data).includes('never-export-'),false);
    assert.ok(outcome.data.controls.some(control=>control.label==='Public control'&&control.canClick===false));
    const element=await manager.execute(connection.id,{op:'read'},{selector:'#identity'},()=>{});
    assert.equal(element.data.text,`Fixture account ${index+1}`);
    await assert.rejects(manager.execute(connection.id,{op:'read'},{selector:'textarea'},()=>{}));
    assert.equal(outcome.verification.status,'observed');
    assert.equal(manager.evidence(connection).account.verified,false);
  }
  assert.equal(new Set(profiles).size,3,'Each app has its own physical profile');
  await manager.shutdown();
  manager=new PersistentBrowser({store,catalog:()=>apps,dataDir,launch});
  for(const [index,connection] of connections.entries()) {
    const outcome=await manager.execute(connection.id,{op:'observe'},{},()=>{});
    const cookies=await contexts.at(-1).cookies(apps[index].webOrigins[0]);
    assert.equal(cookies.find(cookie=>cookie.name==='fabric-fixture-login')?.value,`fixture-${index+1}`,'Persistent HttpOnly login cookies survive a clean browser restart in the same isolated profile');
    assert.match(JSON.stringify(outcome.data),new RegExp(`Fixture account ${index+1}`));
    assert.equal(JSON.stringify(outcome.data).includes('fabric-fixture-login'),false,'Cookies are not exported through page observations');
    for(const other of [1,2,3].filter(n=>n!==index+1))assert.equal(JSON.stringify(outcome.data).includes(`Fixture account ${other}`),false);
    assert.equal(manager.evidence(connection).account.verified,false);
  }
  assert.equal(new Set(profiles).size,3,'Restarts reuse original profile directories');
  // A real sign-out changes the observed page, but never creates an account
  // verification claim or destroys the owner grant. The next read asks again.
  const firstContext=contexts[3],firstPage=firstContext.pages().find(p=>p.url().startsWith(apps[0].webOrigins[0]));
  await firstPage.evaluate(()=>localStorage.removeItem('fixture-identity'));
  await firstPage.reload();
  const loggedOut=await manager.execute(connections[0].id,{op:'observe'},{},()=>{});
  assert.match(JSON.stringify(loggedOut.data),/Sign in required/);
  assert.equal(manager.evidence(connections[0]).account.verified,false);
  for(const connection of connections) {
    await manager.revoke(connection.id);
    await assert.rejects(manager.open(connection.id),/revoked|disconnect|active/i);
    await assert.rejects(manager.execute(connection.id,{op:'observe'},{},()=>{}),/revoked|disconnect|active/i);
  }
  for(const profile of new Set(profiles))await assert.rejects(access(profile));
});

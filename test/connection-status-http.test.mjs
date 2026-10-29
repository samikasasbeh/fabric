import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createApp} from '../server.mjs';

test('runtime exposes real health schedule and browser evidence without implying account authentication',async t=>{
  const dataDir=await mkdtemp(path.join(tmpdir(),'fabric-status-http-'));
  const app=await createApp({dataDir,port:46100+Math.floor(Math.random()*300),request:async()=>{throw new Error('No external calls in this fixture.');}});
  await app.start();t.after(async()=>{await app.close();await rm(dataDir,{recursive:true,force:true});});
  const get=async route=>{const response=await fetch(app.origin+route);assert.equal(response.status,200);return response.json();};
  const initial=await get('/api/state');
  assert.equal(initial.runtime.running,true);
  assert.equal(initial.runtime.backgroundMode,'while-runtime-running');
  assert.equal(initial.runtime.healthCheck.intervalSeconds,60);
  assert.ok(Date.parse(initial.runtime.healthCheck.nextRunAt)>Date.now());
  const session=await fetch(app.origin+'/api/state'),sessionData=await session.json();
  const ownerHeaders={'Content-Type':'application/json','X-Fabric-CSRF':sessionData.csrfToken,Cookie:session.headers.get('set-cookie').split(';')[0]};
  const post=async(route,data,headers=ownerHeaders)=>{
    const response=await fetch(app.origin+route,{method:'POST',headers,body:JSON.stringify(data)});
    const result=await response.json();assert.ok(response.ok,JSON.stringify(result));return result;
  };
  for(const appId of ['slack','notion','github']) {
    const catalogApp=initial.catalog.find(a=>a.id===appId),origin=catalogApp.webOrigins[0];
    const pair=app.browser.createPair(appId),linked=app.browser.pair({code:pair.code,origin,bridgeVersion:'0.2'});
    const state=await get('/api/state'),detail=await get(`/api/connectors/${appId}`);
    for(const c of [state.connections.find(c=>c.id===linked.connection.id),detail.connections.find(c=>c.id===linked.connection.id)]) {
      assert.equal(c.browserEvidence.account.verified,false);
      assert.equal(c.browserEvidence.bridge.status,'waiting');
      assert.equal(c.browserEvidence.page.status,'not_observed');
      assert.equal(c.lifecycle.kind,'browser-tab');
      assert.equal(c.lifecycle.expiresAt,null);
      assert.equal(c.lifecycle.lastVerifiedAt,null);
      assert.equal(c.lifecycle.health.intervalSeconds,60);
      assert.equal(c.lifecycle.health.nextRunAt,state.runtime.healthCheck.nextRunAt);
      assert.equal(JSON.stringify(c).includes(linked.token),false);
    }
    app.browser.poll(linked.token);
    const refreshed=(await get('/api/state')).connections.find(c=>c.id===linked.connection.id);
    assert.equal(refreshed.browserEvidence.bridge.status,'alive');
    assert.equal(refreshed.browserEvidence.account.verified,false);
    const job=await post('/api/jobs',{connectionId:linked.connection.id,capabilityId:`${appId}.browser.observe.v1`,args:{}});
    assert.equal(job.status,'awaiting_approval');
    assert.equal(app.store.list('browserCommands').some(c=>c.connectionId===linked.connection.id),false);
    const approval=post(`/api/jobs/${job.id}/approve`,{approvalDigest:job.approvalDigest});
    let command;
    const extensionHeaders={'Content-Type':'application/json',Origin:`chrome-extension://${'a'.repeat(32)}`,Authorization:`Bearer ${linked.token}`};
    for(let i=0;i<100&&!command;i++){
      command=(await post('/api/browser/poll',{},extensionHeaders)).command;
      if(!command)await new Promise(resolve=>setTimeout(resolve,5));
    }
    assert.ok(command,'Approved job must be delivered to the exact paired helper');
    await post('/api/browser/result',{id:command.id,ok:true,data:{origin,title:'Fixture sign-in page',text:'PRIVATE_FIXTURE_PAGE_CONTENT',controls:[]}},extensionHeaders);
    const completed=await approval;assert.equal(completed.status,'succeeded');
    assert.equal(completed.result.verification.status,'observed');
    const proof=await get('/api/status'),observed=proof.connections.find(c=>c.id===linked.connection.id);
    assert.equal(observed.browserEvidence.page.status,'observed');
    assert.equal(observed.browserEvidence.account.verified,false);
    assert.equal(JSON.stringify(proof).includes('PRIVATE_FIXTURE_PAGE_CONTENT'),false);
    assert.equal(proof.agent.alwaysOnAgent,false);
    app.connections.revoke(linked.connection.id);
    assert.equal((await get('/api/connectors/'+appId)).connections.find(c=>c.id===linked.connection.id).browserEvidence.bridge.status,'revoked');
  }
  const heartbeat=app.store.list('heartbeats')[0];app.heartbeats.setEnabled(heartbeat.id,false);
  const paused=await get('/api/state');
  assert.equal(paused.runtime.healthCheck.enabled,false);
  assert.equal(paused.runtime.healthCheck.nextRunAt,null);
  assert.ok(paused.connections.every(c=>c.lifecycle.health.enabled===false));
});

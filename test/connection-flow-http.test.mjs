import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {createApp} from '../server.mjs';

// Only loopback HTTP and isolated temporary storage are real. The explicit
// extension-pair request below is a test fixture, not a user's browser/account.
test('consumer connection methods and exact browser setup progress work through real HTTP routes',async t=>{
  const dataDir=await mkdtemp(path.join(tmpdir(),'fabric-connection-flow-http-'));
  let providerRequests=0;
  const app=await createApp({dataDir,port:44200+Math.floor(Math.random()*250),request:async()=>{providerRequests++;throw new Error('This connection-flow fixture must never contact a provider.');}});
  app.oauth.clientId='';app.oauth.clientSecret='';
  await app.start();t.after(async()=>{await app.close();await rm(dataDir,{recursive:true,force:true});});
  const boot=await fetch(app.origin+'/api/state'),state=await boot.json(),cookie=boot.headers.get('set-cookie').split(';')[0];
  const request=async(route,{method='GET',data,headers={},expected=200}={})=>{
    const response=await fetch(app.origin+route,{method,headers:{Cookie:cookie,...(method==='POST'?{'Content-Type':'application/json','X-Fabric-CSRF':state.csrfToken}:{}),...headers},...(data!==undefined?{body:JSON.stringify(data)}:{})});
    const result=await response.json();assert.equal(response.status,expected,JSON.stringify(result));return result;
  };
  const post=(route,data,expected=200)=>request(route,{method:'POST',data,expected});

  for(const id of ['github','notion','slack','x','facebook']) {
    const entry=state.catalog.find(a=>a.id===id),primary=entry.connectionOptions.find(option=>option.recommended);
    assert.equal(primary.method,'browser');assert.equal(primary.kind,'consumer');assert.equal(primary.label,'Use in your browser');
    assert.equal(entry.connectionOptions.some(option=>option.recommended&&option.method==='token'),false);
    for(const token of entry.connectionOptions.filter(option=>option.method==='token')) assert.equal(token.kind,'advanced');
    const detail=await request(`/api/connectors/${id}`);assert.deepEqual(detail.app.connectionOptions,entry.connectionOptions);
  }
  const gmail=state.catalog.find(a=>a.id==='gmail'),google=gmail.connectionOptions.find(option=>option.method==='oauth');
  assert.equal(google.availability,'setup_required');assert.equal(google.enabled,false);
  assert.equal(gmail.connectionOptions.find(option=>option.recommended).method,'browser');
  app.oauth.clientId='fixture-client';app.oauth.clientSecret='fixture-secret';
  const configured=await request('/api/state'),configuredGoogle=configured.catalog.find(a=>a.id==='gmail').connectionOptions.find(option=>option.recommended);
  assert.equal(configuredGoogle.method,'oauth');assert.equal(configuredGoogle.availability,'available');
  assert.equal(JSON.stringify(configured).includes('fixture-secret'),false);

  await post('/api/applications',{id:'web-only-fixture',name:'Web fixture',webOrigins:['https://app.fixture.example'],apiOrigins:[]},201);
  const custom=await request('/api/connectors/web-only-fixture');
  assert.equal(custom.app.connectionOptions.length,1);
  assert.deepEqual(custom.app.connectionOptions[0].action,{method:'POST',path:'/api/pair',body:{appId:'web-only-fixture'}});
  const first=await post('/api/pair',{appId:'web-only-fixture'},201),second=await post('/api/pair',{appId:'web-only-fixture'},201);
  const firstPath=`/api/pair/${first.pairingId}/status`,secondPath=`/api/pair/${second.pairingId}/status`;
  const pending=await request(firstPath);assert.equal(pending.status,'pending');assert.equal(pending.connectionId,undefined);
  assert.equal(JSON.stringify(pending).includes(first.code),false);
  await request(`/api/pair/${randomUUID()}/status`,{expected:400});
  await request(firstPath,{headers:{Origin:'https://outside.example'},expected:400});
  await request(firstPath,{headers:{'Sec-Fetch-Site':'cross-site'},expected:400});
  const extensionOrigin=`chrome-extension://${'a'.repeat(32)}`;
  await request('/api/browser/poll',{method:'POST',data:{},headers:{Origin:extensionOrigin,Authorization:`Bearer ${first.pairingId}`},expected:401});
  await request('/api/browser/pair',{method:'POST',data:{code:first.pairingId,origin:'https://app.fixture.example'},headers:{Origin:extensionOrigin},expected:400});
  await request('/api/browser/pair',{method:'POST',data:{code:second.code,origin:'https://wrong.fixture.example'},headers:{Origin:extensionOrigin},expected:400});
  assert.equal((await request(secondPath)).status,'pending');

  const linked=await request('/api/browser/pair',{method:'POST',data:{code:second.code,origin:'https://app.fixture.example',label:'Explicit fixture browser tab'},headers:{Origin:extensionOrigin},expected:201});
  assert.equal(typeof linked.token,'string');assert.equal(linked.connection.driver,'browser');
  const paired=await request(secondPath);assert.equal(paired.status,'paired');assert.equal(paired.connectionId,linked.connection.id);assert.equal(paired.connectionStatus,'session_ready');
  const stillPending=await request(firstPath);assert.equal(stillPending.status,'pending');assert.equal(stillPending.connectionId,undefined);
  const after=await request('/api/state'),detail=await request('/api/connectors/web-only-fixture');
  for(const response of [paired,stillPending,after,detail]) {
    assert.equal(JSON.stringify(response).includes(linked.token),false);
    assert.equal(JSON.stringify(response).includes(first.code),false);
    assert.equal(JSON.stringify(response).includes(second.code),false);
  }
  await request('/api/browser/pair',{method:'POST',data:{code:second.code,origin:'https://app.fixture.example'},headers:{Origin:extensionOrigin},expected:400});
  await post(`/api/connections/${linked.connection.id}/revoke`,{});
  assert.equal((await request(secondPath)).status,'revoked');
  assert.equal(providerRequests,0);
});

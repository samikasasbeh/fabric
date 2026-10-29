import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {createApp} from '../server.mjs';
import http from 'node:http';

test('real loopback product: CSRF, catalog import, approved execution, and persistent restart',async t=>{
  const dir=await mkdtemp(path.join(tmpdir(),'fabric-http-'));const port=42880+Math.floor(Math.random()*300);let app=await createApp({dataDir:dir,port});await app.start();t.after(async()=>{await app.close();await rm(dir,{recursive:true,force:true});});
  const base=`http://127.0.0.1:${port}`;const boot=await fetch(`${base}/api/state`);const cookie=boot.headers.get('set-cookie').split(';')[0];const state=await boot.json();assert.equal(state.catalog.length>=7,true);assert.equal(state.heartbeats.length,1);
  let csrf=state.csrfToken;let sessionCookie=cookie;
  const post=async(route,data)=>{const response=await fetch(`${base}${route}`,{method:'POST',headers:{'Content-Type':'application/json','X-Fabric-CSRF':csrf,Cookie:sessionCookie},body:JSON.stringify(data)});const body=await response.json();assert.equal(response.ok,true,JSON.stringify(body));return body;};
  assert.equal((await fetch(`${base}/api/connections/local`,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})).status,403);
  assert.equal((await fetch(`${base}/api/state`,{headers:{Origin:'https://evil.example'}})).status,400);
  const wrongHost=await new Promise((resolve,reject)=>{http.get(`${base}/api/state`,{headers:{Host:`evil.example:${port}`}},res=>{res.resume();resolve(res.statusCode);}).on('error',reject);});assert.equal(wrongHost,403);
  const c=await post('/api/connections/local',{});const j=await post('/api/jobs',{connectionId:c.id,capabilityId:'workspace.write.v1',args:{path:'http-test.txt',content:'Persistent integration proof'}});assert.equal(j.status,'awaiting_approval');
  const done=await post(`/api/jobs/${j.id}/approve`,{approvalDigest:j.approvalDigest});assert.equal(done.status,'succeeded');assert.equal(done.result.verification.status,'verified');
  const document=JSON.parse(await readFile(new URL('../examples/google-calendar.openapi.json',import.meta.url),'utf8'));const imported=await post('/api/import',{appId:'google-calendar',document});assert.equal(imported.capabilities.length>=4,true);assert.equal(imported.capabilities.every(c=>c.status==='candidate'),true);
  const h=await post('/api/heartbeats',{name:'Integration heartbeat',intervalSeconds:30,connectionId:c.id,capabilityId:'workspace.list.v1',args:{}});app.heartbeats.clock=()=>Date.now()+31000;await app.heartbeats.tick();assert.equal(app.store.get('heartbeats',h.id).runs,1);
  await app.close();app=await createApp({dataDir:dir,port});await app.start();const reboot=await fetch(`${base}/api/state`);const re=await reboot.json();assert.equal(re.connections.some(x=>x.id===c.id),true);assert.equal(re.jobs.find(x=>x.id===j.id).status,'succeeded');assert.equal(re.heartbeats.find(x=>x.id===h.id).runs,1);
  assert.equal(JSON.stringify(re).includes('accessToken'),false);assert.equal(re.capabilities.some(x=>x.id===imported.capabilities[0].id),true);
});

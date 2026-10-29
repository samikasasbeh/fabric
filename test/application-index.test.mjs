import test from 'node:test';
import assert from 'node:assert/strict';
import {ApplicationIndex,INDEX_SOURCES,publicMetadataUrl,specificationOrigins} from '../lib/application-index.mjs';
import {ConnectorResolver} from '../lib/connector-resolver.mjs';

const googleItem=(overrides={})=>({kind:'discovery#directoryItem',name:'sample',version:'v1',title:'Sample API',description:'Sample <b>public metadata</b>',documentationLink:'https://developers.google.com/sample/',discoveryRestUrl:'https://sample.googleapis.com/$discovery/rest?version=v1',icons:{x32:'https://www.gstatic.com/sample.png'},...overrides});
const google=(items=[googleItem()])=>({kind:'discovery#directoryList',items});
const guruItem=(overrides={})=>({preferred:'1.0',versions:{'1.0':{info:{title:'Sample Service',description:'Public directory identity',contact:{url:'https://support.example.com/contact'},'x-providerName':'example.com','x-logo':{url:'https://cdn.example.com/logo.png'}},externalDocs:{url:'https://docs.example.com/'},swaggerUrl:'https://api.apis.guru/v2/specs/example.com/1.0/openapi.json',openapiVer:'3.0.3',...overrides}}});
const guru=(value=guruItem())=>({'example.com':value});
const googleSpec={kind:'discovery#restDescription',protocol:'rest',name:'sample',version:'v1',rootUrl:'https://sample.googleapis.com/',servicePath:'v1/',resources:{}};
const openapi={openapi:'3.0.3',info:{title:'Sample Service',version:'1.0'},servers:[{url:'https://api.example.com/v1'}],paths:{}};
function fixture({googleData=google(),guruData=guru(),spec=openapi,override,now:initialNow=1700000000000}={}){
  const records=new Map(),requests=[],audits=[];let now=initialNow;
  const store={get:(type,id)=>records.get(`${type}:${id}`),put:(type,value)=>{records.set(`${type}:${value.id}`,structuredClone(value));return value;},list:type=>[...records].filter(([key])=>key.startsWith(`${type}:`)).map(([,value])=>value),audit:value=>audits.push(value)};
  const request=async options=>{requests.push(options);if(override)return override(options);return {status:200,data:options.url===INDEX_SOURCES[0].url?googleData:options.url===INDEX_SOURCES[1].url?guruData:options.url.includes('googleapis.com')?googleSpec:spec};};
  const index=new ApplicationIndex({store,request,now:()=>now});
  const resolver=new ConnectorResolver({store,catalog:()=>store.list('applications'),request,index});
  return {index,resolver,records,requests,store,request,audits,advance:ms=>now+=ms,now:()=>now};
}

test('explicit lookup reads public directories once and returns source-attributed candidates without fetching specs, logos, or accounts',async()=>{
  const f=fixture(),result=await f.index.lookup('Sample');assert.equal(result.status,'candidates');assert.equal(result.ambiguous,true);assert.equal(result.candidates.length,2);assert.equal(result.index.accountAuthority,false);assert.equal(f.requests.length,2);
  for(const candidate of result.candidates){assert.equal(candidate.accountConnected,false);assert.equal(candidate.website,null);assert.equal(candidate.logoUrl,undefined);assert.match(candidate.iconUrl,/^\/api\/catalog\/icons\/idx-/);assert.ok(candidate.publisher.domain);assert.ok(candidate.documentationUrl);assert.equal(candidate.indexStale,false);}
  assert.deepEqual(new Set(result.candidates.map(item=>item.source.kind)),new Set(['official-directory','community-directory']));
  for(const [i,request]of f.requests.entries()){assert.equal(request.method,'GET');assert.deepEqual(request.headers,{Accept:'application/json'});assert.deepEqual(request.allowedOrigins,[new URL(INDEX_SOURCES[i].url).origin]);assert.equal(request.maxBytes,INDEX_SOURCES[i].maxBytes);assert.equal(request.timeoutMs,30000);assert.equal(request.body,undefined);}
  assert.equal(f.store.list('connections').length,0);assert.equal(f.store.list('applications').length,0);assert.equal(f.store.list('capabilities').length,0);await f.index.lookup('different');assert.equal(f.requests.length,2);
});
test('lookup never invents domains, renders metadata as plain bounded text, and distinguishes no match from missing directories',async()=>{
  const f=fixture({googleData:google([googleItem({title:'<script>markup</script> Sample API',description:'x'.repeat(800)})])});
  const result=await f.resolver.lookup('Never Listed Application');assert.equal(result.status,'not_found');assert.deepEqual(result.candidates,[]);assert.match(result.message,/no domain was guessed/);assert.equal(f.requests.length,2);
  const candidate=(await f.index.lookup('Sample')).candidates.find(item=>item.source.id==='google-discovery');assert.equal(candidate.name.includes('<'),false);assert.equal(candidate.description.length,500);
  const failed=fixture({override:async()=>{throw new Error('network or credential=do-not-expose');}});const missing=await failed.index.lookup('Sample');assert.equal(missing.status,'not_found');assert.ok(missing.index.sources.every(item=>item.status==='unavailable'));assert.equal(JSON.stringify(missing).includes('do-not-expose'),false);
  for(const invalid of [null,42,'','x'.repeat(501)])await assert.rejects(f.index.lookup(invalid),/Enter an application/);assert.equal(f.requests.length,2);
});
test('directory refreshes coalesce and use persisted TTL caches across restarts; outages retain stale identities with backoff',async()=>{
  const f=fixture();await Promise.all([f.index.lookup('Sample'),f.index.lookup('Sample')]);assert.equal(f.requests.length,2);
  const restarted=new ApplicationIndex({store:f.store,request:f.request,now:f.now});await restarted.lookup('Sample');assert.equal(f.requests.length,2);
  f.advance(24*60*60_000+1);restarted.request=async()=>{throw new Error('offline');};const stale=await restarted.lookup('Sample');assert.equal(stale.candidates.length,2);assert.ok(stale.candidates.every(item=>item.indexStale));assert.ok(stale.index.sources.every(item=>item.error&&item.status==='stale'));
  let attempts=0;restarted.request=async options=>{attempts++;return f.request(options);};await restarted.lookup('Sample');assert.equal(attempts,0);f.advance(5*60_000+1);const refreshed=await restarted.lookup('Sample');assert.equal(attempts,2);assert.ok(refreshed.candidates.every(item=>!item.indexStale));
});
test('malformed, oversized, private or wrong-source directory metadata does not become an application identity',async()=>{
  const f=fixture({googleData:google([googleItem(),googleItem({name:'private',discoveryRestUrl:'https://127.0.0.1/spec.json'}),googleItem({name:'forged',discoveryRestUrl:'https://evil.example.com/discovery.json'})]),guruData:{'example.com':guruItem(),'bad.example.com':guruItem({swaggerUrl:'https://evil.example.com/openapi.json'})}});
  await f.index.lookup('Sample');assert.equal(f.index.status().sources[0].count,1);assert.equal(f.index.status().sources[0].skipped,2);assert.equal(f.index.status().sources[1].count,1);assert.equal(f.index.status().sources[1].skipped,1);
  for(const data of [[],{kind:'wrong',items:[]},google(Array(5001).fill(googleItem())),{...google(),padding:'x'.repeat(2*1024*1024)}]){const bad=fixture({googleData:data});await bad.index.lookup('Sample');assert.equal(bad.index.status().sources[0].status,'unavailable');assert.equal(bad.index.status().sources[1].status,'ready');}
});
test('preferred versions and stable candidate IDs deduplicate identities and cap ambiguous results',async()=>{
  const items=Array.from({length:35},(_,i)=>googleItem({name:`service${i}`,title:`Service ${i}`}));items.push(items[0]);const f=fixture({googleData:google(items)});const result=await f.index.lookup('Service');assert.equal(result.candidates.length,30);assert.equal(f.index.status().sources[0].count,35);
  const id=result.candidates[0].id;assert.equal(f.index.get(id).id,id);assert.throws(()=>f.index.get('../secret'),/Choose an application/);assert.throws(()=>f.index.candidates('x',{limit:31}),/Invalid candidate/);
  const exact=await f.index.lookup('Service 10');assert.equal(exact.candidates[0].name,'Service 10');
});
test('selection fetches only the selected spec, derives actual declared API origins, and never treats docs as an app login or account',async()=>{
  const f=fixture(),candidates=(await f.index.lookup('Sample')).candidates;const chosen=candidates.find(item=>item.source.id==='apis-guru');const result=await f.resolver.select(chosen.id);
  assert.equal(f.requests.length,3);assert.equal(f.requests[2].url,chosen.discovery.url);assert.equal(f.requests[2].maxBytes,2*1024*1024);assert.equal(result.created,true);assert.deepEqual(result.app.apiOrigins,['https://api.example.com']);assert.deepEqual(result.app.webOrigins,[]);assert.equal(result.app.website,null);assert.equal(result.plan.recommended,null);assert.equal(result.plan.connectionEstablished,false);assert.equal(result.app.discoveryEvidence.accountVerified,false);assert.match(result.app.discoveryEvidence.specificationFingerprint,/^[a-f0-9]{64}$/);assert.equal(result.capabilityDiscovery.supported,true);
  assert.equal(f.store.list('connections').length,0);assert.equal(f.store.list('capabilities').length,0);assert.equal(f.store.list('applications').length,1);assert.equal((await f.resolver.select(chosen.id)).created,false);assert.equal(f.requests.length,3);
});
test('Google selected source/version is validated and only actual Google spec base URLs are adopted',async()=>{
  const f=fixture(),chosen=(await f.index.lookup('Sample')).candidates.find(item=>item.source.id==='google-discovery');const result=await f.resolver.select(chosen.id);assert.equal(f.requests[2].url,'https://sample.googleapis.com/$discovery/rest?version=v1');assert.deepEqual(result.app.apiOrigins,['https://sample.googleapis.com']);assert.equal(result.app.discovery.kind,'google-discovery');
  for(const mutation of [{name:'different'},{version:'v2'},{protocol:'rpc'},{kind:'wrong'}]){const bad=fixture();const c=(await bad.index.lookup('Sample')).candidates.find(item=>item.source.id==='google-discovery');bad.index.request=async()=>({status:200,data:{...googleSpec,...mutation}});await assert.rejects(bad.resolver.select(c.id),/does not match/);assert.equal(bad.store.list('applications').length,0);}
});
test('an explicit directory-published website is preserved while contact and documentation pages are not guessed as sign-in URLs',async()=>{
  const published=guruItem();published.versions['1.0'].info['x-website']='https://app.example.com/start';const f=fixture({guruData:guru(published)}),chosen=(await f.index.lookup('Sample')).candidates.find(item=>item.source.id==='apis-guru');assert.equal(chosen.website,'https://app.example.com/start');assert.equal(chosen.publisher.evidenceField,'info.x-website');assert.equal(chosen.publisher.verification,'directory-reported');
  const result=await f.resolver.select(chosen.id);assert.deepEqual(result.app.webOrigins,['https://app.example.com']);assert.equal(result.plan.recommended,'browser');assert.equal(result.plan.connectionEstablished,false);
});
test('spec inspection does not execute schema strings and reports unsupported or undeclared server routes honestly',()=>{
  for(const url of ['/v1','https://{tenant}.example.com','http://api.example.com','https://127.0.0.1','https://private.local','https://api.example.com/?token=x']){const result=specificationOrigins({...openapi,servers:[{url}]},'openapi');assert.deepEqual(result.apiOrigins,[]);assert.equal(result.supported,false);assert.ok(result.gaps.length);}
  const result=specificationOrigins({...openapi,servers:[{url:'https://api.example.com/v1'}],paths:{'/thing':{servers:[{url:'https://regional.example.com/'}],post:{servers:[{url:'https://api.example.com/v2'}]}}}},'openapi');assert.deepEqual(result.apiOrigins,['https://api.example.com','https://regional.example.com']);
  const old=specificationOrigins({swagger:'2.0',host:'legacy.example.com',schemes:['https'],basePath:'/v2'},'openapi');assert.deepEqual(old.apiOrigins,['https://legacy.example.com']);assert.equal(old.supported,false);assert.match(old.gaps[0],/OpenAPI 3 only/);
  assert.equal(specificationOrigins({...openapi,servers:[]},'openapi').supported,false);assert.throws(()=>specificationOrigins({...openapi,servers:Array(51).fill({url:'https://api.example.com'})},'openapi'),/too many/);
});
test('specification size/format bounds and failed fetches preserve the identity but never register or connect an application',async()=>{
  for(const document of ['not-json',{}, {...openapi,padding:'x'.repeat(2*1024*1024)}]){const f=fixture({spec:document}),chosen=(await f.index.lookup('Sample')).candidates.find(item=>item.source.id==='apis-guru');await assert.rejects(f.resolver.select(chosen.id));assert.equal(f.store.list('applications').length,0);assert.equal(f.store.list('connections').length,0);assert.ok(f.index.get(chosen.id));}
});
test('metadata URL validation permits versioned public links but rejects credential-bearing, local, and executable destinations',()=>{
  assert.equal(publicMetadataUrl('https://cdn.example.com/logo.png?v=1&size=32').hostname,'cdn.example.com');
  for(const value of ['javascript:alert(1)','file:///etc/passwd','https://[::1]/','https://2130706433/','https://x.local/','https://x.internal/','https://x.example.com./','https://x.example.com:8443/','https://u:p@x.example.com','https://x.example.com/?api_key=secret','https://{tenant}.example.com','https://x.example.com/#token','https://x.example.com/a b'])assert.throws(()=>publicMetadataUrl(value),undefined,value);
});
test('candidate logos are loaded lazily via local endpoints, cached and never become account evidence',async()=>{
  const f=fixture(),chosen=(await f.index.lookup('Sample')).candidates.find(item=>item.source.id==='apis-guru');assert.equal(f.requests.length,2);assert.match(chosen.iconUrl,/^\/api\/catalog\/icons\//);
  const requests=[],png=Buffer.from([137,80,78,71,13,10,26,10,0]);f.resolver.request=async options=>{requests.push(options);return {status:200,data:png};};const image=await f.resolver.candidateIcon(chosen.id);assert.equal(image.type,'image/png');assert.equal(requests[0].url,'https://cdn.example.com/logo.png');assert.deepEqual(Object.keys(requests[0].headers),['Accept']);await f.resolver.candidateIcon(chosen.id);assert.equal(requests.length,1);assert.equal(f.store.list('applications').length,0);assert.equal(f.store.list('connections').length,0);
});

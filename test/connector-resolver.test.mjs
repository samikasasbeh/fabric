import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import {ConnectorResolver,websiteUrl,planConnection,publisherIconLinks} from '../lib/connector-resolver.mjs';
import {createSafeRequester} from '../lib/network.mjs';

function fixture({apps=[],request=async()=>{throw new Error('Unexpected request');}}={}){
  const records=new Map(),audits=[];
  const store={put:(type,item)=>{records.set(`${type}:${item.id}`,item);return item;},audit:value=>audits.push(value)};
  const catalog=()=>[...apps,...[...records].filter(([key])=>key.startsWith('applications:')).map(([,value])=>value)];
  return {resolver:new ConnectorResolver({store,catalog,request}),records,audits,catalog};
}
const html=(data='<title>Fixture application</title>',headers={})=>({status:200,data,headers:{'content-type':'text/html; charset=utf-8',...headers}});
const app={id:'fixture',name:'Fixture',webOrigins:['https://app.example.com']};

test('website input canonicalizes real HTTPS URLs but refuses credentials, private literals and non-web schemes',()=>{
  assert.equal(websiteUrl('docs.example.com/help').href,'https://docs.example.com/help');assert.equal(websiteUrl('https://DOCS.example.com:443/').origin,'https://docs.example.com');
  for(const value of ['http://public.example.com','https://user:secret@public.example.com','https://public.example.com:8443','https://public.example.com/?token=secret','https://public.example.com/#secret','127.0.0.1','127.1','2130706433','0x7f000001','https://[::1]','https://[::ffff:127.0.0.1]','localhost','printer.local','app.internal','service.localhost','example.test','x.invalid','javascript:alert(1)','file:///etc/passwd'])assert.throws(()=>websiteUrl(value),undefined,value);
});
test('unknown application names require a website without guessed DNS requests or fake connections',async()=>{
  let requests=0;const {resolver,records}=fixture({request:async()=>{requests++;return html();}});
  const result=await resolver.resolve('Unfamiliar Application');assert.equal(result.status,'website_required');assert.equal(result.app,null);assert.equal(requests,0);assert.equal(records.size,0);
  for(const value of ['',null,42,'x'.repeat(501)])await assert.rejects(resolver.resolve(value),/Enter an application/);
});
test('known aliases and existing origins resolve without contacting the provider',async()=>{
  const {resolver}=fixture({apps:[{id:'x',name:'X',webOrigins:['https://x.com']},app]});
  const twitter=await resolver.resolve('Twitter');assert.equal(twitter.app.id,'x');assert.equal(twitter.created,false);assert.equal(twitter.plan.connectionEstablished,false);
  const existing=await resolver.resolve('https://app.example.com/path');assert.equal(existing.app.id,app.id);assert.equal(existing.created,false);
  assert.equal(resolver.search('Twitter')[0].id,'x');assert.equal(resolver.search('Fixture')[0].id,'fixture');
});
test('website registration uses observed final origin and text-only title, never claims an authenticated account',async()=>{
  const requests=[];const {resolver,records}=fixture({request:async options=>{requests.push(options);return options.url.includes('start.example.com')?{status:302,headers:{location:'https://app.example.com/home','set-cookie':'secret'},data:null}:html('<title>Fixture &amp; App <img src=x onerror=evil()>\n</title>');}});
  const result=await resolver.resolve('https://start.example.com');assert.equal(result.created,true);assert.equal(result.app.name,'Fixture & App');assert.deepEqual(result.app.webOrigins,['https://app.example.com']);assert.deepEqual(result.app.apiOrigins,[]);assert.equal(result.app.discoveryEvidence.accountVerified,false);assert.equal(result.plan.connectionEstablished,false);assert.equal(records.size,1);
  assert.equal(requests.length,2);for(const [index,request] of requests.entries()){assert.equal(request.method,'GET');assert.deepEqual(Object.keys(request.headers),['Accept']);assert.deepEqual(request.allowedOrigins,[index?'https://app.example.com':'https://start.example.com']);assert.equal(request.allowRedirectResponse,true);assert.equal(request.maxBytes,512*1024);assert.equal(request.body,undefined);}
});
test('API JSON and non-HTML pages are rejected rather than fabricated into web connectors',async()=>{
  for(const response of [{status:200,data:{title:'Not HTML'},headers:{'content-type':'application/json'}},{status:200,data:'<title>JSON header</title>',headers:{'content-type':'application/json'}},{status:200,data:'plain',headers:{'content-type':'text/plain'}}]){
    const {resolver,records}=fixture({request:async()=>response});await assert.rejects(resolver.resolve('public.example.com'),/not a web application page/);assert.equal(records.size,0);
  }
});
test('redirects to an existing origin and repeated/concurrent website resolves deduplicate registered applications',async()=>{
  const known=fixture({apps:[app],request:async()=>({status:302,headers:{location:'https://app.example.com'},data:null})});
  // The final HTML is read before identifying a known redirected origin.
  known.resolver.request=async options=>options.url.includes('start.example.com')?{status:302,headers:{location:'https://app.example.com'},data:null}:html();
  assert.equal((await known.resolver.resolve('start.example.com')).app.id,'fixture');assert.equal(known.records.size,0);
  const fresh=fixture({request:async()=>html()});const results=await Promise.all([fresh.resolver.resolve('new.example.com'),fresh.resolver.resolve('new.example.com')]);
  assert.equal(fresh.records.size,1);assert.deepEqual(results.map(r=>r.created).sort(),[false,true]);assert.equal(results[0].app.id,results[1].app.id);assert.equal((await fresh.resolver.resolve('new.example.com')).created,false);
});
test('every redirect destination is revalidated and bounded before another request is attempted',async()=>{
  for(const location of ['http://other.example.com','https://localhost','https://169.254.169.254/','https://user:secret@other.example.com','https://other.example.com:8443','https://other.example.com/?token=secret']){
    let calls=0;const {resolver}=fixture({request:async()=>{calls++;return {status:302,headers:{location},data:null};}});await assert.rejects(resolver.resolve('start.example.com'));assert.equal(calls,1);
  }
  let calls=0;const loop=fixture({request:async()=>{calls++;return {status:302,headers:{location:'/again'},data:null};}});await assert.rejects(loop.resolver.resolve('loop.example.com'),/too many/);assert.equal(calls,4);
  const missing=fixture({request:async()=>({status:302,headers:{},data:null})});await assert.rejects(missing.resolver.resolve('start.example.com'),/without a destination/);
});
test('DNS is checked and pinned independently on each discovery redirect hop',async()=>{
  const lookups=[],transports=[];
  const request=createSafeRequester({lookup:async hostname=>{lookups.push(hostname);return [{address:hostname==='public.example.com'?'8.8.8.8':'127.0.0.1',family:4}];},transport:(url,options,callback)=>{
    transports.push(url.hostname);const req=new EventEmitter();req.destroy=()=>{req.destroyed=true;};req.end=()=>queueMicrotask(()=>{const res=new PassThrough();res.statusCode=302;res.headers={location:'https://rebound.example.com/'};callback(res);res.end();});return req;
  }});
  const {resolver,records}=fixture({request});await assert.rejects(resolver.resolve('public.example.com'),/Private or reserved/);assert.deepEqual(lookups,['public.example.com','rebound.example.com']);assert.deepEqual(transports,['public.example.com']);assert.equal(records.size,0);
});
test('connection plans distinguish implemented routes from unavailable OAuth and never establish an account',()=>{
  const google={id:'gmail',webOrigins:['https://mail.google.com']};assert.equal(planConnection(google).routes[0].available,false);assert.equal(planConnection(google).recommended,'browser');assert.equal(planConnection(google,{googleOAuthConfigured:true}).recommended,'oauth');
  assert.equal(planConnection({id:'local-device'}).recommended,'device');assert.match(planConnection({id:'local-device'}).routes[0].limitation,/Inventory only/);assert.equal(planConnection({id:'unsupported'}).recommended,null);
});
test('icons use raster magic instead of remote Content-Type, with bounded request and hourly cache',async()=>{
  const images=[['image/png',Buffer.from([137,80,78,71,13,10,26,10,0])],['image/x-icon',Buffer.from([0,0,1,0,1,0,0])],['image/jpeg',Buffer.from([255,216,255,224])],['image/webp',Buffer.from('RIFF0000WEBPx')]];
  for(const [type,data] of images){let calls=0;const {resolver}=fixture({apps:[{...app,metadataLogoUrl:'https://cdn.example.com/published.png'}],request:async options=>{calls++;assert.equal(options.responseType,'buffer');assert.equal(options.maxBytes,128*1024);assert.ok(options.timeoutMs>0&&options.timeoutMs<=3000);assert.equal(options.url,'https://cdn.example.com/published.png');return {status:200,headers:{'content-type':'image/svg+xml'},data};}});
    const first=await resolver.icon('fixture'),second=await resolver.icon('fixture');assert.equal(first.type,type);assert.deepEqual(first.data,data);assert.equal(second,first);assert.equal(calls,1);assert.ok(first.expires>Date.now());
    first.expires=0;await resolver.icon('fixture');assert.equal(calls,2);
  }
});
test('icons coalesce in-flight reads and return only a local static fallback for SVG, unknown bytes, or failures',async()=>{
  let calls=0,finish;const {resolver}=fixture({apps:[app],request:()=>{calls++;return calls===1?new Promise(resolve=>{finish=resolve;}):Promise.resolve({status:200,data:Buffer.from('not an image')});}});
  const first=resolver.icon('fixture'),second=resolver.icon('fixture');assert.equal(calls,1);finish({status:200,headers:{'content-type':'image/svg+xml'},data:Buffer.from('<svg onload="evil()"><script>evil()</script></svg>')});
  const [a,b]=await Promise.all([first,second]);assert.equal(a,b);assert.equal(a.type,'image/svg+xml');assert.equal(a.data.toString().includes('evil'),false);assert.equal(resolver.inflight.size,0);
  for(const response of [()=>({status:200,data:Buffer.from('not-an-image'),headers:{'content-type':'image/png'}}),()=>{throw new Error('private network');}]){const f=fixture({apps:[app],request:async()=>response()});assert.equal((await f.resolver.icon('fixture')).type,'image/svg+xml');}
  const local=fixture({apps:[{id:'workspace'}]});assert.equal((await local.resolver.icon('workspace')).type,'image/svg+xml');await assert.rejects(local.resolver.icon('missing'),/not found/);
});
test('publisher icon discovery reads only bounded declared raster links, never base tags, script text or private URLs',()=>{
  const page='https://app.example.com/product/home';
  const links=publisherIconLinks(`<base href="https://wrong.example.com/"><script>const x='<link rel="icon" href="https://evil.example.com/icon.png">'</script><!-- <link rel="icon" href="https://comment.example.com/icon.png"> --><link rel="stylesheet" href="/style.css"><link rel="icon" href="/vector.svg"><link rel="icon" type="image/svg+xml" href="/looks.png"><link rel="icon" href="http://insecure.example.com/icon.png"><link rel="icon" href="https://127.0.0.1/icon.png"><link rel="icon" href="https://cdn.example.com/i.png?access_token=secret"><link rel="apple-touch-icon" href="./touch.png?v=2&amp;size=32"><link rel="shortcut icon" href='//cdn.example.com/icon.png'><link rel=icon href=/simple.ico><link rel=icon href=/fourth.png>`,page);
  assert.deepEqual(links,['https://app.example.com/product/touch.png?v=2&size=32','https://cdn.example.com/icon.png','https://app.example.com/simple.ico']);
  assert.deepEqual(publisherIconLinks('x'.repeat(512*1024+1),page),[]);
});
test('icons use the actual publisher HTML link and validate cross-origin redirects without forwarding authority',async()=>{
  const requests=[],png=Buffer.from([137,80,78,71,13,10,26,10,0]);
  const {resolver}=fixture({apps:[app],request:async options=>{requests.push(options);if(options.url==='https://app.example.com/')return html('<link rel="icon" href="https://cdn.example.com/brand.png?v=3">');if(options.url==='https://cdn.example.com/brand.png?v=3')return {status:302,data:null,headers:{location:'https://assets.example.com/logo.png','set-cookie':'do-not-forward'}};return {status:200,data:png,headers:{'content-type':'image/png'}};}});
  assert.deepEqual((await resolver.icon('fixture')).data,png);assert.deepEqual(requests.map(item=>item.url),['https://app.example.com/','https://cdn.example.com/brand.png?v=3','https://assets.example.com/logo.png']);
  for(const item of requests){assert.deepEqual(Object.keys(item.headers),['Accept']);assert.deepEqual(item.allowedOrigins,[new URL(item.url).origin]);assert.equal(item.maxBytes,128*1024);}
});

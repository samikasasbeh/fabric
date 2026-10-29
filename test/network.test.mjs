import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { isPublicAddress, createSafeRequester } from '../lib/network.mjs';

test('public address check blocks loopback, private, mapped, reserved and transition addresses',() => {
  for (const address of ['127.0.0.1','0.0.0.0','10.3.4.5','100.64.0.1','169.254.169.254','172.16.4.2','192.168.1.1','192.0.2.1','198.18.0.1','224.0.0.1','255.255.255.255','::1','::','::ffff:127.0.0.1','::ffff:8.8.8.8','fc00::1','fe80::1','2001:db8::1','2002:7f00:1::1','3fff::1','not-an-ip']) assert.equal(isPublicAddress(address),false,address);
  assert.equal(isPublicAddress('8.8.8.8'),true); assert.equal(isPublicAddress('2606:4700:4700::1111'),true);
});
test('unsafe URLs and mixed public-private DNS are blocked before request',async () => {
  let sent = 0;
  const request = createSafeRequester({lookup:async () => [{address:'8.8.8.8',family:4},{address:'127.0.0.1',family:4}],transport:() => {sent++;}});
  for (const url of ['http://example.com','https://user:pass@example.com','https://example.com:8443','https://example.com/#secret','https://localhost','https://api.example.com']) await assert.rejects(request({url,allowedOrigins:[new URL(url).origin]}));
  assert.equal(sent,0);
});
function transportFixture({status = 200,body = '{"ok":true}',onOptions = () => {},delay = 0,headers = {'content-type':'application/json'}} = {}) {
  return (url,options,callback) => {
    onOptions(url,options);
    const req = new EventEmitter(); req.write = () => {}; req.destroy = () => {req.destroyed = true;};
    req.end = () => setTimeout(() => { if (req.destroyed) return; const response = new PassThrough(); response.statusCode = status; response.headers = headers; callback(response); response.end(body); },delay);
    return req;
  };
}
test('requests pin validated DNS without altering TLS hostname or leaking provider headers',async () => {
  let lookups = 0;
  const request = createSafeRequester({lookup:async () => {lookups++; return [{address:'8.8.8.8',family:4}];},transport:transportFixture({headers:{'set-cookie':'private','content-type':'application/json'},onOptions:(url,options) => {
    assert.equal(url.hostname,'api.example.com'); assert.equal(options.servername,'api.example.com'); assert.equal(options.agent,false);
    options.lookup('attacker.example',{all:false},(error,address,family) => {assert.equal(error,null);assert.equal(address,'8.8.8.8');assert.equal(family,4);});
  }})});
  assert.deepEqual(await request({url:'https://api.example.com/resource',allowedOrigins:['https://api.example.com']}),{status:200,headers:{'content-type':'application/json'},data:{ok:true}});
  assert.equal(lookups,1);
});
test('origin restrictions and sensitive transport headers cannot be overridden',async () => {
  const request = createSafeRequester();
  await assert.rejects(request({url:'https://api.example.com',allowedOrigins:['https://other.example.com']}),/outside/);
  await assert.rejects(request({url:'https://api.example.com',allowedOrigins:['https://api.example.com'],headers:{Host:'evil.example'}}),/Unsafe/);
  await assert.rejects(request({url:'https://api.example.com',allowedOrigins:['https://api.example.com'],headers:{Authorization:'Bearer secret\r\nHost: evil'}}),/Unsafe/);
});
test('redirects, oversize and slow responses fail with bounded sanitized errors',async () => {
  for (const [options,limits,pattern] of [[{status:302},{},/redirects/],[{body:'12345'},{maxBytes:4},/size limit/],[{delay:50},{timeoutMs:5},/timed out/]]) {
    const request = createSafeRequester({lookup:async () => [{address:'8.8.8.8',family:4}],transport:transportFixture(options)});
    await assert.rejects(request({url:'https://api.example.com',allowedOrigins:['https://api.example.com'],...limits}),pattern);
  }
});
test('lookup timeout is bounded and DNS exception text never escapes',async () => {
  const request = createSafeRequester({lookup:async () => {throw new Error('private-secret');}});
  await assert.rejects(request({url:'https://api.example.com',allowedOrigins:['https://api.example.com']}),error => !error.message.includes('private-secret'));
  const hanging = createSafeRequester({lookup:() => new Promise(() => {})});
  await assert.rejects(hanging({url:'https://api.example.com',allowedOrigins:['https://api.example.com'],timeoutMs:5}),/DNS lookup/);
});
test('transport initialization errors do not leak credentials',async () => {
  const request = createSafeRequester({lookup:async () => [{address:'8.8.8.8',family:4}],transport:() => {throw new Error('private-secret');}});
  await assert.rejects(request({url:'https://api.example.com',allowedOrigins:['https://api.example.com']}),error => error.message === 'Provider request could not be initialized.');
});
test('buffer responses preserve exact bytes and retain the response byte limit',async()=>{
  const bytes=Buffer.from([0,255,137,80,78,71]);
  const request=createSafeRequester({lookup:async()=>[{address:'8.8.8.8',family:4}],transport:transportFixture({body:bytes,headers:{'content-type':'image/png','set-cookie':'not exposed'}})});
  const result=await request({url:'https://public.example.com/icon',allowedOrigins:['https://public.example.com'],responseType:'buffer',maxBytes:bytes.length});assert.ok(Buffer.isBuffer(result.data));assert.deepEqual(result.data,bytes);assert.equal(result.headers['set-cookie'],undefined);
  await assert.rejects(request({url:'https://public.example.com/icon',allowedOrigins:['https://public.example.com'],responseType:'buffer',maxBytes:bytes.length-1}),/size limit/);
  await assert.rejects(request({url:'https://public.example.com/icon',allowedOrigins:['https://public.example.com'],responseType:'executable'}),/Unsupported response type/);
});
test('default response parsing preserves HTML text and parses JSON without executing either',async()=>{
  for(const [body,expected] of [['<html><script>evil()</script></html>','<html><script>evil()</script></html>'],['{"value":3}',{value:3}]]){const request=createSafeRequester({lookup:async()=>[{address:'8.8.8.8',family:4}],transport:transportFixture({body})});assert.deepEqual((await request({url:'https://public.example.com',allowedOrigins:['https://public.example.com']})).data,expected);}
});
test('opt-in discovery redirects expose only location, never follow or carry authenticated requests',async()=>{
  const options={status:302,headers:{location:'https://different.example.com/','set-cookie':'secret',authorization:'secret'}};let sent=0;
  const request=createSafeRequester({lookup:async()=>[{address:'8.8.8.8',family:4}],transport:transportFixture({...options,onOptions:()=>{sent++;}})});
  const base={url:'https://public.example.com',allowedOrigins:['https://public.example.com'],allowRedirectResponse:true};
  const response=await request(base);assert.deepEqual(response,{status:302,headers:{location:'https://different.example.com/'},data:null});assert.equal(sent,1);
  for(const headers of [{Authorization:'Bearer secret'},{Cookie:'session=secret'},{'X-Api-Key':'secret'},{'X-Auth-Token':'secret'}])await assert.rejects(request({...base,headers}),/redirects are not followed/);
  await assert.rejects(request({...base,method:'POST'}),/redirects are not followed/);
});
test('accepted redirect response closes transport instead of draining an unbounded redirect body',async()=>{
  let response,requestObject;
  const request=createSafeRequester({lookup:async()=>[{address:'8.8.8.8',family:4}],transport:(url,options,callback)=>{
    requestObject=new EventEmitter();requestObject.destroy=()=>{requestObject.destroyed=true;};requestObject.end=()=>queueMicrotask(()=>{response=new PassThrough();response.statusCode=302;response.headers={location:'https://different.example.com'};callback(response);});return requestObject;
  }});
  await request({url:'https://public.example.com',allowedOrigins:['https://public.example.com'],allowRedirectResponse:true,maxBytes:1});assert.equal(response.destroyed,true);assert.equal(requestObject.destroyed,true);
});

test('report mode returns redirects without following them, and keeps a location only on the same origin', async () => {
  for (const [location, expected] of [['/next?page=2', {location: 'https://api.example.com/next?page=2'}], ['https://evil.example/steal', {}], ['//evil.example/x', {}]]) {
    const request = createSafeRequester({lookup: async () => [{address: '8.8.8.8', family: 4}], transport: transportFixture({status: 302, headers: {location}})});
    assert.deepEqual(await request({url: 'https://api.example.com/x', method: 'POST', allowedOrigins: ['https://api.example.com'], redirect: 'report', headers: {Authorization: 'Bearer t'}}),
      {status: 302, headers: expected, data: null, redirected: true}, location);
  }
});

test('failures before the transport is called carry sent: false; failures after carry sent: true; response headers follow the allowlist', async () => {
  let calls = 0;
  const privateDns = createSafeRequester({lookup: async () => [{address: '10.0.0.1', family: 4}], transport: () => {calls++;}});
  await assert.rejects(privateDns({url: 'https://api.example.com/x', allowedOrigins: ['https://api.example.com']}), error => error.sent === false);
  await assert.rejects(privateDns({url: 'https://api.example.com/x', allowedOrigins: ['https://other.example']}), error => error.sent === false);
  assert.equal(calls, 0);
  const slow = createSafeRequester({lookup: async () => [{address: '8.8.8.8', family: 4}], transport: transportFixture({delay: 50})});
  await assert.rejects(slow({url: 'https://api.example.com/x', allowedOrigins: ['https://api.example.com'], timeoutMs: 5}), error => error.sent === true && /timed out/.test(error.message));
  const headers = createSafeRequester({lookup: async () => [{address: '8.8.8.8', family: 4}], transport: transportFixture({headers: {'content-type': 'application/json', link: '<x>; rel="next"', 'set-cookie': 's', 'x-oauth-scopes': 'repo'}})});
  assert.deepEqual((await headers({url: 'https://api.example.com/x', allowedOrigins: ['https://api.example.com'], responseHeaders: ['content-type', 'link']})).headers, {'content-type': 'application/json', link: '<x>; rel="next"'});
});

test('report mode answers 304 Not Modified as not modified, with its allowlisted headers and no invented location', async () => {
  const request = createSafeRequester({lookup: async () => [{address: '8.8.8.8', family: 4}], transport: transportFixture({status: 304, headers: {etag: '"e1"', 'x-ratelimit-remaining': '10'}})});
  assert.deepEqual(await request({url: 'https://api.example.com/x', allowedOrigins: ['https://api.example.com'], redirect: 'report', responseHeaders: ['etag', 'x-ratelimit-remaining', 'location']}),
    {status: 304, headers: {etag: '"e1"', 'x-ratelimit-remaining': '10'}, data: null, notModified: true});
});

test('an off-origin Location is dropped on every status, not only on redirects', async () => {
  const request = createSafeRequester({lookup: async () => [{address: '8.8.8.8', family: 4}], transport: transportFixture({status: 201, headers: {'content-type': 'application/json', location: 'https://cdn.example/archive.tgz?token=presigned'}})});
  assert.deepEqual((await request({url: 'https://api.example.com/x', allowedOrigins: ['https://api.example.com'], responseHeaders: ['content-type', 'location']})).headers, {'content-type': 'application/json'});
  const same = createSafeRequester({lookup: async () => [{address: '8.8.8.8', family: 4}], transport: transportFixture({status: 201, headers: {location: '/items/7'}})});
  assert.deepEqual((await same({url: 'https://api.example.com/x', allowedOrigins: ['https://api.example.com'], responseHeaders: ['location']})).headers, {location: 'https://api.example.com/items/7'});
});

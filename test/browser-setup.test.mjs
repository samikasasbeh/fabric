import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm,readFile,stat,access,rename,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {BrowserSetup} from '../lib/browser-setup.mjs';
import {resolveHelperDirectory} from '../lib/helper-directory.mjs';
import {discoverTestFiles} from '../scripts/test.mjs';
import {createApp} from '../server.mjs';

const ORIGIN='http://127.0.0.1:4188';
const CHROME='/Applications/Google Chrome.app';
const EDGE='/Applications/Microsoft Edge.app';
const MANIFEST={manifest_version:3,name:'Fabric Local Bridge',version:'0.2.0',background:{service_worker:'background.js'},action:{default_popup:'popup.html'},host_permissions:[`${ORIGIN}/*`],content_scripts:[{matches:[`${ORIGIN}/*`],js:['fabric-handoff.js']}]};
async function writeHelper(directory,manifest=MANIFEST){
  await mkdir(directory,{recursive:true});
  if(manifest!==null)await writeFile(path.join(directory,'manifest.json'),typeof manifest==='string'?manifest:JSON.stringify(manifest));
  for(const name of ['background.js','popup.html','fabric-handoff.js'])await writeFile(path.join(directory,name),'// test fixture, not installed');
}
async function fixture(t,{platform='darwin',installed=['chrome','edge'],manifest=MANIFEST,executeFile}={}){
  const root=await mkdtemp(path.join(tmpdir(),'fabric-browser-setup-'));
  t.after(()=>rm(root,{recursive:true,force:true}));
  await writeHelper(path.join(root,'extension'),manifest);
  const calls=[];
  const installedPaths=new Set(installed.map(id=>id==='chrome'?CHROME:EDGE));
  const fileAccess=async(target,mode)=>{if(target.startsWith('/Applications/')||target.startsWith('/Users/fabric-test/Applications/')){if(installedPaths.has(target))return;throw Object.assign(new Error('not installed'),{code:'ENOENT'});}return access(target,mode);};
  const fileStat=async target=>installedPaths.has(target)?{isDirectory:()=>true}:stat(target);
  const setup=new BrowserSetup({root,origin:ORIGIN,platform,homeDirectory:'/Users/fabric-test',fileAccess,fileStat,executeFile:executeFile||(async(...args)=>{calls.push(args);return {stdout:'',stderr:''};})});
  return {root,setup,calls};
}

test('setup status reads a real helper manifest and reports known browsers without invoking any process',async t=>{
  const {root,setup,calls}=await fixture(t,{installed:['chrome']});
  const status=await setup.status();assert.deepEqual(status,{platform:'darwin',supported:true,extensionAvailable:true,directory:path.join(root,'extension'),browsers:[{id:'chrome',name:'Google Chrome',installed:true},{id:'edge',name:'Microsoft Edge',installed:false}]});assert.equal(calls.length,0);
  assert.equal(JSON.parse(await readFile(path.join(status.directory,'manifest.json'),'utf8')).manifest_version,3);
});
test('renaming the helper directory preserves setup discovery and reveals the existing folder without modifying it',async t=>{
  const {root,setup,calls}=await fixture(t),renamed=path.join(root,'extensionsk');
  const before=await readFile(path.join(root,'extension','manifest.json'),'utf8');
  await rename(path.join(root,'extension'),renamed);
  const status=await setup.status();assert.equal(status.extensionAvailable,true);assert.equal(status.directory,renamed);assert.equal(calls.length,0);
  const result=await setup.perform({action:'reveal-extension',browser:'chrome',appId:'notion'});
  assert.equal(result.directory,renamed);assert.deepEqual(calls[0].slice(0,2),['/usr/bin/open',['-R',renamed]]);
  assert.equal(await readFile(path.join(renamed,'manifest.json'),'utf8'),before);
  await assert.rejects(stat(path.join(root,'extension')),error=>error.code==='ENOENT');
});
test('helper lookup validates Fabric manifest identity and entrypoints rather than choosing any extension manifest',async t=>{
  for(const manifest of [{...MANIFEST,name:'Unrelated extension'},{...MANIFEST,background:{service_worker:'other.js'}},{...MANIFEST,host_permissions:['https://example.com/*']},{...MANIFEST,content_scripts:[]},{manifest_version:3,name:'Fabric Local Bridge',version:'0.2.0'}]){
    const {root,setup,calls}=await fixture(t,{manifest});const result=await resolveHelperDirectory({root});assert.equal(result.status,'missing');assert.equal(result.directory,null);
    assert.equal((await setup.status()).directory,null);await assert.rejects(setup.perform({action:'reveal-extension',browser:'chrome',appId:'notion'}),/helper/i);assert.equal(calls.length,0);
  }
  const {root,setup}=await fixture(t);await rm(path.join(root,'extension','background.js'));assert.equal((await setup.status()).extensionAvailable,false);
});
test('helper lookup fails closed on duplicate matching folders and never favors a conventional name',async t=>{
  const {root,setup,calls}=await fixture(t);await writeHelper(path.join(root,'extensionsk'));
  const helper=await resolveHelperDirectory({root});assert.equal(helper.status,'ambiguous');assert.equal(helper.directory,null);assert.match(helper.reason,/more than one/i);
  const status=await setup.status();assert.equal(status.extensionAvailable,false);assert.equal(status.directory,null);assert.match(status.reason,/more than one/i);
  await assert.rejects(setup.perform({action:'reveal-extension',browser:'chrome',appId:'notion'}),/more than one/i);assert.equal(calls.length,0);
  assert.equal((await stat(path.join(root,'extension'))).isDirectory(),true);assert.equal((await stat(path.join(root,'extensionsk'))).isDirectory(),true);
});
test('helper discovery does not recurse, follow a helper symlink, accept a symlinked root, or follow manifest and entrypoint symlinks',async t=>{
  const {root,setup,calls}=await fixture(t);
  await mkdir(path.join(root,'archive'));await rename(path.join(root,'extension'),path.join(root,'archive','saved-helper'));
  assert.equal((await resolveHelperDirectory({root})).status,'missing');
  await symlink(path.join(root,'archive','saved-helper'),path.join(root,'extensionsk'),'dir');
  assert.equal((await setup.status()).extensionAvailable,false);await assert.rejects(setup.perform({action:'reveal-extension',browser:'chrome',appId:'notion'}),/helper/i);assert.equal(calls.length,0);
  const rootLink=path.join(root,'root-link');await symlink(root,rootLink,'dir');assert.equal((await resolveHelperDirectory({root:rootLink})).status,'unavailable');
  await rm(path.join(root,'extensionsk'));await rename(path.join(root,'archive','saved-helper'),path.join(root,'extensionsk'));
  const manifest=path.join(root,'extensionsk','manifest.json'),saved=path.join(root,'saved-manifest.json');await rename(manifest,saved);await symlink(saved,manifest);
  assert.equal((await setup.status()).extensionAvailable,false);
  await rm(manifest);await rename(saved,manifest);
  const entrypoint=path.join(root,'extensionsk','background.js');await rename(entrypoint,path.join(root,'saved-background.js'));await symlink(path.join(root,'saved-background.js'),entrypoint);
  assert.equal((await setup.status()).extensionAvailable,false);assert.equal(calls.length,0);
});
test('helper lookup is bounded and does not cache a removed or renamed folder between status and dispatch',async t=>{
  const {root,setup,calls}=await fixture(t);assert.equal((await setup.status()).extensionAvailable,true);
  await rename(path.join(root,'extension'),path.join(root,'renamed again'));
  await setup.perform({action:'reveal-extension',browser:'chrome',appId:'notion'});assert.deepEqual(calls[0][1],['-R',path.join(root,'renamed again')]);
  await rm(path.join(root,'renamed again','manifest.json'));await assert.rejects(setup.perform({action:'reveal-extension',browser:'chrome',appId:'notion'}),/helper/i);assert.equal(calls.length,1);
  await Promise.all(Array.from({length:513},(_,i)=>writeFile(path.join(root,`empty-${i}`),'')));
  const bounded=await resolveHelperDirectory({root});assert.equal(bounded.status,'unavailable');assert.equal(bounded.directory,null);assert.match(bounded.reason,/too many entries/i);
  for(const invalid of [undefined,'relative','/tmp/fabric\u0000bad'])await assert.rejects(resolveHelperDirectory({root:invalid}),/absolute local/);
});
test('test discovery includes the renamed helper suite and rejects ambiguity without running any test files',async t=>{
  const {root}=await fixture(t);await mkdir(path.join(root,'test'));await mkdir(path.join(root,'extension','test'));
  await writeFile(path.join(root,'test','root.test.mjs'),'throw new Error("discovery must not execute tests")');await writeFile(path.join(root,'extension','test','bridge.test.mjs'),'throw new Error("discovery must not execute tests")');
  await rename(path.join(root,'extension'),path.join(root,'extensionsk'));
  assert.deepEqual(await discoverTestFiles(root),[path.join(root,'extensionsk','test','bridge.test.mjs'),path.join(root,'test','root.test.mjs')]);
  await writeHelper(path.join(root,'second-helper'));await assert.rejects(discoverTestFiles(root),/more than one/i);
});
test('test discovery rejects symlinked test directories and test files instead of executing outside the helper',async t=>{
  const {root}=await fixture(t);await mkdir(path.join(root,'test'));await writeFile(path.join(root,'test','root.test.mjs'),'');
  await symlink(path.join(root,'test'),path.join(root,'extension','test'),'dir');await assert.rejects(discoverTestFiles(root),/real local directories/);
  await rm(path.join(root,'extension','test'));await mkdir(path.join(root,'extension','test'));
  await assert.rejects(discoverTestFiles(root),/refusing to skip a test suite/);
  await symlink(path.join(root,'test','root.test.mjs'),path.join(root,'extension','test','linked.test.mjs'));await assert.rejects(discoverTestFiles(root),/test files/);
});
test('open-fabric uses only the allowlisted browser bundle and configured loopback connector route',async t=>{
  const {setup,calls}=await fixture(t);const result=await setup.perform({action:'open-fabric',browser:'chrome',appId:'indexed-example-1'});
  assert.deepEqual(calls[0].slice(0,2),['/usr/bin/open',['-b','com.google.Chrome',`${ORIGIN}/#connectors/indexed-example-1`]]);assert.equal(calls[0][2].shell,false);assert.ok(calls[0][2].timeout>0&&calls[0][2].timeout<=10000);assert.ok(calls[0][2].maxBuffer<=65536);assert.equal(result.opened,true);assert.equal(result.connectionEstablished,false);assert.equal(result.installationPerformed,false);
});
test('extensions setup selects the chosen browser and Finder reveals only the exact helper directory',async t=>{
  const {root,setup,calls}=await fixture(t);
  await setup.perform({action:'open-extensions',browser:'edge',appId:'notion'});assert.deepEqual(calls[0].slice(0,2),['/usr/bin/open',['-b','com.microsoft.edgemac','edge://extensions/']]);
  await setup.perform({action:'open-extensions',browser:'chrome',appId:'notion'});assert.deepEqual(calls[1][1],['-b','com.google.Chrome','chrome://extensions/']);
  const result=await setup.perform({action:'reveal-extension',browser:'chrome',appId:'notion'});assert.deepEqual(calls[2].slice(0,2),['/usr/bin/open',['-R',path.join(root,'extension')]]);assert.equal(result.directory,path.join(root,'extension'));assert.equal(result.opened,true);
  for(const call of calls)assert.equal(call[2].shell,false);
});
test('arbitrary commands, URLs, paths, browsers, action fields and invalid app IDs are rejected before process dispatch',async t=>{
  const {setup,calls}=await fixture(t);
  for(const request of [null,[],{action:'install',browser:'chrome',appId:'notion'},{action:'reveal-extension',browser:'safari',appId:'notion'},{action:'reveal-extension',browser:'chrome; touch /tmp/bad',appId:'notion'},{action:'open-fabric',browser:'chrome',appId:'../../bad'},{action:'open-fabric',browser:'chrome',appId:'notion#other'},{action:'open-fabric',browser:'chrome',appId:42},{action:'open-fabric',browser:'chrome'},{action:'open-fabric',browser:'chrome',appId:'notion',url:'https://evil.example.com'},{action:'reveal-extension',browser:'chrome',appId:'notion',directory:'/etc'},{action:'open-extensions',browser:'chrome',appId:'notion',args:['--load-extension=/tmp/bad']}])await assert.rejects(setup.perform(request));
  assert.equal(calls.length,0);
  for(const origin of ['https://remote.example.com','http://localhost:4188','http://127.0.0.1:4188/path','http://127.0.0.1:4188/?url=evil','http://user:pass@127.0.0.1:4188','file:///tmp/x'])assert.throws(()=>new BrowserSetup({root:'/tmp/fabric',origin}),/loopback/i);
});
test('missing, invalid or oversized manifests fail closed without invoking open or changing file permissions',async t=>{
  for(const manifest of [null,'not-json',{manifest_version:2},'x'.repeat(65537)]){
    const {setup,calls}=await fixture(t,{manifest});assert.equal((await setup.status()).extensionAvailable,false);await assert.rejects(setup.perform({action:'reveal-extension',browser:'chrome',appId:'notion'}),/helper/i);assert.equal(calls.length,0);
  }
});
test('unsupported platforms and uninstalled browsers return clear errors without launching any process',async t=>{
  const nonMac=await fixture(t,{platform:'linux'});assert.equal((await nonMac.setup.status()).supported,false);assert.match((await nonMac.setup.status()).reason,/macOS/);await assert.rejects(nonMac.setup.perform({action:'open-fabric',browser:'chrome',appId:'notion'}),/macOS/);assert.equal(nonMac.calls.length,0);
  const absent=await fixture(t,{installed:[]});await assert.rejects(absent.setup.perform({action:'open-extensions',browser:'edge',appId:'notion'}),/not installed/);assert.equal(absent.calls.length,0);
});
test('another loopback port remains a valid host configuration but cannot claim compatible helper setup',async t=>{
  const {setup,calls}=await fixture(t);setup.origin='http://127.0.0.1:4189';const status=await setup.status();assert.equal(status.platform,'darwin');assert.equal(status.supported,false);assert.equal(status.extensionAvailable,true);assert.match(status.reason,/4188/);await assert.rejects(setup.perform({action:'open-fabric',browser:'chrome',appId:'notion'}),/4188/);assert.equal(calls.length,0);
});
test('process errors are sanitized and never claim installation, connection, or successful dispatch',async t=>{
  const {setup}=await fixture(t,{executeFile:async()=>{throw new Error('secret stdout and private account data');}});
  await assert.rejects(setup.perform({action:'open-fabric',browser:'chrome',appId:'notion'}),error=>!error.message.includes('secret')&&!error.message.includes('private account')&&/could not|unable/i.test(error.message));
});

async function httpFixture(t){
  const calls=[],dataDir=await mkdtemp(path.join(tmpdir(),'fabric-browser-setup-http-'));
  const browserSetup={status:async()=>({platform:'darwin',supported:true,extensionAvailable:true,directory:'/fixed/fabric/extension',browsers:[{id:'chrome',name:'Google Chrome',installed:true}]}),perform:async input=>{calls.push(input);return {...input,opened:true,connectionEstablished:false,installationPerformed:false};}};
  const app=await createApp({dataDir,port:59000+Math.floor(Math.random()*2000),browserSetup,request:async()=>{throw new Error('No external requests allowed in browser setup tests.');}});
  await app.start();t.after(async()=>{await app.close();await rm(dataDir,{recursive:true,force:true});});
  const response=await fetch(`${app.origin}/api/state`),state=await response.json();
  const headers={'Content-Type':'application/json',Cookie:response.headers.get('set-cookie').split(';')[0],'X-Fabric-CSRF':state.csrfToken};
  return {app,calls,headers,post:async(input,extra={})=>fetch(`${app.origin}/api/browser-setup`,{method:'POST',headers:{...headers,...extra},body:JSON.stringify(input)})};
}
test('HTTP browser setup status is read-only and explicit valid requests return opened without connected claims',async t=>{
  const {app,calls,headers,post}=await httpFixture(t);const before=(await (await fetch(`${app.origin}/api/state`,{headers})).json()).connections.length;
  const status=await fetch(`${app.origin}/api/browser-setup`,{headers});assert.equal(status.status,200);assert.equal((await status.json()).extensionAvailable,true);assert.equal(calls.length,0);
  for(const action of ['open-fabric','open-extensions','reveal-extension']){const response=await post({action,browser:'chrome',appId:'notion'});assert.equal(response.status,200);const body=await response.json();assert.equal(body.opened,true);assert.equal(body.connectionEstablished,false);assert.equal(body.installationPerformed,false);}
  assert.equal(calls.length,3);assert.ok(calls.every(input=>input.appId==='notion'));assert.equal(app.store.list('connections').length,before);
});
test('HTTP native setup never dispatches for missing CSRF, foreign origins, unknown apps, or extra URL/path fields',async t=>{
  const {app,calls,post}=await httpFixture(t),valid={action:'open-fabric',browser:'chrome',appId:'notion'};
  assert.equal((await post(valid,{'X-Fabric-CSRF':''})).status,403);
  assert.equal((await post(valid,{Origin:'https://foreign.example.com'})).status,400);
  for(const input of [{...valid,appId:'unknown-application'},{...valid,action:'reveal-extension',appId:'unknown-application'},{...valid,url:'https://foreign.example.com'},{...valid,directory:'/etc'}, {action:'reveal-extension',browser:'chrome'}])assert.equal((await post(input)).status,400);
  const foreignGet=await fetch(`${app.origin}/api/browser-setup`,{headers:{Origin:'https://foreign.example.com'}});assert.equal(foreignGet.status,400);assert.equal(calls.length,0);
});

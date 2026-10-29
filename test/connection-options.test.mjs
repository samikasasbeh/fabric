import test from 'node:test';
import assert from 'node:assert/strict';
import {catalog,catalogFor} from '../lib/connections.mjs';
import {describeConnectionOptions} from '../lib/connection-options.mjs';

const app=id=>catalog.find(entry=>entry.id===id);
test('only implemented Google apps advertise real provider sign-in with configuration readiness',()=>{
  for(const id of ['google-calendar','gmail']) {
    const options=describeConnectionOptions(app(id),{googleOAuthConfigured:true}),login=options.find(o=>o.method==='oauth');
    assert.equal(login.label,'Sign in with Google');assert.equal(login.enabled,true);
    assert.equal(login.availability,'available');assert.equal(login.recommended,true);
    assert.deepEqual(login.action,{method:'POST',path:'/api/oauth/google/start',body:{appId:id}});
    assert.equal(options.some(o=>o.method==='token'),false);
  }
  assert.equal(describeConnectionOptions({id:'other',authMethods:['oauth']},{googleOAuthConfigured:true}).length,0);
});
test('unconfigured Google sign-in is truthful and browser pairing is the supported primary alternative',()=>{
  const options=describeConnectionOptions(app('gmail'));
  const login=options.find(o=>o.method==='oauth'),browser=options.find(o=>o.method==='browser');
  assert.equal(login.enabled,false);assert.equal(login.availability,'setup_required');assert.match(login.setupReason,/product operator/);
  assert.equal(browser.recommended,true);assert.equal(browser.enabled,true);assert.equal(browser.availability,'setup_required');
  assert.equal(options.some(o=>o.availability==='ready'||o.availability==='connected'),false);
});
test('GitHub, Slack, and Notion lead with browser pairing, never developer token entry',()=>{
  for(const id of ['github','slack','notion']) {
    const options=describeConnectionOptions(app(id)),token=options.find(o=>o.method==='token');
    assert.equal(options[0].id,'browser-session');assert.equal(options[0].recommended,true);
    assert.equal(options.some(o=>o.method==='oauth'),false);
    assert.equal(token.kind,'advanced');assert.equal(token.recommended,false);
    assert.match(token.description,/not consumer account sign-in/);
    assert.deepEqual(token.action.body,{appId:id});
  }
});
test('browser-only platforms expose approved browser actions and no invented API account connection',()=>{
  for(const id of ['x','facebook']) {
    const options=describeConnectionOptions(app(id));assert.equal(options.length,1);
    const browser=options[0];assert.equal(browser.method,'browser');assert.equal(browser.identityVerification,'origin-and-tab-only');
    assert.deepEqual(browser.capabilities,['Inspect the visible paired page','Read a selected visible page element','Approve a click on an observed control','Approve entry into an observed non-sensitive field']);
    const limitations=browser.limitations.join(' ');
    assert.match(limitations,/exact-action approval/);assert.match(limitations,/not independently verified/);
    assert.match(limitations,/persistent effects are not automatically verified/);assert.match(limitations,/unattended browser schedules are disabled/);
    assert.match(limitations,/not Safari/);assert.match(limitations,/No cookies, passwords/);
    assert.deepEqual(browser.action,{method:'POST',path:'/api/pair',body:{appId:id}});
  }
});
test('disabled bridge is unavailable and cannot be advertised as the recommended working method',()=>{
  const options=describeConnectionOptions(app('github'),{browserBridgeAvailable:false});
  const browser=options.find(o=>o.method==='browser');assert.equal(browser.enabled,false);
  assert.equal(browser.availability,'unavailable');assert.equal(options.some(o=>o.recommended),false);
});
test('local workspace exposes bounded real local operations with no sign-in',()=>{
  const options=describeConnectionOptions(app('workspace'));assert.equal(options.length,1);
  const local=options[0];assert.equal(local.recommended,true);assert.equal(local.availability,'available');
  assert.deepEqual(local.action,{method:'POST',path:'/api/connections/local',body:{}});
  assert.match(local.limitations.join(' '),/not grant access to your entire computer/);
});
test('user manifests inherit only their declared implemented connection routes',()=>{
  const manifests=[{id:'custom-browser',name:'Custom browser',webOrigins:['https://example.com'],apiOrigins:[]},{id:'custom-token',name:'Custom API',webOrigins:[],apiOrigins:['https://api.example.com'],identityProbe:{path:'/me',idPointer:'/id'}}];
  const enriched=catalogFor({list:()=>manifests});
  const browser=describeConnectionOptions(enriched.find(a=>a.id==='custom-browser'));
  assert.equal(browser.length,1);assert.equal(browser[0].method,'browser');assert.deepEqual(browser[0].origins,['https://example.com']);
  const token=describeConnectionOptions(enriched.find(a=>a.id==='custom-token'));
  assert.equal(token.length,1);assert.equal(token[0].kind,'advanced');assert.equal(token[0].recommended,false);
  assert.deepEqual(describeConnectionOptions({id:'not-supported',authMethods:[],apiOrigins:['https://api.example.com']}),[]);
});
test('descriptors neither mutate catalog input nor copy credentials or arbitrary catalog fields',()=>{
  const source=structuredClone(app('gmail'));source.secret='never-export-this';
  const before=structuredClone(source),first=describeConnectionOptions(source),second=describeConnectionOptions(source);
  first[0].requirements.push('caller mutation');
  assert.deepEqual(source,before);assert.equal(second[0].requirements.includes('caller mutation'),false);
  assert.equal(JSON.stringify(second).includes(source.secret),false);
  assert.deepEqual(describeConnectionOptions(null),[]);
});
test('reviewed non-Google providers advertise sign-in from the registry and stay truthful about availability',()=>{
  const routes={
    github:{providerId:'github',name:'GitHub',configured:true,available:true,reason:null},
    slack:{providerId:'slack',name:'Slack',configured:true,available:false,reason:'Slack only accepts HTTPS callbacks. Sign-in becomes available once FABRIC_PUBLIC_CALLBACK_BASE names the hosted callback relay.'},
    notion:{providerId:'notion',name:'Notion',configured:false,available:false,reason:'The product operator must configure the Notion sign-in client.'},
  };
  const oauthRoute=id=>routes[id]??null;
  // F10.7: the catalog lists sign-in for these apps (their cards say so), but only the registry decides whether it is offered (line 28).
  for(const id of ['github','slack','notion'])assert.equal(app(id).authMethods.includes('oauth'),true,'the catalog lists sign-in');
  const github=describeConnectionOptions(app('github'),{oauthRoute}),login=github.find(o=>o.method==='oauth');
  assert.equal(login.id,'github-oauth');assert.equal(login.enabled,true);assert.equal(login.availability,'available');assert.equal(login.recommended,true);
  assert.deepEqual(login.action,{method:'POST',path:'/api/oauth/github/start',body:{appId:'github'}});
  assert.equal(github.find(o=>o.method==='token').recommended,false);
  const slack=describeConnectionOptions(app('slack'),{oauthRoute}),slackLogin=slack.find(o=>o.method==='oauth');
  assert.equal(slackLogin.enabled,false);assert.equal(slackLogin.availability,'unavailable');assert.match(slackLogin.setupReason,/HTTPS callback/);
  assert.equal(slack.find(o=>o.recommended).id,'browser-session');
  const notion=describeConnectionOptions(app('notion'),{oauthRoute}).find(o=>o.method==='oauth');
  assert.equal(notion.availability,'setup_required');assert.match(notion.setupReason,/product operator/);
  assert.equal(describeConnectionOptions(app('x'),{oauthRoute}).some(o=>o.method==='oauth'),false);
});
test('F10.7: a sign-in option says what the sign-in asks for, in the app page\'s words, and promises nothing it cannot',()=>{
  const words=(id,route)=>describeConnectionOptions(app(id),{oauthRoute:()=>route}).find(o=>o.method==='oauth').limitations[0];
  const github={providerId:'github',name:'GitHub',configured:true,available:true,reason:null,levels:['full'],consentMode:'full'};
  assert.equal(words('github',github),'Full access at sign-in. You control each permission below. What GitHub grants and Fabric\'s operation settings are separate.');
  assert.equal(words('notion',{...github,providerId:'notion',name:'Notion',levels:['pages']}),'Notion shares only the pages you pick. You control each permission below. What Notion grants and Fabric\'s operation settings are separate.');
  const google={providerId:'google',name:'Google',configured:true,available:true,reason:null,levels:['full','read'],consentMode:'full'};
  assert.match(words('gmail',google),/^Full access at sign-in\. /);
  assert.match(words('gmail',{...google,consentMode:'required'}),/^Sign-in asks for what this app needs to work\. /);
  // A route that does not say what it offers promises no level.
  assert.equal(words('github',{...github,levels:undefined}),'What GitHub grants and Fabric\'s operation settings are separate.');
  assert.equal(describeConnectionOptions(app('gmail'),{googleOAuthConfigured:true}).find(o=>o.method==='oauth').limitations[0],'What Google grants and Fabric\'s operation settings are separate.');
  for(const id of ['github','gmail']) for(const option of describeConnectionOptions(app(id),{oauthRoute:()=>id==='gmail'?google:github})) assert.doesNotMatch(option.limitations.join(' '),/minimum documented permissions|Initial access is read-only/);
});

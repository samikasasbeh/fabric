import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createApp} from '../server.mjs';

// Actual Fabric HTTP/runtime/permission integration with explicitly fake browser
// contexts. These tests never launch a browser or read a real provider account.
function browserFixture() {
  const launches = [], contexts = [], observations = [];
  class FixturePage extends EventEmitter {
    constructor(context) {super(); this.context = context; this.closed = false; this.currentUrl = 'about:blank'; this.foregrounded = 0;}
    isClosed() {return this.closed;}
    url() {return this.currentUrl;}
    async goto(url) {this.currentUrl = url; return null;}
    async bringToFront() {this.foregrounded++;}
    async evaluate(_readOnlyFunction, input) {
      observations.push({origin:new URL(this.currentUrl).origin, input:structuredClone(input)});
      return {origin:new URL(this.currentUrl).origin, url:this.currentUrl, title:'Fixture page — no live account', text:'Isolated fixture content only.', controls:[], accountVerified:false};
    }
    async close() {if (!this.closed) {this.closed = true; this.emit('close');}}
  }
  class FixtureContext extends EventEmitter {
    constructor() {super(); this.closed = false; this.pageList = [];}
    pages() {return this.pageList.filter(page=>!page.isClosed());}
    async newPage() {assert.equal(this.closed, false); const page = new FixturePage(this); this.pageList.push(page); return page;}
    browser() {return {isConnected:()=>!this.closed};}
    async close() {if (!this.closed) {this.closed = true; for (const page of this.pageList) await page.close(); this.emit('close');}}
  }
  const launch = async(profileDirectory, options)=>{
    launches.push({profileDirectory, options:structuredClone(options)});
    const context = new FixtureContext(); contexts.push(context); return context;
  };
  return {launch, launches, contexts, observations};
}

async function setup(t) {
  const dataDir = await mkdtemp(path.join(tmpdir(), 'fabric-persistent-browser-http-'));
  const fake = browserFixture();
  let app, headers, started = false;
  const start = async()=>{
    app = await createApp({dataDir, port:57000 + Math.floor(Math.random() * 1500), sessionBrowserLaunch:fake.launch, request:async()=>{throw new Error('No external requests permitted in this fixture.');}});
    await app.start(); started = true;
    const boot = await fetch(`${app.origin}/api/state`);
    assert.equal(boot.status, 200);
    const state = await boot.json();
    headers = {Cookie:boot.headers.get('set-cookie').split(';')[0], 'Content-Type':'application/json', 'X-Fabric-CSRF':state.csrfToken};
  };
  t.after(async()=>{
    if (started) await app.close();
    else app?.store.close();
    await rm(dataDir, {recursive:true, force:true});
  });
  await start();
  const request = async(route, {method='GET', data, expected=200, extraHeaders={}}={})=>{
    const response = await fetch(`${app.origin}${route}`, {method, headers:{...headers, ...extraHeaders}, ...(data !== undefined ? {body:JSON.stringify(data)} : {})});
    const result = await response.json();
    assert.equal(response.status, expected, result.error ? JSON.stringify(result.error) : `Unexpected response status for ${route}`);
    return result;
  };
  return {
    fake, dataDir, get app() {return app;}, request,
    post:(route, data={}, expected=200)=>request(route, {method:'POST', data, expected}),
    restart:async()=>{await app.close(); started = false; await start();},
  };
}

const connect = async f=>(await f.post('/api/session-browser/connect', {appId:'notion', consent:true}, 201)).connection;
const observeArgs = connection=>({connectionId:connection.id, capabilityId:'notion.session.observe.v1', args:{}});
const connectionState = async(f, id)=>(await f.request('/api/state')).connections.find(item=>item.id === id);

test('persistent-browser HTTP readiness has no launch side effect; connect opens a dedicated profile without claiming login', async t=>{
  const f = await setup(t);
  const readiness = await f.request('/api/session-browser');
  assert.ok(readiness && typeof readiness === 'object');
  assert.equal(f.fake.launches.length, 0);
  assert.equal(f.fake.observations.length, 0);

  const connection = await connect(f);
  assert.equal(connection.driver, 'browser');
  assert.equal(connection.transport, 'persistent');
  assert.equal(connection.persistentSession, true);
  assert.equal(connection.status, 'session_ready');
  assert.equal(connection.identity.verified, false);
  assert.equal(connection.expiresAt, null);
  assert.equal(f.fake.launches.length, 1);
  assert.equal(f.fake.launches[0].options.headless, false);
  assert.equal(f.fake.launches[0].options.acceptDownloads, false);
  assert.ok(path.relative(f.dataDir, f.fake.launches[0].profileDirectory).split(path.sep)[0] !== '..');
  assert.equal(f.fake.observations.length, 0);
  assert.equal(f.app.store.list('browserDevices').length, 0);
  assert.equal(f.app.store.list('pairings').length, 0);

  const current = await connectionState(f, connection.id);
  assert.equal(current.browserEvidence.account.verified, false);
  assert.equal(current.browserEvidence.page.status, 'not_observed');
  assert.equal(current.browserEvidence.observedPage, null);
});

test('persistent-browser HTTP connect requires exact explicit consent and existing same-origin session protection', async t=>{
  const f = await setup(t);
  for (const data of [
    {appId:'notion'}, {appId:'notion', consent:false}, {appId:'notion', consent:'true'},
    {appId:'notion', consent:true, url:'https://foreign.example'},
    {appId:'notion', consent:true, profileDirectory:'/private/elsewhere'},
    {appId:'notion', consent:true, token:'not-a-provider-token'},
    {appId:'unknown-application', consent:true}, {appId:'local-device', consent:true},
  ]) await f.post('/api/session-browser/connect', data, 400);
  await f.request('/api/session-browser/connect', {method:'POST', data:{appId:'notion', consent:true}, extraHeaders:{'X-Fabric-CSRF':''}, expected:403});
  await f.request('/api/session-browser/connect', {method:'POST', data:{appId:'notion', consent:true}, extraHeaders:{Origin:'https://foreign.example'}, expected:400});
  assert.equal(f.fake.launches.length, 0);
  assert.equal(f.app.store.list('connections').length, 0);
});

test('persistent-browser reads need exact approval even after Allow; denial blocks browser evaluation', async t=>{
  const f = await setup(t), connection = await connect(f), jobData = observeArgs(connection);
  const permission = await f.post(`/api/connections/${connection.id}/permissions`, {capabilityId:jobData.capabilityId, mode:'allow'});
  assert.equal(permission.mode, 'ask');
  assert.equal(permission.requiresApproval, true);
  const pending = await f.post('/api/jobs', jobData, 201);
  assert.equal(pending.status, 'awaiting_approval');
  assert.equal(f.fake.observations.length, 0);
  const completed = await f.post(`/api/jobs/${pending.id}/approve`, {approvalDigest:pending.approvalDigest});
  assert.equal(completed.status, 'succeeded');
  assert.equal(completed.effect, 'read');
  assert.equal(completed.result.verification.status, 'observed');
  assert.equal(f.fake.observations.length, 1);
  const state = await connectionState(f, connection.id);
  assert.equal(state.browserEvidence.account.verified, false);
  assert.equal(state.browserEvidence.page.status, 'observed');
  assert.equal(state.browserEvidence.observedPage.title, 'Fixture page — no live account');
  assert.equal(Object.hasOwn(state.browserEvidence.observedPage, 'text'), false);

  await f.post(`/api/connections/${connection.id}/permissions`, {capabilityId:jobData.capabilityId, mode:'deny'});
  const denied = await f.post('/api/jobs', jobData, 400);
  assert.match(denied.error, /denied/i);
  assert.equal(f.fake.observations.length, 1);
});

test('helper and persistent browser capabilities cannot cross transports through jobs, permissions, or client grants', async t=>{
  const f = await setup(t), persistent = await connect(f);
  const pair = f.app.browser.createPair('notion');
  const helper = f.app.browser.pair({code:pair.code, origin:pair.origins[0], label:'Fixture helper — not a live account', bridgeVersion:'0.2'}).connection;
  await f.post(`/api/session-browser/${helper.id}/open`, {}, 400);
  await f.post(`/api/session-browser/${persistent.id}/open`, {url:'https://foreign.example'}, 400);
  for (const [connection, capabilityId] of [[persistent, 'notion.browser.observe.v1'], [helper, 'notion.session.observe.v1'], [persistent, 'notion.browser.click.v2']]) {
    await f.post('/api/jobs', {connectionId:connection.id, capabilityId, args:{}}, 400);
    await f.post(`/api/connections/${connection.id}/permissions`, {capabilityId, mode:'allow'}, 400);
    await f.post('/api/clients', {name:'Isolated invalid transport fixture', bindings:[{connectionId:connection.id, capabilityId}]}, 400);
  }
  assert.equal(f.fake.observations.length, 0);
  assert.equal(f.app.store.list('browserCommands').length, 0);
  assert.equal(f.app.store.list('clientGrants').length, 0);
});

test('scoped Fabric clients can request a saved-profile read but cannot approve it or retain access after revocation', async t=>{
  const f = await setup(t), connection = await connect(f);
  const binding = {connectionId:connection.id, capabilityId:'notion.session.observe.v1'};
  const grant = await f.post('/api/clients', {name:'Explicit fake-browser protocol test', bindings:[binding]}, 201);
  const rpc = (id, method, params={}, expected=200)=>f.request('/fabric/v1', {method:'POST', data:{protocol:'fabric/0.1', id, method, params}, extraHeaders:{Authorization:`Bearer ${grant.token}`}, expected});
  const listed = await rpc('list-profile-read', 'capabilities.list');
  assert.equal(listed.error, undefined);
  const capability = listed.result.capabilities.find(item=>item.id === binding.capabilityId);
  assert.equal(capability.approval, 'ask');
  const requested = await rpc('request-profile-read', 'calls.create', {...binding, definitionHash:capability.definitionHash, args:{}});
  assert.equal(requested.error, undefined);
  assert.equal(requested.result.status, 'awaiting_approval');
  assert.equal(Object.hasOwn(requested.result, 'approvalDigest'), false);
  assert.equal(f.fake.observations.length, 0);
  const selfApproved = await rpc('not-owner-approval', 'calls.approve', {callId:requested.result.id}, 400);
  assert.equal(selfApproved.error.code, 'method_not_found');
  const ownerJob = f.app.store.get('jobs', requested.result.id);
  await f.post(`/api/jobs/${ownerJob.id}/approve`, {approvalDigest:ownerJob.approvalDigest});
  const completed = await rpc('get-approved-read', 'calls.get', {callId:ownerJob.id});
  assert.equal(completed.result.status, 'succeeded');
  assert.equal(f.fake.observations.length, 1);
  await f.post(`/api/connections/${connection.id}/revoke`);
  const revoked = await rpc('get-revoked-read', 'calls.get', {callId:ownerJob.id}, 403);
  assert.ok(revoked.error);
  assert.equal(revoked.result, undefined);
  assert.equal(f.fake.observations.length, 1);
});

test('persistent-browser close and runtime restart retain an isolated profile, not a fabricated logged-in account', async t=>{
  const f = await setup(t), connection = await connect(f);
  const originalProfile = f.fake.launches[0].profileDirectory;
  await f.fake.contexts[0].pages()[0].close();
  const {connection:reopened} = await f.post(`/api/session-browser/${connection.id}/open`);
  assert.equal(reopened.id, connection.id);
  assert.equal(reopened.identity.verified, false);
  assert.equal(f.fake.contexts[0].pages().length, 1);
  assert.equal(f.fake.observations.length, 0);

  await f.restart();
  assert.equal(f.fake.contexts[0].closed, true);
  const dormant = await connectionState(f, connection.id);
  assert.equal(dormant.browserEvidence.account.verified, false);
  assert.equal(dormant.browserEvidence.session.state, 'dormant');
  assert.equal(f.fake.launches.length, 1);
  const {connection:restored} = await f.post(`/api/session-browser/${connection.id}/open`);
  assert.equal(restored.id, connection.id);
  assert.equal(f.fake.launches.length, 2);
  assert.equal(f.fake.launches[1].profileDirectory, originalProfile);
  assert.equal(f.fake.observations.length, 0);
});

test('persistent-browser HTTP revoke closes its context, blocks reopening, and invalidates pending read approval', async t=>{
  const f = await setup(t), connection = await connect(f);
  const pending = await f.post('/api/jobs', observeArgs(connection), 201);
  assert.equal(pending.status, 'awaiting_approval');
  const revoked = await f.post(`/api/connections/${connection.id}/revoke`);
  assert.equal(revoked.status, 'revoked');
  assert.equal(f.fake.contexts[0].closed, true);
  await f.post(`/api/session-browser/${connection.id}/open`, {}, 400);
  await f.post('/api/jobs', observeArgs(connection), 400);
  const blockedApproval = await f.post(`/api/jobs/${pending.id}/approve`, {approvalDigest:pending.approvalDigest});
  assert.equal(blockedApproval.status, 'failed');
  assert.match(blockedApproval.error, /not ready|revoked/i);
  assert.equal(f.fake.launches.length, 1);
  assert.equal(f.fake.observations.length, 0);
  const state = await connectionState(f, connection.id);
  assert.equal(state.browserEvidence.bridge.status, 'revoked');
  assert.equal(state.browserEvidence.account.verified, false);
});

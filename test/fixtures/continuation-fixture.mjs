import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {Store} from '../../lib/store.mjs';
import {LocalRepository} from '../../lib/repositories/local.mts';
import {LocalDriver} from '../../lib/local-driver.mjs';
import {Runtime} from '../../lib/runtime.mjs';
import {FabricProtocol, FABRIC_PROTOCOL} from '../../lib/fabric-protocol.mjs';
import {ContinuationService} from '../../lib/continuations.mjs';
import {compileOpenApi} from '../../lib/compiler.mjs';
import {validatePrincipal} from '../../contracts/identity.mts';

// Shared F02.3 handoff fixture: isolated temporary designated store, synthetic HTTP provider,
// no private state or network.
export const owner = validatePrincipal({schemaVersion:1,kind:'local_owner',id:'fixture-owner',scope:{schemaVersion:1,kind:'local',localOwnerId:'fixture-owner'}});
export const ORIGIN = 'http://127.0.0.1:4188';
export const github = {openapi:'3.0.3',info:{title:'Synthetic GitHub',version:'1'},servers:[{url:'https://api.github.com'}],paths:{
  '/user/repos':{get:{operationId:'listRepos',parameters:[{name:'per_page',in:'query',schema:{type:'integer'}}],responses:{200:{description:'Repos'}}}},
  '/repos/{owner}/{repo}/issues':{post:{operationId:'createIssue',parameters:[{name:'owner',in:'path',required:true,schema:{type:'string'}},{name:'repo',in:'path',required:true,schema:{type:'string'}}],
    requestBody:{content:{'application/json':{schema:{type:'object',properties:{title:{type:'string'}},required:['title']}}}},responses:{201:{description:'Created'}}}}}};

export async function fixture(t, {authority = 'new', signIn = true} = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-continuations-'));
  const local = new LocalDriver(path.join(dir, 'workspace')); await local.init();
  let now = Date.parse('2026-10-11T10:00:00.000Z'), store, runtime, protocol, service;
  const calls = [], hooks = {request: null};
  const clock = () => now;
  const open = mode => {
    store = new LocalRepository({store: new Store({dataDir: dir, ...(mode ? {localAuthority: mode} : {}), clock}), scope: owner.scope});
    runtime = new Runtime({store, local, clock, ...(mode ? {ownerPrincipal: owner} : {}),
      connections: {credentials: async () => ({headers: {Authorization: 'Bearer synthetic-only'}, allowedOrigins: ['https://api.github.com']})},
      request: async req => { calls.push(req); if (hooks.request) return hooks.request(req); return {status: req.method === 'GET' ? 200 : 201, data: {id: 'synthetic-result', title: 'ok'}}; }});
    protocol = new FabricProtocol({store, runtime, clock, origin: ORIGIN, appName: id => id === 'github' ? 'GitHub' : id});
    service = new ContinuationService({store, runtime, protocol, clock, origin: ORIGIN, appName: id => id === 'github' ? 'GitHub' : id,
      oauthRoute: appId => appId === 'github' ? {providerId: 'github', name: 'GitHub', configured: true, available: signIn} : null});
    protocol.continuations = service; protocol.oauthRoute = service.oauthRoute;
    runtime.authorizeSource = job => protocol.authorizeJob(job);
    runtime.recover(); service.recover();
  };
  open(authority);
  t.after(async () => { store.close(); await rm(dir, {recursive: true, force: true}); });
  const caps = compileOpenApi({appId: 'github', document: github}).capabilities;
  const read = {...caps.find(cap => cap.request.method === 'GET'), status: 'active'}, write = {...caps.find(cap => cap.request.method === 'POST'), status: 'active'};
  store.put('capabilities', read); store.put('capabilities', write);
  const account = (id, identity) => store.put('connections', {id, appId: 'github', driver: 'http', authMethod: 'token', authRevision: `consent-${id}`, status: 'ready', label: `GitHub ${identity}`, identity: {id: identity, displayName: `octo-${identity}`}, allowedOrigins: ['https://api.github.com'], createdAt: new Date(now).toISOString()});
  const f = {
    dir, read, write, calls, hooks, account,
    get store() { return store; }, get runtime() { return runtime; }, get protocol() { return protocol; }, get service() { return service; },
    advance(ms) { now += ms; }, get now() { return now; },
    reopen() { store.close(); open('require'); },
    grant({requestable = [read.id, write.id], bindings = []} = {}) { return protocol.createClient({name: 'Agent', bindings, requestable: requestable.map(capabilityId => ({capabilityId}))}, owner); },
    invoke(token, method, params = {}, id = `req-${Math.random().toString(36).slice(2, 10)}`) { return protocol.handle(`Bearer ${token}`, {protocol: FABRIC_PROTOCOL, id, method, params}); },
    ask(client, cap = read, args = {}) { return {appId: 'github', capabilityId: cap.id, definitionHash: client.requestable.find(entry => entry.capabilityId === cap.id).definitionHash, args}; },
    view(id) { return service.ownerView(id); },
    select(id, connectionId, digest) { return service.select(id, {connectionId, viewDigest: digest ?? service.ownerView(id).viewDigest}, owner); },
    jobs() { return store.list('jobs'); },
  };
  return f;
}

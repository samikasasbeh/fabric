import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm, access, readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import http from 'node:http';
import {fileURLToPath} from 'node:url';
import {createApp} from '../server.mjs';
import {resolveHelperDirectory} from '../lib/helper-directory.mjs';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const APPS = [
  {id:'notes-fixture', name:'Synthetic Notes', field:'Note content', button:'Save note', textarea:true, value:'A note saved through Fabric'},
  {id:'tasks-fixture', name:'Synthetic Tasks', field:'Task title', button:'Add task', value:'Review the connection design'},
  {id:'settings-fixture', name:'Synthetic Settings', field:'Display name', button:'Save settings', value:'Fabric fixture user'},
].map(app=>({...app, origin:`https://${app.id}.fabric.test`}));

async function fabricFixture(t) {
  const dataDir = await mkdtemp(path.join(tmpdir(), 'fabric-access-foundation-'));
  const app = await createApp({dataDir, request:async()=>{throw new Error('No external accounts in this fixture.');}});
  t.after(async()=>{await app.close(); await rm(dataDir, {recursive:true, force:true});});
  const linked = APPS.map(definition=>{
    app.store.put('applications', {id:definition.id, name:definition.name, webOrigins:[definition.origin], apiOrigins:[]});
    const pairing = app.browser.createPair(definition.id);
    return {definition, ...app.browser.pair({code:pairing.code, origin:definition.origin, bridgeVersion:'0.2'})};
  });
  const bindings = linked.flatMap(({definition, connection})=>['observe.v1','read.v1','fill.v2','click.v2'].map(operation=>({connectionId:connection.id, capabilityId:`${definition.id}.browser.${operation}`})));
  // Deliberately precedes browser discovery/startup: the unsupported-route
  // regression must fail even on machines without a Chromium installation.
  const grant = app.protocol.createClient({name:'Synthetic agent — owner approval required', bindings});
  return {app, linked, bindings, grant};
}

test('access foundation lets a scoped client request bounded browser actions without granting self-approval', async t=>{
  const {app, grant} = await fabricFixture(t);
  assert.equal(grant.client.bindings.length, 12);
  assert.equal(app.store.list('jobs').length, 0);
  assert.equal(app.store.list('browserCommands').length, 0);
});

const escapeHTML = value=>String(value).replace(/[&<>"']/g, character=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
function htmlFor(app, state) {
  const field = app.textarea ? `<textarea id="editor" name="value">${escapeHTML(state.value)}</textarea>` : `<input id="editor" name="value" type="text" value="${escapeHTML(state.value)}">`;
  return `<!doctype html><meta charset="utf-8"><title>${escapeHTML(app.name)}</title>
    <style>body{font:16px system-ui;margin:32px}label,input,textarea,button{display:block;margin:16px 0}textarea,input{width:360px}textarea{height:100px}</style>
    <h1>${escapeHTML(app.name)}</h1><main id="stored">${escapeHTML(state.value || 'Nothing saved yet')}</main>
    <form id="editor-form" action="/save" method="post"><label for="editor">${escapeHTML(app.field)}</label>${field}<button id="commit" type="submit">${escapeHTML(app.button)}</button></form><p id="save-status">Ready</p>
    <script>document.querySelector('#editor-form').addEventListener('submit',async event=>{event.preventDefault();const response=await fetch('/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({value:document.querySelector('#editor').value})});if(!response.ok)throw new Error('Fixture save failed');const state=await response.json();document.querySelector('#stored').textContent=state.value;document.querySelector('#save-status').textContent='Saved '+state.writes;});</script>`;
}

async function independentApplications(t) {
  const states = new Map(APPS.map(app=>[app.id, {value:'', writes:0}]));
  const server = http.createServer(async(req, res)=>{
    const [appId, operation=''] = new URL(req.url, 'http://fixture.invalid').pathname.split('/').filter(Boolean);
    const app = APPS.find(item=>item.id === appId), state = states.get(appId);
    const reply = (status, type, body)=>{res.writeHead(status, {'Content-Type':type, 'Cache-Control':'no-store'});res.end(body);};
    if (!app) return reply(404, 'text/plain', 'Unknown fixture');
    try {
      if (req.method === 'GET' && !operation) return reply(200, 'text/html', htmlFor(app, state));
      if (req.method === 'GET' && operation === 'state') return reply(200, 'application/json', JSON.stringify(state));
      if (req.method !== 'POST' || operation !== 'save') return reply(404, 'text/plain', 'Unknown fixture operation');
      const chunks = []; let length = 0;
      for await (const chunk of req) {length += chunk.length; if (length > 2000) throw new Error('Fixture body too large'); chunks.push(chunk);}
      const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (typeof data.value !== 'string' || data.value.length > 500 || Object.keys(data).some(key=>key !== 'value')) throw new Error('Invalid fixture input');
      state.value = data.value; state.writes++;
      return reply(200, 'application/json', JSON.stringify(state));
    } catch {return reply(400, 'text/plain', 'Invalid fixture request');}
  });
  let listening = false;
  t.after(async()=>{if(listening) {server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}});
  await new Promise((resolve, reject)=>{server.once('error', reject);server.listen(0, '127.0.0.1', ()=>{listening = true;resolve();});});
  const origin = `http://127.0.0.1:${server.address().port}`;
  return {
    read:async appId=>{const response = await fetch(`${origin}/${appId}/state`);assert.equal(response.status, 200);return response.json();},
    route:async route=>{
      const request = route.request(), url = new URL(request.url()), app = APPS.find(item=>item.origin === url.origin);
      if (!app || !['GET','POST'].includes(request.method())) return route.abort();
      // No third-party API integration, credentials or internet request: a
      // genuine page request reaches the fixture server and its bytes return.
      const response = await fetch(`${origin}/${app.id}${url.pathname}${url.search}`, {method:request.method(), redirect:'manual', headers:{'Content-Type':request.headers()['content-type'] || 'text/plain'}, ...(request.method() === 'POST' ? {body:request.postDataBuffer()} : {})});
      return route.fulfill({status:response.status, contentType:response.headers.get('content-type'), body:Buffer.from(await response.arrayBuffer())});
    },
  };
}

async function isolatedHelper(context, page, observeSource) {
  const cdp = await context.newCDPSession(page); await cdp.send('Page.enable');
  let executionContextId;
  page.on('framenavigated', frame=>{if (frame === page.mainFrame()) executionContextId = undefined;});
  return async(command, origin)=>{
    if (!executionContextId) {
      const {frameTree} = await cdp.send('Page.getFrameTree');
      ({executionContextId} = await cdp.send('Page.createIsolatedWorld', {frameId:frameTree.frame.id, worldName:'Fabric exact helper transport fixture'}));
    }
    const response = await cdp.send('Runtime.evaluate', {contextId:executionContextId, expression:`(${observeSource})(${JSON.stringify(command)},${JSON.stringify(origin)})`, returnByValue:true, awaitPromise:true});
    assert.equal(response.exceptionDetails, undefined, 'Exact helper function must run in Chromium isolated world');
    assert.ok(response.result.value && typeof response.result.value.ok === 'boolean');
    return response.result.value;
  };
}

// This is an explicit transport harness, NOT an installed-extension E2E test.
// Real Chromium executes the exact helper function in an isolated world. The
// existing BrowserBridge polling/result contract is relayed in-process. App
// writes reach a separate real HTTP server and are independently read back.
// A scripted scoped client drives the agent interface; no LLM is used here.
test('real Chromium: scoped agent observes and requests approved Notes, Tasks and Settings writes that survive reload', {timeout:120000}, async t=>{
  const {app, linked, bindings, grant} = await fabricFixture(t);
  let chromium;
  try {({chromium}=await import('playwright'));await access(chromium.executablePath());}
  catch(error) {if (process.env.FABRIC_REQUIRE_BROWSER_TEST === '1') throw error;t.skip('Install Chromium to run real-browser access proof; FABRIC_REQUIRE_BROWSER_TEST=1 makes absence fail.');return;}
  const helper = await resolveHelperDirectory({root:ROOT});assert.equal(helper.status, 'ready');
  const source = await readFile(path.join(helper.directory, 'background.js'), 'utf8');
  const start = source.indexOf('function observe('), end = source.indexOf('\nfunction extensionPage(', start);
  assert.ok(start >= 0 && end > start, 'Use the actual self-contained helper implementation, never a test copy');
  const observeSource = source.slice(start, end);
  const fixtures = await independentApplications(t);
  const browser = await chromium.launch({headless:true, chromiumSandbox:true});
  t.after(()=>browser.close());
  const context = await browser.newContext({serviceWorkers:'block'});await context.route('**/*', fixtures.route);
  let sequence = 0;
  const invoke = (method, params={}, id=`fixture-request-${++sequence}`, token=grant.token)=>app.protocol.handle(`Bearer ${token}`, {protocol:'fabric/0.1', id, method, params});
  const request = async(link, operation, args={}, id=`fixture-request-${++sequence}`, token=grant.token, client=grant.client)=>{
    const capabilityId = `${link.definition.id}.browser.${operation}`, definitionHash = client.bindings.find(binding=>binding.connectionId === link.connection.id && binding.capabilityId === capabilityId).definitionHash;
    return invoke('calls.create', {connectionId:link.connection.id, capabilityId, definitionHash, args}, id, token);
  };
  const ownAndRelay = async(link, pending, runHelper)=>{
    assert.equal(pending.error, undefined, pending.error?.message);
    assert.equal(pending.result.status, 'awaiting_approval');
    assert.equal(Object.hasOwn(pending.result, 'approvalDigest'), false);
    const job = app.store.get('jobs', pending.result.id);
    const approval = app.runtime.approve(job.id, job.approvalDigest);approval.catch(()=>{});
    let command;
    for (let attempt = 0; attempt < 20 && !command; attempt++) {({command} = app.browser.poll(link.token));if (!command) await new Promise(resolve=>setImmediate(resolve));}
    assert.ok(command, 'Owner approval queued exactly one browser command');
    const result = await runHelper(command, link.definition.origin);
    assert.equal(result.ok, true, result.error);
    assert.equal(app.browser.result(link.token, {id:command.id, ...result}).accepted, true);
    const completed = await approval;
    return {job:completed, data:completed.result?.data};
  };
  const observe = async(link, runHelper)=>{
    const completed = await ownAndRelay(link, await request(link, 'observe.v1'), runHelper);
    assert.equal(completed.job.status, 'succeeded');assert.equal(completed.job.result.verification.kind, 'paired-browser-dom');
    return completed.data;
  };
  let last;
  for (const link of linked) {
    const definition = link.definition, page = await context.newPage();await page.goto(definition.origin);
    const runHelper = await isolatedHelper(context, page, observeSource);
    assert.deepEqual(await fixtures.read(definition.id), {value:'', writes:0});
    const fabricated = await request(link, 'fill.v2', {snapshotId:'invented', targetId:'invented', value:'not allowed'});
    assert.ok(fabricated.error, 'Client cannot invent a prior observation');
    const inspection = await observe(link, runHelper);
    const field = inspection.controls.find(control=>control.label === definition.field && control.canFill);
    assert.ok(field, 'Field capability comes from the actual visible DOM');
    assert.equal(await page.evaluate(()=>Boolean(globalThis.__fabricSnapshotV2)), false, 'Snapshot state is isolated from application JavaScript');

    if (definition.id === APPS[0].id) {
      const other = app.protocol.createClient({name:'Other synthetic agent with no prior observation', bindings});
      const stolen = await request(link, 'fill.v2', {snapshotId:inspection.snapshotId, targetId:field.targetId, value:'not allowed'}, 'other-client-snapshot', other.token, other.client);
      assert.ok(stolen.error, 'An independently scoped client cannot reuse this client’s observation');
    }
    const fillArgs = {snapshotId:inspection.snapshotId, targetId:field.targetId, value:definition.value}, fillId = `${definition.id}-fill`;
    const fill = await request(link, 'fill.v2', fillArgs, fillId);
    assert.equal(fill.error, undefined, fill.error?.message);
    assert.equal(fill.result.status, 'awaiting_approval');
    assert.equal(await page.locator('#editor').inputValue(), '');
    assert.deepEqual(await fixtures.read(definition.id), {value:'', writes:0});
    assert.equal(app.browser.poll(link.token).command, null, 'No browser write before owner approval');
    const preview = app.store.get('jobs', fill.result.id).preview.browserTarget;
    assert.equal(preview.label, definition.field);assert.equal(preview.origin, definition.origin);assert.equal(preview.operation, 'fill');
    const selfApproval = await invoke('calls.approve', {callId:fill.result.id});assert.equal(selfApproval.error.code, 'method_not_found');
    const duplicate = await request(link, 'fill.v2', fillArgs, fillId);assert.equal(duplicate.result.id, fill.result.id);
    const filled = await ownAndRelay(link, fill, runHelper);
    assert.equal(filled.job.status, 'uncertain');assert.equal(filled.job.result.verification.status, 'unverified');
    assert.equal(await page.locator('#editor').inputValue(), definition.value);
    assert.deepEqual(await fixtures.read(definition.id), {value:'', writes:0}, 'Filling a field is not a saved application change');
    const replayedFill = await request(link, 'fill.v2', fillArgs, fillId);assert.equal(replayedFill.result.id, fill.result.id);assert.equal(app.browser.poll(link.token).command, null);

    const afterFill = await observe(link, runHelper);
    const button = afterFill.controls.find(control=>control.label === definition.button && control.canClick);assert.ok(button);
    const clickArgs = {snapshotId:afterFill.snapshotId, targetId:button.targetId}, clickId = `${definition.id}-save`;
    const click = await request(link, 'click.v2', clickArgs, clickId);
    assert.equal(click.error, undefined, click.error?.message);assert.equal(click.result.status, 'awaiting_approval');
    assert.equal(app.store.get('jobs', click.result.id).preview.browserTarget.label, definition.button);
    assert.equal((await fixtures.read(definition.id)).writes, 0);assert.equal(app.browser.poll(link.token).command, null);
    const clicked = await ownAndRelay(link, click, runHelper);
    assert.equal(clicked.job.status, 'uncertain');assert.equal(clicked.job.result.data.persistentEffect, 'unverified');
    await page.waitForFunction(()=>document.querySelector('#save-status').textContent === 'Saved 1');
    assert.deepEqual(await fixtures.read(definition.id), {value:definition.value, writes:1}, 'Independent fixture server, not Fabric/DOM assertion, confirms persistence');
    const duplicateClick = await request(link, 'click.v2', clickArgs, clickId);assert.equal(duplicateClick.result.id, click.result.id);assert.equal(app.browser.poll(link.token).command, null);
    await page.reload();
    const read = await ownAndRelay(link, await request(link, 'read.v1', {selector:'#stored'}), runHelper);
    assert.equal(read.job.status, 'succeeded');assert.equal(read.data.text, definition.value);
    assert.equal(app.browser.getConnectionEvidence(link.connection).account.verified, false);
    assert.equal(app.store.get('jobs', click.result.id).status, 'uncertain', 'Read-back does not retroactively manufacture generic action verification');
    assert.deepEqual(await fixtures.read(definition.id), {value:definition.value, writes:1});
    last = {link, page, runHelper};
  }
  const inspection = await observe(last.link, last.runHelper), field = inspection.controls.find(control=>control.canFill);
  const pending = await request(last.link, 'fill.v2', {snapshotId:inspection.snapshotId, targetId:field.targetId, value:'revoked request'});
  assert.equal(pending.result.status, 'awaiting_approval');
  const ownerJob = app.store.get('jobs', pending.result.id);app.protocol.revokeClient(grant.client.id);
  const revoked = await app.runtime.approve(ownerJob.id, ownerJob.approvalDigest);
  assert.equal(revoked.status, 'failed');assert.equal(app.browser.poll(last.link.token).command, null);
  assert.equal(await last.page.locator('#editor').inputValue(), last.link.definition.value);
  assert.deepEqual(await fixtures.read(last.link.definition.id), {value:last.link.definition.value, writes:1});
  t.diagnostic('Real Chromium proof: 3 synthetic apps; 3 independent backend saves; no third-party accounts or API credentials. Exact helper isolated-world execution with an in-process BrowserBridge transport relay, not installed-extension E2E.');
});

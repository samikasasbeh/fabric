import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../lib/store.mjs';
import { AdapterFactory } from '../lib/adapter-factory.mjs';
import { Runtime } from '../lib/runtime.mjs';
import { safeRequest } from '../lib/network.mjs';

// Real HTTPS descriptions and one public GET, never an account fixture passed
// off as a live connection. No .env, user store, credential or OAuth access.
const apps = [
  { id: 'public-google-discovery', name: 'Google API Discovery', apiOrigins: ['https://www.googleapis.com'], discovery: { kind: 'google-discovery', url: 'https://www.googleapis.com/discovery/v1/apis/discovery/v1/rest' } },
  { id: 'public-google-calendar', name: 'Google Calendar interface only', apiOrigins: ['https://www.googleapis.com', 'https://calendar.googleapis.com'], discovery: { kind: 'google-discovery', url: 'https://www.googleapis.com/discovery/v1/apis/calendar/v3/rest' } },
  { id: 'public-swagger-petstore', name: 'Swagger public example interface only', apiOrigins: ['https://petstore3.swagger.io'], discovery: { kind: 'openapi', url: 'https://petstore3.swagger.io/api/v3/openapi.json' } },
];
const dataDir = await mkdtemp(join(tmpdir(), 'fabric-public-adapter-proof-'));
const store = new Store({ dataDir });
const summaries = [];
try {
  const factory = new AdapterFactory({ store, catalog: () => apps });
  for (const app of apps) {
    const report = await factory.build({ appId: app.id });
    summaries.push({ appId: app.id, status: report.status, source: report.source, counts: report.counts || null, unsupported: report.unsupported.length, error: report.error || null, examplesOfUnsupported: report.unsupported.slice(0, 3).map(item => ({ operationId: item.operationId, reason: item.reason })), accountVerified: false });
  }
  const build = factory.list({ appId: apps[0].id })[0];
  assert.equal(build.status, 'built', build.error);
  const artifact = build.capabilities.find(cap => cap.operationId === 'discovery.apis.list');
  assert.ok(artifact, 'The observed Google schema did not produce the expected public list operation.');
  const candidate = store.get('capabilities', artifact.id);
  assert.equal(candidate.request.method, 'GET');
  assert.equal(candidate.request.url, 'https://www.googleapis.com/discovery/v1/apis');
  assert.equal(store.list('connections').length, 0);
  assert.equal(store.list('permissions').length, 0);

  // Explicit, narrowly reviewed activation in this disposable verification
  // store only. This is not a feature that silently grants public or user access.
  store.put('capabilities', { ...candidate, status: 'active' });
  const connection = store.put('connections', { id: 'public-google-discovery-proof', appId: apps[0].id, driver: 'http', authMethod: 'public-no-auth', status: 'ready', identity: { kind: 'public-endpoint', displayName: 'Unauthenticated Google API Directory, not a user account' }, createdAt: new Date().toISOString() });
  const runtime = new Runtime({ store, connections: { credentials: async id => { assert.equal(id, connection.id); return { headers: {}, allowedOrigins: ['https://www.googleapis.com'] }; } }, request: safeRequest });
  const job = await runtime.createJob({ connectionId: connection.id, capabilityId: candidate.id, args: { name: 'discovery', preferred: true }, source: { kind: 'user' } });
  assert.equal(job.status, 'succeeded', job.error);
  assert.equal(job.result.verification.status, 'observed');
  assert.equal(job.result.data?.kind, 'discovery#directoryList');
  assert.ok(job.result.data.items?.some(item => item.name === 'discovery'));
  const recorded = factory.recordExecution({ buildId: build.id, jobId: job.id });
  assert.equal(recorded.accountVerified, false);
  console.log(JSON.stringify({ schemaObservations: summaries, publicRead: recorded.executions[0], responseCheck: { kind: job.result.data.kind, matchingServices: job.result.data.items.filter(item => item.name === 'discovery').length }, authenticatedAccountsTested: 0, accountDataRequests: 0, liveStoreTouched: false }, null, 2));
  if (summaries.filter(item => item.status === 'built').length < 2) process.exitCode = 1;
} catch (cause) {
  console.error(JSON.stringify({ schemaObservations: summaries, verificationFailed: String(cause.message).slice(0, 800), authenticatedAccountsTested: 0, liveStoreTouched: false }, null, 2));
  process.exitCode = 1;
} finally {
  store.close();
  // Exact path returned by mkdtemp above, never a user-selected path.
  await rm(dataDir, { recursive: true, force: true });
}

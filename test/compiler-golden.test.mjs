import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadManifest, runCoverage, failureClass, singleOperationDocument} from '../scripts/coverage.mjs';

// F09.0 zero churn (docs/F09-COMPILER-COVERAGE.md I1). The baseline records what today's code compiles from the
// hand-written coverage fixtures and the examples. A later slice may add candidates freely. Changing or removing
// anything that compiled needs an entry under `changes` with its slice and reason, and every entry must be in effect.
const FOLDER = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'coverage');
const GOLDEN = JSON.parse(await readFile(path.join(FOLDER, 'golden.json'), 'utf8'));
const SPECS = await loadManifest(path.join(FOLDER, 'manifest.json'));
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/** Every difference from the baseline that no listed change explains, and every listed change not in effect. */
function churn(baseline, current, changes) {
  const problems = [], used = new Set();
  const listed = (appId, key, kind) => {
    const index = changes.findIndex(change => change.app === appId && change.operation === key && change.change === kind);
    if (index >= 0) used.add(index);
    return index >= 0 ? changes[index] : null;
  };
  for (const [appId, expected] of Object.entries(baseline)) {
    const now = current[appId];
    if (!now) { problems.push(`${appId}: fixture missing from the current run`); continue; }
    for (const id of expected.direct?.capabilityIds || []) {
      if ((now.direct?.capabilityIds || []).includes(id)) continue;
      if (!listed(appId, `direct:${id}`, 'refused')) problems.push(`${appId}: direct import no longer compiles ${id}`);
    }
    if (!expected.discovery.operations) continue;
    for (const [id, before] of Object.entries(expected.discovery.operations)) {
      const after = now.discovery.operations?.[id];
      if (!after) { problems.push(`${appId}: operation ${id} disappeared from discovery`); continue; }
      if (before.support !== 'candidate') continue;
      if (after.support !== 'candidate') { if (!listed(appId, id, 'refused')) problems.push(`${appId}: ${id} no longer compiles (${after.failure})`); continue; }
      if (after.capabilityId !== before.capabilityId && !listed(appId, id, 'id')) problems.push(`${appId}: ${id} changed capability id`);
      if (!same(after.scopeSets, before.scopeSets) && !listed(appId, id, 'scopes')) problems.push(`${appId}: ${id} changed scope sets`);
      if (after.defaultMode !== before.defaultMode) {
        const change = listed(appId, id, 'default');
        if (!change) problems.push(`${appId}: ${id} default changed from ${before.defaultMode} to ${after.defaultMode}`);
        else if (change.to !== after.defaultMode) problems.push(`${appId}: ${id} default is ${after.defaultMode}, listed as ${change.to}`);
      }
    }
  }
  changes.forEach((change, index) => {
    if (!change.slice || !change.reason) problems.push(`change ${index} needs a slice and a reason`);
    if (!used.has(index)) problems.push(`change ${index} (${change.app} ${change.operation} ${change.change}) is listed but not in effect`);
  });
  return problems;
}

async function currentRun() {
  const current = {};
  for (const spec of SPECS) {
    const result = await runCoverage(spec);
    current[spec.appId] = {
      ...(result.direct ? {direct: result.direct.capabilityIds ? {capabilityIds: result.direct.capabilityIds} : {error: result.direct.error}} : {}),
      discovery: result.discovery.operations ? {operations: Object.fromEntries(result.discovery.operations.map(operation => [operation.id, operation.support === 'candidate'
        ? {support: operation.support, capabilityId: operation.capabilityId, scopeSets: operation.scopeSets, defaultMode: operation.defaultMode}
        : {support: operation.support, failure: operation.failure}]))} : {error: result.discovery.error},
    };
  }
  return current;
}

test('zero churn: everything that compiled at the baseline still compiles the same, or is a listed deliberate change', async () => {
  assert.deepEqual(churn(GOLDEN.baseline, await currentRun(), GOLDEN.changes), []);
});

test('the churn check catches a changed id, a lost operation, a stricter default and a stale listed change', () => {
  const baseline = {app: {direct: {capabilityIds: ['app.a.1', 'app.b.2']}, discovery: {operations: {a: {support: 'candidate', capabilityId: 'app.a.1', scopeSets: [['r']], defaultMode: 'allow'}, b: {support: 'unsupported', failure: 'x'}}}}};
  const clean = {app: {direct: {capabilityIds: ['app.a.1', 'app.b.2']}, discovery: {operations: {a: {support: 'candidate', capabilityId: 'app.a.1', scopeSets: [['r']], defaultMode: 'allow'}, b: {support: 'candidate', capabilityId: 'app.b.9', scopeSets: [], defaultMode: 'allow'}}}}};
  assert.deepEqual(churn(baseline, clean, []), [], 'growth (b now compiles) needs no listing');
  const mutate = edit => { const copy = structuredClone(clean); edit(copy.app); return copy; };
  assert.match(churn(baseline, mutate(app => {app.discovery.operations.a.capabilityId = 'app.a.2';}), []).join(), /changed capability id/);
  assert.match(churn(baseline, mutate(app => {app.discovery.operations.a.scopeSets = [['w']];}), []).join(), /changed scope sets/);
  assert.match(churn(baseline, mutate(app => {app.discovery.operations.a.defaultMode = 'ask';}), []).join(), /default changed from allow to ask/);
  assert.match(churn(baseline, mutate(app => {app.discovery.operations.a = {support: 'unsupported', failure: 'y'};}), []).join(), /no longer compiles/);
  assert.match(churn(baseline, mutate(app => {delete app.discovery.operations.a;}), []).join(), /disappeared/);
  assert.match(churn(baseline, mutate(app => {app.direct.capabilityIds = ['app.a.1'];}), []).join(), /direct import no longer compiles app.b.2/);
  assert.deepEqual(churn(baseline, mutate(app => {app.discovery.operations.a.defaultMode = 'ask';}), [{app: 'app', operation: 'a', change: 'default', to: 'ask', slice: 'F09.1', reason: 'r'}]), []);
  assert.match(churn(baseline, mutate(app => {app.discovery.operations.a.defaultMode = 'deny';}), [{app: 'app', operation: 'a', change: 'default', to: 'ask', slice: 'F09.1', reason: 'r'}]).join(), /listed as ask/);
  assert.match(churn(baseline, clean, [{app: 'app', operation: 'a', change: 'refused', slice: 'F09.1', reason: 'r'}]).join(), /listed but not in effect/);
  assert.match(churn(baseline, mutate(app => {app.discovery.operations.a = {support: 'unsupported', failure: 'y'};}), [{app: 'app', operation: 'a', change: 'refused'}]).join(), /needs a slice and a reason/);
});

test('the harness reads local files only, never fetches, and is deterministic', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-coverage-'));
  t.after(() => rm(dir, {recursive: true, force: true}));
  for (const file of ['https://example.com/openapi.json', 'file:///etc/hosts', 'HTTP://example.com/x.json']) {
    await writeFile(path.join(dir, 'manifest.json'), JSON.stringify([{appId: 'x', file, sourceUrl: 'https://specs.example.com/x.json', apiOrigins: ['https://api.example.com']}]));
    await assert.rejects(loadManifest(path.join(dir, 'manifest.json')), /reads local files only and never fetches/, file);
  }
  const original = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('The coverage harness must not fetch.'); };
  t.after(() => { globalThis.fetch = original; });
  const spec = SPECS.find(item => item.appId === 'coverage');
  const first = await runCoverage(spec, {perOperation: true}), second = await runCoverage(spec, {perOperation: true});
  assert.deepEqual(first, second);
  const whole = new Set(first.discovery.operations.map(operation => operation.capabilityId).filter(Boolean));
  const single = new Set(first.perOperation.operations.map(operation => operation.capabilityId).filter(Boolean));
  assert.deepEqual([...single].sort(), [...whole].sort(), 'one operation alone compiles exactly as it does inside its document');
});

test('single-operation documents keep only what the operation references, and failures fall into stable classes', () => {
  const document = {openapi: '3.0.3', info: {title: 't', version: '1'}, servers: [{url: 'https://api.example.com'}], security: [{s: []}],
    components: {securitySchemes: {s: {type: 'http', scheme: 'bearer'}}, schemas: {A: {type: 'object', properties: {b: {$ref: '#/components/schemas/B'}}}, B: {type: 'string'}, Unused: {type: 'string'}}},
    paths: {'/a': {post: {requestBody: {content: {'application/json': {schema: {$ref: '#/components/schemas/A'}}}}, responses: {}}}, '/other': {get: {responses: {}}}}};
  const single = singleOperationDocument(document, '/a', 'post');
  assert.deepEqual(Object.keys(single.paths), ['/a']);
  assert.deepEqual(Object.keys(single.components.schemas).sort(), ['A', 'B']);
  assert.deepEqual(single.components.securitySchemes, document.components.securitySchemes);
  assert.equal(failureClass('Skipped GET /x: GET /x:q: unsupported schema keyword example'), 'schema: annotation');
  assert.equal(failureClass('Skipped POST /y: POST /y:body: unsupported schema keyword oneOf'), 'schema: oneOf');
  assert.equal(failureClass('Security scheme k is not supported by the bearer-credential broker.'), 'auth: scheme not servable');
  assert.equal(failureClass('Something new'), 'other: Something new');
});

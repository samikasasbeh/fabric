import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, readFile, writeFile, rm, symlink, mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {buildBatchFile, runIntegrationPipelineCLI} from '../scripts/integration-pipeline.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const example = JSON.parse(await readFile(new URL('../examples/integration-batch.json', import.meta.url), 'utf8'));
const github = JSON.parse(await readFile(new URL('../examples/github.openapi.json', import.meta.url), 'utf8'));

async function fixture(t, batch = structuredClone(example)) {
  const directory = await mkdtemp(path.join(tmpdir(), 'fabric-pipeline-cli-'));
  t.after(() => rm(directory, {recursive: true, force: true}));
  await writeFile(path.join(directory, 'batch.json'), JSON.stringify(batch));
  await writeFile(path.join(directory, 'github.openapi.json'), JSON.stringify(github));
  return {directory, file: path.join(directory, 'batch.json')};
}

const capture = () => {
  const result = {out: '', err: ''};
  return {result, stdout: {write: text => { result.out += text; }}, stderr: {write: text => { result.err += text; }}};
};

test('offline batch builds both existing authored subsets without runtime access', async () => {
  const report = await buildBatchFile('examples/integration-batch.json', {cwd: root});
  assert.equal(report.counts.total, 2);
  assert.equal(report.counts.candidate, 2);
  assert.equal(report.counts.blocked, 0);
  assert.equal(report.counts.capabilities, 9);
  for (const result of report.results) {
    assert.equal(result.status, 'candidate');
    assert.ok(result.package.requiredGates.length > 0);
    assert.ok(result.package.capabilities.every(capability => capability.status === 'candidate'));
  }
});

test('CLI runs before the local-server branch and does not need Fabric running', () => {
  const result = spawnSync(process.execPath, ['cli.mjs', 'pipeline', 'build', 'examples/integration-batch.json'], {
    cwd: root, env: {...process.env, FABRIC_URL: 'intentionally-invalid-no-runtime-needed'}, encoding: 'utf8', timeout: 10000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).counts.capabilities, 9);
});

test('CLI help and usage do not attempt a batch or runtime request', async () => {
  for (const args of [['--help'], [], ['publish', 'batch.json'], ['build', 'batch.json', '--activate']]) {
    const io = capture();
    const code = await runIntegrationPipelineCLI(args, io);
    assert.equal(code, args[0] === '--help' ? 0 : 2);
    assert.match(io.result.out + io.result.err, /Offline intake only/);
  }
});

test('one missing source does not discard the valid integration', async t => {
  const {directory} = await fixture(t);
  const io = capture();
  const code = await runIntegrationPipelineCLI(['build', 'batch.json'], {...io, cwd: directory});
  assert.equal(code, 1);
  const report = JSON.parse(io.result.out);
  assert.deepEqual(report.counts, {total: 2, candidate: 1, blocked: 1, capabilities: 4});
  assert.equal(report.results[1].intakeError.code, 'source_unavailable');
  assert.equal(io.result.err, '');
});

test('batch manifest rejects unknown fields and excessive entries', async t => {
  const {file} = await fixture(t);
  for (const batch of [[], null, {...example, execute: true}, {...example, schemaVersion: 2}, {...example, integrations: []}, {...example, integrations: Array(26).fill(example.integrations[0])}]) {
    await writeFile(file, JSON.stringify(batch));
    await assert.rejects(buildBatchFile(file), error => error.code === 'batch_format');
  }
});

test('entry paths reject traversal absolute paths and non-JSON files', async t => {
  const {file} = await fixture(t);
  for (const documentPath of ['../secret.json', '/tmp/secret.json', 'nested/../../secret.json', './github.openapi.json', 'github.openapi.json/../secret.json', 'secret.env', 'https://example.com/spec.json', 'folder\\secret.json']) {
    await writeFile(file, JSON.stringify({schemaVersion: 1, integrations: [{...example.integrations[0], documentPath}]}));
    const report = await buildBatchFile(file);
    assert.equal(report.counts.blocked, 1, documentPath);
    assert.equal(report.results[0].intakeError.code, 'source_path', documentPath);
  }
});

test('entry source symlinks are rejected even within the batch folder', async t => {
  const {directory, file} = await fixture(t);
  await symlink(path.join(directory, 'github.openapi.json'), path.join(directory, 'alias.json'));
  await writeFile(file, JSON.stringify({schemaVersion: 1, integrations: [{...example.integrations[0], documentPath: 'alias.json'}]}));
  const report = await buildBatchFile(file);
  assert.equal(report.results[0].intakeError.code, 'source_path');
  assert.equal(report.counts.candidate, 0);
});

test('batch symlinks and directories are not accepted as input files', async t => {
  const {directory, file} = await fixture(t);
  const alias = path.join(directory, 'alias.json');
  await symlink(file, alias);
  await assert.rejects(buildBatchFile(alias), error => error.code === 'source_type');
  await assert.rejects(buildBatchFile(directory), error => error.code === 'source_type');
});

test('nested regular JSON source files work', async t => {
  const {directory, file} = await fixture(t);
  await mkdir(path.join(directory, 'specs'));
  await writeFile(path.join(directory, 'specs', 'github.json'), JSON.stringify(github));
  await writeFile(file, JSON.stringify({schemaVersion: 1, integrations: [{...example.integrations[0], documentPath: 'specs/github.json'}]}));
  assert.equal((await buildBatchFile(file)).counts.candidate, 1);
});

for (const phase of ['before-open', 'after-open', 'replace-file']) {
  test(`a source ${phase} swap is blocked before reading source content`, async t => {
    const {directory} = await fixture(t);
    const batchFolder = path.join(directory, 'batch');
    await mkdir(path.join(batchFolder, 'specs'), {recursive: true});
    await mkdir(path.join(directory, 'outside'));
    const file = path.join(batchFolder, 'batch.json');
    await writeFile(file, JSON.stringify({schemaVersion: 1, integrations: [{...example.integrations[0], documentPath: 'specs/source.json'}]}));
    await writeFile(path.join(batchFolder, 'specs', 'source.json'), JSON.stringify(github));
    const outside = structuredClone(github);
    for (const item of Object.values(outside.paths)) {
      for (const operation of Object.values(item)) {
        if (operation && typeof operation === 'object' && typeof operation.operationId === 'string') operation.summary = 'OUTSIDE_DIRECTORY_PROOF';
      }
    }
    await writeFile(path.join(directory, 'outside', 'source.json'), JSON.stringify(outside));
    // A subprocess contains the deterministic filesystem interleaving and its
    // builtin hooks; no global test-runner filesystem functions are replaced.
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', `
      import fs from 'node:fs/promises';
      import path from 'node:path';
      import {syncBuiltinESMExports} from 'node:module';
      const batchFile = process.argv[1], phase = process.argv[2];
      const batchFolder = await fs.realpath(path.dirname(batchFile));
      const sourceFolder = path.join(batchFolder, 'specs');
      const source = path.join(sourceFolder, 'source.json');
      const outsideFolder = path.join(path.dirname(batchFolder), 'outside');
      const originalRealpath = fs.realpath, originalOpen = fs.open;
      let swapped = false, sourceReads = 0;
      async function swapParent() {
        swapped = true;
        await fs.rename(sourceFolder, path.join(batchFolder, 'original-specs'));
        await fs.symlink(outsideFolder, sourceFolder);
      }
      fs.realpath = async (file, ...args) => {
        const resolved = await originalRealpath(file, ...args);
        if (file === source && phase === 'before-open' && !swapped) await swapParent();
        return resolved;
      };
      fs.open = async (file, ...args) => {
        if (file === source && phase === 'replace-file' && !swapped) {
          swapped = true;
          await fs.rename(source, path.join(sourceFolder, 'original.json'));
          await fs.copyFile(path.join(outsideFolder, 'source.json'), source);
        }
        const handle = await originalOpen(file, ...args);
        if (file === source) {
          const read = handle.read.bind(handle);
          handle.read = (...args) => { sourceReads++; return read(...args); };
          if (phase === 'after-open' && !swapped) await swapParent();
        }
        return handle;
      };
      syncBuiltinESMExports();
      const {buildBatchFile} = await import('./scripts/integration-pipeline.mjs');
      const report = await buildBatchFile(batchFile);
      console.log(JSON.stringify({swapped, sourceReads, report}));
    `, file, phase], {cwd: root, encoding: 'utf8', timeout: 10000});
    assert.equal(result.status, 0, result.stderr);
    const observed = JSON.parse(result.stdout);
    assert.equal(observed.swapped, true);
    assert.equal(observed.sourceReads, 0, 'A changed source must be rejected before any source content read');
    assert.equal(observed.report.counts.candidate, 0);
    assert.equal(observed.report.results[0].status, 'blocked');
    assert.equal(observed.report.results[0].intakeError.code, 'source_changed');
  });
}

test('oversized and malformed source failures remain bounded and isolated', async t => {
  const {directory, file} = await fixture(t);
  await writeFile(path.join(directory, 'google-calendar.openapi.json'), 'x'.repeat(2 * 1024 * 1024 + 1));
  let report = await buildBatchFile(file);
  assert.equal(report.counts.candidate, 1);
  assert.equal(report.results[1].intakeError.code, 'source_size');
  await writeFile(path.join(directory, 'google-calendar.openapi.json'), '{"password":"do-not-echo-secret"');
  report = await buildBatchFile(file);
  assert.equal(report.results[1].intakeError.code, 'source_json');
  assert.equal(JSON.stringify(report).includes('do-not-echo-secret'), false);
});

test('entry extra fields fail without silently executing an instruction', async t => {
  const {file} = await fixture(t, {schemaVersion: 1, integrations: [{...example.integrations[0], command: 'do-not-run'}, example.integrations[0]]});
  const report = await buildBatchFile(file);
  assert.equal(report.results[0].status, 'blocked');
  assert.equal(report.results[0].intakeError.code, 'entry_format');
});

test('malformed top-level input is not printed in CLI errors', async t => {
  const {file} = await fixture(t);
  await writeFile(file, '{"secret":"do-not-echo-secret"');
  const io = capture();
  assert.equal(await runIntegrationPipelineCLI(['build', file], io), 1);
  assert.equal(io.result.out, '');
  assert.equal(io.result.err.includes('do-not-echo-secret'), false);
  assert.equal(JSON.parse(io.result.err).error.code, 'source_json');
});

test('manifest schema example version and maintenance fields remain documented', async () => {
  const schema = JSON.parse(await readFile(new URL('../schemas/integration.manifest.schema.json', import.meta.url), 'utf8'));
  const regex = new RegExp(schema.properties.version.pattern);
  assert.equal(regex.test('1.2.3'), true);
  assert.equal(regex.test('01.2.3'), false);
  assert.equal(regex.test('1.2.3-beta'), false);
  assert.ok(schema.properties.maintenance.required.includes('backupOwner'));
  for (const entry of example.integrations) assert.equal(regex.test(entry.manifest.version), true);
});

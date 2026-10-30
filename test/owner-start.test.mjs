import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

// Hand tests B3 and S21.3, 2026-10-30: a start Fabric refuses says one plain line, with no stack trace in front of it.
test('a second copy on the same folder stops with one plain line and no stack trace', t => {
  const folder = mkdtempSync(path.join(tmpdir(), 'fabric-owner-start-'));
  t.after(() => rmSync(folder, {recursive: true, force: true}));
  writeFileSync(path.join(folder, 'runtime.lock'), String(process.pid));
  const run = spawnSync(process.execPath, ['server.mjs'], {cwd: ROOT, encoding: 'utf8', timeout: 20_000, env: {PATH: process.env.PATH, FABRIC_DATA_DIR: folder, FABRIC_PORT: '4399'}});
  assert.equal(run.status, 1);
  assert.equal(run.stderr.trim(), `Error: Fabric is already running (PID ${process.pid}).`);
  assert.equal(run.stdout, '');
});

// Hand test B28, 2026-10-30: Element.replaceChildren() writes null as the word "null", which the workspace's Activity page showed.
test('the workspace never hands main.replaceChildren() a null at the top level', () => {
  const source = readFileSync(path.join(ROOT, 'public', 'app.js'), 'utf8');
  for (const line of source.split('\n').filter(text => text.includes('main.replaceChildren('))) {
    let depth = 1, quote = null, index = line.indexOf('main.replaceChildren(') + 'main.replaceChildren('.length;
    for (; index < line.length && depth > 0; index++) {
      const char = line[index];
      if (quote) { if (char === '\\') index++; else if (char === quote) quote = null; }
      else if ('\'"`'.includes(char)) quote = char;
      else if ('([{'.includes(char)) depth++;
      else if (')]}'.includes(char)) depth--;
      else if (depth === 1) assert.ok(!line.startsWith(': null', index), line.slice(0, 80));
    }
  }
});

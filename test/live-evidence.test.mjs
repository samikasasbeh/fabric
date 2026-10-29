import test from 'node:test';
import assert from 'node:assert/strict';
import {readdirSync, readFileSync} from 'node:fs';
import {loadActionCatalog} from '../lib/action-catalog.mjs';
import {TOKEN_PREFIXES} from '../lib/live-certify.mjs';
import {googleMap} from './fixtures/access/google-maps.mjs';

// F10.14 (branch review of step 14): what the shipped live evidence says, held in one place for every app. An action with a certified
// block is active, and only such an action: its block names its app's evidence file and the hash of exactly its definition, and that
// file holds a passing record for its id, on the current pins. Each app's own test file checks only the block's shape, so an edit of an
// action file is caught there by the behaviour it breaks, not by its id moving.
const EVIDENCE = new URL('../docs/live-evidence/', import.meta.url);
const ACTIONS = new URL('../catalog/actions/', import.meta.url);
const files = () => readdirSync(ACTIONS).filter(name => name.endsWith('.json')).map(name => JSON.parse(readFileSync(new URL(name, ACTIONS), 'utf8')));

test('a certified action is active on its own evidence, and an action without a certified block never is', () => {
  const catalog = loadActionCatalog({maps: new Map(['google-calendar', 'gmail'].map(appId => [appId, googleMap(appId)]))});
  const certified = new Set(files().flatMap(file => file.actions.filter(action => action.certified !== undefined).map(action => action.id)));
  assert.ok(certified.size >= 13, 'Calendar\'s 13 at least');
  for (const item of catalog.entries.values()) {
    const action = item.entry.action;
    assert.equal(item.status, certified.has(item.entry.id) ? 'active' : 'candidate', `${item.entry.id}: ${item.reason ?? ''}`);
    if (action.certified === undefined) continue;
    assert.deepEqual(action.certified, {evidence: `docs/live-evidence/${item.appId}/actions.json`, definitionHash: item.entry.definitionHash}, item.entry.id);
    const records = JSON.parse(readFileSync(new URL(`${item.appId}/actions.json`, EVIDENCE), 'utf8'));
    assert.deepEqual([records[item.entry.id]?.passed, records[item.entry.id]?.definitionHash], [true, item.entry.definitionHash], `${item.entry.id}: its record passed on this definition`);
  }
});

test('no shipped evidence holds an address, a token or a cookie: sign-in records and action records alike', () => {
  const walk = url => readdirSync(url, {withFileTypes: true}).flatMap(entry => entry.isDirectory() ? walk(new URL(`${entry.name}/`, url)) : entry.name.endsWith('.json') ? [new URL(entry.name, url)] : []);
  const found = walk(EVIDENCE);
  assert.ok(found.length >= 5, 'Calendar\'s actions and four sign-in files at least');
  for (const url of found) {
    const text = readFileSync(url, 'utf8'), where = url.pathname.split('/docs/')[1];
    const addresses = [...text.matchAll(/[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g)].map(match => match[0]).filter(address => !/@example\.(com|invalid)$/.test(address));
    assert.deepEqual(addresses, [], `${where}: only synthetic example addresses`);
    for (const prefix of TOKEN_PREFIXES) assert.equal(text.includes(prefix), false, `${where}: no ${prefix} token`);
    assert.doesNotMatch(text, /set-cookie|"cookie"|Bearer /i, `${where}: no cookie or bearer header`);
  }
});

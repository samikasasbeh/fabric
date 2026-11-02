import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {triggerIds} from '../lib/triggers.mjs';
import {loadActionCatalog} from '../lib/action-catalog.mjs';
import {gmailDeps} from './fixtures/actions/gmail-harness.mjs';
import {shippedTriggers} from './fixtures/actions/trigger-harness.mjs';

// Iteration 9 step 7 (docs/I07-BUILD-MAP.md, step 7): Gmail's trigger file as it ships, apart from test/triggers-gmail.test.mjs, so a fault planted in the file is caught there by what it does and not by its id.
const KEYS = ['new-inbox-email', 'label-added', 'email-sent', 'reply-on-my-thread', 'new-email-with-attachment', 'new-email-matching-search'];
const bare = list => list.map(({id: _id, ...item}) => item);

test('the shipped file is the draft with its ids computed: six candidates, none certified, so nothing is promoted before its review and its evidence', () => {
  const file = shippedTriggers('gmail'), draft = JSON.parse(readFileSync(new URL('./fixtures/docs/trigger-drafts/gmail.json', import.meta.url), 'utf8')), ids = triggerIds(file, gmailDeps());
  assert.equal(file.reviewStatus, 'candidate');
  assert.deepEqual(file.triggers.map(item => item.key), KEYS);
  for (const item of file.triggers) {
    assert.equal(item.id, ids.get(`${item.key} v1`), item.key);
    assert.equal(Object.hasOwn(item, 'certified'), false, item.key);
  }
  assert.deepEqual(bare(file.triggers), bare(draft.triggers));
});

test('the attachment card says what the owner approves: the first file\'s name, which the sender chose, and that each new message is read in full to check', () => {
  const block = shippedTriggers('gmail').triggers.find(item => item.key === 'new-email-with-attachment'), fields = Object.keys(block.event.schema.properties);
  assert.ok(fields.includes('firstFilename') && !fields.some(name => /count/i.test(name)), 'the event names the first file and counts none');
  assert.doesNotMatch(block.description, /file count/);
  assert.match(block.description, /first file's name/);
  assert.match(block.description, /reads each new message in full/);
  assert.equal(block.poll.enrich.steps[0].query.format.const, 'full', 'the one Gmail trigger that fetches a body, so the card must say so');
});

test('the real catalog loads all six and offers none: a candidate runs only in a certification Fabric', () => {
  const {triggersRefused, triggerOf} = loadActionCatalog({maps: new Map([['gmail', gmailDeps().maps.get('gmail')]])});
  assert.equal(triggersRefused.has('gmail'), false);
  for (const {id} of shippedTriggers('gmail').triggers) assert.equal(triggerOf(id).status, 'candidate', id);
});

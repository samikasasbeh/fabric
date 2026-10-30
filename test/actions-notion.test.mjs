import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {validateActionFile} from '../lib/actions.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {createGuard, RULES, NOTION_PERMANENT_DELETE} from '../lib/live-guard.mjs';
import {checkPlan, evidenceRecords, fillPlaceholders} from '../lib/live-certify.mjs';
import {ORIGIN as NOTION_ORIGIN} from './fixtures/provider-simulators/notion.mjs';
import {ACTION_REFUSED, PREPARED, RUN_WORDS} from '../lib/actions-runtime.mjs';
import {STATUS_WORDS} from '../lib/action-catalog.mjs';
import {FabricProtocol} from '../lib/fabric-protocol.mjs';
import {notionHarness, notionDeps, notionFile, OWNER, TOKEN} from './fixtures/actions/notion-harness.mjs';
import {caseTests} from './fixtures/provider-simulators/cases.mjs';
import {actionSchema, withIds} from './fixtures/actions/fixture-app.mjs';

// F10.19 part 2 (docs/F10.19-BUILD-MAP.md section 3, part 2): Notion's 16 reviewed actions (catalog/actions/notion.json) on the Notion
// simulator, through the action runtime, as an agent's call and the owner's approval run them, every request carrying Notion-Version
// 2026-03-11 from the shipped sign-in; and every case of Notion's simulator case list (test/fixtures/provider-simulators/notion.cases.json)
// through caseTests(). Nothing here reaches Notion. Every test reads the file with its ids recomputed (withIds()), so a seeded fault inside
// it is caught by what the action does; test/f10-19-churn.test.mjs checks the shipped ids.

const READ = {readOnly: true, destructive: false, idempotent: true, openWorld: true}, WRITE = {readOnly: false, destructive: false, idempotent: false, openWorld: true};
const TRASH = {readOnly: false, destructive: true, idempotent: true, openWorld: true}, RESTORE = {readOnly: false, destructive: true, idempotent: false, openWorld: true};
/** Section 2's table, as built: each action's row, effect and hints. Update page or row is Rename page and Update database row (section 9, as built: part 2). */
const TABLE = Object.freeze({
  search: ['notion.search.read', 'read', READ], 'read-page': ['notion.content.read', 'read', READ], 'describe-database': ['notion.content.read', 'read', READ],
  'find-rows': ['notion.content.read', 'read', READ], 'create-page': ['notion.content.create', 'write', WRITE], 'add-row': ['notion.content.create', 'write', WRITE],
  'rename-page': ['notion.content.edit', 'write', WRITE], 'update-row': ['notion.content.edit', 'write', WRITE], 'add-to-page': ['notion.content.edit', 'write', WRITE],
  'edit-page-text': ['notion.content.edit', 'write', WRITE], 'move-page': ['notion.content.edit', 'write', WRITE], 'trash-page': ['notion.content.trash', 'delete', TRASH],
  'restore-page': ['notion.content.trash', 'delete', RESTORE], comment: ['notion.comments.write', 'write', WRITE], 'read-comments': ['notion.comments.read', 'read', READ],
  'find-person': ['notion.users.read', 'read', READ]});
/** The data source every test's database holds: one property of each writable type, a formula and a created time. */
const TASKS = Object.freeze({Name: {type: 'title'}, Notes: {type: 'rich_text'}, Cost: {type: 'number'}, Done: {type: 'checkbox'}, Stage: {type: 'select', options: ['Open', 'Done']},
  State: {type: 'status', options: ['Not started', 'Finished']}, Tags: {type: 'multi_select', options: ['red', 'blue', 'green']}, Due: {type: 'date'}, Site: {type: 'url'},
  Mail: {type: 'email'}, Phone: {type: 'phone_number'}, Owner: {type: 'people'}, Link: {type: 'relation'}, Total: {type: 'formula'}, Created: {type: 'created_time'}});
const NOTION_ERROR = (status, code) => ({status, data: {object: 'error', status, code, message: `Simulated ${code}.`, request_id: '00000000-0000-4000-8000-0000000000ff'}});
const ROUTES = Object.freeze({create: 'POST /pages', patch: 'PATCH /pages/{page_id}', markdown: 'PATCH /pages/{page_id}/markdown', move: 'POST /pages/{page_id}/move',
  trash: 'DELETE /blocks/{block_id}', comment: 'POST /comments', page: 'GET /pages/{page_id}', search: 'POST /search', query: 'POST /data_sources/{data_source_id}/query',
  users: 'GET /users', comments: 'GET /comments', database: 'GET /databases/{database_id}', source: 'GET /data_sources/{data_source_id}', getMarkdown: 'GET /pages/{page_id}/markdown'});

/** Asserts how a job ended, and any of its fields. */
function ended(job, status, errorCode, extra = {}) {
  assert.deepEqual([job.status, job.errorCode ?? null], [status, errorCode], `${job.error} ${JSON.stringify(job.details ?? job.reason ?? '')}`);
  for (const [key, value] of Object.entries(extra)) assert.deepEqual(job[key], value, key);
  return job;
}
/** An action refusal: failed, action_refused, its reason (and transform) in details. */
const refusedAs = (job, reason) => { ended(job, 'failed', ACTION_REFUSED); assert.equal(job.details?.reason, reason, JSON.stringify(job.details)); return job; };
const writes = h => h.simulator.writes().map(call => call.route);
const routes = h => h.simulator.calls.map(call => call.route);
/** A write job prepared to its one card: awaiting the owner, phase final, nothing written yet. */
async function prepared(h, key, input) {
  const before = h.simulator.writes().length, job = await h.run(key, input);
  assert.deepEqual([job.status, job.action?.phase, h.simulator.writes().length], ['awaiting_approval', 'final', before], `${key}: ${job.error ?? ''} ${JSON.stringify(job.details ?? '')}`);
  return job;
}
const approved = async (h, key, input) => h.approve(await prepared(h, key, input));
/** The exact body a prepared job will send, parsed. */
const bodyOf = (h, job, index = 0) => JSON.parse(h.prepared(job).content.perform[index].body);
const stored = (h, id) => h.simulator.state().pages[id];
const titleText = page => page.properties.title?.title.map(piece => piece.plain_text).join('') ?? Object.values(page.properties).find(item => item.type === 'title').title.map(piece => piece.plain_text).join('');
const pieces = text => [{text: {content: text}}];

/** A shared top page A with a child page under it, a shared page B, an unshared page, and under A a database whose one data source holds TASKS and one row. */
function world(h) {
  const a = h.simulator.seedPage({title: '[SYNTHETIC] A', markdown: 'Hello from A', shared: true});
  const b = h.simulator.seedPage({title: '[SYNTHETIC] B', markdown: 'Hello from B', shared: true});
  const child = h.simulator.seedPage({title: 'Child', parent: {page_id: a.id}, markdown: 'Child text'});
  const {database, sources: [source]} = h.simulator.seedDatabase({title: 'Tasks', parent: {page_id: a.id}, sources: [{name: 'Tasks', properties: structuredClone(TASKS)}]});
  const row = h.simulator.seedRow({dataSource: source.id, properties: {Name: {title: pieces('Row 1')}, Stage: {select: {name: 'Open'}}, Cost: {number: 3}, Tags: {multi_select: [{name: 'red'}]}}});
  const unshared = h.simulator.seedPage({title: 'Private'});
  return {a, b, child, database, source, row, unshared};
}
const idOf = (source, name) => source.properties[name].id;

// ---- the file ---------------------------------------------------------------------------------------------------------------------------
/** Notion's shipped file with each id recomputed from its content, as an author writes them. */
const currentFile = (deps = notionDeps()) => withIds(notionFile(), deps);

// Step 20's live pass (run X4G5USDP) certified all 16, each naming the shipped evidence; that each names the hash of exactly its definition,
// with a passing record, is test/live-evidence.test.mjs's, so an edit of the file is caught here by what it breaks.
test('the file: 16 actions, each placed in its row with its effect and hints; each certified by step 20\'s evidence, no superseded id; at most 4 steps and 10 requests', () => {
  const file = currentFile(), {actions} = validateActionFile(file, notionDeps());
  assert.deepEqual(actions.map(entry => entry.key), Object.keys(TABLE));
  for (const entry of actions) {
    const [row, effect, hints] = TABLE[entry.key];
    assert.deepEqual([entry.version, entry.row, entry.effect, entry.action.hints, entry.unplaced, entry.sensitive], [1, row, effect, hints, false, false], entry.key);
    assert.ok(entry.placements.every(placement => !placement.unplaced && placement.groupId.startsWith('notion.')), entry.key);
    assert.equal(entry.placements.filter(placement => placement.phase === 'perform').at(-1).groupId, row, `${entry.key}: the last perform step lands in its row`);
    assert.deepEqual([Object.keys(entry.action.certified), entry.action.certified.evidence], [['evidence', 'definitionHash'], 'docs/live-evidence/notion/actions.json'], `${entry.key}: certified by step 20's evidence`);
    assert.ok(entry.placements.length <= 4, `${entry.key}: at most 4 steps`);
  }
  assert.deepEqual([file.specVersion, file.pinnedParameters, file.superseded, ['candidate', 'reviewed'].includes(file.reviewStatus)], ['fabric/0.2', {}, undefined, true]);
  const schema = actionSchema();
  assert.ok(schema(file), JSON.stringify(schema.errors));
  // Notion places by method and path: the file validates with no map.
  assert.deepEqual(notionDeps().maps, new Map());
  // The worst cases: Find person reads at most 10 pages, Describe database the database and 5 data sources.
  const users = actions.find(entry => entry.key === 'find-person').action.perform[0], sources = actions.find(entry => entry.key === 'describe-database').action.perform[0];
  assert.deepEqual([users.page.max, sources.forEach.max], [10, 5]);
  // Restore's PATCH lands in the trash row by its body route; Update database row and Rename page stay in the edit row.
  assert.deepEqual(actions.find(entry => entry.key === 'restore-page').placements.find(placement => placement.phase === 'perform').routedFrom?.groupId, 'notion.content.edit');
});

test('at start without live evidence: 16 candidates that never run and that no agent can be given', async t => {
  const h = notionHarness(t, {evidence: false});
  assert.deepEqual([...h.catalog.entries.values()].map(item => [item.status, item.reason]), Array(16).fill(['candidate', STATUS_WORDS.evidence]));
  assert.ok(h.store.list('capabilities').filter(capability => capability.driver === 'action').every(capability => capability.status === 'candidate'));
  await assert.rejects(h.run('search v1', {}));
  const protocol = new FabricProtocol({store: h.store, runtime: h.runtime, clock: () => h.now, origin: 'http://127.0.0.1:59996'});
  assert.throws(() => protocol.createClient({name: 'Notion agent', bindings: [{connectionId: h.account, capabilityId: h.idOf('search v1')}]}, null), {code: 'permission_denied'});
  assert.deepEqual([h.simulator.calls.length, h.store.list('clientGrants').length], [0, 0]);
});

// ---- trash and restore (spec line 1191) ------------------------------------------------------------------------------------------------
test('Restore sends exactly {"in_trash":false} and its step lands in the trash row: one Ask card in "Trash or restore pages, or replace content"; Move to trash reads back in_trash true', async t => {
  const h = notionHarness(t), {a, child} = world(h);
  const trashed = ended(await approved(h, 'trash-page v1', {page: child.url}), 'succeeded', null);
  assert.deepEqual([trashed.result.data.inTrash, trashed.result.verification.status, stored(h, child.id).in_trash], [true, 'verified', true]);
  const job = await prepared(h, 'restore-page v1', {page: child.id});
  assert.deepEqual([job.effect, job.action.writeRows, h.groups.get('notion').groups.find(group => group.id === 'notion.content.trash').label],
    ['delete', ['group:notion.content.trash'], 'Trash or restore pages, or replace content']);
  assert.deepEqual([h.card(job).effect, h.card(job).phase, h.prepared(job).content.perform[0].body], ['delete', 'final', '{"in_trash":false}']);
  assert.deepEqual(h.fields(job), {Page: 'Child', Link: child.url});
  const done = ended(await h.approve(job), 'succeeded', null);
  assert.deepEqual(h.simulator.writes().map(call => [call.route, JSON.stringify(call.body)]), [[ROUTES.trash, undefined], [ROUTES.patch, '{"in_trash":false}']]);
  assert.deepEqual([done.result.data.inTrash, done.result.verification.status, stored(h, child.id).in_trash, stored(h, a.id).in_trash], [false, 'verified', false, false]);
  // The trash card says what Notion keeps.
  assert.deepEqual(h.fields(await prepared(h, 'trash-page v1', {page: child.id})), {Page: 'Child', Link: child.url, Trash: 'Notion keeps it in its trash; Restore brings it back.'});
});

// ---- chunking (spec line 1187) ---------------------------------------------------------------------------------------------------------
test('chunking through the actions: a 4,500-character title is 3 title pieces; a comment of 100,001 emoji (200,002 UTF-16 units) refuses too_many_chunks with nothing sent', async t => {
  const h = notionHarness(t), {a} = world(h);
  const title = `[SYNTHETIC] ${'t'.repeat(4488)}`;
  const job = await prepared(h, 'create-page v1', {parent: a.url, title, content: 'Body text'});
  assert.deepEqual(bodyOf(h, job).properties.title.title.map(piece => piece.text.content.length), [2000, 2000, 500]);
  assert.deepEqual(bodyOf(h, job).parent, {page_id: a.id});
  const done = ended(await h.approve(job), 'succeeded', null);
  assert.equal(titleText(stored(h, done.result.data.id)), title, 'the whole title, never cut');
  const sent = h.simulator.calls.length;
  refusedAs(await h.run('comment v1', {page: a.id, text: '😀'.repeat(100_001)}), 'too_many_chunks');
  const renamed = refusedAs(await h.run('rename-page v1', {page: a.id, title: '😀'.repeat(100_001)}), 'too_many_chunks');
  assert.equal(renamed.details.transform, 'text.chunk@1');
  assert.deepEqual(writes(h), [ROUTES.create], 'nothing more written');
  assert.ok(h.simulator.calls.slice(sent).every(call => !call.write));
});

// ---- typed values (spec lines 1188-1190) -----------------------------------------------------------------------------------------------
test('Add database row: each writable type reaches the body typed and keyed by property id; the card names the database; it reads back the same values', async t => {
  const h = notionHarness(t), {source} = world(h), owner = h.simulator.owner.id;
  const values = {Name: '[SYNTHETIC] New row', Notes: 'Line one\nline two', Cost: 12.5, Done: true, Stage: 'Done', State: 'Finished', Tags: ['blue', 'green'], Due: {start: '2026-11-02', end: '2026-11-04'},
    Site: 'https://example.com/a', Mail: 'ann@example.com', Phone: '+1 555 0100', Owner: [owner], Link: [source.id]};
  const job = await prepared(h, 'add-row v1', {dataSource: source.id, values});
  const body = bodyOf(h, job), id = name => idOf(source, name);
  assert.deepEqual(body.parent, {type: 'data_source_id', data_source_id: source.id});
  assert.deepEqual(body.properties, Object.fromEntries([[id('Name'), {title: pieces('[SYNTHETIC] New row')}], [id('Notes'), {rich_text: pieces('Line one\nline two')}], [id('Cost'), {number: 12.5}],
    [id('Done'), {checkbox: true}], [id('Stage'), {select: {name: 'Done'}}], [id('State'), {status: {name: 'Finished'}}], [id('Tags'), {multi_select: [{name: 'blue'}, {name: 'green'}]}],
    [id('Due'), {date: {start: '2026-11-02', end: '2026-11-04'}}], [id('Site'), {url: 'https://example.com/a'}], [id('Mail'), {email: 'ann@example.com'}], [id('Phone'), {phone_number: '+1 555 0100'}],
    [id('Owner'), {people: [{object: 'user', id: owner}]}], [id('Link'), {relation: [{id: source.id}]}]].sort(([x], [y]) => x < y ? -1 : x > y ? 1 : 0)));
  assert.deepEqual(h.fields(job), {Database: 'Tasks', 'Data source': source.id});
  const done = ended(await h.approve(job), 'succeeded', null);
  assert.deepEqual([done.result.verification.status, done.result.data.parentDataSourceId, done.result.data.title], ['verified', source.id, '[SYNTHETIC] New row']);
  const row = stored(h, done.result.data.id).properties;
  assert.deepEqual([row.Stage.select.name, row.Tags.multi_select.map(option => option.name), row.Owner.people.map(person => person.id), row.Due.date.start], ['Done', ['blue', 'green'], [owner], '2026-11-02']);
});

test('Add database row and Update database row refuse a read-only property, an unknown name or an unknown option before any write (invalid_arguments)', async t => {
  const h = notionHarness(t), {source, row} = world(h);
  for (const values of [{Total: 3}, {Created: '2026-10-26'}, {Nope: 'x'}, {Stage: 'Archived'}, {Tags: ['red', 'purple']}, {State: 'Started'}, {Cost: 'three'}]) {
    ended(await h.run('add-row v1', {dataSource: source.id, values}), 'failed', 'invalid_arguments', {reason: 'values_invalid', error: RUN_WORDS.invalid_values});
    ended(await h.run('update-row v1', {page: row.id, values}), 'failed', 'invalid_arguments', {reason: 'values_invalid', error: RUN_WORDS.invalid_values});
  }
  assert.deepEqual(writes(h), [], 'nothing written');
});

test('Update database row: values typed by property id, a list replaced whole, the other values kept; the card shows the row, its database and its values now; a plain page refuses before any write', async t => {
  const h = notionHarness(t), {a, source, row} = world(h);
  const job = await prepared(h, 'update-row v1', {page: row.url, values: {Stage: 'Done', Tags: ['green'], Cost: 4}});
  assert.deepEqual(bodyOf(h, job), {properties: Object.fromEntries([[idOf(source, 'Cost'), {number: 4}], [idOf(source, 'Stage'), {select: {name: 'Done'}}], [idOf(source, 'Tags'), {multi_select: [{name: 'green'}]}]]
    .sort(([x], [y]) => x < y ? -1 : x > y ? 1 : 0))});
  const fields = h.fields(job);
  assert.deepEqual([fields.Page, fields.Link, fields.Database], ['Row 1', row.url, 'Tasks']);
  assert.match(fields['Values now'], /^Cost: 3$/m);
  assert.match(fields['Values now'], /^Stage: Open$/m);
  assert.match(fields['Values now'], /^Tags: red$/m);
  assert.match(fields['Values now'], /^Name: Row 1$/m);
  assert.equal(fields['Values now'].split('\n').length, Object.keys(TASKS).length, 'one line a property');
  const done = ended(await h.approve(job), 'succeeded', null);
  const after = stored(h, row.id).properties;
  assert.deepEqual([after.Stage.select.name, after.Tags.multi_select.map(option => option.name), after.Cost.number, after.Name.title[0].plain_text], ['Done', ['green'], 4, 'Row 1']);
  assert.deepEqual([done.result.verification.status, done.result.data.id], ['verified', row.id]);
  // A plain page has no data source: its schema read is skipped and the derive refuses, before any write. Rename page renames it.
  const plain = refusedAs(await h.run('update-row v1', {page: a.id, values: {title: 'x'}}), 'input_invalid');
  assert.deepEqual([plain.details.transform, plain.action.skipped], ['notion.schema@1', ['source']]);
  assert.deepEqual(writes(h), [ROUTES.patch]);
});

test('Rename page sends only the new title, on a plain page and on a row; the card shows the title now and the new one', async t => {
  const h = notionHarness(t), {a, row} = world(h);
  const page = await prepared(h, 'rename-page v1', {page: a.url, title: '[SYNTHETIC] A renamed'});
  assert.deepEqual(bodyOf(h, page), {properties: {title: {title: pieces('[SYNTHETIC] A renamed')}}});
  assert.deepEqual(h.fields(page), {Page: '[SYNTHETIC] A', Link: a.url, 'New title': '[SYNTHETIC] A renamed'});
  ended(await h.approve(page), 'succeeded', null);
  const onRow = ended(await approved(h, 'rename-page v1', {page: row.id, title: '[SYNTHETIC] Row renamed'}), 'succeeded', null);
  assert.deepEqual([titleText(stored(h, a.id)), stored(h, row.id).properties.Name.title[0].plain_text, stored(h, row.id).properties.Stage.select.name, onRow.result.verification.status],
    ['[SYNTHETIC] A renamed', '[SYNTHETIC] Row renamed', 'Open', 'verified']);
});

test('Update database row\'s schema at dispatch: an option added between prepare and approval ends input_schema_changed with nothing sent; a row that left its database too', async t => {
  let h = notionHarness(t), {source, row, a} = world(h);
  let job = await prepared(h, 'update-row v1', {page: row.id, values: {Stage: 'Done'}});
  h.simulator.data.sources[source.id].properties.Stage.select.options.push({id: 'new', name: 'Blocked', color: 'default', description: null});
  ended(await h.approve(job), 'failed', 'input_schema_changed', {error: RUN_WORDS.input_schema_changed});
  assert.deepEqual(writes(h), []);
  assert.equal(routes(h).filter(route => route === ROUTES.source).length, 2, 'read at prepare and again at dispatch');
  h = notionHarness(t);
  ({source, row, a} = world(h));
  job = await prepared(h, 'update-row v1', {page: row.id, values: {Stage: 'Done'}});
  h.simulator.data.pages[row.id].parent = {type: 'page_id', page_id: a.id};
  ended(await h.approve(job), 'failed', 'input_schema_changed');
  assert.deepEqual(writes(h), []);
});

// ---- markdown --------------------------------------------------------------------------------------------------------------------------
test('The read-back goes by what changed: Notion\'s rewritten text confirms, and find works with or without its backslashes', async t => {
  const h = notionHarness(t), {a} = world(h);
  const content = '[SYNTHETIC] a * b ~ c ` d $ e [f] <g> {h} | i ^ j \\ k\n\n##### H5\n* star\n1. one\n1. two\n```js\nlet a = [1];\n```\n| a | b |\n| --- | --- |\n| 1 | 2 |\n[a link](https://example.com/x) _it_';
  ended(await approved(h, 'add-to-page v1', {page: a.id, content}), 'succeeded', null);
  assert.equal(stored(h, a.id).text, `Hello from A\n${content}`);
  ended(await approved(h, 'edit-page-text v1', {page: a.id, find: '[f] <g>', replace: '[SYNTHETIC] {edited}'}), 'succeeded', null);
  ended(await approved(h, 'edit-page-text v1', {page: a.id, find: '\\[SYNTHETIC\\] \\{edited\\}', replace: ''}), 'succeeded', null);
  assert.ok(!stored(h, a.id).text.includes('edited'));
});

test('A change Notion swallowed never confirms: every form the review tried, on a page that already looks right', async t => {
  const h = notionHarness(t), {a} = world(h);
  const page = markdown => h.simulator.seedPage({title: 'Seeded', parent: {page_id: a.id}, markdown}).id;
  for (const [markdown, content] of [['[SYNTHETIC] Done', '[SYNTHETIC] Done'], ['Plan', 'a'], ['Done.', '.'], ['105 kg', '10.5 kg'], ['Pay $1,000', 'Pay 100'], ['the end\nstart here', 'end start'], ['**Status: Done**', 'Status Done']]) {
    const id = page(markdown);
    await swallowed(h, ROUTES.markdown, 'add-to-page v1', {page: id, content});
    assert.equal(stored(h, id).text, markdown);
  }
  for (const [markdown, find, replace] of [['Hello', 'Hello', '[SYNTHETIC] never there'], ['Hello', 'Hello', ''], ['$1000', '$1000', '$1,000'], ['x < 5', 'x < 5', 'x > 5'], ['one\ntwo', 'one\ntwo', 'one two'], ['[DRAFT] Plan', '[DRAFT] Plan', 'Plan'],
    ['Stage Open\nClosed Tuesday', 'Open', 'Closed'], ['foo bar', 'foo', ' '], ['Release v1.2 notes', 'v1.2', 'v12'], ['a-b', 'a-b', 'a b'], ['A\n\nB', 'A\n\nB', '']]) {
    const id = page(markdown);
    await swallowed(h, ROUTES.markdown, 'edit-page-text v1', {page: id, find, replace});
    assert.equal(stored(h, id).text, markdown);
  }
});

test('A page that changed for another reason just before a swallowed write confirms nothing: the text must show, and a removal must be gone', async t => {
  const h = notionHarness(t), {a} = world(h);
  const race = async (key, input) => {
    const job = await prepared(h, key, input), held = h.simulator.hold(ROUTES.markdown);
    h.simulator.swallow(ROUTES.markdown);
    const run = h.approve(job);
    await held.reached;
    h.simulator.data.pages[a.id].text += '\nSomeone else wrote this';
    held.release();
    return run;
  };
  assert.equal(ended(await race('add-to-page v1', {page: a.id, content: '[SYNTHETIC] never there'}), 'uncertain', 'outcome_uncertain').result.verification.status, 'unverified');
  assert.equal(ended(await race('edit-page-text v1', {page: a.id, find: 'Hello from A', replace: ''}), 'uncertain', 'outcome_uncertain').result.verification.status, 'unverified');
});

test('A page with an uploaded file reads differently every time, and that is never taken for the write', async t => {
  const h = notionHarness(t), {a} = world(h), page = h.simulator.seedPage({title: 'Files', parent: {page_id: a.id}, markdown: '[SYNTHETIC] Done\nold'});
  h.simulator.uploadFile(page.id, 'image.png');
  await swallowed(h, ROUTES.markdown, 'add-to-page v1', {page: page.id, content: '[SYNTHETIC] Done'});
  await swallowed(h, ROUTES.markdown, 'edit-page-text v1', {page: page.id, find: 'old', replace: '[SYNTHETIC] Done'});
  ended(await approved(h, 'add-to-page v1', {page: page.id, content: '[SYNTHETIC] landed'}), 'succeeded', null);
});

test('The page is read just before the write, so an edit during the approval wait is not taken for it', async t => {
  const h = notionHarness(t), {a} = world(h), held = h.simulator.seedPage({title: 'Waits', parent: {page_id: a.id}, markdown: '[SYNTHETIC] Done'});
  const job = await prepared(h, 'add-to-page v1', {page: held.id, content: '[SYNTHETIC] Done'});
  h.simulator.data.pages[held.id].text += '\nA teammate wrote this during the wait';
  h.simulator.swallow(ROUTES.markdown);
  assert.equal(ended(await h.approve(job), 'uncertain', 'outcome_uncertain').result.verification.status, 'unverified');
});

test('A read-back Notion answers in a shape the comparison refuses leaves the write unverified: true words, its output kept, never "Nothing was sent"', async t => {
  const h = notionHarness(t), {a} = world(h);
  const job = await prepared(h, 'add-to-page v1', {page: a.id, content: '[SYNTHETIC] landed'});
  h.simulator.fail('GET /pages/{page_id}/markdown', {status: 200, data: {object: 'page_markdown', id: a.id}});
  const done = ended(await h.approve(job), 'uncertain', 'outcome_uncertain', {reason: 'not_verified'});
  assert.equal(done.error, RUN_WORDS.unverified);
  assert.equal(done.result.verification.status, 'unverified');
  assert.equal(done.result.data.id, a.id);
  assert.ok(stored(h, a.id).text.endsWith('[SYNTHETIC] landed'), 'the write landed');
});

test('A landed write whose output a transform refuses never says nothing was sent', async t => {
  const h = notionHarness(t), {a} = world(h);
  const job = await prepared(h, 'trash-page v1', {page: a.id});
  h.simulator.fail(ROUTES.page, {status: 200, data: []});
  const done = ended(await h.approve(job), 'uncertain', 'outcome_uncertain', {reason: 'not_verified'});
  assert.equal(done.error, RUN_WORDS.unverified);
  assert.equal(stored(h, a.id).in_trash, true, 'the write landed');
});

test('A landed write whose read-back cannot be built or sent never says nothing was sent, and keeps its code', async t => {
  const h = notionHarness(t), {a} = world(h);
  const job = await prepared(h, 'comment v1', {page: a.id, text: '[SYNTHETIC] landed'});
  h.simulator.fail(ROUTES.comment, {status: 200, data: {object: 'comment'}});
  const done = ended(await h.approve(job), 'uncertain', 'outcome_uncertain', {details: {reason: 'path_value'}});
  assert.equal(done.error, RUN_WORDS.uncertain);
  const lost = await prepared(h, 'rename-page v1', {page: a.id, title: '[SYNTHETIC] Renamed'});
  const send = h.runtime.request;
  h.runtime.request = async options => {
    if (options.method === 'GET') throw Object.assign(new Error('no route'), {sent: false});
    return send(options);
  };
  const failed = await h.approve(lost);
  h.runtime.request = send;
  assert.deepEqual([failed.status, failed.error], ['uncertain', RUN_WORDS.uncertain]);
});

test('A read-back too large to compare leaves the write unverified with true words', async t => {
  const h = notionHarness(t), {a} = world(h), big = h.simulator.seedPage({title: 'Big', parent: {page_id: a.id}, markdown: 'word '.repeat(240_000)});
  const done = ended(await approved(h, 'add-to-page v1', {page: big.id, content: '[SYNTHETIC] landed'}), 'uncertain', 'outcome_uncertain', {reason: 'not_verified'});
  assert.equal(done.error, RUN_WORDS.unverified);
  assert.ok(stored(h, big.id).text.endsWith('[SYNTHETIC] landed'), 'the write landed');
});
test('Add to page appends and reads back the added text; Edit page text replaces text found once, never sends allow_deleting_content, and text not found once fails with nothing changed', async t => {
  const h = notionHarness(t), {a} = world(h);
  const add = await prepared(h, 'add-to-page v1', {page: a.id, content: '[SYNTHETIC] marker'});
  assert.deepEqual(bodyOf(h, add, 1), {type: 'insert_content', insert_content: {content: '[SYNTHETIC] marker'}});
  assert.deepEqual(h.fields(add), {Page: '[SYNTHETIC] A', Link: a.url, 'Text added': '[SYNTHETIC] marker'});
  const added = ended(await h.approve(add), 'succeeded', null);
  assert.deepEqual([added.result.verification.status, stored(h, a.id).text], ['verified', 'Hello from A\n[SYNTHETIC] marker']);
  const edit = await prepared(h, 'edit-page-text v1', {page: a.id, find: 'Hello from A', replace: '[SYNTHETIC] Hello edited'});
  assert.deepEqual(bodyOf(h, edit, 1), {type: 'update_content', update_content: {content_updates: [{old_str: 'Hello from A', new_str: '[SYNTHETIC] Hello edited'}]}});
  assert.deepEqual(h.fields(edit), {Page: '[SYNTHETIC] A', Link: a.url, Find: 'Hello from A', 'Replace with': '[SYNTHETIC] Hello edited'});
  ended(await h.approve(edit), 'succeeded', null);
  assert.equal(stored(h, a.id).text, '[SYNTHETIC] Hello edited\n[SYNTHETIC] marker');
  // Removing the marker: an empty replacement.
  ended(await approved(h, 'edit-page-text v1', {page: a.id, find: '\n[SYNTHETIC] marker', replace: ''}), 'succeeded', null);
  assert.equal(stored(h, a.id).text, '[SYNTHETIC] Hello edited');
  for (const call of h.simulator.writes()) assert.equal(JSON.stringify(call.body).includes('allow_deleting_content'), false);
  // Text that is not there, or that is there twice, changes nothing: Notion answers 400, a definitive refusal.
  const twice = h.simulator.seedPage({title: 'Twice', parent: {page_id: a.id}, markdown: 'same same'});
  for (const [page, find] of [[a.id, 'not on the page'], [twice.id, 'same']]) {
    const job = ended(await approved(h, 'edit-page-text v1', {page, find, replace: '[SYNTHETIC] x'}), 'failed', 'provider_failed', {providerStatus: 400});
    assert.equal(job.error, RUN_WORDS.failed);
  }
  assert.deepEqual([stored(h, a.id).text, stored(h, twice.id).text], ['[SYNTHETIC] Hello edited', 'same same']);
});

test('cards: Create page names the page it goes under, its link, the title and the text; a read whose row asks shows what it reads', async t => {
  const h = notionHarness(t), {a, source} = world(h);
  const create = await prepared(h, 'create-page v1', {parent: a.url, title: '[SYNTHETIC] New page', content: 'First line\nSecond line'});
  assert.deepEqual(h.fields(create), {Under: '[SYNTHETIC] A', Link: a.url, Title: '[SYNTHETIC] New page', Content: 'First line\nSecond line'});
  assert.deepEqual(bodyOf(h, create), {parent: {page_id: a.id}, properties: {title: {title: pieces('[SYNTHETIC] New page')}}, markdown: 'First line\nSecond line'});
  const untitled = await prepared(h, 'create-page v1', {parent: a.id, title: '[SYNTHETIC] Empty'});
  assert.equal(Object.hasOwn(bodyOf(h, untitled), 'markdown'), false, 'no markdown unless given');
  h.setRow('notion.search.read', 'ask');
  h.setRow('notion.content.read', 'ask');
  const search = await h.run('search v1', {query: 'synthetic', kind: 'page'});
  assert.deepEqual([search.status, h.fields(search)], ['awaiting_approval', {Search: 'synthetic', Kind: 'page'}]);
  const rows = await h.run('find-rows v1', {dataSource: source.id, match: 'all'});
  assert.equal(rows.status, 'awaiting_approval');
  const final = await h.approve(rows);
  assert.deepEqual([final.status, h.fields(final)], ['awaiting_approval', {Database: 'Tasks', 'Data source': source.id}]);
  assert.deepEqual(writes(h), [], 'nothing sent before an approval');
});

// ---- moving ----------------------------------------------------------------------------------------------------------------------------
test('Move page refuses a database row (wrong_kind) with nothing sent, moves a page under another and reads back the new parent; the card names the destination', async t => {
  const h = notionHarness(t), {a, b, child, row} = world(h);
  const refused = refusedAs(await h.run('move-page v1', {page: row.id, to: b.id}), 'wrong_kind');
  assert.deepEqual([refused.details.transform, refused.details.transformReason, writes(h)], ['collections.oneOf@1', 'not_one_of', []]);
  const job = await prepared(h, 'move-page v1', {page: child.url, to: b.url});
  assert.deepEqual(bodyOf(h, job), {parent: {type: 'page_id', page_id: b.id}});
  assert.deepEqual(h.fields(job), {Page: 'Child', Link: child.url, 'Move to': '[SYNTHETIC] B', 'Move to link': b.url});
  const moved = ended(await h.approve(job), 'succeeded', null);
  assert.deepEqual([moved.result.data.parentPageId, stored(h, child.id).parent.page_id, moved.result.verification.status], [b.id, b.id, 'verified']);
  assert.notEqual(a.id, b.id);
});

// ---- comments --------------------------------------------------------------------------------------------------------------------------
test('Comment or reply: both or neither of page and discussionId refuse wrong_kind before any request; a reply carries the discussion id; display_name is never sent', async t => {
  const h = notionHarness(t), {a} = world(h);
  refusedAs(await h.run('comment v1', {text: '[SYNTHETIC] neither'}), 'wrong_kind');
  const discussion = h.simulator.seedComment({page: a.id, text: 'Owner note'}).discussion_id;
  refusedAs(await h.run('comment v1', {page: a.id, discussionId: discussion, text: '[SYNTHETIC] both'}), 'wrong_kind');
  assert.deepEqual(h.simulator.calls, [], 'refused before any request');
  const first = await prepared(h, 'comment v1', {page: a.url, text: '[SYNTHETIC] Comment'});
  assert.deepEqual(bodyOf(h, first), {parent: {page_id: a.id}, rich_text: pieces('[SYNTHETIC] Comment')});
  assert.deepEqual(h.fields(first), {Link: a.url, Comment: '[SYNTHETIC] Comment'});
  const made = ended(await h.approve(first), 'succeeded', null);
  assert.deepEqual([made.result.data.pageId, made.result.verification.status], [a.id, 'verified']);
  const reply = await prepared(h, 'comment v1', {discussionId: made.result.data.discussionId, text: '[SYNTHETIC] Reply'});
  assert.deepEqual(bodyOf(h, reply), {discussion_id: made.result.data.discussionId, rich_text: pieces('[SYNTHETIC] Reply')});
  assert.deepEqual(h.fields(reply), {'Reply in discussion': made.result.data.discussionId, Comment: '[SYNTHETIC] Reply'});
  const replied = ended(await h.approve(reply), 'succeeded', null);
  assert.equal(replied.result.data.discussionId, made.result.data.discussionId);
  for (const call of h.simulator.writes()) assert.equal(Object.hasOwn(call.body, 'display_name'), false);
  const listed = ended(await h.run('read-comments v1', {page: a.id}), 'succeeded', null).result.data.comments;
  assert.deepEqual(listed.map(item => item.text), [['Owner note'], ['[SYNTHETIC] Comment'], ['[SYNTHETIC] Reply']]);
  assert.deepEqual(listed.map(item => item.discussionId), [discussion, made.result.data.discussionId, made.result.data.discussionId]);
  // A resolved discussion leaves the list.
  h.simulator.resolve(listed[0].id);
  assert.equal(ended(await h.run('read-comments v1', {page: a.id}), 'succeeded', null).result.data.comments.length, 2);
});

// ---- errors ----------------------------------------------------------------------------------------------------------------------------
test('errors: an unshared page fails with the not_shared words, a capability turned off with capability_off; a 429 shows Retry-After and is not retried', async t => {
  let h = notionHarness(t), {a, unshared} = world(h);
  ended(await h.run('read-page v1', {page: unshared.url}), 'failed', 'provider_failed', {providerStatus: 404, reason: 'not_shared', error: RUN_WORDS.not_shared});
  ended(await h.run('rename-page v1', {page: unshared.id, title: '[SYNTHETIC] x'}), 'failed', 'provider_failed', {reason: 'not_shared'});
  h.simulator.limit(ROUTES.search, 30);
  ended(await h.run('search v1', {}), 'failed', 'provider_failed', {providerStatus: 429, retryAfterSeconds: 30, error: RUN_WORDS.limited});
  assert.equal(routes(h).filter(route => route === ROUTES.search).length, 1, 'never retried');
  h.simulator.limit(ROUTES.patch, 12);
  ended(await approved(h, 'rename-page v1', {page: a.id, title: '[SYNTHETIC] y'}), 'failed', 'provider_failed', {providerStatus: 429, retryAfterSeconds: 12});
  assert.equal(writes(h).length, 1, 'sent once');
  h = notionHarness(t, {capabilities: ['read_content', 'insert_content', 'read_comments', 'insert_comments', 'user_email']});
  ({a} = world(h));
  ended(await approved(h, 'add-to-page v1', {page: a.id, content: '[SYNTHETIC] z'}), 'failed', 'provider_failed', {providerStatus: 403, reason: 'capability_off', error: RUN_WORDS.capability_off});
  assert.equal(h.simulator.state().pages[a.id].text, 'Hello from A');
});

// ---- reads -----------------------------------------------------------------------------------------------------------------------------
test('Read page: its fields, its properties as plain text, its markdown in two requests and no follow-up; truncated when Notion left a block out; cut at 200,000 characters', async t => {
  const h = notionHarness(t), {a, child, database, row} = world(h);
  h.simulator.unknown(a.id, {markdown: 'A table'});
  const read = ended(await h.run('read-page v1', {page: a.url}), 'succeeded', null).result.data;
  assert.deepEqual([read.id, read.url, read.title, read.parentType, read.inTrash, read.truncated, read.markdownTruncated], [a.id, a.url, '[SYNTHETIC] A', 'workspace', false, true, undefined]);
  assert.match(read.markdown, new RegExp(`^Hello from A\\n<page url="${child.url}">Child</page>\\n<database url="${database.url}">Tasks</database>\\n<unknown url="[^"]+" alt="block"/>$`));
  assert.deepEqual(routes(h), [ROUTES.page, ROUTES.getMarkdown], 'two requests, no follow-up');
  const values = ended(await h.run('read-page v1', {page: row.id}), 'succeeded', null).result.data;
  assert.deepEqual([values.parentType, values.parentDataSourceId, values.properties.find(item => item.name === 'Stage').text, values.properties.find(item => item.name === 'Tags').text],
    ['data_source_id', row.parent.data_source_id, 'Open', 'red']);
  const long = h.simulator.seedPage({title: 'Long', parent: {page_id: a.id}, markdown: 'x'.repeat(200_500)});
  const cut = ended(await h.run('read-page v1', {page: long.id}), 'succeeded', null).result.data;
  assert.deepEqual([[...cut.markdown].length, cut.markdownTruncated, cut.markdown.endsWith('\n[truncated]')], [200_000, true, true]);
});

test('Describe database: every property with whether it is writable and why not, and its options; Find rows filters by property id and type, or reads every row', async t => {
  const h = notionHarness(t), {a, database, source, row} = world(h);
  const described = ended(await h.run('describe-database v1', {database: database.url}), 'succeeded', null).result.data;
  assert.deepEqual([described.id, described.title, described.dataSources.length, described.dataSources[0].id, described.dataSources[0].name], [database.id, 'Tasks', 1, source.id, 'Tasks']);
  const properties = Object.fromEntries(described.dataSources[0].properties.map(item => [item.name, item]));
  assert.deepEqual([properties.Total.writable, properties.Total.reason, properties.Created.reason, properties.Stage.writable, properties.Stage.options], [false, 'read_only', 'read_only', true, ['Open', 'Done']]);
  for (const index of [2, 3]) h.simulator.seedRow({dataSource: source.id, properties: {Name: {title: pieces(`Row ${index}`)}, Stage: {select: {name: index === 2 ? 'Done' : 'Open'}}, Cost: {number: index}}});
  const all = ended(await h.run('find-rows v1', {dataSource: source.id, match: 'all'}), 'succeeded', null).result.data;
  assert.deepEqual([all.rows.map(item => item.title), all.hasMore, all.nextCursor], [['Row 1', 'Row 2', 'Row 3'], false, undefined]);
  assert.equal(all.rows[0].values.find(item => item.name === 'Stage').text, 'Open');
  assert.equal(h.simulator.calls.at(-1).body.filter, undefined, 'match all sends no filter');
  const open = ended(await h.run('find-rows v1', {dataSource: source.id, match: 'where', where: {Stage: 'Open', Name: 'Row'}}), 'succeeded', null).result.data;
  assert.deepEqual(open.rows.map(item => item.id), [row.id, open.rows[1].id]);
  assert.deepEqual(open.rows.map(item => item.title), ['Row 1', 'Row 3']);
  assert.deepEqual(h.simulator.calls.at(-1).body.filter, {and: [{property: 'title', title: {contains: 'Row'}}, {property: idOf(source, 'Stage'), select: {equals: 'Open'}}]});
  // A condition on a read-only or unknown property, or match where without where, refuses before any query.
  const queries = () => routes(h).filter(route => route === ROUTES.query).length, before = queries();
  ended(await h.run('find-rows v1', {dataSource: source.id, match: 'where', where: {Total: 3}}), 'failed', 'invalid_arguments');
  refusedAs(await h.run('find-rows v1', {dataSource: source.id, match: 'where'}), 'input_invalid');
  assert.equal(queries(), before);
  // A database of 6 data sources is more than Describe reads: refused, never cut short.
  const wide = h.simulator.seedDatabase({title: 'Wide', parent: {page_id: a.id}, sources: Array.from({length: 6}, (_, index) => ({name: `S${index}`, properties: {Name: {type: 'title'}}}))});
  refusedAs(await h.run('describe-database v1', {database: wide.database.id}), 'each_too_long');
});

// ---- pages ---------------------------------------------------------------------------------------------------------------------------
test('pages: Search (100 a page), Find rows (25) and Read comments (25) return nextCursor and take it back; Find person reads at most 10 pages and matches across them', async t => {
  const h = notionHarness(t), {a, source} = world(h);
  for (let index = 0; index < 120; index++) h.simulator.seedPage({title: `Note ${index}`, parent: {page_id: a.id}});
  const first = ended(await h.run('search v1', {query: 'note'}), 'succeeded', null).result.data;
  assert.deepEqual([first.results.length, first.hasMore, typeof first.nextCursor, h.simulator.calls.at(-1).body.page_size], [100, true, 'string', 100]);
  const rest = ended(await h.run('search v1', {query: 'note', cursor: first.nextCursor}), 'succeeded', null).result.data;
  assert.deepEqual([rest.results.length, rest.hasMore, rest.nextCursor], [20, false, undefined]);
  assert.equal(h.simulator.calls.at(-1).body.start_cursor, first.nextCursor);
  const kinds = ended(await h.run('search v1', {kind: 'data_source'}), 'succeeded', null).result.data.results;
  assert.deepEqual(kinds.map(item => [item.object, item.title]), [['data_source', 'Tasks']]);
  for (let index = 2; index <= 30; index++) h.simulator.seedRow({dataSource: source.id, properties: {Name: {title: pieces(`Row ${index}`)}}});
  const rows = ended(await h.run('find-rows v1', {dataSource: source.id, match: 'all'}), 'succeeded', null).result.data;
  const more = ended(await h.run('find-rows v1', {dataSource: source.id, match: 'all', cursor: rows.nextCursor}), 'succeeded', null).result.data;
  assert.deepEqual([rows.rows.length, more.rows.length, more.hasMore], [25, 5, false]);
  for (let index = 0; index < 30; index++) h.simulator.seedComment({page: a.id, text: `Comment ${index}`});
  const comments = ended(await h.run('read-comments v1', {page: a.id}), 'succeeded', null).result.data;
  const later = ended(await h.run('read-comments v1', {page: a.id, cursor: comments.nextCursor}), 'succeeded', null).result.data;
  assert.deepEqual([comments.comments.length, later.comments.length, later.nextCursor], [25, 5, undefined]);
  // Find person: 950 people besides the bot and the owner, two named Sam Lee on different pages; 10 pages of 100 read them all.
  for (let index = 0; index < 950; index++) h.simulator.seedUser({name: index === 5 || index === 940 ? 'Sam Lee' : `Person ${index}`, email: `p${index}@example.com`});
  const sent = routes(h).length;
  const found = ended(await h.run('find-person v1', {name: 'sam lee'}), 'succeeded', null).result.data;
  assert.deepEqual([found.matches.length, found.matches.every(match => match.name === 'Sam Lee'), routes(h).length - sent], [2, true, 10]);
  assert.deepEqual(ended(await h.run('find-person v1', {name: OWNER.name}), 'succeeded', null).result.data.matches, [{id: h.simulator.owner.id, name: OWNER.name}]);
  // 50 people more make an 11th page: refused, never cut short.
  for (let index = 0; index < 50; index++) h.simulator.seedUser({name: `More ${index}`, email: `m${index}@example.com`});
  refusedAs(await h.run('find-person v1', {name: 'Sam Lee'}), 'too_many_pages');
});

// ---- modes -----------------------------------------------------------------------------------------------------------------------------
test('modes: reads run at Allow with no card and no write lock; a write asks once under the defaults; with "Access pages and databases" at Ask it stops twice', async t => {
  const h = notionHarness(t), {a} = world(h);
  const read = ended(await h.run('read-page v1', {page: a.id}), 'succeeded', null, {effect: 'read'});
  assert.deepEqual([read.action.modes, read.action.approvals, [...h.runtime.writeLocks]], [{prepare: 'allow', resolve: null, perform: 'allow'}, [], []]);
  const once = await prepared(h, 'rename-page v1', {page: a.id, title: '[SYNTHETIC] One stop'});
  assert.deepEqual(once.action.modes, {prepare: 'allow', resolve: null, perform: 'ask'});
  h.setRow('notion.content.read', 'ask');
  const reads = await h.run('rename-page v1', {page: a.id, title: '[SYNTHETIC] Two stops'});
  assert.deepEqual([reads.status, reads.action.phase], ['awaiting_approval', 'reads']);
  const final = await h.approve(reads);
  assert.deepEqual([final.status, final.action.phase, h.simulator.writes().length], ['awaiting_approval', 'final', 0]);
  ended(await h.approve(final), 'succeeded', null);
  assert.equal(titleText(stored(h, a.id)), '[SYNTHETIC] Two stops');
});

// ---- secrets and evidence --------------------------------------------------------------------------------------------------------------
test('credentials never reach a job, a prepared request, a card, an audit row or an output; evidence and stores stay under the temp root', async t => {
  const shipped = new URL('../docs/live-evidence/notion/actions.json', import.meta.url), before = existsSync(shipped) ? readFileSync(shipped, 'utf8') : null;
  const h = notionHarness(t), {a} = world(h);
  h.simulator.seedPage({title: `Notes ${TOKEN} end`, parent: {page_id: a.id}, markdown: `Body ${TOKEN}`});
  const search = ended(await h.run('search v1', {query: 'notes'}), 'succeeded', null);
  const job = await prepared(h, 'rename-page v1', {page: a.id, title: '[SYNTHETIC] Checked'});
  const card = h.card(job), done = ended(await h.approve(job), 'succeeded', null);
  for (const [name, value] of [['jobs', h.store.list('jobs')], ['prepared', h.store.list(PREPARED)], ['card', card], ['audit', h.store.list('activity')], ['outputs', [search.result, done.result]]]) {
    assert.ok(!JSON.stringify(value).includes(TOKEN), name);
  }
  assert.equal(search.result.data.results[0].title, 'Notes [redacted] end', 'the token an answer echoes is scrubbed before anything reads it');
  assert.ok(existsSync(`${h.root}/docs/live-evidence/notion/actions.json`));
  assert.equal(existsSync(shipped) ? readFileSync(shipped, 'utf8') : null, before, 'the shipped evidence is never written by a test');
});

// ---- the evidence of step 20's live run ----------------------------------------------------------------------------------------------
test('Evidence: a step a body route moved fits by its own template, the trace keeping no body bytes, and a path no step names still does not', () => {
  const restore = validateActionFile(currentFile(), notionDeps()).actions.find(entry => entry.key === 'restore-page');
  const page = '/v1/pages/409e1475-16c6-8111-b5dc-e2826b3a8804';
  const run = {appId: 'notion', runId: 'ABCDEFGH', order: ['N8'], rows: [], results: {N8: {id: 'N8', passed: true, calls: [{action: 'restore-page@1', actionId: restore.id, jobs: []}], proxies: [], reads: [], checks: [], undo: {kind: 'none', why: 'test'}}}};
  const passed = trace => evidenceRecords(run, {key: Buffer.alloc(32, 1), entries: [restore], trace: () => trace, job: () => null}).records[restore.id].passed;
  assert.equal(passed([{method: 'GET', path: page, bodyHmac: null, status: 200}, {method: 'PATCH', path: page, bodyHmac: 'hmac', status: 200}]), true);
  assert.equal(passed([{method: 'PATCH', path: '/v1/blocks/409e1475-16c6-8111-b5dc-e2826b3a8804', bodyHmac: 'hmac', status: 200}]), false);
});

// ---- the simulator case list (check 5) -------------------------------------------------------------------------------------------------
const MANIFEST = JSON.parse(readFileSync(new URL('./fixtures/provider-simulators/notion.cases.json', import.meta.url), 'utf8'));
const ENTRIES = validateActionFile(currentFile(), notionDeps()).actions;
/** A write's case: run it to its card and approve it, with the answer lost or swallowed. */
const lost = async (h, route, key, input) => { h.simulator.drop(route); return ended(await approved(h, key, input), 'uncertain', 'outcome_uncertain'); };
const swallowed = async (h, route, key, input) => {
  h.simulator.swallow(route);
  const job = ended(await approved(h, key, input), 'uncertain', 'outcome_uncertain');
  assert.equal(job.result.verification.status, 'unverified');
  return job;
};
const refusedNever = async (h, row, key, input) => {
  h.setRow(row, 'deny');
  await assert.rejects(h.run(key, input), error => error.code === 'permission_denied' || /Never/.test(error.message));
  assert.equal(h.simulator.calls.length, 0);
};
const failedWith = async (h, route, status, code, key, input, write = true) => {
  h.simulator.fail(route, NOTION_ERROR(status, code));
  return ended(write ? await approved(h, key, input) : await h.run(key, input), 'failed', 'provider_failed', {providerStatus: status});
};
/** One harness and world per case. */
const setup = (t, options) => { const h = notionHarness(t, options); return {h, ...world(h)}; };
const IMPLEMENTATIONS = {
  'search v1/succeeds': async t => { const {h} = setup(t); assert.deepEqual(ended(await h.run('search v1', {query: 'synthetic', kind: 'page'}), 'succeeded', null).result.data.results.map(item => item.title).sort(), ['[SYNTHETIC] A', '[SYNTHETIC] B']); },
  'search v1/refused': async t => refusedNever(setup(t).h, 'notion.search.read', 'search v1', {}),
  'search v1/provider-refusal': async t => { const {h} = setup(t); await failedWith(h, ROUTES.search, 400, 'validation_error', 'search v1', {}, false); },
  'read-page v1/succeeds': async t => { const {h, a, child, database} = setup(t); assert.equal(ended(await h.run('read-page v1', {page: a.id}), 'succeeded', null).result.data.markdown, `Hello from A\n<page url="${child.url}">Child</page>\n<database url="${database.url}">Tasks</database>`); },
  'read-page v1/refused': async t => { const {h} = setup(t); refusedAs(await h.run('read-page v1', {page: 'https://evil.example/page-1429989fe8ac4effbc8f57f56486db54'}), 'notion_id_invalid'); assert.equal(h.simulator.calls.length, 0); },
  'read-page v1/provider-refusal': async t => { const {h, unshared} = setup(t); ended(await h.run('read-page v1', {page: unshared.id}), 'failed', 'provider_failed', {providerStatus: 404, reason: 'not_shared'}); },
  'describe-database v1/succeeds': async t => { const {h, database} = setup(t); assert.equal(ended(await h.run('describe-database v1', {database: database.id}), 'succeeded', null).result.data.dataSources[0].properties.length, Object.keys(TASKS).length); },
  'describe-database v1/refused': async t => refusedNever(setup(t).h, 'notion.content.read', 'describe-database v1', {database: '1429989fe8ac4effbc8f57f56486db54'}),
  'describe-database v1/provider-refusal': async t => { const {h, database} = setup(t); await failedWith(h, ROUTES.database, 403, 'restricted_resource', 'describe-database v1', {database: database.id}, false); },
  'find-rows v1/succeeds': async t => { const {h, source, row} = setup(t); assert.deepEqual(ended(await h.run('find-rows v1', {dataSource: source.id, match: 'where', where: {Stage: 'Open'}}), 'succeeded', null).result.data.rows.map(item => item.id), [row.id]); },
  'find-rows v1/refused': async t => { const {h, source} = setup(t); ended(await h.run('find-rows v1', {dataSource: source.id, match: 'where', where: {Stage: 'Lost'}}), 'failed', 'invalid_arguments'); assert.ok(!routes(h).includes(ROUTES.query)); },
  'find-rows v1/provider-refusal': async t => { const {h, source} = setup(t); await failedWith(h, ROUTES.query, 400, 'validation_error', 'find-rows v1', {dataSource: source.id, match: 'all'}, false); },
  'create-page v1/succeeds': async t => { const {h, a} = setup(t); const job = ended(await approved(h, 'create-page v1', {parent: a.id, title: '[SYNTHETIC] New', content: 'Text'}), 'succeeded', null); assert.deepEqual([job.result.verification.status, job.result.data.parentPageId], ['verified', a.id]); },
  'create-page v1/refused': async t => refusedNever(setup(t).h, 'notion.content.create', 'create-page v1', {parent: '1429989fe8ac4effbc8f57f56486db54', title: '[SYNTHETIC] New'}),
  'create-page v1/provider-refusal': async t => { const {h, a} = setup(t); await failedWith(h, ROUTES.create, 400, 'validation_error', 'create-page v1', {parent: a.id, title: '[SYNTHETIC] New'}); assert.equal(Object.keys(h.simulator.state().pages).length, 5); },
  'create-page v1/unverified': async t => { const {h, a} = setup(t); await swallowed(h, ROUTES.create, 'create-page v1', {parent: a.id, title: '[SYNTHETIC] New'}); },
  'create-page v1/lost-answer': async t => { const {h, a} = setup(t); await lost(h, ROUTES.create, 'create-page v1', {parent: a.id, title: '[SYNTHETIC] New'}); assert.equal(Object.keys(h.simulator.state().pages).length, 6, 'applied'); },
  'add-row v1/succeeds': async t => { const {h, source} = setup(t); ended(await approved(h, 'add-row v1', {dataSource: source.id, values: {Name: '[SYNTHETIC] Row', Cost: 1}}), 'succeeded', null); },
  'add-row v1/refused': async t => { const {h, source} = setup(t); ended(await h.run('add-row v1', {dataSource: source.id, values: {Total: 1}}), 'failed', 'invalid_arguments'); assert.deepEqual(writes(h), []); },
  'add-row v1/provider-refusal': async t => { const {h, source} = setup(t); await failedWith(h, ROUTES.create, 409, 'conflict_error', 'add-row v1', {dataSource: source.id, values: {Name: '[SYNTHETIC] Row'}}); },
  'add-row v1/unverified': async t => { const {h, source} = setup(t); await swallowed(h, ROUTES.create, 'add-row v1', {dataSource: source.id, values: {Name: '[SYNTHETIC] Row'}}); },
  'add-row v1/lost-answer': async t => { const {h, source} = setup(t); await lost(h, ROUTES.create, 'add-row v1', {dataSource: source.id, values: {Name: '[SYNTHETIC] Row'}}); },
  'rename-page v1/succeeds': async t => { const {h, b} = setup(t); ended(await approved(h, 'rename-page v1', {page: b.id, title: '[SYNTHETIC] B2'}), 'succeeded', null); assert.equal(titleText(stored(h, b.id)), '[SYNTHETIC] B2'); },
  'rename-page v1/refused': async t => refusedNever(setup(t).h, 'notion.content.edit', 'rename-page v1', {page: '1429989fe8ac4effbc8f57f56486db54', title: '[SYNTHETIC] x'}),
  'rename-page v1/provider-refusal': async t => { const {h, b} = setup(t); await failedWith(h, ROUTES.patch, 409, 'conflict_error', 'rename-page v1', {page: b.id, title: '[SYNTHETIC] B2'}); assert.equal(titleText(stored(h, b.id)), '[SYNTHETIC] B'); },
  'rename-page v1/unverified': async t => { const {h, b} = setup(t); await swallowed(h, ROUTES.patch, 'rename-page v1', {page: b.id, title: '[SYNTHETIC] B2'}); },
  'rename-page v1/lost-answer': async t => { const {h, b} = setup(t); await lost(h, ROUTES.patch, 'rename-page v1', {page: b.id, title: '[SYNTHETIC] B2'}); assert.equal(titleText(stored(h, b.id)), '[SYNTHETIC] B2'); },
  'update-row v1/succeeds': async t => { const {h, row} = setup(t); ended(await approved(h, 'update-row v1', {page: row.id, values: {Done: true}}), 'succeeded', null); assert.equal(stored(h, row.id).properties.Done.checkbox, true); },
  'update-row v1/refused': async t => { const {h, a} = setup(t); refusedAs(await h.run('update-row v1', {page: a.id, values: {Cost: 1}}), 'input_invalid'); assert.deepEqual(writes(h), []); },
  'update-row v1/provider-refusal': async t => { const {h, row} = setup(t); await failedWith(h, ROUTES.patch, 400, 'validation_error', 'update-row v1', {page: row.id, values: {Done: true}}); },
  'update-row v1/unverified': async t => { const {h, row} = setup(t); await swallowed(h, ROUTES.patch, 'update-row v1', {page: row.id, values: {Done: true}}); },
  'update-row v1/lost-answer': async t => { const {h, row} = setup(t); await lost(h, ROUTES.patch, 'update-row v1', {page: row.id, values: {Done: true}}); },
  'add-to-page v1/succeeds': async t => { const {h, b} = setup(t); ended(await approved(h, 'add-to-page v1', {page: b.id, content: '[SYNTHETIC] more'}), 'succeeded', null); },
  'add-to-page v1/refused': async t => refusedNever(setup(t).h, 'notion.content.edit', 'add-to-page v1', {page: '1429989fe8ac4effbc8f57f56486db54', content: '[SYNTHETIC] more'}),
  'add-to-page v1/provider-refusal': async t => { const {h, b} = setup(t); await failedWith(h, ROUTES.markdown, 400, 'validation_error', 'add-to-page v1', {page: b.id, content: '[SYNTHETIC] more'}); assert.equal(stored(h, b.id).text, 'Hello from B'); },
  'add-to-page v1/unverified': async t => { const {h, b} = setup(t); await swallowed(h, ROUTES.markdown, 'add-to-page v1', {page: b.id, content: '[SYNTHETIC] more'}); },
  'add-to-page v1/lost-answer': async t => { const {h, b} = setup(t); await lost(h, ROUTES.markdown, 'add-to-page v1', {page: b.id, content: '[SYNTHETIC] more'}); },
  'edit-page-text v1/succeeds': async t => { const {h, b} = setup(t); ended(await approved(h, 'edit-page-text v1', {page: b.id, find: 'Hello', replace: '[SYNTHETIC] Hi'}), 'succeeded', null); },
  'edit-page-text v1/refused': async t => refusedNever(setup(t).h, 'notion.content.edit', 'edit-page-text v1', {page: '1429989fe8ac4effbc8f57f56486db54', find: 'a', replace: 'b'}),
  'edit-page-text v1/provider-refusal': async t => { const {h, b} = setup(t); ended(await approved(h, 'edit-page-text v1', {page: b.id, find: 'missing', replace: '[SYNTHETIC] x'}), 'failed', 'provider_failed', {providerStatus: 400}); },
  'edit-page-text v1/unverified': async t => { const {h, b} = setup(t); await swallowed(h, ROUTES.markdown, 'edit-page-text v1', {page: b.id, find: 'Hello', replace: '[SYNTHETIC] Hi'}); },
  'edit-page-text v1/lost-answer': async t => { const {h, b} = setup(t); await lost(h, ROUTES.markdown, 'edit-page-text v1', {page: b.id, find: 'Hello', replace: '[SYNTHETIC] Hi'}); },
  'move-page v1/succeeds': async t => { const {h, child, b} = setup(t); ended(await approved(h, 'move-page v1', {page: child.id, to: b.id}), 'succeeded', null); },
  'move-page v1/refused': async t => { const {h, row, b} = setup(t); refusedAs(await h.run('move-page v1', {page: row.id, to: b.id}), 'wrong_kind'); assert.deepEqual(writes(h), []); },
  'move-page v1/provider-refusal': async t => { const {h, a, child} = setup(t); ended(await approved(h, 'move-page v1', {page: a.id, to: child.id}), 'failed', 'provider_failed', {providerStatus: 400}); assert.equal(stored(h, child.id).parent.page_id, a.id); },
  'move-page v1/unverified': async t => { const {h, child, b} = setup(t); await swallowed(h, ROUTES.move, 'move-page v1', {page: child.id, to: b.id}); },
  'move-page v1/lost-answer': async t => { const {h, child, b} = setup(t); await lost(h, ROUTES.move, 'move-page v1', {page: child.id, to: b.id}); },
  'trash-page v1/succeeds': async t => { const {h, child} = setup(t); ended(await approved(h, 'trash-page v1', {page: child.id}), 'succeeded', null); },
  'trash-page v1/refused': async t => refusedNever(setup(t).h, 'notion.content.trash', 'trash-page v1', {page: '1429989fe8ac4effbc8f57f56486db54'}),
  'trash-page v1/provider-refusal': async t => { const {h, child} = setup(t); await failedWith(h, ROUTES.trash, 403, 'restricted_resource', 'trash-page v1', {page: child.id}); assert.equal(stored(h, child.id).in_trash, false); },
  'trash-page v1/unverified': async t => { const {h, child} = setup(t); await swallowed(h, ROUTES.trash, 'trash-page v1', {page: child.id}); assert.equal(stored(h, child.id).in_trash, false); },
  'trash-page v1/lost-answer': async t => { const {h, child} = setup(t); await lost(h, ROUTES.trash, 'trash-page v1', {page: child.id}); assert.equal(stored(h, child.id).in_trash, true, 'applied'); },
  'restore-page v1/succeeds': async t => { const {h, child} = setup(t); h.simulator.data.pages[child.id].in_trash = true; ended(await approved(h, 'restore-page v1', {page: child.id}), 'succeeded', null); },
  'restore-page v1/refused': async t => refusedNever(setup(t).h, 'notion.content.trash', 'restore-page v1', {page: '1429989fe8ac4effbc8f57f56486db54'}),
  'restore-page v1/provider-refusal': async t => { const {h, child} = setup(t); h.simulator.data.pages[child.id].in_trash = true; await failedWith(h, ROUTES.patch, 404, 'object_not_found', 'restore-page v1', {page: child.id}); },
  'restore-page v1/unverified': async t => { const {h, child} = setup(t); h.simulator.data.pages[child.id].in_trash = true; await swallowed(h, ROUTES.patch, 'restore-page v1', {page: child.id}); },
  'restore-page v1/lost-answer': async t => { const {h, child} = setup(t); h.simulator.data.pages[child.id].in_trash = true; await lost(h, ROUTES.patch, 'restore-page v1', {page: child.id}); assert.equal(stored(h, child.id).in_trash, false); },
  'comment v1/succeeds': async t => { const {h, a} = setup(t); ended(await approved(h, 'comment v1', {page: a.id, text: '[SYNTHETIC] Hello'}), 'succeeded', null); },
  'comment v1/refused': async t => { const {h, a} = setup(t); refusedAs(await h.run('comment v1', {page: a.id, discussionId: 'd1', text: '[SYNTHETIC] Hello'}), 'wrong_kind'); assert.equal(h.simulator.calls.length, 0); },
  'comment v1/provider-refusal': async t => { const {h, a} = setup(t); await failedWith(h, ROUTES.comment, 403, 'restricted_resource', 'comment v1', {page: a.id, text: '[SYNTHETIC] Hello'}); assert.deepEqual(h.simulator.state().comments, {}); },
  'comment v1/unverified': async t => { const {h, a} = setup(t); await swallowed(h, ROUTES.comment, 'comment v1', {page: a.id, text: '[SYNTHETIC] Hello'}); },
  'comment v1/lost-answer': async t => { const {h, a} = setup(t); await lost(h, ROUTES.comment, 'comment v1', {page: a.id, text: '[SYNTHETIC] Hello'}); assert.equal(Object.keys(h.simulator.state().comments).length, 1); },
  'read-comments v1/succeeds': async t => { const {h, a} = setup(t); h.simulator.seedComment({page: a.id, text: 'Hi'}); assert.deepEqual(ended(await h.run('read-comments v1', {page: a.id}), 'succeeded', null).result.data.comments[0].text, ['Hi']); },
  'read-comments v1/refused': async t => refusedNever(setup(t).h, 'notion.comments.read', 'read-comments v1', {page: '1429989fe8ac4effbc8f57f56486db54'}),
  'read-comments v1/provider-refusal': async t => { const {h, a} = setup(t, {capabilities: ['read_content', 'update_content', 'insert_content', 'insert_comments', 'user_email']}); ended(await h.run('read-comments v1', {page: a.id}), 'failed', 'provider_failed', {providerStatus: 403, reason: 'capability_off'}); },
  'find-person v1/succeeds': async t => { const {h} = setup(t); assert.equal(ended(await h.run('find-person v1', {name: 'AVERY OWNER'}), 'succeeded', null).result.data.matches[0].id, h.simulator.owner.id); },
  'find-person v1/refused': async t => refusedNever(setup(t).h, 'notion.users.read', 'find-person v1', {name: 'Avery Owner'}),
  'find-person v1/provider-refusal': async t => { const {h} = setup(t); await failedWith(h, ROUTES.users, 400, 'validation_error', 'find-person v1', {name: 'Avery Owner'}, false); },
};
caseTests(test, MANIFEST, ENTRIES, IMPLEMENTATIONS);

// ---- the live plan (step 20's N0 to N11) -----------------------------------------------------------------------------------------------
const PLAN = () => JSON.parse(readFileSync(new URL('../catalog/live-tests/notion.json', import.meta.url), 'utf8'));
const planDeps = () => ({entries: ENTRIES, superseded: [], groups: PERMISSION_GROUPS.get('notion'), config: PROXY_CONFIGS.get('notion'), rules: RULES});

test('the live plan N0 to N11 passes step 12\'s plan check against the shipped file, calls all 16 actions, undoes every write, and deletes N9\'s and N10\'s comments through the one-time Ask', () => {
  const checked = checkPlan(PLAN(), planDeps()), steps = id => checked.plan.tests.find(item => item.id === id);
  assert.deepEqual(checked.plan.tests.map(item => item.id), ['N0', 'N1', 'N2', 'N2b', 'N3', 'N4', 'N5', 'N6', 'N7', 'N8', 'N9', 'N10', 'N11']);
  assert.deepEqual([...checked.actions.keys()].sort(), ENTRIES.map(entry => `${entry.key}@${entry.version}`).sort());
  assert.deepEqual(Object.keys(checked.plan.recorded), ['pageA', 'pageB', 'database', 'dataSource', 'row1', 'ownerName']);
  assert.deepEqual(checked.plan.readRows, ['notion.content.read', 'notion.comments.read', 'notion.search.read']);
  // N0 reads only; N8 trashes, restores and trashes again; N1 is undone by N8, N9 and N10 by N11's one-time Ask on the Never row.
  assert.ok(steps('N0').steps.every(step => checked.actions.get(step.call.action).effect === 'read'));
  assert.deepEqual(steps('N8').steps.filter(step => step.call).map(step => step.call.action), ['trash-page@1', 'restore-page@1', 'trash-page@1']);
  assert.deepEqual([steps('N1').undo, steps('N9').undo, steps('N10').undo], [{test: 'N8'}, {test: 'N11'}, {test: 'N11'}]);
  const ask = steps('N11').steps[0].oneTimeAsk;
  assert.deepEqual([ask.row, ask.requests.map(request => `${request.method} ${request.path}`)], [NOTION_PERMANENT_DELETE, ['DELETE /v1/comments/{comment}', 'DELETE /v1/comments/{comment}']]);
  // Row 1 changes only its number, never its text, and goes back to 1.
  assert.deepEqual([steps('N7').steps[0].call.args.values, steps('N7').undo.steps[0].call.args.values], [{Count: 7}, {Count: 1}]);
});

/** The value at a JSON pointer, or undefined. */
const pointed = (value, pointer) => pointer === '' ? value : pointer.slice(1).split('/').reduce((current, part) => current === undefined || current === null ? undefined
  : Array.isArray(current) ? current[Number(part)] : Object.hasOwn(current, part) ? current[part] : undefined, value);
/** One plan check, as lib/live-certify.mjs holds() reads it, on {status, body}. */
function holdsCheck(check, {status, body}, fill) {
  if (Object.hasOwn(check, 'status')) return [check.status].flat().includes(status);
  if (Object.hasOwn(check, 'gone')) return status === 404 || status === 410;
  const value = pointed(body, check.pointer);
  if (Object.hasOwn(check, 'where')) {
    const chosen = (Array.isArray(value) ? value : []).filter(entry => Object.entries(fill(check.where)).every(([pointer, wanted]) => JSON.stringify(pointed(entry, pointer)) === JSON.stringify(wanted)));
    return chosen.length === 1 && JSON.stringify(pointed(chosen[0], check.field)) === JSON.stringify(fill(check.equals));
  }
  if (Object.hasOwn(check, 'equals')) return value !== undefined && JSON.stringify(value) === JSON.stringify(fill(check.equals));
  if (Object.hasOwn(check, 'present')) return (value !== undefined && value !== null) === check.present;
  if (Object.hasOwn(check, 'count')) return Array.isArray(value) && value.length === check.count;
  return false;
}

test('every step of the plan, its placeholders filled for a run, runs on the simulator through the live guard: nothing refused, every check holds, and the area is as it was', async t => {
  const folder = mkdtempSync(path.join(tmpdir(), 'fabric-notion-plan-'));
  t.after(() => rmSync(folder, {recursive: true, force: true}));
  let guard = null;
  const h = notionHarness(t, {wrap: inner => options => guard.wrap(inner)(options)});
  guard = createGuard({appId: 'notion', runId: 'ABCDEFGH', folder, key: randomBytes(32), clock: () => h.now});
  // Muse's setup: A and B shared, a database under A whose data source has Name, Stage (Open, Done) and Count, three rows, row 1's Count 1.
  const a = h.simulator.seedPage({title: '[SYNTHETIC] A', markdown: 'Page A', shared: true}), b = h.simulator.seedPage({title: '[SYNTHETIC] B', markdown: 'Page B', shared: true});
  const {database, sources: [source]} = h.simulator.seedDatabase({title: '[SYNTHETIC] Tasks', parent: {page_id: a.id}, sources: [{name: 'Tasks', properties: {Name: {type: 'title'}, Stage: {type: 'select', options: ['Open', 'Done']}, Count: {type: 'number'}}}]});
  const rows = [1, 2, 3].map(index => h.simulator.seedRow({dataSource: source.id, properties: {Name: {title: pieces(`[SYNTHETIC] Row ${index}`)}, Stage: {select: {name: 'Open'}}, Count: {number: index}}}));
  const recorded = {pageA: a.id.replace(/-/g, ''), pageB: b.id, database: database.id, dataSource: source.id, row1: rows[0].id, ownerName: OWNER.name};
  guard.setOwner({email: OWNER.email, timeZone: 'UTC', runDate: '2026-10-26', recorded});
  const run = {runId: 'ABCDEFGH', runDate: '2026-10-26', timeZone: 'UTC', recorded, saved: {}};
  const send = options => guard.wrap(h.simulator.request)({...options, url: `${NOTION_ORIGIN}${options.path}`, headers: {Authorization: `Bearer ${TOKEN}`, 'Notion-Version': '2026-03-11'}, allowedOrigins: [NOTION_ORIGIN]});
  const ran = [];
  for (const item of PLAN().tests) {
    const fill = value => fillPlaceholders(value, {run, account: {email: OWNER.email}}, item);
    const filled = (template, params) => template.replace(/\{([A-Za-z0-9_]+)\}/g, (_, slot) => encodeURIComponent(fill(params)[slot]));
    guard.begin(item.id);
    for (const step of [...item.steps, ...(item.undo?.steps ?? [])]) {
      const [kind] = Object.keys(step), body = step[kind], where = `${item.id} ${kind} ${body.action ?? body.path ?? body.row}`;
      if (kind === 'call') {
        let job = await h.run(body.action.replace('@', ' v'), fill(body.args ?? {}));
        for (let stops = 0; job.status === 'awaiting_approval' && stops < 3; stops++) job = await h.approve(job);
        ended(job, 'succeeded', null);
        for (const check of body.checks ?? []) assert.ok(holdsCheck(check, {body: job.result.data}, fill), `${where}: ${JSON.stringify(check)}`);
        for (const [name, pointer] of Object.entries(body.save ?? {})) run.saved[name] = pointed(job.result.data, pointer);
        ran.push(body.action);
      } else if (kind === 'read') {
        const answer = await send({method: 'GET', path: filled(body.path, body.params ?? {})});
        for (const check of body.checks ?? []) assert.ok(holdsCheck(check, {status: answer.status, body: answer.data}, fill), `${where}: ${JSON.stringify(check)}`);
      } else {
        guard.beginOneTimeAsk(body.row);
        for (const request of body.requests) assert.equal((await send({method: request.method, path: filled(request.path, request.params ?? {})})).status, 200, where);
        guard.endOneTimeAsk();
      }
    }
    guard.end();
  }
  assert.deepEqual([...new Set(ran)].sort(), ENTRIES.map(entry => `${entry.key}@${entry.version}`).sort(), 'every action ran');
  // What the run leaves: N1's page in the trash, N6's row in the trash, row 1's Count back at 1, no comment of the run, A and B untouched.
  const state = h.simulator.state(), page = state.pages[run.saved.page.replace(/-/g, '')] ?? Object.values(state.pages).find(item => item.id === run.saved.page);
  assert.deepEqual([page.in_trash, page.parent.page_id, page.text.includes('marker'), page.text.includes('edited')], [true, a.id, false, false]);
  assert.equal(Object.values(state.pages).find(item => item.id === run.saved.row).in_trash, true);
  assert.equal(Object.values(state.pages).find(item => item.id === rows[0].id).properties.Count.number, 1);
  assert.deepEqual(Object.values(state.comments).filter(comment => !comment.deleted), []);
  assert.deepEqual([titleText(Object.values(state.pages).find(item => item.id === a.id)), Object.values(state.pages).find(item => item.id === b.id).text], ['[SYNTHETIC] A', 'Page B']);
  assert.equal(guard.counts().writes, ['N1', 'N2', 'N2b', 'N3', 'N4', 'N5', 'N6', 'N7', 'N8', 'N9', 'N10', 'N11'].reduce((total, id) => total + (guard.counts().testWrites[id] ?? 0), 0));
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {runTransform} from '../lib/transforms/index.mjs';
import {TOKEN} from './fixtures/actions/notion-harness.mjs';
import {shippedTriggers, triggerWorld} from './fixtures/actions/trigger-harness.mjs';
import {caseTests} from './fixtures/provider-simulators/cases.mjs';
import {BASE, NotionApiSimulator, ORIGIN, VERSION} from './fixtures/provider-simulators/notion.mjs';

// Iteration 9 step 5 (docs/I07-BUILD-MAP.md): Notion's seven triggers on its simulator. Each trigger runs the shared cases of notion.trigger-cases.json on the shared harness, with the shipped rows
// and proxy settings, and its own cases follow. Nothing here listens on a port or reaches Notion. Writes go through the simulator's own routes, so each is held to what Notion takes.
const manifest = JSON.parse(readFileSync(new URL('./fixtures/provider-simulators/notion.trigger-cases.json', import.meta.url), 'utf8'));
const KEYS = Object.freeze(['new-row', 'row-changed', 'page-content-changed', 'new-comment', 'trashed-or-restored', 'schema-changed', 'new-child-page']);
const INTERVAL = 150_000, QUERY = 'POST /data_sources/{data_source_id}/query', SCHEMA = {Name: {type: 'title'}, Stage: {type: 'select', options: ['Open', 'Done']}, Note: {type: 'rich_text'}, Total: {type: 'formula'}, Receipt: {type: 'files'}};

/** A write sent as an integration sends it, through the simulator's own route. */
async function send(world, method, path, {query, body} = {}) {
  const url = new URL(`${BASE}${path}`);
  for (const [name, value] of Object.entries(query ?? {})) url.searchParams.set(name, String(value));
  const answer = await world.simulator.request({url: url.href, method, allowedOrigins: [ORIGIN], headers: {authorization: `Bearer ${TOKEN}`, 'notion-version': VERSION}, ...(body === undefined ? {} : {body: JSON.stringify(body)})});
  return answer;
}
const write = async (world, ...request) => { const answer = await send(world, ...request); assert.equal(answer.status, 200, JSON.stringify(answer.data)); return answer.data; };
const title = text => ({Name: {title: [{text: {content: text}}]}});
const note = text => ({Note: {rich_text: [{text: {content: text}}]}});
const rename = (world, id, text) => write(world, 'PATCH', `/pages/${id}`, {body: {properties: {title: {title: [{text: {content: text}}]}}}});
const trash = (world, id) => write(world, 'PATCH', `/pages/${id}`, {body: {in_trash: true}});
const restore = (world, id) => write(world, 'PATCH', `/pages/${id}`, {body: {in_trash: false}});
const addText = (world, id, content) => write(world, 'PATCH', `/pages/${id}/markdown`, {body: {type: 'insert_content', insert_content: {content}}});
const swapText = (world, id, from, to) => write(world, 'PATCH', `/pages/${id}/markdown`, {body: {type: 'update_content', update_content: {content_updates: [{old_str: from, new_str: to}]}}});
const editRow = (world, id, properties) => write(world, 'PATCH', `/pages/${id}`, {body: {properties}});
const editSchema = (world, id, properties) => write(world, 'PATCH', `/data_sources/${id}`, {body: {properties}});
const move = (world, id, pageId) => write(world, 'POST', `/pages/${id}/move`, {body: {parent: {type: 'page_id', page_id: pageId}}});

/** A world with a shared home page, a page and a data source under it, and two rows made long before any watch. */
function notionWorld(t, keys, options) {
  const world = triggerWorld(t, 'notion', {keys, ...options}), {simulator} = world, home = simulator.seedPage({title: 'Home', markdown: 'Home text', shared: true});
  const {sources: [source]} = simulator.seedDatabase({title: 'Tasks', parent: {page_id: home.id}, sources: [{name: 'Tasks', properties: SCHEMA}]});
  const page = simulator.seedPage({title: 'Plan', parent: {page_id: home.id}, markdown: 'First line'}), row = simulator.seedRow({dataSource: source.id, properties: title('Old row')});
  simulator.seedRow({dataSource: source.id, properties: title('Older row')});
  world.advance(3_600_000);
  return Object.assign(world, {home, source, page, row});
}
/** Subscribes, approves and runs the silent first poll. */
async function watch(world, key, args) {
  const {id} = await world.subscribe(key, args);
  assert.equal(world.approve(id).status, 'starting');
  assert.equal((await world.pollNow(id)).status, 'active');
  return id;
}
const poll = async (world, id, ms = INTERVAL) => { world.advance(ms); return world.pollNow(id); };
const fired = async world => (await world.events()).events;
const reads = (world, route) => world.simulator.calls.filter(call => call.route === route);
const stored = (world, id) => world.store.get('triggerFeeds', world.record(id).feeds[0]);

/** Each trigger: the arguments of its watch, the one write that gives one event, and the route of its first read. */
const TRIGGERS = Object.freeze({
  'new-row': {args: world => ({dataSourceId: world.source.id}), write: world => { world.simulator.seedRow({dataSource: world.source.id, properties: title('New row')}); }, route: QUERY},
  'row-changed': {args: world => ({dataSourceId: world.source.id}), write: world => editRow(world, world.row.id, title('Edited row')), route: QUERY},
  'page-content-changed': {args: world => ({pages: [world.page.id]}), write: world => addText(world, world.page.id, 'Second line'), route: 'GET /pages/{page_id}'},
  'new-comment': {args: world => ({pages: [world.page.id]}), write: world => { world.simulator.seedComment({page: world.page.id, text: 'A comment'}); }, route: 'GET /comments'},
  'trashed-or-restored': {args: world => ({pages: [world.page.id]}), write: world => trash(world, world.page.id), route: 'GET /pages/{page_id}'},
  'schema-changed': {args: world => ({dataSourceId: world.source.id}), write: world => editSchema(world, world.source.id, {Due: {date: {}}}), route: 'GET /data_sources/{data_source_id}'},
  'new-child-page': {args: world => ({pages: [world.home.id]}), write: world => { world.simulator.seedPage({title: 'Child', parent: {page_id: world.home.id}}); }, route: 'GET /blocks/{block_id}/children'},
});
const NOT_SHARED = {status: 404, data: {object: 'error', status: 404, code: 'object_not_found', message: 'Could not find object.'}};
const CAPABILITY_OFF = {status: 403, data: {object: 'error', status: 403, code: 'restricted_resource', message: 'Insufficient permissions for this endpoint.'}};
/** What a malformed stored place is, for a trigger's cursor. A snapshot's cursor is its seen rows, so its one stored place is a page token. */
const malformed = key => ({'new-row': {cursors: {created: 'not a time'}}, 'row-changed': {cursors: {edited: 'not a time'}}})[key] ?? {page: {token: 'not\na token', walk: 'delta'}};

const shared = Object.fromEntries(KEYS.flatMap(key => {
  const {args, write: change, route} = TRIGGERS[key], name = `${key} v1/`, world = t => notionWorld(t, [key]);
  return [
    [`${name}baseline-silent`, async t => {
      const here = world(t);
      await change(here);
      here.advance(1000);
      await watch(here, key, args(here));
      assert.deepEqual(await fired(here), [], 'what stood before the watch is not news, even a write seconds old');
    }],
    [`${name}one-then-zero`, async t => {
      const here = world(t), id = await watch(here, key, args(here));
      here.advance(1000);
      await change(here);
      await poll(here, id);
      const first = await fired(here);
      assert.deepEqual(first.map(event => [event.type, event.subscriptionId]), [['trigger.event', id]]);
      await poll(here, id);
      assert.deepEqual(await fired(here), [], 'a re-poll gives zero');
      assert.equal(here.record(id).status, 'active');
    }],
    [`${name}crash-before-cursor`, async t => {
      const here = world(t), id = await watch(here, key, args(here)), {store} = here, append = store.appendPoll.bind(store);
      here.advance(1000);
      await change(here);
      store.appendPoll = options => { const answer = append(options); store.appendPoll = append; throw new Error('stopped between the events and the feed'); };
      await assert.rejects(poll(here, id), /stopped between/);
      await poll(here, id);
      await poll(here, id);
      assert.deepEqual((await fired(here)).map(event => event.type), ['trigger.event'], 'the replay finds its seen row and stores nothing twice');
    }],
    [`${name}background-never`, async t => {
      const here = world(t), id = await watch(here, key, args(here)), before = here.simulator.reads().length;
      here.store.put('backgroundPolicies', {id: here.account, connectionId: here.account, mode: 'deny', updatedAt: 'x'});
      await change(here);
      const held = await poll(here, id);
      assert.deepEqual([held.status, held.reason], ['paused', 'background_off']);
      assert.equal(here.simulator.reads().length, before, 'no read goes out');
    }],
    [`${name}row-never-mid-poll`, async t => {
      const here = world(t), id = await watch(here, key, args(here)), row = key === 'new-comment' ? 'notion.comments.read' : 'notion.content.read';
      here.advance(1000);
      await change(here);
      const gate = here.simulator.hold(route);
      here.advance(INTERVAL);
      const running = here.pollNow(id);
      await gate.reached;
      here.setRow(row, 'deny');
      gate.release();
      const held = await running;
      assert.deepEqual([held.status, held.reason], ['paused', 'permission_changed']);
      assert.deepEqual((await fired(here)).filter(event => !event.withheld), [], 'nothing read past a Never is told');
    }],
    [`${name}malformed-cursor`, async t => {
      const here = world(t), id = await watch(here, key, args(here)), before = here.simulator.reads().length;
      here.store.put('triggerFeeds', {...stored(here, id), ...malformed(key)});
      const held = await poll(here, id);
      assert.deepEqual([held.status, held.reason], ['paused', 'cursor_invalid']);
      assert.equal(here.simulator.reads().length, before, 'a place Fabric cannot trust is never sent');
    }],
    [`${name}caps`, async t => {
      const here = world(t), ids = Array.from({length: 11}, (_, index) => `0f0e0d0c-0b0a-4908-8706-0504030201${String(index).padStart(2, '0')}`);
      const of = value => ('pages' in args(here) ? {pages: [value]} : {dataSourceId: value});
      for (const value of ids.slice(0, 10)) await here.subscribe(key, of(value));
      await assert.rejects(here.subscribe(key, of(ids[10])), error => error.code === 'pending_limit', 'a client holds at most 10 waiting');
      assert.equal(here.simulator.reads().length, 0, 'a subscribe sends nothing');
    }],
    [`${name}pause-on-refusal`, async t => {
      for (const [answer, detail] of [[NOT_SHARED, 'not_shared'], [CAPABILITY_OFF, 'capability_off']]) {
        const here = world(t), id = await watch(here, key, args(here));
        here.simulator.fail(route, answer);
        const held = await poll(here, id);
        assert.deepEqual([held.status, held.reason, held.detail], ['paused', 'provider_refused', detail], `${key}: ${detail}, never a resync`);
        assert.deepEqual((await fired(here)).filter(event => event.type === 'trigger.gap'), []);
      }
    }],
  ];
}));
caseTests(test, manifest, shippedTriggers('notion').triggers.map(({key, version}) => ({key, version})), shared);

// ---- the file --------------------------------------------------------------------------------------------------------------------------------------
// The loader itself refuses a stored id that is not the computed one (test/trigger-catalog.test.mjs), and a world recomputes ids, so a fault in this file reaches behaviour here.
test('the shipped file holds the seven triggers, each a candidate until a live pass, on its reviewed polling fallback at the table\'s cadence, and all seven load together', t => {
  const file = shippedTriggers('notion'), world = triggerWorld(t, 'notion');
  assert.deepEqual([...world.catalog.triggersRefused], []);
  assert.deepEqual(KEYS.map(key => world.catalog.triggerOf(world.triggerId(key)).status), Array(7).fill('active'), 'in a world\'s reviewed copy');
  assert.deepEqual(file.triggers.map(item => item.key), KEYS);
  assert.equal(file.reviewStatus, 'candidate');
  for (const item of file.triggers) {
    assert.deepEqual([item.delivery.method, item.delivery.registration, item.delivery.fallback], ['webhook', 'operator', 'polling'], item.key);
    assert.equal(Object.hasOwn(item, 'certified'), false, item.key);
  }
  assert.deepEqual(Object.fromEntries(file.triggers.map(item => [item.key, item.poll.minIntervalSeconds])), {'new-row': 120, 'row-changed': 120, 'page-content-changed': 240, 'new-comment': 120, 'trashed-or-restored': 240, 'schema-changed': 600, 'new-child-page': 240});
});

// ---- the transforms ---------------------------------------------------------------------------------------------------------------------------------
test('notion.rowFingerprint@1 past 100 properties refuses with its code, so a watch pauses and never guesses', () => {
  const properties = Object.fromEntries(Array.from({length: 101}, (_, index) => [`P${index}`, {id: `p${index}`, type: 'number', number: index}]));
  assert.throws(() => runTransform('notion.rowFingerprint@1', {page: {object: 'page', properties}}), error => error.code === 'too_many_properties');
});
test('notion.markdownFingerprint@1 takes exactly its limit, refuses one character more, and a page built to be slow costs what any other does', () => {
  const limit = 1_000_000;
  assert.equal(runTransform('notion.markdownFingerprint@1', {markdown: 'a'.repeat(limit)}).text.length, limit);
  assert.throws(() => runTransform('notion.markdownFingerprint@1', {markdown: 'a'.repeat(limit + 1)}), error => error.code === 'input_invalid');
  const started = performance.now();
  for (const part of ['https://', 'https://s3', 'https://s3.amazonaws.com/a?', '?', 'a.s3.']) runTransform('notion.markdownFingerprint@1', {markdown: part.repeat(Math.floor(limit / part.length))});
  assert.ok(performance.now() - started < 5000, 'no pattern looks back over the page');
});

// ---- new row ----------------------------------------------------------------------------------------------------------------------------------------
test('new row: one row is one event with its fields and its title, read through filter_properties, and an old row edited gives zero', async t => {
  const world = notionWorld(t, ['new-row']), id = await watch(world, 'new-row', {dataSourceId: world.source.id});
  await editRow(world, world.row.id, title('Old row, edited'));
  await poll(world, id);
  assert.deepEqual(await fired(world), [], 'an edit of a row made long ago is no new row');
  const row = world.simulator.seedRow({dataSource: world.source.id, properties: title('New row')});
  await poll(world, id);
  const [event, ...rest] = await fired(world);
  assert.deepEqual(rest, []);
  assert.deepEqual(event.fields, {dataSourceId: world.source.id, pageId: row.id, title: 'New row', url: row.url, createdTime: row.created_time, createdBy: row.created_by.id});
  assert.deepEqual(event.summary, [{label: 'Row', value: 'New row'}, {label: 'Created', value: row.created_time}]);
  assert.deepEqual([event.id, event.occurredAt], [row.id, row.created_time]);
  assert.equal(world.record(id).status, 'active');
  const call = reads(world, QUERY).at(-1);
  assert.equal(call.query.filter_properties, 'title', 'a query parameter, as Notion takes it');
  assert.equal(Object.hasOwn(call.body, 'filter_properties'), false);
  assert.deepEqual(call.body.sorts, [{timestamp: 'created_time', direction: 'ascending'}]);
  assert.equal(call.body.result_type, 'page');
});

test('new row: rows that share a stamp\'s minute across two polls are each one event, and the overlap re-reads the first without a second', async t => {
  const world = notionWorld(t, ['new-row']), id = await watch(world, 'new-row', {dataSourceId: world.source.id}), add = text => world.simulator.seedRow({dataSource: world.source.id, properties: title(text)});
  world.advance(90_000 - (world.now % 60_000));
  const first = add('First');
  await world.pollNow(id);
  world.advance(10_000);
  const second = add('Second');
  assert.equal(first.created_time, second.created_time, 'both stamps read one minute');
  await world.pollNow(id);
  await poll(world, id);
  assert.deepEqual((await fired(world)).map(event => event.fields.title), ['First', 'Second']);
});

test('new row: an untitled row and a row with a long title are each one event, cut to what the card lists', async t => {
  const world = notionWorld(t, ['new-row']), id = await watch(world, 'new-row', {dataSourceId: world.source.id});
  world.simulator.seedRow({dataSource: world.source.id, properties: {}});
  world.simulator.seedRow({dataSource: world.source.id, properties: title('Long '.repeat(100))});
  await poll(world, id);
  const events = await fired(world), lengths = events.map(event => [...event.fields.title].length).sort((a, b) => a - b);
  assert.deepEqual(events.map(event => event.type), ['trigger.event', 'trigger.event'], 'neither is lost to a gap');
  assert.equal(lengths[0], 0);
  assert.ok(lengths[1] > 100 && lengths[1] <= 200, String(lengths[1]));
});

test('new row: a row that reaches the query late sits inside the overlap, so a later row\'s mark does not pass it', async t => {
  const world = notionWorld(t, ['new-row']), id = await watch(world, 'new-row', {dataSourceId: world.source.id}), add = text => world.simulator.seedRow({dataSource: world.source.id, properties: title(text)});
  world.simulator.lag(100_000);
  add('Late');
  world.simulator.lag(0);
  world.advance(60_000);
  add('Prompt');
  await world.pollNow(id);
  assert.deepEqual((await fired(world)).map(event => event.fields.title), ['Prompt']);
  await poll(world, id, 60_000);
  assert.deepEqual((await fired(world)).map(event => event.fields.title), ['Late']);
  await poll(world, id);
  assert.deepEqual(await fired(world), []);
});

test('an empty data source: the seed finds no row, a poll binds the body cursor to 1970, the first row is one event, and two rows 10 minutes apart give two', async t => {
  const world = notionWorld(t, ['new-row']), {simulator} = world, {sources: [empty]} = simulator.seedDatabase({title: 'Empty', parent: {page_id: world.home.id}, sources: [{name: 'Empty', properties: SCHEMA}]});
  const id = await watch(world, 'new-row', {dataSourceId: empty.id}), before = reads(world, QUERY).length;
  assert.equal(before, 1, 'a baseline with no cursor runs the seed in the poll step\'s place, so nothing sends an empty filter');
  assert.deepEqual(stored(world, id).cursors, {}, 'a cursor comes only from a provider\'s answer, and none named one');
  assert.equal(stored(world, id).baselined, true);
  await poll(world, id);
  assert.deepEqual(reads(world, QUERY).at(-1).body.filter, {timestamp: 'created_time', created_time: {on_or_after: '1970-01-01T00:00:00.000Z'}});
  assert.deepEqual(stored(world, id).cursors, {}, 'the constant is sent, and never stored');
  const row = simulator.seedRow({dataSource: empty.id, properties: title('First')});
  await poll(world, id);
  assert.deepEqual((await fired(world)).map(event => event.fields.pageId), [row.id]);
  assert.equal(stored(world, id).cursors.created, row.created_time);
  simulator.seedRow({dataSource: empty.id, properties: title('Second')});
  await poll(world, id, 600_000);
  simulator.seedRow({dataSource: empty.id, properties: title('Third')});
  await poll(world, id, 600_000);
  assert.deepEqual((await fired(world)).map(event => event.fields.title), ['Second', 'Third']);
});

test('a seed whose newest row is partial says nothing of the time, so the baseline backs off, and no row reads as new', async t => {
  const world = notionWorld(t, ['new-row']), {simulator} = world, newest = simulator.seedRow({dataSource: world.source.id, properties: title('Newest')}), {id} = await world.subscribe('new-row', {dataSourceId: world.source.id});
  world.approve(id);
  simulator.partial(newest.id);
  assert.equal((await world.pollNow(id)).status, 'starting', 'an empty list and a partial row are not the same answer');
  const feed = stored(world, id);
  assert.deepEqual([feed.baselined, feed.failures, world.store.get('triggerRuns', feed.id).runs.at(-1).code], [false, 1, 'seed_partial']);
  simulator.partial(newest.id, false);
  world.advance(feed.nextPollAt - world.now);
  assert.equal((await world.pollNow(id)).status, 'active');
  await poll(world, id);
  assert.deepEqual(await fired(world), [], 'the old rows stay old');
});

test('a partial item adds no mark and no seen row: it is skipped and counted, and read whole later it is one event', async t => {
  const world = notionWorld(t, ['new-row']), id = await watch(world, 'new-row', {dataSourceId: world.source.id}), mark = stored(world, id).cursors.created;
  const row = world.simulator.seedRow({dataSource: world.source.id, properties: title('Partial')});
  world.simulator.partial(row.id);
  await poll(world, id);
  assert.deepEqual(await fired(world), []);
  assert.equal(stored(world, id).cursors.created, mark, 'an item with no time moves no mark');
  assert.equal(world.store.get('triggerRuns', stored(world, id).id).runs.at(-1).skipped, 1);
  world.simulator.partial(row.id, false);
  await poll(world, id);
  assert.deepEqual((await fired(world)).map(event => event.fields.pageId), [row.id], 'no seen row held it back');
});

// ---- changed row ------------------------------------------------------------------------------------------------------------------------------------
test('changed row: two edits in one minute give two events, an old row first edited reads edited, and a new row reads created', async t => {
  const world = notionWorld(t, ['row-changed']), id = await watch(world, 'row-changed', {dataSourceId: world.source.id});
  world.advance(90_000 - (world.now % 60_000));
  const one = await editRow(world, world.row.id, title('Once'));
  await world.pollNow(id);
  world.advance(5000);
  const two = await editRow(world, world.row.id, title('Twice'));
  assert.equal(one.last_edited_time, two.last_edited_time, 'one stamp, so a key on the stamp would lose the second edit');
  await world.pollNow(id);
  const events = await fired(world);
  assert.deepEqual(events.map(event => [event.fields.title, event.fields.changeKind]), [['Once', 'edited'], ['Twice', 'edited']]);
  assert.deepEqual(Object.keys(events[0].fields).sort(), ['changeKind', 'createdTime', 'dataSourceId', 'editedBy', 'lastEditedTime', 'pageId', 'title', 'url']);
  const row = world.simulator.seedRow({dataSource: world.source.id, properties: title('Brand new')});
  await poll(world, id);
  assert.deepEqual((await fired(world)).map(event => [event.fields.pageId, event.fields.changeKind]), [[row.id, 'created']]);
});

test('changed row: A to B to A gives three events, an edit of the page body alone gives one, and a re-poll gives zero', async t => {
  const world = notionWorld(t, ['row-changed']), id = await watch(world, 'row-changed', {dataSourceId: world.source.id});
  for (const text of ['A', 'B', 'A']) { await editRow(world, world.row.id, note(text)); await poll(world, id); }
  assert.equal((await fired(world)).length, 3, 'the latest value is compared, never a set of all values');
  await addText(world, world.row.id, 'Body text');
  await poll(world, id);
  assert.equal((await fired(world)).length, 1);
  await poll(world, id);
  assert.deepEqual(await fired(world), []);
});

test('changed row: a formula that moves with no edit and a file link signed anew give zero on the re-read the overlap makes', async t => {
  const world = notionWorld(t, ['row-changed']), id = await watch(world, 'row-changed', {dataSourceId: world.source.id});
  world.simulator.attachFile(world.row.id, 'Receipt', 'receipt.pdf');
  await editRow(world, world.row.id, note('Filed'));
  await poll(world, id, 30_000);
  assert.equal((await fired(world)).length, 1);
  world.simulator.setFormula(world.row.id, 'Total', 41);
  await poll(world, id, 30_000);
  const sent = reads(world, QUERY).at(-1).body.filter.last_edited_time.on_or_after;
  assert.ok(sent <= world.simulator.state().pages[world.row.id].last_edited_time, 'the overlap read this row again');
  assert.deepEqual(await fired(world), [], 'a raw hash of the properties would fire here');
});

/** Every event a client can read now, past one page's limit. */
async function allEvents(world) {
  const events = [];
  for (let page = await world.events({limit: 100}); page.events.length; page = await world.events({limit: 100})) events.push(...page.events);
  return events;
}
/** A burst of 600 rows in one minute, read to its stall: the first poll reads 500, and the next reads the same 500 and gives up on that minute. */
async function burst(world, id) {
  world.advance(INTERVAL);
  const rows = Array.from({length: 600}, (_, index) => world.simulator.seedRow({dataSource: world.source.id, properties: title(`Row ${index}`)}));
  assert.equal(new Set(rows.map(row => row.last_edited_time)).size, 1, 'they share one minute');
  await world.pollNow(id);
}
const counted = events => ({events: new Set(events.filter(event => event.type === 'trigger.event').map(event => event.fields.pageId)).size, rows: events.filter(event => event.type === 'trigger.event').length,
  gaps: events.filter(event => event.type === 'trigger.gap').map(event => event.fields.reason)});
for (const key of ['new-row', 'row-changed']) {
  test(`${key}: 600 rows in one minute give 500 events and one gap, and a later change still arrives`, async t => {
    const world = notionWorld(t, [key]), id = await watch(world, key, {dataSourceId: world.source.id});
    await burst(world, id);
    await poll(world, id);
    await poll(world, id);
    assert.deepEqual(counted(await allEvents(world)), {events: 500, rows: 500, gaps: ['stall']});
    await poll(world, id);
    assert.deepEqual(await fired(world), [], 'the floor holds: the stalled minute is not read again');
    const later = world.simulator.seedRow({dataSource: world.source.id, properties: title('Later')});
    await poll(world, id);
    assert.deepEqual((await fired(world)).map(event => event.fields.pageId), [later.id]);
  });
  test(`${key}: a crash between the events and the feed, on the poll that stalls, stores one gap when it runs again`, async t => {
    const world = notionWorld(t, [key]), id = await watch(world, key, {dataSourceId: world.source.id}), {store} = world, append = store.appendPoll.bind(store);
    await burst(world, id);
    store.appendPoll = options => { const answer = append(options); store.appendPoll = append; throw new Error('stopped between the events and the feed'); };
    await assert.rejects(poll(world, id), /stopped between/);
    await poll(world, id);
    await poll(world, id);
    assert.deepEqual(counted(await allEvents(world)), {events: 500, rows: 500, gaps: ['stall']});
  });
}

test('changed row: a trashed row and an archived row leave the query, so neither gives an event, as the card says', async t => {
  const world = notionWorld(t, ['row-changed']), {simulator} = world, id = await watch(world, 'row-changed', {dataSourceId: world.source.id});
  const [one, two] = ['One', 'Two'].map(text => simulator.seedRow({dataSource: world.source.id, properties: title(text)}));
  await poll(world, id);
  assert.equal((await fired(world)).length, 2);
  await trash(world, one.id);
  simulator.archive(two.id);
  simulator.touch(two.id);
  await poll(world, id);
  assert.deepEqual(await fired(world), []);
});

test('new row and changed row on one data source take two feeds and two marks, so each hears only its own', async t => {
  const world = notionWorld(t, ['new-row', 'row-changed']), args = {dataSourceId: world.source.id}, added = await watch(world, 'new-row', args), changed = await watch(world, 'row-changed', args);
  assert.notEqual(world.record(added).feeds[0], world.record(changed).feeds[0]);
  assert.deepEqual([Object.keys(stored(world, added).cursors), Object.keys(stored(world, changed).cursors)], [['created'], ['edited']]);
  await editRow(world, world.row.id, title('Edited'));
  world.advance(INTERVAL);
  await world.pollNow(added);
  await world.pollNow(changed);
  assert.deepEqual((await fired(world)).map(event => event.subscriptionId), [changed]);
});

// ---- page content -----------------------------------------------------------------------------------------------------------------------------------
test('page content: a signed link gives zero on re-poll, a rename gives zero, A to B to A gives two, and the markdown version is pinned', async t => {
  const world = notionWorld(t, ['page-content-changed']), {page, simulator} = world;
  simulator.uploadFile(page.id, 'photo.png');
  const id = await watch(world, 'page-content-changed', {pages: [page.id]});
  for (let times = 0; times < 2; times++) await poll(world, id);
  assert.deepEqual(await fired(world), [], 'each read signed the link anew');
  await rename(world, page.id, 'A new name');
  await poll(world, id);
  assert.deepEqual(await fired(world), [], 'a rename leaves the text as it was');
  await swapText(world, page.id, 'First line', 'Changed line');
  await poll(world, id);
  await swapText(world, page.id, 'Changed line', 'First line');
  await poll(world, id);
  const events = await fired(world);
  assert.equal(events.length, 2, 'back to the first text is a change, so the latest value is compared');
  assert.deepEqual(Object.keys(events[0].fields).sort(), ['editedBy', 'lastEditedTime', 'pageId', 'truncated', 'url']);
  assert.equal(events[0].fields.pageId, page.id);
  assert.deepEqual(reads(world, 'GET /pages/{page_id}/markdown').map(call => call.query.markdown_version), Array(6).fill('v2'));
});

test('page content: chosen pages each read by their own feed, and a repeated page is one feed', async t => {
  const world = notionWorld(t, ['page-content-changed']), other = world.simulator.seedPage({title: 'Other', parent: {page_id: world.home.id}, markdown: 'Other text'});
  const id = await watch(world, 'page-content-changed', {pages: [world.page.id, other.id, world.page.id.replaceAll('-', '')]});
  assert.equal(world.record(id).feeds.length, 2);
  await addText(world, other.id, 'More');
  await poll(world, id);
  assert.deepEqual((await fired(world)).map(event => event.fields.pageId), [other.id]);
});

test('page content: a page over 1,000,000 characters pauses too_many_items, and one at the limit reads', async t => {
  const world = notionWorld(t, ['page-content-changed']), {simulator} = world, page = simulator.seedPage({title: 'Long', parent: {page_id: world.home.id}, markdown: 'a'.repeat(1_000_001)});
  const {id} = await world.subscribe('page-content-changed', {pages: [page.id]});
  world.approve(id);
  const held = await world.pollNow(id);
  assert.deepEqual([held.status, held.reason, held.detail], ['paused', 'too_many_items', 'input_invalid']);
  const exact = simulator.seedPage({title: 'Exact', parent: {page_id: world.home.id}, markdown: 'a'.repeat(1_000_000)});
  await watch(world, 'page-content-changed', {pages: [exact.id]});
});

// ---- comments ---------------------------------------------------------------------------------------------------------------------------------------
test('comment: a comment and a reply are each one event, resolve and reopen gives zero, and a delete gives zero', async t => {
  const world = notionWorld(t, ['new-comment']), {page, simulator} = world, id = await watch(world, 'new-comment', {pages: [page.id]});
  const comment = simulator.seedComment({page: page.id, text: 'A question'});
  await poll(world, id);
  const [event, ...rest] = await fired(world);
  assert.deepEqual(rest, []);
  assert.deepEqual(event.fields, {commentId: comment.id, discussionId: comment.discussion_id, pageId: page.id, createdTime: comment.created_time, createdBy: comment.created_by.id});
  assert.deepEqual(event.summary, [{label: 'Comment', value: 'A question'}, {label: 'Created', value: comment.created_time}]);
  const reply = simulator.seedComment({page: page.id, text: 'An answer', discussion: comment.discussion_id});
  await poll(world, id);
  assert.deepEqual((await fired(world)).map(item => item.fields.commentId), [reply.id]);
  simulator.resolve(comment.id);
  await poll(world, id);
  simulator.reopen(comment.id);
  await poll(world, id);
  assert.deepEqual(await fired(world), [], 'a comment that went and came back is the same comment');
  await write(world, 'DELETE', `/comments/${reply.id}`);
  await poll(world, id);
  assert.deepEqual(await fired(world), []);
});

test('comment: a comment on a block is absent from the page\'s list, a comment on a row\'s property is told, and a partial comment adds no seen row', async t => {
  const world = notionWorld(t, ['new-comment']), {page, simulator} = world, id = await watch(world, 'new-comment', {pages: [page.id]}), block = simulator.seedBlock({page: page.id, text: 'A block'});
  simulator.seedComment({page: page.id, block: block.id, text: 'On a block'});
  await poll(world, id);
  assert.deepEqual(await fired(world), [], 'the card says so');
  const onProperty = simulator.seedComment({page: page.id, text: 'On a value', propertyId: 'title'});
  simulator.seedComment({page: page.id, text: 'Half here', partial: true});
  await poll(world, id);
  assert.deepEqual((await fired(world)).map(event => event.fields.commentId), [onProperty.id]);
  assert.equal(world.store.get('triggerRuns', stored(world, id).id).runs.at(-1).skipped, 1);
});

// ---- trashed or restored ----------------------------------------------------------------------------------------------------------------------------
test('trashed or restored: a rename gives zero, and trash, restore, trash gives three in one minute', async t => {
  const world = notionWorld(t, ['trashed-or-restored']), {page} = world, id = await watch(world, 'trashed-or-restored', {pages: [page.id]});
  await rename(world, page.id, 'A new name');
  await poll(world, id);
  assert.deepEqual(await fired(world), []);
  world.advance(70_000 - (world.now % 60_000));
  const stamps = [];
  for (const change of [trash, restore, trash]) {
    stamps.push((await change(world, page.id)).last_edited_time);
    await world.pollNow(id);
    world.advance(1000);
  }
  assert.equal(new Set(stamps).size, 1, 'one stamp for all three');
  const events = await fired(world);
  assert.deepEqual(events.map(event => event.fields.inTrash), [true, false, true]);
  assert.deepEqual(Object.keys(events[0].fields).sort(), ['editedBy', 'inTrash', 'lastEditedTime', 'pageId', 'title', 'url']);
  await poll(world, id);
  assert.deepEqual(await fired(world), []);
});

// ---- schema -----------------------------------------------------------------------------------------------------------------------------------------
test('schema: a column added, renamed and removed each fire, an option added fires, and an option\'s colour alone gives zero', async t => {
  const world = notionWorld(t, ['schema-changed']), {source} = world, id = await watch(world, 'schema-changed', {dataSourceId: source.id});
  const steps = [[{Due: {date: {}}}, 1], [{Due: {name: 'Deadline'}}, 1], [{Deadline: null}, 1], [{Stage: {select: {options: [{name: 'Open', color: 'red'}, {name: 'Done', color: 'default'}]}}}, 0],
    [{Stage: {select: {options: [{name: 'Open'}, {name: 'Done'}, {name: 'Waiting'}]}}}, 1]];
  for (const [change, count] of steps) {
    await editSchema(world, source.id, change);
    await poll(world, id);
    assert.equal((await fired(world)).length, count, JSON.stringify(change));
  }
  await poll(world, id);
  assert.deepEqual(await fired(world), []);
});

test('schema: a relation whose database is unshared reads as a removal and fires, and shared again it fires again', async t => {
  const world = notionWorld(t, ['schema-changed']), {simulator, home} = world, other = simulator.seedPage({title: 'Elsewhere', shared: true});
  const {sources: [target]} = simulator.seedDatabase({title: 'Target', parent: {page_id: other.id}, sources: [{name: 'Target', properties: {Name: {type: 'title'}}}]});
  const {sources: [source]} = simulator.seedDatabase({title: 'Linked', parent: {page_id: home.id}, sources: [{name: 'Linked', properties: {Name: {type: 'title'}, Link: {type: 'relation', target: target.id}}}]});
  const id = await watch(world, 'schema-changed', {dataSourceId: source.id});
  simulator.unshare(other.id);
  await poll(world, id);
  const [event] = await fired(world);
  assert.deepEqual(event.fields, {dataSourceId: source.id, title: 'Linked', lastEditedTime: source.last_edited_time, editedBy: source.last_edited_by.id});
  simulator.share(other.id);
  await poll(world, id);
  assert.equal((await fired(world)).length, 1);
});

test('schema and rows: past 100 properties or 256 options a watch pauses too_many_items with the transform\'s code, for its own lens', async t => {
  const world = notionWorld(t, ['schema-changed', 'row-changed']), {simulator, home} = world, wide = Object.fromEntries(Array.from({length: 101}, (_, index) => [`P${index}`, {type: 'number'}]));
  const {sources: [many]} = simulator.seedDatabase({title: 'Wide', parent: {page_id: home.id}, sources: [{name: 'Wide', properties: {Name: {type: 'title'}, ...wide}}]});
  const {sources: [choices]} = simulator.seedDatabase({title: 'Choices', parent: {page_id: home.id}, sources: [{name: 'Choices', properties: {Name: {type: 'title'}, Stage: {type: 'select', options: Array.from({length: 257}, (_, index) => `O${index}`)}}}]});
  simulator.seedRow({dataSource: many.id, properties: title('A wide row')});
  for (const [key, source, code] of [['schema-changed', many, 'too_many_properties'], ['schema-changed', choices, 'too_many_options'], ['row-changed', many, 'too_many_properties']]) {
    const {id} = await world.subscribe(key, {dataSourceId: source.id});
    world.approve(id);
    const held = await world.pollNow(id);
    assert.deepEqual([held.status, held.reason, held.detail], ['paused', 'too_many_items', code], key);
  }
});

test('schema and rows: a column named constructor is a name the transform harness will not take, so the two watches that read columns stop, say why, and Resume works once it is renamed', async t => {
  const world = notionWorld(t, ['schema-changed', 'row-changed', 'new-row']), {simulator, home} = world;
  const {sources: [odd]} = simulator.seedDatabase({title: 'Odd', parent: {page_id: home.id}, sources: [{name: 'Odd', properties: {Name: {type: 'title'}, constructor: {type: 'number'}}}]});
  simulator.seedRow({dataSource: odd.id, properties: title('A row')});
  const watches = {};
  for (const key of ['schema-changed', 'row-changed']) {
    const {id} = await world.subscribe(key, {dataSourceId: odd.id});
    world.approve(id);
    const held = await world.pollNow(id);
    assert.deepEqual([held.status, held.reason, held.detail], ['paused', 'too_many_items', 'value_unreadable'], `${key}: a name is no size`);
    watches[key] = id;
  }
  assert.equal((await world.pollNow(await watch(world, 'new-row', {dataSourceId: odd.id}))).status, 'active', 'this one reads no column');
  world.advance(1000);
  await editSchema(world, odd.id, {constructor: {name: 'Builder'}});
  for (const [key, id] of Object.entries(watches)) {
    world.resume(id);
    assert.equal((await world.pollNow(id)).status, 'active', key);
  }
});

// ---- new child page ---------------------------------------------------------------------------------------------------------------------------------
test('new child page: a child is one event with its fields, and a rename, a paragraph, a database, a toggle, an unsupported block and a page nested in the toggle give zero', async t => {
  const world = notionWorld(t, ['new-child-page']), {home, simulator} = world, id = await watch(world, 'new-child-page', {pages: [home.id]});
  const child = await write(world, 'POST', '/pages', {body: {parent: {page_id: home.id}, properties: {title: {title: [{text: {content: 'A child'}}]}}}});
  await poll(world, id);
  const [event, ...rest] = await fired(world);
  assert.deepEqual(rest, []);
  assert.deepEqual(event.fields, {parentPageId: home.id, pageId: child.id, title: 'A child', createdTime: child.created_time, createdBy: child.created_by.id});
  await rename(world, child.id, 'Renamed child');
  simulator.seedBlock({page: home.id, text: 'A paragraph'});
  simulator.seedBlock({page: home.id, type: 'unsupported'});
  simulator.seedDatabase({title: 'A database', parent: {page_id: home.id}, sources: [{name: 'A database', properties: {Name: {type: 'title'}}}]});
  const toggle = simulator.seedBlock({page: home.id, type: 'toggle', text: 'Open me'});
  const nested = simulator.seedPage({title: 'Nested', parent: {block_id: toggle.id}});
  await poll(world, id);
  assert.deepEqual(await fired(world), [], 'the list reads the first level alone, and its filter keeps child pages');
  assert.equal((await send(world, 'GET', `/blocks/${nested.id}`)).status, 200, 'the nested page exists, and is shared through its toggle');
});

test('new child page: trash and restore give zero, moved in gives one, and moved out and back gives zero', async t => {
  const world = notionWorld(t, ['new-child-page']), {home, page, simulator} = world, elsewhere = simulator.seedPage({title: 'Elsewhere', markdown: 'Text', shared: true}), moved = simulator.seedPage({title: 'Moved', parent: {page_id: elsewhere.id}});
  world.advance(INTERVAL);
  simulator.seedPage({title: 'Newest', parent: {page_id: home.id}});
  const id = await watch(world, 'new-child-page', {pages: [home.id]});
  await trash(world, page.id);
  await poll(world, id);
  await restore(world, page.id);
  await poll(world, id);
  assert.deepEqual(await fired(world), [], 'a child known at the baseline comes back as the same child');
  await move(world, moved.id, home.id);
  await poll(world, id);
  assert.deepEqual((await fired(world)).map(event => event.fields.pageId), [moved.id], 'a page older than the newest child moved in fires: the trigger has no item time, so no floor holds it back');
  await move(world, moved.id, elsewhere.id);
  await poll(world, id);
  await move(world, moved.id, home.id);
  await poll(world, id);
  assert.deepEqual(await fired(world), []);
});

test('new child page: a list past its bounds pauses too_many_items, since a cut whole list could never tell new from old', async t => {
  const world = notionWorld(t, ['new-child-page']), {simulator} = world, page = simulator.seedPage({title: 'Long', markdown: Array.from({length: 501}, (_, index) => `Line ${index}`).join('\n'), shared: true});
  const {id} = await world.subscribe('new-child-page', {pages: [page.id]});
  world.approve(id);
  const held = await world.pollNow(id);
  assert.deepEqual([held.status, held.reason, held.detail], ['paused', 'too_many_items', 'bounds']);
});

// ---- limits -----------------------------------------------------------------------------------------------------------------------------------------
test('limits: a Retry-After above a minute is honoured in full, on every feed of the account, in this round too, and nothing moves', async t => {
  const world = notionWorld(t, ['new-row', 'new-comment']), {simulator} = world, id = await watch(world, 'new-row', {dataSourceId: world.source.id});
  world.advance(1000);
  const other = await watch(world, 'new-comment', {pages: [world.page.id]}), mark = stored(world, id).cursors.created, comments = reads(world, 'GET /comments').length;
  simulator.limit(QUERY, 300, {reason: 'workspace_rate_limit'});
  world.advance(INTERVAL);
  await world.engine.tick();
  const now = world.now, feed = stored(world, id);
  assert.equal(feed.wait.reason, 'limited');
  assert.ok(feed.wait.until >= now + 300_000, 'the wait is the provider\'s, in full');
  assert.ok(stored(world, other).wait.until >= now + 300_000, 'a Notion limit covers the connection');
  assert.equal(reads(world, 'GET /comments').length, comments, 'the other feed was due in this round, and still sends nothing');
  assert.equal(feed.cursors.created, mark);
  assert.equal(world.record(id).status, 'active');
  const calls = simulator.reads().length;
  world.advance(200_000);
  await world.engine.tick();
  assert.equal(simulator.reads().length, calls, 'no request before the wait ends');
});

test('limits: 529 waits as a 429 does and pauses nothing, and a 503 backs off', async t => {
  for (const hit of [world => world.simulator.overload(QUERY), world => world.simulator.fail(QUERY, {status: 503, data: {object: 'error', status: 503, code: 'database_connection_unavailable', message: 'Unavailable.'}})]) {
    const world = notionWorld(t, ['new-row']), id = await watch(world, 'new-row', {dataSourceId: world.source.id});
    hit(world);
    world.advance(INTERVAL);
    await world.engine.tick();
    assert.equal(world.record(id).status, 'active');
    assert.equal(stored(world, id).failures, 1);
  }
});

test('limits: public_api_request_blocked pauses with its code whichever status carries it, and never waits', async t => {
  for (const status of [403, 429]) {
    const world = notionWorld(t, ['new-row']), id = await watch(world, 'new-row', {dataSourceId: world.source.id});
    world.simulator.block(QUERY, {status});
    const held = await poll(world, id);
    assert.deepEqual([held.status, held.reason, held.detail], ['paused', 'provider_refused', 'public_api_request_blocked'], String(status));
  }
});

test('limits: request_status incomplete sets a run note, and the next poll carries on from the mark', async t => {
  const world = notionWorld(t, ['new-row']), {simulator} = world, id = await watch(world, 'new-row', {dataSourceId: world.source.id});
  const rows = ['One', 'Two', 'Three'].map(text => simulator.seedRow({dataSource: world.source.id, properties: title(text)}));
  simulator.queryCap = 2;
  await poll(world, id);
  assert.equal(world.store.get('triggerRuns', stored(world, id).id).runs.at(-1).note, 'incomplete');
  simulator.queryCap = 10_000;
  await poll(world, id);
  assert.equal(world.store.get('triggerRuns', stored(world, id).id).runs.at(-1).note, undefined);
  assert.deepEqual((await fired(world)).map(event => event.fields.pageId).sort(), rows.map(row => row.id).sort());
});

test('a short page with has_more true is no end, on a body cursor and on a query cursor: only has_more ends a list', async t => {
  const writes = {'new-row': world => { world.simulator.seedRow({dataSource: world.source.id, properties: title('A row')}); }, 'new-comment': world => { world.simulator.seedComment({page: world.page.id, text: 'A comment'}); },
    'new-child-page': world => { world.simulator.seedPage({title: 'A child', parent: {page_id: world.home.id}}); }};
  for (const [key, add] of Object.entries(writes)) {
    const world = notionWorld(t, [key]), id = await watch(world, key, TRIGGERS[key].args(world));
    for (let times = 0; times < 5; times++) add(world);
    world.simulator.shortPages(2);
    await poll(world, id);
    assert.deepEqual([key, (await fired(world)).length], [key, 5]);
  }
});

// ---- the simulator ----------------------------------------------------------------------------------------------------------------------------------
const simulator = () => {
  let now = Date.parse('2026-10-26T12:00:30.500Z');
  const notion = new NotionApiSimulator({clock: () => now, token: TOKEN}), home = notion.seedPage({title: 'Home', shared: true});
  const {sources: [source]} = notion.seedDatabase({title: 'Rows', parent: {page_id: home.id}, sources: [{name: 'Rows', properties: {Name: {type: 'title'}, Count: {type: 'number'}}}]});
  return {notion, home, source, advance: ms => { now += ms; }};
};
const ask = (notion, method, path, {query, body} = {}) => send({simulator: notion}, method, path, {query, body});
const named = answer => answer.data.results.map(page => page.properties.Name?.title?.[0]?.plain_text);

test('simulator: stamps are stored to the minute by default, finer on request, and a timestamp filter compares in milliseconds, with an empty condition refused', async () => {
  const {notion, source, advance} = simulator(), row = notion.seedRow({dataSource: source.id, properties: title('One')});
  assert.equal(row.created_time, '2026-10-26T12:00:00.000Z');
  assert.equal(new NotionApiSimulator({clock: () => Date.parse('2026-10-26T12:00:30.500Z'), stampGrain: 1}).seedPage({}).created_time, '2026-10-26T12:00:30.500Z');
  advance(60_000);
  notion.seedRow({dataSource: source.id, properties: title('Two')});
  const query = condition => ask(notion, 'POST', `/data_sources/${source.id}/query`, {body: {filter: {timestamp: 'created_time', created_time: condition}}});
  for (const [condition, names] of [[{on_or_after: '2026-10-26T12:00:00.000Z'}, ['One', 'Two']], [{after: '2026-10-26T12:00:00.000Z'}, ['Two']], [{on_or_before: '2026-10-26T12:00:00.000Z'}, ['One']],
    [{before: '2026-10-26T12:00:00.000Z'}, []], [{equals: '2026-10-26T12:01:00.000Z'}, ['Two']], [{after: '2026-10-26T12:00:00.001Z'}, ['Two']]]) assert.deepEqual(named(await query(condition)), names, JSON.stringify(condition));
  for (const condition of [{}, {on_or_after: 'soon'}, {sometime: '2026-10-26T12:00:00.000Z'}, {on_or_after: 1}]) assert.equal((await query(condition)).data.code, 'validation_error', JSON.stringify(condition));
});

test('simulator: sorts order rows by a timestamp or a property, ties fall to the seed, and an unknown sort is refused', async () => {
  const {notion, source, advance} = simulator(), add = (text, count) => notion.seedRow({dataSource: source.id, properties: {...title(text), Count: {number: count}}});
  add('Early', 2);
  advance(60_000);
  add('Late', 1);
  const query = sorts => ask(notion, 'POST', `/data_sources/${source.id}/query`, {body: {sorts}});
  assert.deepEqual(named(await query([{timestamp: 'created_time', direction: 'descending'}])), ['Late', 'Early']);
  assert.deepEqual(named(await query([{property: 'Count', direction: 'ascending'}])), ['Late', 'Early']);
  assert.deepEqual(named(await query([{property: 'Name', direction: 'ascending'}])), ['Early', 'Late']);
  for (const sorts of [[{timestamp: 'never', direction: 'ascending'}], [{property: 'Nope', direction: 'ascending'}], [{timestamp: 'created_time', direction: 'up'}], 'created_time']) assert.equal((await query(sorts)).status, 400, JSON.stringify(sorts));
  const orderWith = async tieSeed => {
    const seeded = new NotionApiSimulator({clock: () => 0, token: TOKEN, tieSeed}), page = seeded.seedPage({title: 'H', shared: true});
    const {sources: [ties]} = seeded.seedDatabase({parent: {page_id: page.id}, sources: [{name: 'T', properties: {Name: {type: 'title'}}}]}), read = {body: {sorts: [{timestamp: 'created_time', direction: 'ascending'}]}};
    for (let index = 0; index < 12; index++) seeded.seedRow({dataSource: ties.id, properties: title(`Row ${index}`)});
    const once = named(await ask(seeded, 'POST', `/data_sources/${ties.id}/query`, read));
    assert.deepEqual(once, named(await ask(seeded, 'POST', `/data_sources/${ties.id}/query`, read)), 'one seed gives one order, so a re-read reads the same rows first');
    return once;
  };
  const [first, second] = [await orderWith('one'), await orderWith('two')];
  assert.notDeepEqual(first, second);
  assert.deepEqual([...first].sort(), [...second].sort());
});

test('simulator: filter_properties is a repeated query parameter, refused in the body, and result_type, is_archived and a body in_trash answer as Notion does', async () => {
  const {notion, source} = simulator(), row = notion.seedRow({dataSource: source.id, properties: {...title('One'), Count: {number: 1}}}), path = `/data_sources/${source.id}/query`;
  const shown = (await ask(notion, 'POST', `${path}?filter_properties=title&filter_properties=Count`)).data.results[0].properties;
  assert.deepEqual(Object.keys(shown).sort(), ['Count', 'Name']);
  assert.deepEqual(Object.keys((await ask(notion, 'POST', path, {query: {filter_properties: 'title'}})).data.results[0].properties), ['Name']);
  assert.equal((await ask(notion, 'POST', path, {body: {filter_properties: ['title']}})).status, 400);
  assert.equal((await ask(notion, 'POST', path, {body: {in_trash: false}})).data.code, 'validation_error');
  assert.equal((await ask(notion, 'POST', path, {body: {result_type: 'page'}})).status, 200);
  assert.equal((await ask(notion, 'POST', path, {body: {result_type: 'nothing'}})).status, 400);
  assert.equal((await ask(notion, 'POST', path, {body: {is_archived: 'yes'}})).status, 400);
  notion.archive(row.id);
  assert.deepEqual(named(await ask(notion, 'POST', path)), []);
  assert.deepEqual(named(await ask(notion, 'POST', path, {body: {is_archived: true}})), ['One']);
  assert.equal((await ask(notion, 'GET', `/pages/${row.id}`)).data.is_archived, true);
});

test('simulator: a cursor is opaque, a short page keeps has_more, request_status reads complete below the cap, and past it the list stops as incomplete', async () => {
  const {notion, source} = simulator(), path = `/data_sources/${source.id}/query`;
  const rows = ['One', 'Two', 'Three'].map(text => notion.seedRow({dataSource: source.id, properties: title(text)}));
  const first = (await ask(notion, 'POST', path, {body: {page_size: 1}})).data;
  assert.equal(rows.some(row => first.next_cursor.includes(row.id)), false, 'a cursor names no id');
  assert.deepEqual(first.request_status, {type: 'complete'});
  notion.shortPages(1);
  const short = (await ask(notion, 'POST', path, {body: {page_size: 5}})).data;
  assert.deepEqual([short.results.length, short.has_more], [1, true]);
  notion.shortPages(null);
  notion.queryCap = 2;
  const capped = (await ask(notion, 'POST', path)).data;
  assert.deepEqual([capped.results.length, capped.has_more, capped.request_status.type, capped.request_status.incomplete_reason], [2, false, 'incomplete', 'query_result_limit_reached']);
});

test('simulator: blocks list the first level alone, with has_children, and a child under a toggle sits under the toggle; an unshared block is 404', async () => {
  const {notion, home} = simulator(), toggle = notion.seedBlock({page: home.id, type: 'toggle', text: 'Open me'}), inner = notion.seedBlock({block: toggle.id, text: 'Inside'});
  const nested = notion.seedPage({title: 'Nested', parent: {block_id: toggle.id}}), plainBlock = notion.seedBlock({page: home.id, type: 'unsupported'}), hidden = notion.seedPage({title: 'Hidden'});
  const hiddenBlock = notion.seedBlock({page: hidden.id, text: 'Hidden'});
  const listed = (await ask(notion, 'GET', `/blocks/${home.id}/children`, {query: {page_size: 100}})).data.results;
  assert.deepEqual(listed.map(block => block.type), ['child_database', 'toggle', 'unsupported']);
  assert.deepEqual(listed.map(block => block.has_children), [false, true, false]);
  assert.deepEqual((await ask(notion, 'GET', `/blocks/${toggle.id}/children`)).data.results.map(block => [block.id, block.type]), [[nested.id, 'child_page'], [inner.id, 'paragraph']]);
  assert.equal((await ask(notion, 'GET', `/blocks/${plainBlock.id}`)).data.type, 'unsupported');
  assert.equal((await ask(notion, 'GET', `/blocks/${nested.id}`)).data.child_page.title, 'Nested');
  assert.equal((await ask(notion, 'GET', `/blocks/${hiddenBlock.id}`)).status, 404);
  assert.equal((await ask(notion, 'GET', `/blocks/${hidden.id}/children`)).status, 404);
  const texty = notion.seedPage({title: 'Texty', parent: {page_id: home.id}, markdown: 'One\n\nTwo'});
  assert.deepEqual((await ask(notion, 'GET', `/blocks/${texty.id}/children`)).data.results.map(block => block.paragraph.rich_text[0].plain_text), ['One', 'Two']);
});

test('simulator: PATCH /data_sources adds, renames and removes by null, moves its rows with it, and keeps its title; a relation hides while its target is unshared', async () => {
  const {notion, home, source} = simulator(), row = notion.seedRow({dataSource: source.id, properties: {...title('One'), Count: {number: 3}}}), path = `/data_sources/${source.id}`;
  const after = async properties => { const answer = await ask(notion, 'PATCH', path, {body: {properties}}); assert.equal(answer.status, 200, JSON.stringify(answer.data)); return Object.keys(answer.data.properties).sort(); };
  assert.deepEqual(await after({Due: {date: {}}}), ['Count', 'Due', 'Name']);
  assert.deepEqual(await after({Count: {name: 'Total'}}), ['Due', 'Name', 'Total']);
  assert.equal((await ask(notion, 'GET', `/pages/${row.id}`)).data.properties.Total.number, 3);
  assert.deepEqual(await after({Due: null}), ['Name', 'Total']);
  assert.equal(Object.hasOwn((await ask(notion, 'GET', `/pages/${row.id}`)).data.properties, 'Due'), false);
  for (const properties of [{Name: null}, {Nope: null}, {Bad: {nonsense: {}}}, 'nope']) assert.equal((await ask(notion, 'PATCH', path, {body: {properties}})).status, 400, JSON.stringify(properties));
  const other = notion.seedPage({title: 'Other', shared: true}), {sources: [target]} = notion.seedDatabase({parent: {page_id: other.id}, sources: [{name: 'T', properties: {Name: {type: 'title'}}}]});
  const {sources: [linked]} = notion.seedDatabase({parent: {page_id: home.id}, sources: [{name: 'L', properties: {Name: {type: 'title'}, Link: {type: 'relation', target: target.id}}}]});
  assert.ok(Object.hasOwn((await ask(notion, 'GET', `/data_sources/${linked.id}`)).data.properties, 'Link'));
  notion.unshare(other.id);
  assert.equal(Object.hasOwn((await ask(notion, 'GET', `/data_sources/${linked.id}`)).data.properties, 'Link'), false);
});

test('simulator: comments carry a block parent, a property id and a partial form, reopen brings one back, and a block\'s list holds its own', async () => {
  const {notion, home} = simulator(), block = notion.seedBlock({page: home.id, text: 'A block'}), list = id => ask(notion, 'GET', '/comments', {query: {block_id: id}});
  const onBlock = notion.seedComment({page: home.id, block: block.id, text: 'On a block'}), onValue = notion.seedComment({page: home.id, text: 'On a value', propertyId: 'title'}), partial = notion.seedComment({page: home.id, text: 'Half', partial: true});
  assert.deepEqual(onBlock.parent, {type: 'block_id', block_id: block.id});
  assert.equal(onValue.property_id, 'title');
  assert.deepEqual(partial, {object: 'comment', id: partial.id});
  assert.deepEqual((await list(block.id)).data.results.map(comment => comment.id), [onBlock.id]);
  assert.deepEqual((await list(home.id)).data.results.map(comment => comment.id), [onValue.id, partial.id]);
  notion.resolve(onValue.id);
  assert.deepEqual((await list(home.id)).data.results.map(comment => comment.id), [partial.id]);
  notion.reopen(onValue.id);
  assert.deepEqual((await list(home.id)).data.results.map(comment => comment.id), [onValue.id, partial.id]);
});

test('simulator: markdown_version takes v1 and v2 and refuses anything else, a file link is signed anew on each read of a row or a page, and a formula moves with no edit', async () => {
  const {notion, home} = simulator(), markdown = version => ask(notion, 'GET', `/pages/${home.id}/markdown`, {query: {markdown_version: version}});
  assert.deepEqual([(await markdown('v1')).status, (await markdown('v2')).status, (await markdown('v3')).status], [200, 200, 400]);
  const {sources: [filed]} = notion.seedDatabase({parent: {page_id: home.id}, sources: [{name: 'F', properties: {Name: {type: 'title'}, Receipt: {type: 'files'}, Total: {type: 'formula'}}}]}), held = notion.seedRow({dataSource: filed.id, properties: title('Filed')});
  notion.attachFile(held.id, 'Receipt', 'a.pdf');
  notion.setFormula(held.id, 'Total', 7);
  const [one, two] = [await ask(notion, 'GET', `/pages/${held.id}`), await ask(notion, 'GET', `/pages/${held.id}`)];
  assert.notEqual(one.data.properties.Receipt.files[0].file.url, two.data.properties.Receipt.files[0].file.url);
  assert.equal(one.data.properties.Receipt.files[0].name, 'a.pdf');
  assert.deepEqual([one.data.properties.Total.formula.number, one.data.last_edited_time], [7, held.last_edited_time]);
});

test('simulator: a 429 names its limit and repeats its wait, 529 and a blocked request answer in Notion\'s shape, and lag holds a write back from queries alone', async () => {
  const {notion, source, advance} = simulator(), path = `/data_sources/${source.id}/query`;
  notion.limit(QUERY, 300, {reason: 'workspace_rate_limit'});
  const limited = await ask(notion, 'POST', path);
  assert.deepEqual([limited.status, limited.headers['retry-after'], limited.data.additional_data], [429, '300', {retry_after: '300', rate_limit_reason: 'workspace_rate_limit'}]);
  notion.overload(QUERY);
  const overloaded = await ask(notion, 'POST', path);
  assert.deepEqual([overloaded.status, overloaded.data.code], [529, 'service_overload']);
  notion.block(QUERY);
  const blocked = await ask(notion, 'POST', path);
  assert.deepEqual([blocked.status, blocked.data.code], [403, 'public_api_request_blocked']);
  notion.lag(90_000);
  const row = notion.seedRow({dataSource: source.id, properties: title('Slow')});
  assert.deepEqual(named(await ask(notion, 'POST', path)), []);
  assert.equal((await ask(notion, 'GET', `/pages/${row.id}`)).status, 200, 'the row itself reads at once');
  advance(90_000);
  assert.deepEqual(named(await ask(notion, 'POST', path)), ['Slow']);
});

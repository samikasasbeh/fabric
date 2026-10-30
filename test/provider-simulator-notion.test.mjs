import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {NotionApiSimulator, ORIGIN, BASE, VERSION, CAPABILITIES} from './fixtures/provider-simulators/notion.mjs';

// F10.19 part 1 (docs/F10.19-BUILD-MAP.md part 1 item 5 and section 3): the Notion simulator Notion's actions run against in step 19. It must
// keep the network seam's contract (lib/network.mjs) and Notion's documented behaviour for Notion-Version 2026-03-11, as its own header
// comment names it. It is written from that comment and from Notion's reference, never from Notion's action file, rows or proxy settings, so
// an action bug and a simulator bug cannot cancel out. Nothing here calls Notion.
const TOKEN = 'ntn_simulator-test-token-7d1c', AUTH = {Authorization: `Bearer ${TOKEN}`, 'Notion-Version': VERSION};
const sim = (options = {}) => new NotionApiSimulator({token: TOKEN, owner: {name: 'Avery Owner', email: 'avery@example.com'}, clock: () => Date.parse('2026-10-26T12:00:00.000Z'), ...options});
/** One request through the seam below the API base, with the token and the version unless `headers` says otherwise. */
const send = (simulator, method, path, {body, headers = AUTH, query, ...more} = {}) => {
  const url = new URL(`${BASE}${path}`);
  for (const [name, value] of Object.entries(query ?? {})) url.searchParams.append(name, String(value));
  return simulator.request({url: url.href, method, headers: {...headers, ...(body === undefined ? {} : {'Content-Type': 'application/json'})}, ...(body === undefined ? {} : {body: JSON.stringify(body)}),
    allowedOrigins: [ORIGIN], ...more});
};
const text = content => [{text: {content}}];
const code = answer => [answer.status, answer.data?.code];
/** A shared top page A with a child page A1, an unshared page B, and under A a database with one data source of a few property types and one row. */
function world(options) {
  const simulator = sim(options);
  const a = simulator.seedPage({title: '[SYNTHETIC] A', markdown: 'First line\nSecond line', shared: true});
  const child = simulator.seedPage({title: 'A1', parent: {page_id: a.id}, markdown: 'Child text'});
  const b = simulator.seedPage({title: 'B', markdown: 'Private'});
  const {database, sources: [source]} = simulator.seedDatabase({title: 'Tasks', parent: {page_id: a.id}, sources: [{name: 'Tasks', properties: {
    Name: {type: 'title'}, Cost: {type: 'number'}, Stage: {type: 'select', options: ['Open', 'Closed']}, Tags: {type: 'multi_select', options: ['red', 'blue']},
    Due: {type: 'date'}, Owner: {type: 'people'}, Total: {type: 'formula'}, Created: {type: 'created_time'}, Ticket: {type: 'unique_id', prefix: 'T'}}}]});
  const row = simulator.seedRow({dataSource: source.id, properties: {Name: {title: text('Row 1')}, Cost: {number: 3}, Stage: {select: {name: 'Open'}}}});
  return {simulator, a, child, b, database, source, row};
}

test('the seam: only the headers asked for come back, an answer over maxBytes throws sent true, and requests refused before sending are never recorded', async () => {
  const {simulator, a} = world();
  const read = await send(simulator, 'GET', `/pages/${a.id}`);
  assert.deepEqual([read.status, Object.keys(read.headers)], [200, ['content-type']]);
  await assert.rejects(send(simulator, 'GET', `/pages/${a.id}`, {maxBytes: 64}), error => error.sent === true && /size limit/.test(error.message));
  const before = simulator.calls.length;
  for (const [label, request] of [['an origin outside the grant', {url: `${BASE}/users/me`, method: 'GET', headers: AUTH, allowedOrigins: ['https://www.googleapis.com']}],
    ['plain http', {url: 'http://api.notion.com/v1/users/me', method: 'GET', headers: AUTH, allowedOrigins: [ORIGIN]}],
    ['an unsafe header', {url: `${BASE}/users/me`, method: 'GET', headers: {...AUTH, Host: 'x'}, allowedOrigins: [ORIGIN]}],
    ['a body that is not serialized', {url: `${BASE}/pages`, method: 'POST', headers: AUTH, body: {parent: {page_id: a.id}}, allowedOrigins: [ORIGIN]}],
    ['a body over 1 MiB', {url: `${BASE}/pages`, method: 'POST', headers: AUTH, body: JSON.stringify({markdown: 'x'.repeat(1024 * 1024)}), allowedOrigins: [ORIGIN]}],
    ['an origin the simulator does not serve', {url: 'https://www.googleapis.com/calendar/v3/users/me/calendarList', method: 'GET', headers: AUTH, allowedOrigins: ['https://www.googleapis.com']}]]) {
    await assert.rejects(simulator.request(request), error => error.sent === false, label);
  }
  assert.equal(simulator.calls.length, before, 'refused before sending: never recorded');
  const outside = await simulator.request({url: `${ORIGIN}/v2/pages`, method: 'GET', headers: AUTH, allowedOrigins: [ORIGIN]});
  assert.deepEqual([code(outside), simulator.calls.at(-1).route], [[400, 'invalid_request_url'], null]);
  assert.equal(simulator.calls.at(-1).headers.authorization, undefined, 'calls are recorded without Authorization');
});

test('401 without the token and 400 without Notion-Version 2026-03-11 exactly, in Notion\'s error shape; nothing changes', async () => {
  const {simulator, a} = world();
  const create = headers => send(simulator, 'POST', '/pages', {body: {parent: {page_id: a.id}, properties: {title: {title: text('New')}}}, headers});
  const missing = await create({Authorization: `Bearer ${TOKEN}`}), old = await create({...AUTH, 'Notion-Version': '2025-09-03'}), unauthorized = await create({'Notion-Version': VERSION});
  const wrong = await create({...AUTH, Authorization: 'Bearer wrong'});
  assert.deepEqual([code(missing), code(old), code(unauthorized), code(wrong)], [[400, 'missing_version'], [400, 'validation_error'], [401, 'unauthorized'], [401, 'unauthorized']]);
  assert.deepEqual(Object.keys(unauthorized.data).sort(), ['code', 'message', 'object', 'request_id', 'status']);
  assert.deepEqual([unauthorized.data.object, unauthorized.data.status], ['error', 401]);
  assert.equal(Object.keys(simulator.state().pages).length, 4, 'no page was made');
  assert.equal(code(await create(AUTH))[0], 200);
});

test('only pages shared with the integration and their descendants are visible; anything else is 404 object_not_found', async () => {
  const {simulator, a, child, b, database, source, row} = world();
  for (const path of [`/pages/${a.id}`, `/pages/${child.id}`, `/pages/${row.id}`, `/databases/${database.id}`, `/data_sources/${source.id}`, `/pages/${a.id}/markdown`]) {
    assert.equal((await send(simulator, 'GET', path)).status, 200, path);
  }
  assert.deepEqual(code(await send(simulator, 'GET', `/pages/${b.id}`)), [404, 'object_not_found']);
  assert.deepEqual(code(await send(simulator, 'PATCH', `/pages/${b.id}`, {body: {properties: {title: {title: text('x')}}}})), [404, 'object_not_found']);
  assert.equal(simulator.state().pages[b.id].properties.title.title[0].plain_text, 'B', 'nothing changed');
  assert.equal((await send(simulator, 'GET', `/pages/${a.id.replace(/-/g, '')}`)).status, 200, 'an undashed id names the same page');
  simulator.unshare(a.id);
  assert.deepEqual(code(await send(simulator, 'GET', `/pages/${row.id}`)), [404, 'object_not_found'], 'unsharing A hides what is under it');
  simulator.share(b.id);
  assert.equal((await send(simulator, 'GET', `/pages/${b.id}`)).status, 200);
});

test('a route needing a capability the integration lacks answers 403 restricted_resource; a person\'s email shows only with user_email', async () => {
  const {simulator, a} = world();
  simulator.capabilities(CAPABILITIES.filter(item => item !== 'update_content'));
  assert.deepEqual(code(await send(simulator, 'PATCH', `/pages/${a.id}/markdown`, {body: {type: 'insert_content', insert_content: {content: 'x'}}})), [403, 'restricted_resource']);
  assert.equal(simulator.state().pages[a.id].text, 'First line\nSecond line', 'nothing changed');
  assert.equal((await send(simulator, 'GET', `/pages/${a.id}`)).status, 200, 'reading still works');
  simulator.capabilities(['read_content']);
  assert.deepEqual(code(await send(simulator, 'GET', '/comments', {query: {block_id: a.id}})), [403, 'restricted_resource']);
  assert.deepEqual(code(await send(simulator, 'POST', '/pages', {body: {parent: {page_id: a.id}}})), [403, 'restricted_resource']);
  const without = (await send(simulator, 'GET', '/users')).data.results.find(user => user.name === 'Avery Owner');
  assert.deepEqual(without.person, {}, 'no email without user_email');
  simulator.capabilities(CAPABILITIES);
  assert.deepEqual((await send(simulator, 'GET', '/users')).data.results.find(user => user.name === 'Avery Owner').person, {email: 'avery@example.com'});
  assert.deepEqual([(await send(simulator, 'GET', '/users/me')).data.type, (await send(simulator, 'GET', '/users/me')).data.name], ['bot', 'Fabric']);
});

test('pages: a page parent takes title only, a row takes typed values by its schema, rich text is capped, archived is refused, and a list value replaces the whole value', async () => {
  const {simulator, a, source, row} = world();
  const made = await send(simulator, 'POST', '/pages', {body: {parent: {page_id: a.id}, properties: {title: {title: text('Notes')}}, markdown: 'Hello'}});
  assert.equal(made.status, 200);
  assert.deepEqual([made.data.object, made.data.parent, made.data.in_trash, made.data.properties.title.title[0].plain_text], ['page', {type: 'page_id', page_id: a.id}, false, 'Notes']);
  assert.equal((await send(simulator, 'GET', `/pages/${made.data.id}/markdown`)).data.markdown, 'Hello');
  assert.deepEqual(code(await send(simulator, 'POST', '/pages', {body: {parent: {page_id: a.id}, properties: {title: {title: text('x')}, Cost: {number: 1}}}})), [400, 'validation_error'], 'title only under a page');
  const rowMade = await send(simulator, 'POST', '/pages', {body: {parent: {type: 'data_source_id', data_source_id: source.id}, properties: {Name: {title: text('Row 2')}, c: {number: 1}}}});
  assert.equal(rowMade.status, 400, 'an unknown property name or id');
  const typed = await send(simulator, 'POST', '/pages', {body: {parent: {type: 'data_source_id', data_source_id: source.id},
    properties: {Name: {title: text('Row 2')}, [source.properties.Tags.id]: {multi_select: [{name: 'red'}, {name: 'blue'}]}, Due: {date: {start: '2026-11-02'}}}}});
  assert.equal(typed.status, 200);
  assert.deepEqual([typed.data.parent.type, typed.data.properties.Tags.multi_select.map(option => option.name), typed.data.properties.Due.date, typed.data.properties.Cost.number],
    ['data_source_id', ['red', 'blue'], {start: '2026-11-02', end: null, time_zone: null}, null], 'by name or id; every property present, empty ones included');
  for (const [label, properties] of [['an unknown option', {Stage: {select: {name: 'Maybe'}}}], ['a read-only property', {Total: {formula: {string: 'x'}}}],
    ['a created time', {Created: {created_time: '2026-01-01'}}], ['a number as text', {Cost: {number: '3'}}], ['a person who is not a user', {Owner: {people: [{id: '00000000-0000-4000-8000-000000000000'}]}}]]) {
    assert.deepEqual(code(await send(simulator, 'PATCH', `/pages/${row.id}`, {body: {properties}})), [400, 'validation_error'], label);
  }
  assert.deepEqual(simulator.state().pages[row.id].properties.Stage.select.name, 'Open', 'nothing changed');
  const tags = async list => (await send(simulator, 'PATCH', `/pages/${typed.data.id}`, {body: {properties: {Tags: {multi_select: list}}}})).data.properties.Tags.multi_select.map(option => option.name);
  assert.deepEqual(await tags([{name: 'blue'}]), ['blue'], 'the whole list is replaced');
  assert.deepEqual(await tags([]), []);
  for (const [label, properties] of [['a piece over 2,000 units', {Name: {title: text('x'.repeat(2001))}}], ['101 pieces', {Name: {title: Array.from({length: 101}, () => ({text: {content: 'x'}}))}}]]) {
    assert.deepEqual(code(await send(simulator, 'PATCH', `/pages/${row.id}`, {body: {properties}})), [400, 'validation_error'], label);
  }
  assert.equal((await send(simulator, 'PATCH', `/pages/${row.id}`, {body: {properties: {Name: {title: [...text('x'.repeat(2000)), ...Array.from({length: 99}, () => ({text: {content: 'y'}}))]}}}})).status, 200,
    '100 pieces of 2,000 units fit');
  assert.deepEqual(code(await send(simulator, 'PATCH', `/pages/${a.id}`, {body: {archived: true}})), [400, 'validation_error'], 'archived is gone in 2026-03-11');
  assert.deepEqual(code(await send(simulator, 'PATCH', `/pages/${a.id}`, {body: {is_locked: true}})), [400, 'validation_error']);
  assert.equal(simulator.state().pages[a.id].in_trash, false);
});

test('markdown: get answers page_markdown with child tags; insert_content appends; update_content applies a find once and refuses twice or none, changing nothing', async () => {
  const {simulator, a, child, database} = world();
  const read = (await send(simulator, 'GET', `/pages/${a.id}/markdown`)).data;
  assert.deepEqual(Object.keys(read).sort(), ['id', 'markdown', 'object', 'truncated', 'unknown_block_ids']);
  assert.deepEqual([read.object, read.id, read.truncated, read.unknown_block_ids], ['page_markdown', a.id, false, []]);
  assert.equal(read.markdown, `First line\nSecond line\n<page url="https://www.notion.so/${child.id.replace(/-/g, '')}">A1</page>\n<database url="https://www.notion.so/${database.id.replace(/-/g, '')}">Tasks</database>`);
  const patch = body => send(simulator, 'PATCH', `/pages/${a.id}/markdown`, {body});
  const added = await patch({type: 'insert_content', insert_content: {content: 'Third line'}});
  assert.equal(added.status, 200);
  assert.ok(added.data.markdown.startsWith('First line\nSecond line\nThird line\n<page'), 'appended to the text');
  const before = simulator.state().pages[a.id].text;
  assert.deepEqual(code(await patch({type: 'update_content', update_content: {content_updates: [{old_str: 'line', new_str: 'row'}]}})), [400, 'validation_error'], 'found three times');
  assert.deepEqual(code(await patch({type: 'update_content', update_content: {content_updates: [{old_str: 'Nowhere', new_str: 'x'}]}})), [400, 'validation_error'], 'found nowhere');
  assert.equal(simulator.state().pages[a.id].text, before, 'nothing changed');
  const once = await patch({type: 'update_content', update_content: {content_updates: [{old_str: 'Second line', new_str: 'Middle line'}, {old_str: 'Nowhere', new_str: 'x'}]}});
  assert.equal(once.status, 200);
  assert.ok(once.data.markdown.startsWith('First line\nMiddle line\nThird line'));
  assert.deepEqual(once.data.warnings.map(warning => warning.code), ['old_str_not_found'], 'a miss beside a match is a warning');
  assert.equal((await patch({type: 'update_content', update_content: {content_updates: [{old_str: 'line', new_str: 'row', replace_all_matches: true}]}})).status, 200);
  assert.equal(simulator.state().pages[a.id].text, 'First row\nMiddle row\nThird row');
  assert.deepEqual(code(await patch({type: 'update_content', update_content: {content_updates: [{old_str: 'Third row', new_str: ''}]}})), [200, undefined], 'an empty new_str removes the text');
  for (const type of ['replace_content', 'replace_content_range']) assert.deepEqual(code(await patch({type, [type]: {new_str: 'x', content: 'x'}})), [400, 'not_simulated'], type);
});

test('markdown reads back as Notion reads it: a backslash before its marks, no blank lines, code and links as written; old_str matches with or without the backslashes', async () => {
  const {simulator, a} = world();
  const patch = body => send(simulator, 'PATCH', `/pages/${a.id}/markdown`, {body});
  const written = '[SYNTHETIC] <x> {y} | z ^ ~ $ \\\n\n```\n[code]\n```\n[a link](https://example.com/p) [b]';
  const answer = await patch({type: 'insert_content', insert_content: {content: written}});
  assert.ok(answer.data.markdown.includes('\\[SYNTHETIC\\] \\<x\\> \\{y\\} \\| z \\^ \\~ \\$ \\\\\n```\n[code]\n```\n[a link](https://example.com/p) \\[b\\]'), answer.data.markdown);
  assert.equal((await send(simulator, 'GET', `/pages/${a.id}/markdown`)).data.markdown, answer.data.markdown);
  assert.equal(simulator.state().pages[a.id].text, `First line\nSecond line\n${written}`, 'stored as written: only the reading changes it');
  const edit = (old_str, new_str) => patch({type: 'update_content', update_content: {content_updates: [{old_str, new_str}]}});
  assert.equal((await edit('[SYNTHETIC] <x>', '[SYNTHETIC] <w>')).status, 200);
  assert.equal((await edit('\\[SYNTHETIC\\] \\<w\\>', '[SYNTHETIC] <v>')).status, 200);
  assert.ok(simulator.state().pages[a.id].text.includes('[SYNTHETIC] <v> {y}'));
});

test('markdown reads back in the forms the live probe of 2026-10-30 recorded: heading, bullet, count, fence language, table and italic rewritten; a real backslash matches as written', async () => {
  const {simulator, a} = world();
  const patch = body => send(simulator, 'PATCH', `/pages/${a.id}/markdown`, {body});
  const answer = await patch({type: 'insert_content', insert_content: {content: '##### H5\n* star\n1. one\n1. two\n```js\nlet a = [1];\n```\n| a | b |\n| --- | --- |\n| 1 | 2 |\n\nafter gap\n---\n**bold** _it_ [l](https://example.com/p)'}});
  assert.ok(answer.data.markdown.includes('#### H5\n- star\n1. one\n2. two\n```javascript\nlet a = [1];\n```\n<table header-row="true">\n<tr>\n<td>a</td>\n<td>b</td>\n</tr>\n<tr>\n<td>1</td>\n<td>2</td>\n</tr>\n</table>\nafter gap\n---\n**bold** *it* [l](https://example.com/p)'), answer.data.markdown);
  const other = simulator.seedPage({title: 'Paths', parent: {page_id: a.id}, markdown: 'C:\\[dir]\nb[1]\nb\\[1]'});
  const on = (old_str, new_str) => send(simulator, 'PATCH', `/pages/${other.id}/markdown`, {body: {type: 'update_content', update_content: {content_updates: [{old_str, new_str}]}}});
  assert.equal((await on('C:\\[dir]', 'D:\\[dir]')).status, 200, 'the plain form of text holding a real backslash matches');
  assert.equal((await on('b\\[1]', 'HIT')).status, 200);
  assert.equal(simulator.state().pages[other.id].text, 'D:\\[dir]\nb[1]\nHIT', 'the line that equals old_str is the one changed');
});

test('an uploaded file\'s link is signed anew on every read, and stays out of the stored text', async () => {
  const {simulator, a} = world();
  simulator.uploadFile(a.id, 'image.png');
  const read = async () => (await send(simulator, 'GET', `/pages/${a.id}/markdown`)).data.markdown;
  const [one, two] = [await read(), await read()];
  assert.match(one, /\?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=/);
  assert.notEqual(one, two);
  assert.ok(!simulator.state().pages[a.id].text.includes('X-Amz'));
});

test('removing a child page from the markdown is refused without allow_deleting_content, and with it moves the child to the trash', async () => {
  const {simulator, a, child} = world();
  const tag = `<page url="https://www.notion.so/${child.id.replace(/-/g, '')}">A1</page>`, patch = body => send(simulator, 'PATCH', `/pages/${a.id}/markdown`, {body});
  const refused = await patch({type: 'update_content', update_content: {content_updates: [{old_str: `Second line\n${tag}`, new_str: 'Second line'}]}});
  assert.deepEqual(code(refused), [400, 'validation_error']);
  assert.match(refused.data.message, new RegExp(child.id));
  assert.equal(simulator.state().pages[child.id].in_trash, false);
  assert.equal(simulator.state().pages[a.id].text, 'First line\nSecond line', 'nothing changed');
  const allowed = await patch({type: 'update_content', update_content: {content_updates: [{old_str: `Second line\n${tag}`, new_str: 'Second line'}], allow_deleting_content: true}});
  assert.equal(allowed.status, 200);
  assert.equal(simulator.state().pages[child.id].in_trash, true);
});

test('trash: a deleted page reads 200 with in_trash true and refuses every write but restore; restore by in_trash false; a second delete is refused', async () => {
  const {simulator, a, child} = world();
  const gone = await send(simulator, 'DELETE', `/blocks/${child.id}`);
  assert.deepEqual([gone.status, gone.data.object, gone.data.type, gone.data.in_trash], [200, 'block', 'child_page', true]);
  const read = await send(simulator, 'GET', `/pages/${child.id}`);
  assert.deepEqual([read.status, read.data.in_trash], [200, true]);
  assert.ok(!(await send(simulator, 'GET', `/pages/${a.id}/markdown`)).data.markdown.includes('A1'), 'a trashed child leaves its parent\'s markdown');
  for (const [label, method, path, body] of [['a rename', 'PATCH', `/pages/${child.id}`, {properties: {title: {title: text('x')}}}], ['a rename with restore', 'PATCH', `/pages/${child.id}`, {in_trash: false, properties: {title: {title: text('x')}}}],
    ['markdown', 'PATCH', `/pages/${child.id}/markdown`, {type: 'insert_content', insert_content: {content: 'x'}}], ['a move', 'POST', `/pages/${child.id}/move`, {parent: {type: 'page_id', page_id: a.id}}],
    ['a comment', 'POST', '/comments', {parent: {page_id: child.id}, rich_text: text('x')}], ['a second delete', 'DELETE', `/blocks/${child.id}`, undefined]]) {
    assert.deepEqual(code(await send(simulator, method, path, {body})), [400, 'validation_error'], label);
  }
  assert.equal(simulator.state().pages[child.id].properties.title.title[0].plain_text, 'A1');
  const restored = await send(simulator, 'PATCH', `/pages/${child.id}`, {body: {in_trash: false}});
  assert.deepEqual([restored.status, restored.data.in_trash], [200, false]);
  assert.ok((await send(simulator, 'GET', `/pages/${a.id}/markdown`)).data.markdown.includes('A1'));
  assert.equal((await send(simulator, 'PATCH', `/pages/${child.id}`, {body: {in_trash: true}})).data.in_trash, true, 'in_trash true trashes too');
});

test('move: a page moves under another shared page, never under itself or a descendant, and a data source parent is not simulated', async () => {
  const {simulator, a, child, b, source} = world();
  const grandchild = simulator.seedPage({title: 'A1a', parent: {page_id: child.id}});
  const move = (id, parent) => send(simulator, 'POST', `/pages/${id}/move`, {body: {parent}});
  assert.deepEqual(code(await move(child.id, {type: 'page_id', page_id: child.id})), [400, 'validation_error'], 'under itself');
  assert.deepEqual(code(await move(child.id, {type: 'page_id', page_id: grandchild.id})), [400, 'validation_error'], 'under a descendant');
  assert.deepEqual(code(await move(child.id, {type: 'page_id', page_id: b.id})), [404, 'object_not_found'], 'under an unshared page');
  assert.deepEqual(code(await move(child.id, {type: 'data_source_id', data_source_id: source.id})), [400, 'not_simulated']);
  assert.equal(simulator.state().pages[child.id].parent.page_id, a.id, 'nothing moved');
  const other = simulator.seedPage({title: 'Other', shared: true});
  const moved = await move(child.id, {type: 'page_id', page_id: other.id});
  assert.deepEqual([moved.status, moved.data.parent], [200, {type: 'page_id', page_id: other.id}]);
  assert.ok((await send(simulator, 'GET', `/pages/${other.id}/markdown`)).data.markdown.includes('A1'));
  assert.ok(!(await send(simulator, 'GET', `/pages/${a.id}/markdown`)).data.markdown.includes('A1'));
});

test('comments: open comments only, oldest first and paged; a new discussion or a reply in one, exactly one of the two; get and delete one', async () => {
  const {simulator, a} = world();
  const first = simulator.seedComment({page: a.id, text: 'First'}), resolved = simulator.seedComment({page: a.id, text: 'Done already'});
  simulator.resolve(resolved.id);
  const listed = await send(simulator, 'GET', '/comments', {query: {block_id: a.id}});
  assert.deepEqual(listed.data.results.map(comment => plainOf(comment)), ['First'], 'the resolved one is not listed');
  const made = await send(simulator, 'POST', '/comments', {body: {parent: {page_id: a.id}, rich_text: text('[SYNTHETIC] hello')}});
  assert.equal(made.status, 200);
  assert.notEqual(made.data.discussion_id, first.discussion_id, 'a new discussion');
  const reply = await send(simulator, 'POST', '/comments', {body: {discussion_id: made.data.discussion_id, rich_text: text('[SYNTHETIC] reply')}});
  assert.deepEqual([reply.status, reply.data.discussion_id, reply.data.parent], [200, made.data.discussion_id, {type: 'page_id', page_id: a.id}]);
  for (const body of [{parent: {page_id: a.id}, discussion_id: made.data.discussion_id, rich_text: text('x')}, {rich_text: text('x')}]) {
    assert.deepEqual(code(await send(simulator, 'POST', '/comments', {body})), [400, 'validation_error']);
  }
  assert.deepEqual(code(await send(simulator, 'POST', '/comments', {body: {discussion_id: 'no-such-discussion', rich_text: text('x')}})), [404, 'object_not_found']);
  const paged = await send(simulator, 'GET', '/comments', {query: {block_id: a.id, page_size: 2}});
  assert.deepEqual([paged.data.results.length, paged.data.has_more], [2, true]);
  const rest = await send(simulator, 'GET', '/comments', {query: {block_id: a.id, page_size: 2, start_cursor: paged.data.next_cursor}});
  assert.deepEqual([rest.data.results.map(comment => plainOf(comment)), rest.data.has_more, rest.data.next_cursor], [['[SYNTHETIC] reply'], false, null]);
  assert.equal((await send(simulator, 'GET', `/comments/${reply.data.id}`)).data.id, reply.data.id);
  assert.equal((await send(simulator, 'DELETE', `/comments/${reply.data.id}`)).status, 200);
  assert.deepEqual(code(await send(simulator, 'GET', `/comments/${reply.data.id}`)), [404, 'object_not_found']);
});
const plainOf = comment => comment.rich_text.map(piece => piece.plain_text).join('');

test('a 429 rate_limited with its Retry-After under limit(), for the next call only; fail, swallow and drop', async () => {
  const {simulator, a} = world();
  simulator.limit('GET /pages/{page_id}', 30);
  const limited = await send(simulator, 'GET', `/pages/${a.id}`);
  assert.deepEqual([code(limited), limited.headers['retry-after']], [[429, 'rate_limited'], '30']);
  assert.equal((await send(simulator, 'GET', `/pages/${a.id}`)).status, 200, 'the next call passes');
  simulator.swallow('PATCH /pages/{page_id}');
  assert.equal((await send(simulator, 'PATCH', `/pages/${a.id}`, {body: {properties: {title: {title: text('Renamed')}}}})).data.properties.title.title[0].plain_text, 'Renamed');
  assert.equal(simulator.state().pages[a.id].properties.title.title[0].plain_text, '[SYNTHETIC] A', 'swallowed: nothing changed');
  simulator.drop('PATCH /pages/{page_id}');
  await assert.rejects(send(simulator, 'PATCH', `/pages/${a.id}`, {body: {properties: {title: {title: text('Dropped')}}}}), error => error.sent === true);
  assert.equal(simulator.state().pages[a.id].properties.title.title[0].plain_text, 'Dropped', 'dropped: applied, answer lost');
  simulator.fail('GET /pages/{page_id}', {status: 503, data: {object: 'error', status: 503, code: 'service_unavailable'}});
  assert.equal((await send(simulator, 'GET', `/pages/${a.id}`)).status, 503);
  assert.deepEqual([simulator.writes().length, simulator.reads().length], [2, 3]);
});

test('queries filter by property name or id and page by start_cursor; search matches titles in any case, filters on object and pages', async () => {
  const {simulator, a, source} = world();
  for (const [index, name] of ['Taxi', 'Hotel', 'Taxi home'].entries()) {
    simulator.seedRow({dataSource: source.id, properties: {Name: {title: text(name)}, Cost: {number: index + 10}, Tags: {multi_select: [{name: index ? 'blue' : 'red'}]}}});
  }
  const query = body => send(simulator, 'POST', `/data_sources/${source.id}/query`, {body});
  const names = answer => answer.data.results.map(page => page.properties.Name.title.map(piece => piece.plain_text).join(''));
  assert.deepEqual(names(await query({})), ['Row 1', 'Taxi', 'Hotel', 'Taxi home'], 'every row, in the order made');
  assert.deepEqual(names(await query({filter: {and: [{property: 'Name', title: {contains: 'taxi'}}, {property: source.properties.Cost.id, number: {equals: 12}}]}})), ['Taxi home']);
  assert.deepEqual(names(await query({filter: {property: 'Tags', multi_select: {contains: 'blue'}}})), ['Hotel', 'Taxi home']);
  assert.deepEqual(names(await query({filter: {or: [{property: 'Stage', select: {equals: 'Open'}}, {property: 'Cost', number: {equals: 11}}]}})), ['Row 1', 'Hotel']);
  assert.deepEqual(code(await query({filter: {property: 'Nope', number: {equals: 1}}})), [400, 'validation_error']);
  assert.deepEqual(code(await query({filter: {property: 'Cost', number: {contains: 1}}})), [400, 'validation_error']);
  const first = await query({page_size: 3});
  assert.deepEqual([names(first), first.data.has_more, first.data.object], [['Row 1', 'Taxi', 'Hotel'], true, 'list']);
  assert.deepEqual(names(await query({page_size: 3, start_cursor: first.data.next_cursor})), ['Taxi home']);
  for (const body of [{page_size: 101}, {page_size: 0}, {start_cursor: 'nope'}]) assert.deepEqual(code(await query(body)), [400, 'validation_error'], JSON.stringify(body));
  const search = body => send(simulator, 'POST', '/search', {body});
  const titles = answer => answer.data.results.map(item => item.object === 'page' ? Object.values(item.properties).find(property => property.type === 'title').title.map(piece => piece.plain_text).join('') : item.title[0].plain_text);
  assert.deepEqual(titles(await search({query: 'TAXI', filter: {property: 'object', value: 'page'}})).sort(), ['Taxi', 'Taxi home']);
  assert.deepEqual(titles(await search({filter: {property: 'object', value: 'data_source'}})), ['Tasks']);
  const all = await search({});
  assert.equal(all.data.results.length, 7, 'A, A1, the data source and four rows; B is not shared');
  const paged = await search({page_size: 5});
  assert.deepEqual([paged.data.results.length, paged.data.has_more, (await search({page_size: 5, start_cursor: paged.data.next_cursor})).data.results.length], [5, true, 2]);
  assert.deepEqual(code(await search({filter: {property: 'object', value: 'database'}})), [400, 'validation_error'], 'databases are searched as data sources');
  await send(simulator, 'DELETE', `/blocks/${a.id}`);
  assert.equal((await search({query: '[SYNTHETIC] A'})).data.results.length, 0, 'a trashed page leaves search');
});

test('markdown follow-ups: a block Notion could not render is listed in unknown_block_ids and reads by its own id; an unshared one is 404', async () => {
  const {simulator, a, b} = world();
  const block = simulator.unknown(a.id, {markdown: 'Rest of the page'});
  const read = (await send(simulator, 'GET', `/pages/${a.id}/markdown`)).data;
  assert.deepEqual([read.truncated, read.unknown_block_ids], [true, [block]]);
  assert.ok(read.markdown.endsWith(`<unknown url="https://www.notion.so/${block.replace(/-/g, '')}" alt="block"/>`));
  const follow = await send(simulator, 'GET', `/pages/${block}/markdown`);
  assert.deepEqual([follow.status, follow.data.markdown, follow.data.unknown_block_ids], [200, 'Rest of the page', []]);
  const hidden = simulator.unknown(b.id, {markdown: 'Private rest'});
  assert.deepEqual(code(await send(simulator, 'GET', `/pages/${hidden}/markdown`)), [404, 'object_not_found']);
});

test('a source scan finds only node: imports in the simulator', () => {
  const source = readFileSync(new URL('./fixtures/provider-simulators/notion.mjs', import.meta.url), 'utf8');
  const imports = [...source.matchAll(/^\s*import\b[^'"]*['"]([^'"]+)['"]/gm)].map(match => match[1]);
  assert.deepEqual(imports, ['node:crypto']);
  assert.equal(/\bimport\s*\(/.test(source), false, 'no dynamic import');
});

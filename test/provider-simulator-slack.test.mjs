import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {SlackSimulator, ORIGIN, BASE, IDS} from './fixtures/provider-simulators/slack.mjs';

// F10.21 part 1 f (docs/F10.21-BUILD-MAP.md part 1 f and section 3): the Slack simulator Slack's actions run against in step 21. It must
// keep the network seam's contract (lib/network.mjs) and Slack's documented Web API behaviour, as its own header comment names it. It is
// written from that comment and from Slack's Web API reference, never from Slack's action file, rows or proxy settings, so an action bug
// and a simulator bug cannot cancel out. Nothing here calls Slack.
const TOKEN = 'xoxp-slack-simulator-token-4d2c', AUTH = {Authorization: `Bearer ${TOKEN}`};
const REQUIRED = ['channels:read', 'groups:read', 'im:read', 'mpim:read', 'channels:history', 'groups:history', 'im:history', 'mpim:history', 'users:read', 'chat:write', 'im:write'];
const OPTIONAL = ['users:read.email', 'users.profile:read', 'users.profile:write', 'search:read', 'reactions:read', 'reactions:write', 'canvases:read'];
const START = Date.parse('2026-10-26T15:00:00.000Z'), DAY = 86_400_000;
function sim(options = {}) {
  let now = options.start ?? START;
  const simulator = new SlackSimulator({token: TOKEN, scopes: [...REQUIRED, ...OPTIONAL], clock: () => now, ...options});
  return Object.assign(simulator, {advance(ms) { now += ms; }, get now() { return now; }});
}
/** One Slack Web API call through the seam: GET with the arguments in the query, or POST with a JSON body. */
function call(simulator, name, args = {}, {method = 'GET', headers = AUTH, body, ...more} = {}) {
  const url = new URL(`${BASE}/${name}`);
  if (method === 'GET') for (const [key, value] of Object.entries(args)) url.searchParams.set(key, String(value));
  const json = method !== 'GET' && body === undefined;
  return simulator.request({url: url.href, method, headers: {...headers, ...(json ? {'Content-Type': 'application/json; charset=utf-8'} : {})},
    ...(json ? {body: JSON.stringify(args)} : body === undefined ? {} : {body}), allowedOrigins: [ORIGIN], ...more});
}
const post = (simulator, name, args, options = {}) => call(simulator, name, args, {method: 'POST', ...options});
const big = ts => { const [seconds, micros] = ts.split('.'); return BigInt(seconds) * 1_000_000n + BigInt(micros); };

test('the seam: only the headers asked for come back, an answer over maxBytes throws sent true, and requests refused before sending are never recorded', async () => {
  const simulator = sim();
  const answer = await call(simulator, 'conversations.history', {channel: IDS.fabricTest});
  assert.deepEqual([answer.status, Object.keys(answer.headers)], [200, ['content-type']]);
  assert.equal((await call(simulator, 'conversations.history', {channel: IDS.fabricTest}, {responseHeaders: []})).headers['content-type'], undefined);
  await assert.rejects(call(simulator, 'conversations.history', {channel: IDS.fabricTest}, {maxBytes: 32}), error => error.sent === true && /size limit/.test(error.message));
  const before = simulator.calls.length;
  for (const [label, request] of [['an origin outside the grant', {url: `${BASE}/auth.test`, method: 'POST', headers: AUTH, allowedOrigins: ['https://example.com']}],
    ['plain http', {url: 'http://slack.com/api/users.list', method: 'GET', headers: AUTH, allowedOrigins: [ORIGIN]}],
    ['a port', {url: 'https://slack.com:8443/api/users.list', method: 'GET', headers: AUTH, allowedOrigins: ['https://slack.com:8443']}],
    ['an unsafe header', {url: `${BASE}/users.list`, method: 'GET', headers: {...AUTH, Host: 'x'}, allowedOrigins: [ORIGIN]}],
    ['a body that is not serialized', {url: `${BASE}/chat.postMessage`, method: 'POST', headers: AUTH, body: {channel: IDS.fabricTest}, allowedOrigins: [ORIGIN]}],
    ['a body over 1 MiB', {url: `${BASE}/chat.postMessage`, method: 'POST', headers: AUTH, body: JSON.stringify({text: 'x'.repeat(1024 * 1024)}), allowedOrigins: [ORIGIN]}],
    ['an origin the simulator does not serve', {url: 'https://files.slack.com/api/x', method: 'GET', headers: AUTH, allowedOrigins: ['https://files.slack.com']}]]) {
    await assert.rejects(simulator.request(request), error => error.sent === false, label);
  }
  assert.equal(simulator.calls.length, before, 'refused before sending: never recorded');
  const outside = await simulator.request({url: `${ORIGIN}/archives/x`, method: 'GET', headers: AUTH, allowedOrigins: [ORIGIN]});
  assert.deepEqual([outside.status, simulator.calls.at(-1).name], [404, null], 'a path outside /api is answered 404');
});

test('every answer is HTTP 200 JSON with ok; no token is not_authed, a wrong one invalid_auth, and calls are recorded without Authorization', async () => {
  const simulator = sim();
  assert.deepEqual((await post(simulator, 'chat.postMessage', {channel: IDS.fabricTest, text: 'x'}, {headers: {}})).data, {ok: false, error: 'not_authed'});
  assert.deepEqual((await post(simulator, 'chat.postMessage', {channel: IDS.fabricTest, text: 'x'}, {headers: {Authorization: 'Bearer xoxp-wrong'}})).data, {ok: false, error: 'invalid_auth'});
  assert.equal(simulator.state().channels[IDS.fabricTest].messages.length, 2, 'nothing was posted');
  const unknown = await call(simulator, 'conversations.kick');
  assert.deepEqual([unknown.status, unknown.data], [200, {ok: false, error: 'unknown_method'}]);
  for (const recorded of simulator.calls) assert.equal(JSON.stringify(recorded).includes('xoxp-'), false, 'no call records a token');
});

test('missing_scope names what is needed and what the token has, by conversation type for history and replies, and changes nothing', async () => {
  const simulator = sim({scopes: ['channels:history', 'chat:write', 'users:read']});
  assert.equal((await call(simulator, 'conversations.history', {channel: IDS.fabricTest})).data.ok, true, 'a public channel needs channels:history');
  for (const [channel, needed] of [[IDS.private, 'groups:history'], [IDS.selfDm, 'im:history']]) {
    const {data} = await call(simulator, 'conversations.history', {channel});
    assert.deepEqual(data, {ok: false, error: 'missing_scope', needed, provided: 'channels:history,chat:write,users:read'}, channel);
    assert.equal((await call(simulator, 'conversations.replies', {channel, ts: '1.000001'})).data.needed, needed);
  }
  for (const [name, needed, args] of [['reactions.add', 'reactions:write', {channel: IDS.fabricTest, timestamp: simulator.synthetic.one, name: 'eyes'}],
    ['users.profile.set', 'users.profile:write', {profile: {status_text: 'x', status_emoji: ':x:', status_expiration: 0}}], ['search.messages', 'search:read', {query: 'x'}],
    ['canvases.getContent', 'canvases:read', {canvas_id: IDS.canvas}], ['users.lookupByEmail', 'users:read.email', {email: 'ada@example.com'}], ['conversations.open', 'im:write', {users: IDS.ada}]]) {
    const {data} = await (name.startsWith('users.lookup') || name === 'search.messages' ? call : post)(simulator, name, args);
    assert.deepEqual([data.ok, data.error, data.needed], [false, 'missing_scope', needed], name);
  }
  assert.deepEqual(simulator.state().channels[IDS.fabricTest].messages.find(message => message.ts === simulator.synthetic.one).reactions, [], 'nothing changed');
  // revokeScope: the token loses a scope the account record may still hold.
  const full = sim();
  assert.equal((await post(full, 'reactions.add', {channel: IDS.fabricTest, timestamp: full.synthetic.one, name: 'eyes'})).data.ok, true);
  full.revokeScope('reactions:write');
  const refused = (await post(full, 'reactions.add', {channel: IDS.fabricTest, timestamp: full.synthetic.two, name: 'eyes'})).data;
  assert.deepEqual([refused.error, refused.needed, refused.provided.split(',').includes('reactions:write')], ['missing_scope', 'reactions:write', false]);
});

test('a POST that is not JSON is invalid_form_data, and a token argument anywhere is refused and recorded', async () => {
  const simulator = sim();
  const form = await post(simulator, 'chat.postMessage', {}, {headers: {...AUTH, 'Content-Type': 'application/x-www-form-urlencoded'}, body: `channel=${IDS.fabricTest}&text=x`});
  assert.deepEqual(form.data, {ok: false, error: 'invalid_form_data'});
  for (const [label, request] of [['the query', () => call(simulator, 'users.list', {token: TOKEN})], ['the body', () => post(simulator, 'chat.postMessage', {channel: IDS.fabricTest, text: 'x', token: TOKEN})],
    ['a nested body field', () => post(simulator, 'users.profile.set', {profile: {status_text: 'x', token: TOKEN}})]]) {
    assert.deepEqual((await request()).data, {ok: false, error: 'token_argument'}, label);
    assert.equal(simulator.calls.at(-1).tokenArgument, true, label);
  }
  assert.equal(simulator.state().channels[IDS.fabricTest].messages.length, 2, 'nothing was posted');
});

test('history: top-level messages newest first, paged by cursor with has_more; ts values are strings and sort as numbers, never as text', async () => {
  const simulator = sim();
  const old = simulator.seed(IDS.general, {ts: '999999999.999999', user: IDS.ada, text: 'older'});
  const newer = simulator.seed(IDS.general, {ts: '1000000000.000000', user: IDS.ada, text: 'newer'});
  assert.deepEqual([old, newer], ['999999999.999999', '1000000000.000000']);
  const all = (await call(simulator, 'conversations.history', {channel: IDS.general})).data.messages.map(message => message.ts);
  assert.deepEqual(all.slice(-2), ['1000000000.000000', '999999999.999999'], 'the ten-digit second is newer than the nine-digit one');
  for (let index = 1; index < all.length; index++) assert.ok(big(all[index - 1]) > big(all[index]), 'newest first');
  assert.ok(all.every(ts => typeof ts === 'string'));
  const first = (await call(simulator, 'conversations.history', {channel: IDS.general, limit: 2})).data;
  assert.deepEqual([first.messages.length, first.has_more, typeof first.response_metadata.next_cursor], [2, true, 'string']);
  const second = (await call(simulator, 'conversations.history', {channel: IDS.general, limit: 2, cursor: first.response_metadata.next_cursor})).data;
  assert.deepEqual(second.messages.map(message => message.ts), all.slice(2, 4));
  const last = (await call(simulator, 'conversations.history', {channel: IDS.general, limit: 100})).data;
  assert.deepEqual([last.has_more, last.response_metadata.next_cursor], [false, '']);
  assert.deepEqual((await call(simulator, 'conversations.history', {channel: IDS.general, cursor: 'nonsense'})).data, {ok: false, error: 'invalid_cursor'});
  // A thread's replies stay out of history; their parent carries thread_ts and reply_count.
  const parent = (await call(simulator, 'conversations.history', {channel: IDS.general})).data.messages.find(message => message.text === 'Welcome to #general');
  assert.deepEqual([parent.thread_ts, parent.reply_count, last.messages.some(message => message.text === 'Thanks')], [parent.ts, 2, false]);
  // oldest, latest and inclusive bound the window.
  const window = (await call(simulator, 'conversations.history', {channel: IDS.general, oldest: old, latest: newer, inclusive: true})).data.messages.map(message => message.ts);
  assert.deepEqual(window, [newer, old]);
  assert.deepEqual((await call(simulator, 'conversations.history', {channel: IDS.general, oldest: old, latest: newer})).data.messages, [], 'without inclusive the ends are out');
  assert.deepEqual((await call(simulator, 'conversations.history', {channel: 'C0NOWHERE1'})).data, {ok: false, error: 'channel_not_found'});
  assert.deepEqual((await call(simulator, 'conversations.history', {channel: IDS.others})).data.ok, true, 'a user token reads a public channel it is not in');
  assert.deepEqual((await call(simulator, 'conversations.history', {channel: IDS.secret})).data, {ok: false, error: 'channel_not_found'}, 'a private channel it is not in does not exist for it');
});

test('replies: the parent first, then replies oldest first; a reply\'s ts reads its whole thread; oldest, latest and inclusive cut it', async () => {
  const simulator = sim();
  const {messages} = (await call(simulator, 'conversations.history', {channel: IDS.general})).data, parent = messages.find(message => message.text === 'Welcome to #general');
  const thread = (await call(simulator, 'conversations.replies', {channel: IDS.general, ts: parent.ts})).data.messages;
  assert.deepEqual(thread.map(message => message.text), ['Welcome to #general', 'Thanks', 'Hello']);
  assert.ok(thread.slice(1).every(reply => reply.thread_ts === parent.ts && reply.parent_user_id === IDS.ada));
  assert.deepEqual((await call(simulator, 'conversations.replies', {channel: IDS.general, ts: thread[2].ts})).data.messages.map(message => message.ts), thread.map(message => message.ts));
  const one = (await call(simulator, 'conversations.replies', {channel: IDS.general, ts: thread[2].ts, oldest: thread[2].ts, latest: thread[2].ts, inclusive: true, limit: 1})).data;
  assert.deepEqual(one.messages.map(message => message.text), ['Hello'], 'a window that holds only the reply');
  const alone = (await call(simulator, 'conversations.replies', {channel: IDS.fabricTest, ts: simulator.synthetic.one})).data.messages;
  assert.deepEqual(alone.map(message => message.ts), [simulator.synthetic.one], 'a message with no replies comes back alone');
  assert.deepEqual((await call(simulator, 'conversations.replies', {channel: IDS.general, ts: '1.000001'})).data, {ok: false, error: 'thread_not_found'});
  const paged = (await call(simulator, 'conversations.replies', {channel: IDS.general, ts: parent.ts, limit: 2})).data;
  assert.deepEqual([paged.messages.length, paged.has_more], [2, true]);
  const rest = (await call(simulator, 'conversations.replies', {channel: IDS.general, ts: parent.ts, limit: 2, cursor: paged.response_metadata.next_cursor})).data;
  assert.deepEqual(rest.messages.map(message => message.text), ['Hello']);
});

test('chat.postMessage stores the text exactly as sent; unescaped <!channel>, <!here> and <@U...> notify people, escaped text notifies nobody', async () => {
  const simulator = sim();
  const escaped = await post(simulator, 'chat.postMessage', {channel: IDS.fabricTest, text: '&lt;!channel&gt; R&amp;D &lt;@U0ADA0001&gt;', parse: 'none', link_names: false});
  assert.equal(escaped.data.ok, true);
  assert.equal(simulator.state().channels[IDS.fabricTest].messages.at(-1).text, '&lt;!channel&gt; R&amp;D &lt;@U0ADA0001&gt;');
  assert.deepEqual(simulator.notifications(), []);
  await post(simulator, 'chat.postMessage', {channel: IDS.fabricTest, text: '<!channel> and <@U0ADA0001>'});
  assert.deepEqual(simulator.notifications().map(item => item.kind), ['channel', 'user']);
  await post(simulator, 'chat.postMessage', {channel: IDS.fabricTest, text: '<!here|here>'});
  assert.equal(simulator.notifications().at(-1).kind, 'here');
  // Without parse none, plain @channel is a mention too (parse full); with it, it is text.
  await post(simulator, 'chat.postMessage', {channel: IDS.fabricTest, text: '@channel plain', parse: 'none'});
  assert.equal(simulator.notifications().length, 3);
  await post(simulator, 'chat.postMessage', {channel: IDS.fabricTest, text: '@channel plain', parse: 'full'});
  assert.equal(simulator.notifications().length, 4);
  const {data} = escaped;
  assert.deepEqual([data.channel, typeof data.ts, data.message.text, data.message.user], [IDS.fabricTest, 'string', '&lt;!channel&gt; R&amp;D &lt;@U0ADA0001&gt;', IDS.owner]);
  assert.ok(big(data.ts) > big(simulator.synthetic.two), 'a new ts is later than every earlier one');
});

test('chat.postMessage refuses what Slack refuses and changes nothing; a thread reply needs a parent of that channel', async () => {
  const simulator = sim(), count = () => Object.values(simulator.state().channels).reduce((sum, channel) => sum + channel.messages.length, 0), before = count();
  for (const [args, error] of [[{channel: 'C0NOWHERE1', text: 'x'}, 'channel_not_found'], [{channel: IDS.others, text: 'x'}, 'not_in_channel'], [{channel: IDS.archived, text: 'x'}, 'is_archived'],
    [{channel: IDS.fabricTest}, 'no_text'], [{channel: IDS.fabricTest, text: ''}, 'no_text'], [{channel: IDS.fabricTest, text: 'x'.repeat(40_001)}, 'msg_too_long'],
    [{channel: IDS.fabricTest, text: 'x', thread_ts: '1.000001'}, 'thread_not_found']]) {
    assert.deepEqual((await post(simulator, 'chat.postMessage', args)).data, {ok: false, error}, error);
  }
  const reply = (await post(simulator, 'chat.postMessage', {channel: IDS.fabricTest, text: 'r', thread_ts: simulator.synthetic.one})).data;
  assert.deepEqual([reply.ok, reply.message.thread_ts], [true, simulator.synthetic.one]);
  assert.deepEqual((await post(simulator, 'chat.postMessage', {channel: IDS.fabricTest, text: 'x', thread_ts: reply.ts})).data, {ok: false, error: 'cannot_reply_to_message'}, 'a reply is no parent');
  assert.equal(count(), before + 1);
  assert.equal((await post(simulator, 'chat.postMessage', {channel: IDS.fabricTest, text: 'x'.repeat(40_000)})).data.ok, true, '40,000 characters post');
});

test('chat.update: only the owner\'s own messages; text without blocks drops the blocks, and attachments stay unless [] is sent', async () => {
  const simulator = sim(), message = ts => simulator.state().channels[IDS.fabricTest].messages.find(item => item.ts === ts);
  const other = await post(simulator, 'chat.update', {channel: IDS.fabricTest, ts: simulator.synthetic.two, text: 'mine now'});
  assert.deepEqual(other.data, {ok: false, error: 'cant_update_message'});
  assert.equal(message(simulator.synthetic.two).text, '[SYNTHETIC] Fabric message 2', 'Ada\'s message is unchanged');
  const ts = (await post(simulator, 'chat.postMessage', {channel: IDS.fabricTest, text: 'v1', blocks: [{type: 'section'}], attachments: [{text: 'a'}]})).data.ts;
  const updated = await post(simulator, 'chat.update', {channel: IDS.fabricTest, ts, text: 'v2', parse: 'none', link_names: false});
  assert.deepEqual([updated.data.ok, updated.data.ts, updated.data.text], [true, ts, 'v2']);
  assert.deepEqual([message(ts).text, message(ts).blocks, message(ts).attachments, Boolean(message(ts).edited)], ['v2', undefined, [{text: 'a'}], true]);
  await post(simulator, 'chat.update', {channel: IDS.fabricTest, ts, text: 'v3', attachments: []});
  assert.deepEqual([message(ts).text, message(ts).attachments], ['v3', undefined]);
  for (const [args, error] of [[{channel: IDS.fabricTest, ts: '1.000001', text: 'x'}, 'message_not_found'], [{channel: IDS.fabricTest, ts, text: 'x'.repeat(4001)}, 'msg_too_long'],
    [{channel: IDS.fabricTest, ts}, 'no_text'], [{channel: 'C0NOWHERE1', ts, text: 'x'}, 'channel_not_found']]) {
    assert.deepEqual((await post(simulator, 'chat.update', args)).data, {ok: false, error}, error);
  }
  simulator.closeEditWindow();
  assert.deepEqual((await post(simulator, 'chat.update', {channel: IDS.fabricTest, ts, text: 'v4'})).data, {ok: false, error: 'edit_window_closed'});
  assert.equal(message(ts).text, 'v3');
});

test('chat.scheduleMessage: post_at in whole seconds, after now and at most 120 days ahead; listed until deleted or due', async () => {
  const simulator = sim(), seconds = Math.floor(START / 1000);
  for (const [postAt, error] of [[seconds, 'time_in_past'], [seconds - 1, 'time_in_past'], [seconds + 120 * 86_400 + 1, 'time_too_far'], [seconds + 60.5, 'invalid_time'], ['soon', 'invalid_time']]) {
    assert.deepEqual((await post(simulator, 'chat.scheduleMessage', {channel: IDS.fabricTest, text: 'x', post_at: postAt})).data, {ok: false, error}, String(postAt));
  }
  const edge = (await post(simulator, 'chat.scheduleMessage', {channel: IDS.fabricTest, text: 'edge', post_at: seconds + 120 * 86_400})).data;
  assert.deepEqual([edge.ok, edge.post_at, edge.channel, /^Q[A-Z0-9]{8,}$/.test(edge.scheduled_message_id)], [true, seconds + 120 * 86_400, IDS.fabricTest, true], '120 days exactly');
  const soon = (await post(simulator, 'chat.scheduleMessage', {channel: IDS.fabricTest, text: 'soon', post_at: seconds + 7200})).data;
  const listed = (await call(simulator, 'chat.scheduledMessages.list', {channel: IDS.fabricTest})).data.scheduled_messages;
  assert.deepEqual(listed.map(item => [item.id, item.channel_id, item.post_at, item.text]).sort(), [[edge.scheduled_message_id, IDS.fabricTest, edge.post_at, 'edge'], [soon.scheduled_message_id, IDS.fabricTest, soon.post_at, 'soon']].sort());
  assert.equal((await post(simulator, 'chat.deleteScheduledMessage', {channel: IDS.fabricTest, scheduled_message_id: soon.scheduled_message_id})).data.ok, true);
  assert.deepEqual((await post(simulator, 'chat.deleteScheduledMessage', {channel: IDS.fabricTest, scheduled_message_id: soon.scheduled_message_id})).data, {ok: false, error: 'invalid_scheduled_message_id'}, 'a second delete');
  assert.deepEqual((await call(simulator, 'chat.scheduledMessages.list', {channel: IDS.fabricTest})).data.scheduled_messages.map(item => item.id), [edge.scheduled_message_id]);
  // Due within a minute it can no longer be deleted; once due it posts and leaves the list.
  const due = (await post(simulator, 'chat.scheduleMessage', {channel: IDS.fabricTest, text: 'due', post_at: seconds + 30})).data;
  assert.deepEqual((await post(simulator, 'chat.deleteScheduledMessage', {channel: IDS.fabricTest, scheduled_message_id: due.scheduled_message_id})).data.error, 'invalid_scheduled_message_id');
  simulator.advance(31_000);
  assert.deepEqual((await call(simulator, 'chat.scheduledMessages.list', {channel: IDS.fabricTest})).data.scheduled_messages.map(item => item.id), [edge.scheduled_message_id]);
  assert.equal(simulator.state().channels[IDS.fabricTest].messages.at(-1).text, 'due');
});

test('reactions: add and remove as the owner; already_reacted and no_reaction change nothing; reactions.get lists who reacted, all of them with full', async () => {
  const simulator = sim(), target = {channel: IDS.fabricTest, timestamp: simulator.synthetic.two};
  const reactions = () => simulator.state().channels[IDS.fabricTest].messages.find(item => item.ts === simulator.synthetic.two).reactions;
  assert.equal((await post(simulator, 'reactions.add', {...target, name: 'white_check_mark'})).data.ok, true);
  const once = structuredClone(reactions());
  assert.deepEqual((await post(simulator, 'reactions.add', {...target, name: 'white_check_mark'})).data, {ok: false, error: 'already_reacted'});
  assert.deepEqual(reactions(), once);
  for (const name of ['👍', ':thumbsup:', 'no_such_emoji', 'Thumbsup']) assert.deepEqual((await post(simulator, 'reactions.add', {...target, name})).data, {ok: false, error: 'invalid_name'}, name);
  assert.equal((await post(simulator, 'reactions.add', {...target, name: 'thumbsup::skin-tone-3'})).data.ok, true, 'a skin tone');
  assert.deepEqual((await post(simulator, 'reactions.add', {channel: IDS.fabricTest, timestamp: '1.000001', name: 'eyes'})).data, {ok: false, error: 'message_not_found'});
  for (const user of [IDS.ada, IDS.grace, 'U0EXTRA001', 'U0EXTRA002']) simulator.react(IDS.fabricTest, simulator.synthetic.two, 'white_check_mark', user);
  const short = (await call(simulator, 'reactions.get', target)).data, full = (await call(simulator, 'reactions.get', {...target, full: true})).data;
  const check = data => data.message.reactions.find(item => item.name === 'white_check_mark');
  assert.deepEqual([short.type, short.channel, short.message.ts, check(short).count, check(full).count], ['message', IDS.fabricTest, simulator.synthetic.two, 5, 5]);
  assert.ok(check(short).users.includes(IDS.owner) && check(short).users.length < 5, 'without full the list is cut but holds the caller');
  assert.deepEqual(check(full).users, [IDS.owner, IDS.ada, IDS.grace, 'U0EXTRA001', 'U0EXTRA002']);
  assert.equal((await post(simulator, 'reactions.remove', {...target, name: 'white_check_mark'})).data.ok, true);
  assert.equal(check((await call(simulator, 'reactions.get', {...target, full: true})).data).users.includes(IDS.owner), false);
  const without = structuredClone(reactions());
  assert.deepEqual((await post(simulator, 'reactions.remove', {...target, name: 'white_check_mark'})).data, {ok: false, error: 'no_reaction'});
  assert.deepEqual((await post(simulator, 'reactions.remove', {...target, name: 'tada'})).data, {ok: false, error: 'no_reaction'});
  assert.deepEqual(reactions(), without);
});

test('conversations.open: one direct message per person, the same id every time; the owner\'s own id opens the self-DM; never more than one person', async () => {
  const simulator = sim();
  const first = (await post(simulator, 'conversations.open', {users: IDS.ada})).data, again = (await post(simulator, 'conversations.open', {users: IDS.ada})).data;
  assert.deepEqual([first.ok, first.channel.id, again.channel.id], [true, first.channel.id, first.channel.id]);
  assert.match(first.channel.id, /^D[A-Z0-9]{8,}$/);
  assert.equal((await post(simulator, 'conversations.open', {users: IDS.owner})).data.channel.id, IDS.selfDm);
  const detail = (await post(simulator, 'conversations.open', {users: IDS.ada, return_im: true})).data;
  assert.deepEqual([detail.already_open, detail.channel.is_im, detail.channel.user], [true, true, IDS.ada]);
  for (const [users, error] of [['U0NOBODY01', 'user_not_found'], [IDS.gone, 'user_disabled'], [undefined, 'users_list_not_supplied'], [`${IDS.ada},${IDS.grace}`, 'not_simulated']]) {
    assert.deepEqual((await post(simulator, 'conversations.open', users === undefined ? {} : {users})).data, {ok: false, error}, error);
  }
  const posted = (await post(simulator, 'chat.postMessage', {channel: first.channel.id, text: 'hi'})).data;
  assert.deepEqual([posted.ok, posted.channel], [true, first.channel.id]);
  const history = (await call(simulator, 'conversations.history', {channel: first.channel.id})).data.messages;
  assert.deepEqual(history.map(item => item.text), ['hi']);
});

test('users: list in cursor pages with email only under users:read.email, info, lookupByEmail; deleted people and bots are marked', async () => {
  const simulator = sim(), narrow = sim({scopes: REQUIRED});
  const page = (await call(simulator, 'users.list', {limit: 2})).data;
  assert.deepEqual([page.members.length, typeof page.response_metadata.next_cursor], [2, 'string']);
  const rest = (await call(simulator, 'users.list', {limit: 200, cursor: page.response_metadata.next_cursor})).data;
  const members = [...page.members, ...rest.members];
  assert.deepEqual(members.map(member => member.id).sort(), [IDS.ada, IDS.bot, IDS.gone, IDS.grace, IDS.owner].sort());
  assert.equal(rest.response_metadata.next_cursor, '');
  assert.deepEqual([members.find(member => member.id === IDS.bot).is_bot, members.find(member => member.id === IDS.gone).deleted], [true, true]);
  assert.equal(members.find(member => member.id === IDS.ada).profile.email, 'ada@example.com');
  const hidden = (await call(narrow, 'users.list', {limit: 200})).data.members;
  assert.ok(hidden.every(member => member.profile.email === undefined), 'no email without users:read.email');
  assert.equal((await call(narrow, 'users.info', {user: IDS.ada})).data.user.profile.email, undefined);
  const info = (await call(simulator, 'users.info', {user: IDS.ada})).data.user;
  assert.deepEqual([info.id, info.real_name, info.profile.display_name, info.profile.email], [IDS.ada, 'Ada Lovelace', 'ada', 'ada@example.com']);
  assert.deepEqual((await call(simulator, 'users.info', {user: 'U0NOBODY01'})).data, {ok: false, error: 'user_not_found'});
  assert.equal((await call(simulator, 'users.lookupByEmail', {email: 'GRACE@example.com'})).data.user.id, IDS.grace);
  for (const email of ['nobody@example.com', 'gone@example.com']) assert.deepEqual((await call(simulator, 'users.lookupByEmail', {email})).data, {ok: false, error: 'users_not_found'}, email);
});

test('users.profile.get and users.profile.set: status fields only, as the caller only; text over 100 characters is too_long; an expired status reads cleared', async () => {
  const simulator = sim(), profile = async () => (await call(simulator, 'users.profile.get')).data.profile;
  assert.deepEqual(await profile().then(item => [item.status_text, item.status_emoji, item.status_expiration]), ['', '', 0]);
  const until = Math.floor(START / 1000) + 600;
  const set = (await post(simulator, 'users.profile.set', {profile: {status_text: '[SYNTHETIC] Fabric', status_emoji: ':white_check_mark:', status_expiration: until}})).data;
  assert.deepEqual([set.ok, set.profile.status_text, set.profile.status_emoji, set.profile.status_expiration], [true, '[SYNTHETIC] Fabric', ':white_check_mark:', until]);
  assert.deepEqual((await post(simulator, 'users.profile.set', {user: IDS.ada, profile: {status_text: 'x', status_emoji: ':x:', status_expiration: 0}})).data, {ok: false, error: 'not_admin'});
  for (const [body, error] of [[{profile: {status_text: 'x'.repeat(101), status_emoji: ':x:'}}, 'too_long'], [{profile: {status_text: ''}}, 'must_clear_both_status_text_and_status_emoji'],
    [{profile: {status_text: 'x', status_emoji: 'thumbsup'}}, 'invalid_emoji_not_allowed'], [{profile: {status_text: 'x', status_emoji: ':x:', status_expiration: 'later'}}, 'invalid_profile'],
    [{profile: {real_name: 'Someone else'}}, 'not_simulated'], [{}, 'invalid_profile']]) {
    assert.deepEqual((await post(simulator, 'users.profile.set', body)).data, {ok: false, error}, error);
  }
  assert.equal((await profile()).status_text, '[SYNTHETIC] Fabric', 'a refused set changes nothing');
  simulator.advance(601_000);
  assert.deepEqual(await profile().then(item => [item.status_text, item.status_emoji, item.status_expiration]), ['', '', 0], 'expired');
  await post(simulator, 'users.profile.set', {profile: {status_text: 'back', status_emoji: ':wave:', status_expiration: 0}});
  assert.equal((await post(simulator, 'users.profile.set', {profile: {status_text: '', status_emoji: '', status_expiration: 0}})).data.ok, true);
  assert.deepEqual(await profile().then(item => [item.status_text, item.status_emoji]), ['', ''], 'cleared');
});

test('search.messages: the quoted phrase, in:<#C>, from:<@U>, after: and before: days, count and page; only conversations the owner can read', async () => {
  const simulator = sim(), search = async query => (await call(simulator, 'search.messages', {query, count: 20, sort: 'timestamp', sort_dir: 'desc', highlight: false})).data.messages;
  const found = await search('"[SYNTHETIC] Fabric"');
  assert.deepEqual(found.matches.map(match => match.text), ['[SYNTHETIC] Fabric message 2', '[SYNTHETIC] Fabric message 1']);
  const [match] = found.matches;
  assert.deepEqual([match.channel.id, match.channel.name, match.user, typeof match.ts, match.permalink.startsWith('https://fabric-test.slack.com/archives/C0FABTEST1/p')], [IDS.fabricTest, 'fabric-test', IDS.ada, 'string', true]);
  assert.deepEqual(found.paging, {count: 20, total: 2, page: 1, pages: 1});
  assert.deepEqual((await search(`"[SYNTHETIC]" from:<@${IDS.owner}>`)).matches.map(item => item.ts), [simulator.synthetic.one]);
  assert.deepEqual((await search(`"[SYNTHETIC]" in:<#${IDS.general}>`)).matches, []);
  assert.deepEqual((await search('"message 2 [SYNTHETIC]"')).matches, [], 'a phrase matches in order only');
  const day = new Date(START).toISOString().slice(0, 10), before = new Date(START - DAY).toISOString().slice(0, 10);
  assert.equal((await search(`"[SYNTHETIC]" after:${before}`)).matches.length, 2);
  assert.equal((await search(`"[SYNTHETIC]" after:${day}`)).matches.length, 0, 'after excludes the day itself');
  assert.equal((await search(`"[SYNTHETIC]" before:${day}`)).matches.length, 0, 'before excludes the day itself');
  simulator.seed(IDS.secret, {user: IDS.ada, text: '[SYNTHETIC] hidden'});
  assert.equal((await search('"hidden"')).matches.length, 0, 'a private channel the owner is not in');
  const paged = (await call(simulator, 'search.messages', {query: '"[SYNTHETIC]"', count: 1, page: 2})).data.messages;
  assert.deepEqual([paged.matches.length, paged.paging.page, paged.paging.pages], [1, 2, 2]);
  assert.deepEqual((await call(simulator, 'search.messages', {query: ''})).data, {ok: false, error: 'no_query'});
});

test('channels: users.conversations by type with cursors, conversations.info with its member count, chat.getPermalink, canvases.getContent', async () => {
  const simulator = sim();
  const listed = (await call(simulator, 'users.conversations', {types: 'public_channel,private_channel,mpim,im', exclude_archived: true, limit: 100})).data.channels;
  assert.deepEqual(listed.map(item => item.id).sort(), [IDS.fabricTest, IDS.general, IDS.private, IDS.selfDm].sort());
  const dm = listed.find(item => item.id === IDS.selfDm);
  assert.deepEqual([dm.is_im, dm.user, listed.find(item => item.id === IDS.private).is_private], [true, IDS.owner, true]);
  assert.ok((await call(simulator, 'users.conversations', {types: 'public_channel'})).data.channels.every(item => !item.is_private && !item.is_im), 'the default type list');
  assert.ok((await call(simulator, 'users.conversations', {types: 'public_channel,private_channel,mpim,im'})).data.channels.some(item => item.id === IDS.archived), 'archived ones without exclude_archived');
  const first = (await call(simulator, 'users.conversations', {types: 'public_channel,private_channel,mpim,im', limit: 2})).data;
  const second = (await call(simulator, 'users.conversations', {types: 'public_channel,private_channel,mpim,im', limit: 2, cursor: first.response_metadata.next_cursor})).data;
  assert.equal(new Set([...first.channels, ...second.channels].map(item => item.id)).size, 4);
  const info = (await call(simulator, 'conversations.info', {channel: IDS.fabricTest, include_num_members: true})).data.channel;
  assert.deepEqual([info.id, info.name, info.num_members, info.is_member], [IDS.fabricTest, 'fabric-test', 2, true]);
  assert.equal((await call(simulator, 'conversations.info', {channel: IDS.fabricTest})).data.channel.num_members, undefined);
  assert.deepEqual((await call(simulator, 'conversations.info', {channel: 'C0NOWHERE1'})).data, {ok: false, error: 'channel_not_found'});
  const link = (await call(simulator, 'chat.getPermalink', {channel: IDS.fabricTest, message_ts: simulator.synthetic.one})).data;
  assert.deepEqual(link, {ok: true, channel: IDS.fabricTest, permalink: `https://fabric-test.slack.com/archives/${IDS.fabricTest}/p${simulator.synthetic.one.replace('.', '')}`});
  const thread = (await call(simulator, 'conversations.history', {channel: IDS.general})).data.messages.find(message => message.text === 'Welcome to #general');
  const reply = (await call(simulator, 'conversations.replies', {channel: IDS.general, ts: thread.ts})).data.messages[1];
  assert.equal((await call(simulator, 'chat.getPermalink', {channel: IDS.general, message_ts: reply.ts})).data.permalink,
    `https://fabric-test.slack.com/archives/${IDS.general}/p${reply.ts.replace('.', '')}?thread_ts=${thread.ts}&cid=${IDS.general}`);
  assert.deepEqual((await call(simulator, 'chat.getPermalink', {channel: IDS.fabricTest, message_ts: '1.000001'})).data, {ok: false, error: 'message_not_found'});
  const canvas = (await post(simulator, 'canvases.getContent', {canvas_id: IDS.canvas, content_type: 'markdown'})).data;
  assert.deepEqual([canvas.ok, canvas.content.startsWith('# [SYNTHETIC] Fabric canvas')], [true, true]);
  assert.deepEqual((await post(simulator, 'canvases.getContent', {canvas_id: 'F0NOWHERE1'})).data, {ok: false, error: 'canvas_not_found'});
});

test('rateLimit: a second history or replies call within 60 seconds in the workspace answers 429 with Retry-After, each method apart', async () => {
  const simulator = sim({rateLimit: true});
  assert.equal((await call(simulator, 'conversations.history', {channel: IDS.fabricTest})).status, 200);
  simulator.advance(20_000);
  const limited = await call(simulator, 'conversations.history', {channel: IDS.general});
  assert.deepEqual([limited.status, limited.headers['retry-after'], limited.data], [429, '40', {ok: false, error: 'ratelimited'}]);
  assert.equal((await call(simulator, 'conversations.replies', {channel: IDS.fabricTest, ts: simulator.synthetic.one})).status, 200, 'replies is limited apart');
  simulator.advance(40_000);
  assert.equal((await call(simulator, 'conversations.history', {channel: IDS.fabricTest})).status, 200);
  const plain = sim();
  await call(plain, 'conversations.history', {channel: IDS.fabricTest});
  assert.equal((await call(plain, 'conversations.history', {channel: IDS.general})).status, 200, 'off by default');
});

test('switches: fail, drop, swallow, oversize and hold, each for one call to one method; writes() and reads() split the calls', async () => {
  const simulator = sim(), count = () => simulator.state().channels[IDS.fabricTest].messages.length, start = count();
  simulator.fail('chat.postMessage', {status: 200, data: {ok: false, error: 'internal_error'}});
  assert.deepEqual((await post(simulator, 'chat.postMessage', {channel: IDS.fabricTest, text: 'a'})).data, {ok: false, error: 'internal_error'});
  assert.equal(count(), start);
  simulator.drop('chat.postMessage');
  await assert.rejects(post(simulator, 'chat.postMessage', {channel: IDS.fabricTest, text: 'b'}), error => error.sent === true);
  assert.equal(count(), start + 1, 'a dropped call was applied');
  simulator.swallow('chat.postMessage');
  assert.equal((await post(simulator, 'chat.postMessage', {channel: IDS.fabricTest, text: 'c'})).data.ok, true);
  assert.equal(count(), start + 1, 'a swallowed call changed nothing');
  simulator.oversize('conversations.history', 4096);
  assert.ok(JSON.stringify((await call(simulator, 'conversations.history', {channel: IDS.fabricTest})).data).length > 4096);
  const {reached, release} = simulator.hold('chat.postMessage');
  const running = post(simulator, 'chat.postMessage', {channel: IDS.fabricTest, text: 'd'});
  await reached;
  assert.equal(count(), start + 1, 'held: nothing applied yet');
  release();
  assert.equal((await running).data.ok, true);
  assert.equal(count(), start + 2);
  assert.ok(simulator.writes().every(item => item.name === 'chat.postMessage') && simulator.reads().every(item => item.name === 'conversations.history'));
  assert.deepEqual([simulator.writes().length, simulator.reads().length], [4, 1]);
});

test('test data: seed and post are other people\'s messages, edit changes one, react adds someone else\'s reaction; none is a recorded call', async () => {
  const simulator = sim();
  const posted = simulator.post(IDS.fabricTest, {user: IDS.grace, text: 'from Grace'});
  const reply = simulator.post(IDS.fabricTest, {user: IDS.ada, text: 'in thread', threadTs: posted});
  simulator.edit(IDS.fabricTest, posted, 'from Grace, edited');
  const thread = (await call(simulator, 'conversations.replies', {channel: IDS.fabricTest, ts: posted})).data.messages;
  assert.deepEqual(thread.map(item => [item.ts, item.user, item.text]), [[posted, IDS.grace, 'from Grace, edited'], [reply, IDS.ada, 'in thread']]);
  assert.ok(big(reply) > big(posted));
  assert.deepEqual(simulator.calls.map(item => item.name), ['conversations.replies']);
});

// F10.21 part 2: the people and channels the action tests add (Find a person's name search, List channels and DMs' second page).
test('test data: addPerson adds someone to users.list, users.info and users.lookupByEmail; addChannel adds a channel the owner is in; neither is a recorded call', async () => {
  const simulator = sim();
  simulator.addPerson({id: 'U0ADA0002', name: 'ada2', realName: 'Ada Lovelace', email: 'ada2@example.com'});
  assert.throws(() => simulator.addPerson({id: IDS.ada, name: 'again', realName: 'Again'}), /taken/);
  const list = (await call(simulator, 'users.list')).data.members;
  assert.deepEqual(list.filter(item => item.real_name === 'Ada Lovelace').map(item => [item.id, item.profile.display_name, item.profile.email]),
    [[IDS.ada, 'ada', 'ada@example.com'], ['U0ADA0002', 'ada2', 'ada2@example.com']]);
  assert.equal((await call(simulator, 'users.info', {user: 'U0ADA0002'})).data.user.deleted, false);
  assert.equal((await call(simulator, 'users.lookupByEmail', {email: 'ADA2@example.com'})).data.user.id, 'U0ADA0002');
  simulator.addChannel({id: 'C1PAGE0001', name: 'page-1'});
  assert.throws(() => simulator.addChannel({id: IDS.general, name: 'general'}), /taken/);
  const mine = (await call(simulator, 'users.conversations', {types: 'public_channel', exclude_archived: true})).data.channels.map(item => item.id);
  assert.deepEqual(mine, [IDS.general, IDS.fabricTest, 'C1PAGE0001']);
  assert.equal((await post(simulator, 'chat.postMessage', {channel: 'C1PAGE0001', text: 'first'})).data.ok, true);
  assert.deepEqual(simulator.calls.map(item => item.name), ['users.list', 'users.info', 'users.lookupByEmail', 'users.conversations', 'chat.postMessage']);
});

test('the simulator imports only node built-ins: never lib/, catalog/, an action file or Slack\'s rows', () => {
  const text = readFileSync(new URL('./fixtures/provider-simulators/slack.mjs', import.meta.url), 'utf8');
  const specifiers = [...text.matchAll(/(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)(['"`])([^'"`]+)\1/g)].map(match => match[2]);
  assert.ok(specifiers.length > 0);
  assert.deepEqual(specifiers.filter(specifier => !specifier.startsWith('node:')), []);
});

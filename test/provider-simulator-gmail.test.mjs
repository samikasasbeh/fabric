import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {GmailSimulator, ORIGIN, BASE} from './fixtures/provider-simulators/gmail.mjs';

// F10.15 part 1 (docs/F10.15-BUILD-MAP.md part 1 and section 3): the Gmail simulator Gmail's actions run against in step 15. It must keep the
// network seam's contract (lib/network.mjs) and Gmail's documented behaviour, as its own header comment names it. It is written from that
// comment and from Gmail's v1 reference and guides, never from Gmail's action file, rows or scope facts, so an action bug and a simulator
// bug cannot cancel out. Nothing here calls Google.
const TOKEN = 'gmail-token-7c1d', AUTH = {Authorization: `Bearer ${TOKEN}`};
const SCOPE = name => `https://www.googleapis.com/auth/${name}`;
const BOTH = [SCOPE('gmail.modify'), SCOPE('gmail.settings.basic')];
const OWNER = 'owner@example.com';
const NOW = Date.parse('2026-10-26T13:00:00.000Z');
const sim = (options = {}) => new GmailSimulator({token: TOKEN, owner: {email: OWNER}, scopes: BOTH, clock: () => NOW, ...options});
/** One request through the seam below the API base (users/me), with the account's token unless `headers` says otherwise. */
const send = (simulator, method, path, {body, headers = AUTH, query, base = BASE, ...more} = {}) => {
  const url = new URL(`${base}${path}`);
  for (const [name, value] of Object.entries(query ?? {})) for (const item of [value].flat()) url.searchParams.append(name, String(item));
  return simulator.request({url: url.href, method, headers: {...headers, ...(body === undefined ? {} : {'Content-Type': 'application/json'})},
    ...(body === undefined ? {} : {body: typeof body === 'string' ? body : JSON.stringify(body)}), allowedOrigins: [ORIGIN], ...more});
};
/** A raw RFC 5322 message, base64url as Gmail takes it. */
const raw = (headers, body = 'Hello.') => Buffer.from(`${headers.join('\r\n')}\r\n\r\n${body}\r\n`, 'utf8').toString('base64url');
const text = encoded => Buffer.from(encoded, 'base64url').toString('utf8');
const headerOf = (message, name) => message.payload.headers.find(item => item.name.toLowerCase() === name.toLowerCase())?.value;
const reasonOf = answer => [answer.status, answer.data?.error?.errors?.[0]?.reason];
const sendMail = (simulator, headers, extra = {}) => send(simulator, 'POST', '/messages/send', {body: {raw: raw(headers), ...extra}});
const getMessage = (simulator, id, query) => send(simulator, 'GET', `/messages/${id}`, {query});

test('the seam: only the headers asked for come back, an answer over maxBytes throws sent true, requests refused before sending are never recorded, and only users/me is served', async () => {
  const simulator = sim();
  const labels = await send(simulator, 'GET', '/labels');
  assert.deepEqual(Object.keys(labels.headers), ['content-type'], 'the default list: content-type, etag, retry-after, x-ratelimit-remaining');
  assert.deepEqual((await send(simulator, 'GET', '/labels', {responseHeaders: []})).headers, {});
  await assert.rejects(send(simulator, 'GET', '/labels', {maxBytes: 64}), error => error.sent === true && /size limit/.test(error.message));
  const before = simulator.calls.length;
  for (const [label, request] of [['an origin outside the grant', {url: `${BASE}/labels`, method: 'GET', headers: AUTH, allowedOrigins: ['https://www.googleapis.com']}],
    ['plain http', {url: 'http://gmail.googleapis.com/gmail/v1/users/me/labels', method: 'GET', headers: AUTH, allowedOrigins: [ORIGIN]}],
    ['an unsafe header', {url: `${BASE}/labels`, method: 'GET', headers: {...AUTH, Host: 'x'}, allowedOrigins: [ORIGIN]}],
    ['a body that is not serialized', {url: `${BASE}/messages/send`, method: 'POST', headers: AUTH, body: {raw: 'x'}, allowedOrigins: [ORIGIN]}],
    ['a body over 1 MiB', {url: `${BASE}/messages/send`, method: 'POST', headers: AUTH, body: JSON.stringify({raw: 'x'.repeat(1024 * 1024)}), allowedOrigins: [ORIGIN]}],
    ['an origin the simulator does not serve', {url: 'https://www.googleapis.com/calendar/v3/users/me/calendarList', method: 'GET', headers: AUTH, allowedOrigins: ['https://www.googleapis.com']}]]) {
    await assert.rejects(simulator.request(request), error => error.sent === false, label);
  }
  assert.equal(simulator.calls.length, before, 'refused before sending: never recorded');
  // A path on Gmail's origin outside /gmail/v1/users is sent and answered 404; another user id than "me" answers 400 and changes nothing.
  const outside = await simulator.request({url: `${ORIGIN}/gmail/v2/users/me/labels`, method: 'GET', headers: AUTH, allowedOrigins: [ORIGIN]});
  assert.deepEqual([outside.status, simulator.calls.at(-1).route], [404, null]);
  for (const user of [OWNER, 'someone@example.com', 'ME']) {
    const other = await send(simulator, 'POST', '/messages/send', {base: `${ORIGIN}/gmail/v1/users/${encodeURIComponent(user)}`, body: {raw: raw([`To: ${OWNER}`, 'Subject: x'])}});
    assert.deepEqual([...reasonOf(other), other.data.error.status], [400, 'invalidArgument', 'INVALID_ARGUMENT'], user);
  }
  assert.deepEqual(simulator.deliveries(), []);
  assert.deepEqual(reasonOf(await send(simulator, 'GET', '/messages/abc/modify')), [404, 'notFound'], 'a route the simulator does not serve');
});

test('401 without the token and 403 for a scope the token lacks, both in Google\'s error shape, change nothing; calls are recorded without Authorization', async () => {
  const simulator = sim();
  for (const headers of [{}, {Authorization: 'Bearer wrong'}]) {
    const answer = await send(simulator, 'POST', '/messages/send', {body: {raw: raw([`To: ${OWNER}`, 'Subject: x'])}, headers});
    assert.equal(answer.status, 401);
    assert.deepEqual(Object.keys(answer.data.error).sort(), ['code', 'errors', 'message', 'status']);
    assert.deepEqual([answer.data.error.code, answer.data.error.errors[0].domain, answer.data.error.errors[0].reason, answer.data.error.status], [401, 'global', 'authError', 'UNAUTHENTICATED']);
  }
  assert.deepEqual([simulator.state().messages, simulator.deliveries()], [{}, []], 'nothing was sent');
  // gmail.modify alone: the vacation reply and filters can be read, never written (they need gmail.settings.basic).
  const modify = sim({scopes: [SCOPE('gmail.modify')]});
  const vacation = await send(modify, 'PUT', '/settings/vacation', {body: {enableAutoReply: false}});
  assert.deepEqual([vacation.status, vacation.data.error.code, vacation.data.error.errors[0].domain, vacation.data.error.errors[0].reason, vacation.data.error.status], [403, 403, 'global', 'insufficientPermissions', 'PERMISSION_DENIED']);
  const label = (await send(modify, 'POST', '/labels', {body: {name: 'Lists'}})).data.id;
  assert.deepEqual(reasonOf(await send(modify, 'POST', '/settings/filters', {body: {criteria: {from: 'a@example.com'}, action: {addLabelIds: [label]}}})), [403, 'insufficientPermissions']);
  assert.deepEqual([(await send(modify, 'GET', '/settings/vacation')).status, reasonOf(await send(modify, 'GET', '/settings/filters/f1'))], [200, [404, 'notFound']]);
  assert.deepEqual(modify.state().filters, {}, 'a refused filter is not made');
  // gmail.settings.basic alone reaches only the settings; gmail.readonly reads and never writes; gmail.send sends and never reads.
  const settings = sim({scopes: [SCOPE('gmail.settings.basic')]});
  assert.deepEqual([(await send(settings, 'PUT', '/settings/vacation', {body: {enableAutoReply: false}})).status, reasonOf(await send(settings, 'GET', '/labels'))], [200, [403, 'insufficientPermissions']]);
  const readonly = sim({scopes: [SCOPE('gmail.readonly')]});
  assert.equal((await send(readonly, 'GET', '/messages')).status, 200);
  assert.deepEqual(reasonOf(await sendMail(readonly, [`To: ${OWNER}`, 'Subject: x'])), [403, 'insufficientPermissions']);
  assert.deepEqual(reasonOf(await send(readonly, 'POST', '/drafts', {body: {message: {raw: raw([`To: ${OWNER}`, 'Subject: x'])}}})), [403, 'insufficientPermissions']);
  const sendOnly = sim({scopes: [SCOPE('gmail.send')]});
  const sent = await sendMail(sendOnly, [`To: ${OWNER}`, 'Subject: x']);
  assert.deepEqual([sent.status, reasonOf(await getMessage(sendOnly, sent.data.id))], [200, [403, 'insufficientPermissions']]);
  // gmail.metadata limits the formats and searches it allows, which the simulator does not model, so it reaches no message route.
  assert.deepEqual(reasonOf(await send(sim({scopes: [SCOPE('gmail.metadata')]}), 'GET', '/messages')), [403, 'insufficientPermissions']);
  assert.equal((await send(sim({scopes: ['https://mail.google.com/']}), 'PUT', '/settings/vacation', {body: {enableAutoReply: false}})).status, 403, 'the full mail scope does not hold settings.basic');
  assert.equal(JSON.stringify(simulator.calls).includes(TOKEN), false, 'the token is never recorded');
  assert.ok(simulator.calls.every(call => !Object.keys(call.headers).some(name => /authorization/i.test(name))));
  assert.deepEqual(simulator.calls.map(call => call.route), ['POST /messages/send', 'POST /messages/send']);
});

test('send to the owner lands with SENT, INBOX and UNREAD and a Message-ID; it reads back in the four formats; no recipient or a bad raw answers 400 and sends nothing', async () => {
  const simulator = sim();
  const sent = await sendMail(simulator, [`From: ${OWNER}`, `To: Owner <${OWNER}>`, 'Subject: Hello self', 'Date: Mon, 26 Oct 2026 13:00:00 +0000']);
  assert.equal(sent.status, 200);
  assert.match(sent.data.id, /^[0-9a-f]{16}$/, '16 hex digits, as Gmail ids read');
  assert.deepEqual([sent.data.threadId, [...sent.data.labelIds].sort()], [sent.data.id, ['INBOX', 'SENT', 'UNREAD']], 'a new thread takes the first message\'s id');
  const minimal = await getMessage(simulator, sent.data.id, {format: 'minimal'});
  assert.deepEqual(Object.keys(minimal.data).sort(), ['historyId', 'id', 'internalDate', 'labelIds', 'sizeEstimate', 'snippet', 'threadId']);
  assert.deepEqual([minimal.data.internalDate, minimal.data.snippet], [String(NOW), 'Hello.']);
  const full = await getMessage(simulator, sent.data.id);
  assert.equal(full.data.payload.mimeType, 'text/plain', 'full is the default format');
  assert.equal(headerOf(full.data, 'Subject'), 'Hello self');
  assert.match(headerOf(full.data, 'Message-ID'), /^<[^<>@\s]+@mail\.gmail\.com>$/, 'Gmail adds a Message-ID');
  assert.deepEqual([full.data.payload.body.size, text(full.data.payload.body.data)], [8, 'Hello.\r\n']);
  const metadata = await getMessage(simulator, sent.data.id, {format: 'metadata', metadataHeaders: ['subject', 'TO']});
  assert.deepEqual(metadata.data.payload.headers, [{name: 'To', value: `Owner <${OWNER}>`}, {name: 'Subject', value: 'Hello self'}], 'only the headers named, in any case, in message order');
  assert.equal(metadata.data.payload.body, undefined, 'metadata carries no body');
  assert.equal((await getMessage(simulator, sent.data.id, {format: 'metadata'})).data.payload.headers.length, 5, 'with none named, every header');
  const rawRead = await getMessage(simulator, sent.data.id, {format: 'raw'});
  assert.equal(rawRead.data.payload, undefined);
  assert.match(text(rawRead.data.raw), /^Message-ID: <[^>]+>\r\nFrom: owner@example\.com\r\nTo: Owner <owner@example\.com>\r\nSubject: Hello self\r\n/);
  assert.deepEqual(simulator.deliveries().map(item => item.to), [OWNER]);
  // Refused, and nothing stored or delivered.
  const count = Object.keys(simulator.state().messages).length;
  assert.deepEqual([...reasonOf(await sendMail(simulator, ['Subject: Nobody'])), (await sendMail(simulator, ['Subject: Nobody'])).data.error.message], [400, 'invalidArgument', 'Recipient address required']);
  assert.deepEqual(reasonOf(await sendMail(simulator, ['To: not an address', 'Subject: x'])), [400, 'invalidArgument'], 'a To with no address');
  for (const body of [{}, {raw: ''}, {raw: 'not base64!'}, {raw: 42}, {raw: raw([`To: ${OWNER}`]), labelIds: 'x', extra: true}]) {
    assert.deepEqual(reasonOf(await send(simulator, 'POST', '/messages/send', {body})), [400, 'invalidArgument'], JSON.stringify(body));
  }
  assert.deepEqual(reasonOf(await send(simulator, 'POST', '/messages/send', {body: 'not json'})), [400, 'parseError']);
  assert.deepEqual([Object.keys(simulator.state().messages).length, simulator.deliveries().length], [count, 1]);
  assert.deepEqual(reasonOf(await getMessage(simulator, '0000000000000000')), [404, 'notFound']);
  assert.deepEqual(reasonOf(await getMessage(simulator, sent.data.id, {format: 'html'})), [400, 'invalidArgument']);
});

test('Bcc: every Bcc recipient is delivered, and no delivered copy carries a Bcc header, folded or not; the sender\'s own copy keeps it', async () => {
  const simulator = sim();
  const sent = await sendMail(simulator, ['From: owner@example.com', 'To: ann@example.org', 'Cc: Bob <bob@example.org>', 'Bcc: carol@example.org,', ' dan@example.org', 'BCC: erin@example.org', 'Subject: Plans']);
  assert.equal(sent.status, 200);
  assert.deepEqual(sent.data.labelIds, ['SENT'], 'the owner is not a recipient, so no INBOX');
  const deliveries = simulator.deliveries();
  assert.deepEqual(deliveries.map(item => item.to), ['ann@example.org', 'bob@example.org', 'carol@example.org', 'dan@example.org', 'erin@example.org']);
  for (const delivery of deliveries) {
    const copy = text(delivery.raw), head = copy.slice(0, copy.indexOf('\r\n\r\n'));
    assert.equal(delivery.messageId, sent.data.id);
    assert.doesNotMatch(head, /^bcc:/im, delivery.to);
    assert.doesNotMatch(copy, /carol|dan@|erin/, `${delivery.to}: no Bcc address anywhere in the copy`);
    assert.match(head, /^To: ann@example\.org\r\nCc: Bob <bob@example\.org>\r\nSubject: Plans$/m);
    assert.ok(copy.endsWith('\r\n\r\nHello.\r\n'), 'the body is unchanged');
  }
  assert.match(text((await getMessage(simulator, sent.data.id, {format: 'raw'})).data.raw), /\r\nBcc: carol@example\.org,\r\n dan@example\.org\r\nBCC: erin@example\.org\r\n/);
  // A recipient named twice is delivered once.
  await sendMail(simulator, ['To: ann@example.org, ANN@example.org', 'Cc: ann@example.org', 'Subject: Once']);
  assert.equal(simulator.deliveries().length, 6);
});

test('threads: a reply joins its thread only with the threadId, a References or In-Reply-To naming a message of it, and the same subject after "Re:"', async () => {
  const simulator = sim();
  const first = await sendMail(simulator, ['To: ann@example.org', 'Subject: Budget']);
  const parentId = headerOf((await getMessage(simulator, first.data.id, {format: 'metadata'})).data, 'Message-ID');
  const reply = (headers, threadId = first.data.threadId) => sendMail(simulator, ['To: ann@example.org', ...headers], {threadId});
  const joined = await reply(['Subject: Re: Budget', `In-Reply-To: ${parentId}`]);
  assert.equal(joined.data.threadId, first.data.threadId, 'In-Reply-To and the subject match');
  assert.equal((await reply(['Subject: RE: Re: Budget', `References: <x@example.org> ${parentId}`])).data.threadId, first.data.threadId, 'References and the subject match');
  for (const [label, headers] of [['no In-Reply-To or References', ['Subject: Re: Budget']], ['another subject', ['Subject: Re: Budget 2', `In-Reply-To: ${parentId}`]],
    ['a message of no thread here', ['Subject: Re: Budget', 'In-Reply-To: <other@example.org>']]]) {
    const own = await reply(headers);
    assert.deepEqual([own.status, own.data.threadId], [200, own.data.id], `${label}: it starts its own thread`);
  }
  assert.deepEqual(reasonOf(await reply(['Subject: Re: Budget', `In-Reply-To: ${parentId}`], 'ffffffffffffffff')), [404, 'notFound'], 'a threadId of no thread');
  assert.deepEqual(reasonOf(await reply(['Subject: Re: Budget'], 42)), [400, 'invalidArgument']);
  // Mail that arrives threads by the same rule, with no threadId.
  const answer = simulator.deliver(raw(['From: ann@example.org', `To: ${OWNER}`, 'Subject: Re: Budget', `In-Reply-To: ${headerOf((await getMessage(simulator, joined.data.id)).data, 'Message-ID')}`]));
  assert.equal(answer.threadId, first.data.threadId);
  const thread = await send(simulator, 'GET', `/threads/${first.data.threadId}`);
  assert.equal(thread.status, 200);
  assert.deepEqual(thread.data.messages.map(item => item.id), [first.data.id, joined.data.id, thread.data.messages[2].id, answer.id], 'oldest first');
  assert.deepEqual([thread.data.id, headerOf(thread.data.messages[3], 'From')], [first.data.threadId, 'ann@example.org']);
  assert.deepEqual(Object.keys((await send(simulator, 'GET', `/threads/${first.data.threadId}`, {query: {format: 'minimal'}})).data.messages[0]).sort(),
    ['historyId', 'id', 'internalDate', 'labelIds', 'sizeEstimate', 'snippet', 'threadId']);
  assert.deepEqual(reasonOf(await send(simulator, 'GET', `/threads/${first.data.threadId}`, {query: {format: 'raw'}})), [400, 'invalidArgument'], 'a thread has no raw format');
  assert.deepEqual(reasonOf(await send(simulator, 'GET', '/threads/ffffffffffffffff')), [404, 'notFound']);
});

test('drafts: create, update (a new message id), and send with message.raw: the raw given goes out, not the draft as edited in Gmail, and the draft is gone', async () => {
  const simulator = sim();
  const v0 = raw(['To: ann@example.org', 'Subject: Draft v0'], 'v0'), v1 = raw(['To: ann@example.org', 'Subject: Draft v1'], 'v1'), v2 = raw(['To: ann@example.org', 'Subject: Draft v2'], 'v2');
  const made = await send(simulator, 'POST', '/drafts', {body: {message: {raw: v0}}});
  assert.equal(made.status, 200);
  assert.match(made.data.id, /^r[0-9]+$/);
  assert.deepEqual([made.data.message.labelIds, made.data.message.threadId], [['DRAFT'], made.data.message.id]);
  assert.equal(text((await send(simulator, 'GET', `/drafts/${made.data.id}`, {query: {format: 'raw'}})).data.message.raw), text(v0));
  const updated = await send(simulator, 'PUT', `/drafts/${made.data.id}`, {body: {id: made.data.id, message: {raw: v1}}});
  assert.deepEqual([updated.status, updated.data.id], [200, made.data.id]);
  assert.notEqual(updated.data.message.id, made.data.message.id, 'an update replaces the message: a new message id');
  assert.deepEqual(reasonOf(await getMessage(simulator, made.data.message.id)), [404, 'notFound'], 'the old message is gone');
  assert.deepEqual(reasonOf(await send(simulator, 'PUT', `/drafts/${made.data.id}`, {body: {id: 'r1', message: {raw: v2}}})), [400, 'invalidArgument'], 'a body id that is not the path\'s');
  assert.deepEqual(reasonOf(await send(simulator, 'PUT', '/drafts/r999', {body: {message: {raw: v2}}})), [404, 'notFound']);
  // The owner edits the draft in Gmail to v2; a send that carries v1 sends v1.
  simulator.editDraft(made.data.id, v2);
  assert.equal(headerOf((await send(simulator, 'GET', `/drafts/${made.data.id}`)).data.message, 'Subject'), 'Draft v2');
  const sent = await send(simulator, 'POST', '/drafts/send', {body: {id: made.data.id, message: {raw: v1}}});
  assert.deepEqual([sent.status, sent.data.labelIds], [200, ['SENT']]);
  const out = await getMessage(simulator, sent.data.id, {format: 'raw'});
  assert.match(text(out.data.raw), /Subject: Draft v1\r\n\r\nv1\r\n$/);
  assert.deepEqual(simulator.deliveries().map(item => [item.to, /Subject: Draft v1/.test(text(item.raw))]), [['ann@example.org', true]]);
  assert.deepEqual(reasonOf(await send(simulator, 'GET', `/drafts/${made.data.id}`)), [404, 'notFound'], 'a sent draft is gone');
  assert.deepEqual(reasonOf(await send(simulator, 'POST', '/drafts/send', {body: {id: made.data.id, message: {raw: v1}}})), [404, 'notFound']);
  // Without message.raw the draft is sent as it is stored; a draft the owner wrote in Gmail is one like any other.
  const seeded = simulator.seedDraft(raw(['To: bob@example.org', 'Subject: Hand written'], 'by hand'));
  const plain = await send(simulator, 'POST', '/drafts/send', {body: {id: seeded.id}});
  assert.match(text((await getMessage(simulator, plain.data.id, {format: 'raw'})).data.raw), /Subject: Hand written\r\n\r\nby hand\r\n$/);
  assert.deepEqual(reasonOf(await send(simulator, 'POST', '/drafts/send', {body: {}})), [400, 'invalidArgument']);
});

test('a draft created or updated without raw holds an empty message, and an empty draft cannot be sent', async () => {
  const simulator = sim();
  const empty = await send(simulator, 'POST', '/drafts', {body: {message: {}}});
  assert.equal(empty.status, 200);
  const read = await send(simulator, 'GET', `/drafts/${empty.data.id}`);
  assert.deepEqual([read.data.message.payload.headers, read.data.message.sizeEstimate, read.data.message.snippet], [[], 0, '']);
  const made = await send(simulator, 'POST', '/drafts', {body: {message: {raw: raw(['To: ann@example.org', 'Subject: Keep me'], 'Long text')}}});
  const blanked = await send(simulator, 'PUT', `/drafts/${made.data.id}`, {body: {id: made.data.id, message: {threadId: made.data.message.threadId}}});
  assert.equal(blanked.status, 200);
  assert.deepEqual((await send(simulator, 'GET', `/drafts/${made.data.id}`, {query: {format: 'raw'}})).data.message.raw, '', 'an update without raw blanks the draft');
  assert.deepEqual([...reasonOf(await send(simulator, 'POST', '/drafts/send', {body: {id: made.data.id}}))], [400, 'invalidArgument']);
  assert.equal((await send(simulator, 'GET', `/drafts/${made.data.id}`)).status, 200, 'a refused send keeps the draft');
  assert.deepEqual(simulator.deliveries(), []);
});

test('labels: the system labels and the user\'s; a new name equal to another in any ASCII case, a system one included, answers 409 and makes nothing', async () => {
  const simulator = sim();
  const list = await send(simulator, 'GET', '/labels');
  assert.deepEqual(list.data.labels.map(label => [label.id, label.type]), ['INBOX', 'SENT', 'DRAFT', 'TRASH', 'SPAM', 'UNREAD', 'STARRED', 'IMPORTANT'].map(id => [id, 'system']));
  const made = await send(simulator, 'POST', '/labels', {body: {name: 'Receipts', labelListVisibility: 'labelShow', messageListVisibility: 'show'}});
  assert.deepEqual([made.status, made.data], [200, {id: 'Label_1', name: 'Receipts', type: 'user', labelListVisibility: 'labelShow', messageListVisibility: 'show'}]);
  for (const name of ['receipts', 'RECEIPTS', 'Inbox', 'trash']) {
    const again = await send(simulator, 'POST', '/labels', {body: {name}});
    assert.deepEqual([...reasonOf(again), again.data.error.status], [409, 'alreadyExists', 'ALREADY_EXISTS'], name);
  }
  assert.equal((await send(simulator, 'POST', '/labels', {body: {name: 'Récéipts'}})).status, 200, 'only ASCII letters fold');
  for (const body of [{}, {name: ''}, {name: 'A', labelListVisibility: 'sometimes'}, {name: 'B', messageListVisibility: 'maybe'}, {name: 'C', other: 1}]) {
    assert.deepEqual(reasonOf(await send(simulator, 'POST', '/labels', {body})), [400, 'invalidArgument'], JSON.stringify(body));
  }
  assert.deepEqual((await send(simulator, 'GET', '/labels')).data.labels.slice(8).map(label => label.name), ['Receipts', 'Récéipts']);
  assert.deepEqual([(await send(simulator, 'GET', '/labels/Label_1')).data.name, reasonOf(await send(simulator, 'GET', '/labels/Label_9'))], ['Receipts', [404, 'notFound']]);
  assert.equal((await send(simulator, 'GET', '/labels/STARRED')).data.type, 'system');
});

test('batchModify and threads.modify: an unknown label or message, SENT or DRAFT, or a label both added and removed answer 400 or 404 and change nothing', async () => {
  const simulator = sim();
  const one = simulator.deliver(raw(['From: ann@example.org', `To: ${OWNER}`, 'Subject: One'])), two = simulator.deliver(raw(['From: ann@example.org', `To: ${OWNER}`, 'Subject: Two']));
  const label = (await send(simulator, 'POST', '/labels', {body: {name: 'Kept'}})).data.id;
  const modify = body => send(simulator, 'POST', '/messages/batchModify', {body});
  const before = simulator.state().messages;
  for (const [note, body, expected] of [
    ['an unknown label id', {ids: [one.id], addLabelIds: ['Label_99']}, [400, 'invalidArgument']],
    ['a label name, not an id', {ids: [one.id], addLabelIds: ['Kept']}, [400, 'invalidArgument']],
    ['SENT added', {ids: [one.id], addLabelIds: ['SENT']}, [400, 'invalidArgument']],
    ['DRAFT added', {ids: [one.id], addLabelIds: ['DRAFT']}, [400, 'invalidArgument']],
    ['SENT removed', {ids: [one.id], removeLabelIds: ['SENT']}, [400, 'invalidArgument']],
    ['both added and removed', {ids: [one.id], addLabelIds: [label], removeLabelIds: [label]}, [400, 'invalidArgument']],
    ['no ids', {ids: [], addLabelIds: [label]}, [400, 'invalidArgument']],
    ['over 1,000 ids', {ids: Array.from({length: 1001}, () => one.id), addLabelIds: [label]}, [400, 'invalidArgument']],
    ['an unknown message among known ones', {ids: [one.id, 'ffffffffffffffff'], addLabelIds: [label]}, [404, 'notFound']]]) {
    assert.deepEqual(reasonOf(await modify(body)), expected, note);
  }
  assert.deepEqual(simulator.state().messages, before, 'nothing changed');
  const done = await modify({ids: [one.id, two.id], addLabelIds: [label, 'STARRED'], removeLabelIds: ['UNREAD', 'INBOX']});
  assert.deepEqual([done.status, done.data], [204, null]);
  for (const id of [one.id, two.id]) assert.deepEqual((await getMessage(simulator, id, {format: 'minimal'})).data.labelIds, [label, 'STARRED']);
  const thread = await send(simulator, 'POST', `/threads/${one.threadId}/modify`, {body: {addLabelIds: ['IMPORTANT'], removeLabelIds: [label]}});
  assert.deepEqual([thread.status, thread.data.id, thread.data.messages.map(item => item.labelIds)], [200, one.threadId, [['STARRED', 'IMPORTANT']]]);
  assert.deepEqual(reasonOf(await send(simulator, 'POST', `/threads/${one.threadId}/modify`, {body: {addLabelIds: ['DRAFT']}})), [400, 'invalidArgument']);
  assert.deepEqual(reasonOf(await send(simulator, 'POST', '/threads/ffffffffffffffff/modify', {body: {addLabelIds: ['STARRED']}})), [404, 'notFound']);
});

test('trash and untrash, for a message and for a thread: TRASH is added or taken off every message, and mail in the trash leaves a search', async () => {
  const simulator = sim();
  const sent = await sendMail(simulator, ['To: ann@example.org', 'Subject: Trip']);
  const reply = simulator.deliver(raw(['From: ann@example.org', `To: ${OWNER}`, 'Subject: Re: Trip', `References: ${headerOf((await getMessage(simulator, sent.data.id)).data, 'Message-ID')}`]));
  assert.equal(reply.threadId, sent.data.threadId);
  const trashed = await send(simulator, 'POST', `/messages/${reply.id}/trash`);
  assert.deepEqual([trashed.status, trashed.data.id, trashed.data.labelIds], [200, reply.id, ['INBOX', 'UNREAD', 'TRASH']]);
  assert.deepEqual((await send(simulator, 'GET', '/messages', {query: {q: '"Trip"'}})).data.messages.map(item => item.id), [sent.data.id], 'mail in the trash leaves a search');
  assert.equal((await send(simulator, 'GET', '/messages', {query: {q: '"Trip"', includeSpamTrash: 'true'}})).data.messages.length, 2);
  const restored = await send(simulator, 'POST', `/messages/${reply.id}/untrash`);
  assert.deepEqual(restored.data.labelIds, ['INBOX', 'UNREAD']);
  const all = await send(simulator, 'POST', `/threads/${sent.data.threadId}/trash`);
  assert.deepEqual([all.status, all.data.messages.map(item => item.labelIds.includes('TRASH'))], [200, [true, true]]);
  const back = await send(simulator, 'POST', `/threads/${sent.data.threadId}/untrash`);
  assert.deepEqual(back.data.messages.map(item => item.labelIds.includes('TRASH')), [false, false]);
  assert.deepEqual([reasonOf(await send(simulator, 'POST', '/messages/ffffffffffffffff/trash')), reasonOf(await send(simulator, 'POST', '/threads/ffffffffffffffff/untrash'))], [[404, 'notFound'], [404, 'notFound']]);
});

test('the vacation reply: read and replaced whole; an end not after the start, a time that is not an epoch-millisecond string, or an unknown field answers 400 and changes nothing', async () => {
  const simulator = sim();
  assert.deepEqual((await send(simulator, 'GET', '/settings/vacation')).data, {enableAutoReply: false});
  const on = {enableAutoReply: true, responseSubject: 'Away', responseBodyPlainText: 'Back Monday.', restrictToContacts: true, startTime: '1793534400000', endTime: '1793620800000'};
  const put = await send(simulator, 'PUT', '/settings/vacation', {body: on});
  assert.deepEqual([put.status, put.data], [200, on]);
  assert.deepEqual((await send(simulator, 'GET', '/settings/vacation')).data, on);
  for (const [note, body] of [['an end before the start', {...on, startTime: '1793620800000', endTime: '1793534400000'}], ['an end equal to the start', {...on, endTime: on.startTime}],
    ['seconds as a number', {...on, startTime: 1793534400, endTime: 1793620800}], ['a time that is not digits', {...on, startTime: '2026-11-02T09:00:00Z'}],
    ['an unknown field', {...on, forwardTo: 'x@example.org'}], ['a flag that is not a boolean', {...on, restrictToContacts: 'yes'}]]) {
    assert.deepEqual(reasonOf(await send(simulator, 'PUT', '/settings/vacation', {body})), [400, 'invalidArgument'], note);
  }
  assert.deepEqual(reasonOf(await send(simulator, 'PUT', '/settings/vacation', {body: {...on, restrictToDomain: true}})), [400, 'failedPrecondition'], 'restrictToDomain is for Google Workspace only');
  assert.deepEqual((await send(simulator, 'GET', '/settings/vacation')).data, on, 'nothing changed');
  assert.deepEqual((await send(simulator, 'PUT', '/settings/vacation', {body: {enableAutoReply: false}})).data, {enableAutoReply: false}, 'an update replaces every field');
  assert.deepEqual((await send(simulator, 'GET', '/settings/vacation')).data, {enableAutoReply: false});
});

test('filters: made and read back; one that forwards answers 403, an identical one 400, an unknown label 400', async () => {
  const simulator = sim();
  const label = (await send(simulator, 'POST', '/labels', {body: {name: 'Synthetic'}})).data.id;
  const filter = {criteria: {from: 'synthetic-sender@example.invalid'}, action: {addLabelIds: [label]}};
  const made = await send(simulator, 'POST', '/settings/filters', {body: filter});
  assert.equal(made.status, 200);
  assert.deepEqual([typeof made.data.id, made.data.criteria, made.data.action], ['string', filter.criteria, filter.action]);
  assert.deepEqual((await send(simulator, 'GET', `/settings/filters/${made.data.id}`)).data, made.data);
  const again = await send(simulator, 'POST', '/settings/filters', {body: filter});
  assert.deepEqual([...reasonOf(again), again.data.error.message], [400, 'failedPrecondition', 'Filter already exists']);
  const forward = await send(simulator, 'POST', '/settings/filters', {body: {criteria: {from: 'boss@example.org'}, action: {forward: 'me@elsewhere.example'}}});
  assert.deepEqual([...reasonOf(forward), forward.data.error.status], [403, 'insufficientPermissions', 'PERMISSION_DENIED'], 'forwarding needs gmail.settings.sharing');
  const sharing = sim({scopes: [...BOTH, SCOPE('gmail.settings.sharing')]});
  assert.deepEqual(reasonOf(await send(sharing, 'POST', '/settings/filters', {body: {criteria: {from: 'boss@example.org'}, action: {forward: 'me@elsewhere.example'}}})), [400, 'failedPrecondition'], 'and a verified forwarding address, which the simulator has none of');
  for (const [note, body] of [['an unknown label', {criteria: {from: 'a@example.org'}, action: {addLabelIds: ['Label_77']}}], ['no criteria', {criteria: {}, action: {addLabelIds: [label]}}],
    ['no action', {criteria: {from: 'a@example.org'}, action: {}}], ['an unknown criterion', {criteria: {sender: 'a@example.org'}, action: {addLabelIds: [label]}}]]) {
    assert.deepEqual(reasonOf(await send(simulator, 'POST', '/settings/filters', {body})), [400, 'invalidArgument'], note);
  }
  assert.equal(Object.keys(simulator.state().filters).length, 1, 'only the first was made');
  assert.deepEqual(reasonOf(await send(simulator, 'GET', '/settings/filters/ANe1BmNone')), [404, 'notFound']);
});

test('limit(): each limit Google documents for Gmail answers the next call once in its shape, sending nothing; then the route answers normally', async () => {
  const shapes = {tooManyRequests: [429, 'rateLimitExceeded', 'Rate Limit Exceeded', 'RESOURCE_EXHAUSTED'], dailyLimitExceeded: [403, 'dailyLimitExceeded', 'Daily Limit Exceeded', 'PERMISSION_DENIED'],
    userRateLimitExceeded: [403, 'userRateLimitExceeded', 'User Rate Limit Exceeded', 'PERMISSION_DENIED'], rateLimitExceeded: [403, 'rateLimitExceeded', 'Rate Limit Exceeded', 'PERMISSION_DENIED']};
  for (const [kind, [status, reason, message, canonical]] of Object.entries(shapes)) {
    const simulator = sim();
    simulator.limit('POST /messages/send', kind);
    const limited = await sendMail(simulator, ['To: ann@example.org', 'Subject: x']);
    assert.deepEqual([limited.status, limited.data], [status, {error: {code: status, message, errors: [{domain: 'usageLimits', reason, message}], status: canonical}}], kind);
    assert.deepEqual([simulator.state().messages, simulator.deliveries()], [{}, []], `${kind}: nothing was sent`);
    assert.equal(simulator.calls.at(-1).status, status);
    assert.equal((await sendMail(simulator, ['To: ann@example.org', 'Subject: x'])).status, 200, `${kind}: once`);
  }
  assert.throws(() => sim().limit('POST /messages/send', 'quotaExceeded'), /limit/);
});

test('switches: fail, drop, swallow, oversize and hold, each for the next call to one route; reads() and writes() split the calls', async () => {
  const route = 'POST /messages/batchModify';
  const simulator = sim(), message = simulator.deliver(raw(['From: ann@example.org', `To: ${OWNER}`, 'Subject: Switch']));
  const labels = async () => (await getMessage(simulator, message.id, {format: 'minimal'})).data.labelIds;
  simulator.fail(route, {status: 500, data: {error: {code: 500, message: 'Backend Error', errors: [{domain: 'global', reason: 'backendError', message: 'Backend Error'}]}}});
  assert.deepEqual(reasonOf(await send(simulator, 'POST', '/messages/batchModify', {body: {ids: [message.id], addLabelIds: ['STARRED']}})), [500, 'backendError']);
  assert.deepEqual(await labels(), ['INBOX', 'UNREAD'], 'fail changes nothing');
  simulator.drop(route);
  await assert.rejects(send(simulator, 'POST', '/messages/batchModify', {body: {ids: [message.id], addLabelIds: ['STARRED']}}), error => error.sent === true);
  assert.deepEqual(await labels(), ['INBOX', 'UNREAD', 'STARRED'], 'drop applies the change, then loses the answer');
  simulator.swallow(route);
  assert.equal((await send(simulator, 'POST', '/messages/batchModify', {body: {ids: [message.id], removeLabelIds: ['UNREAD']}})).status, 204);
  assert.deepEqual(await labels(), ['INBOX', 'UNREAD', 'STARRED'], 'swallow answers as if applied: a readback sees the old state');
  simulator.swallow('POST /messages/send');
  const ghost = await sendMail(simulator, ['To: ann@example.org', 'Subject: Ghost']);
  assert.deepEqual([ghost.status, reasonOf(await getMessage(simulator, ghost.data.id)), simulator.deliveries()], [200, [404, 'notFound'], []], 'a swallowed send leaves no message');
  simulator.oversize('GET /messages/{id}', 4096);
  await assert.rejects(send(simulator, 'GET', `/messages/${message.id}`, {maxBytes: 2048}), error => error.sent === true);
  assert.equal((await send(simulator, 'GET', `/messages/${message.id}`, {maxBytes: 2048})).status, 200, 'once');
  const gate = simulator.hold(route), running = send(simulator, 'POST', '/messages/batchModify', {body: {ids: [message.id], removeLabelIds: ['STARRED']}});
  await gate.reached;
  assert.deepEqual(await labels(), ['INBOX', 'UNREAD', 'STARRED'], 'held: not applied yet');
  gate.release();
  assert.equal((await running).status, 204);
  assert.deepEqual(await labels(), ['INBOX', 'UNREAD']);
  assert.deepEqual(simulator.writes().map(call => call.route), [route, route, route, 'POST /messages/send', route]);
  assert.ok(simulator.reads().every(call => !call.write && call.route.startsWith('GET ')));
  assert.deepEqual(simulator.writes()[0].body, {ids: [message.id], addLabelIds: ['STARRED']});
});

test('search: a quoted phrase matches only that phrase; from, to, subject, label, has:attachment, after and before read as Gmail does; pages of maxResults', async () => {
  let now = Date.parse('2026-10-20T09:00:00.000Z');
  const simulator = sim({clock: () => now});
  const at = (day, headers, body, labels) => { now = Date.parse(`2026-10-${day}T09:00:00.000Z`); return simulator.deliver(raw(headers, body), labels).id; };
  const a = at(20, ['From: Ann <ann@example.org>', `To: ${OWNER}`, 'Subject: [SYNTHETIC] Fabric read pass 1'], 'First.');
  const b = at(21, ['From: bob@example.org', `To: ${OWNER}`, 'Subject: Fabric [SYNTHETIC] read pass'], 'Words apart.');
  const c = at(22, ['From: bob@example.org', `To: team@example.org`, 'Subject: Lunch'], 'Notes on [SYNTHETIC] fabric READ pass in the body.');
  const d = at(23, ['From: carol@example.org', `To: ${OWNER}`, 'Subject: Invoice', 'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="b1"'],
    ['--b1', 'Content-Type: text/plain; charset=UTF-8', '', 'See attached.', '--b1', 'Content-Type: application/pdf; name="invoice.pdf"', 'Content-Disposition: attachment; filename="invoice.pdf"',
      'Content-Transfer-Encoding: base64', '', Buffer.from('%PDF-1.4 fake').toString('base64'), '--b1--'].join('\r\n'));
  const e = at(24, ['From: ann@example.org', `To: ${OWNER}`, 'Subject: =?UTF-8?B?w4ljaG8=?='], 'Encoded subject.', ['SPAM']);
  const label = (await send(simulator, 'POST', '/labels', {body: {name: 'Work Stuff'}})).data.id;
  await send(simulator, 'POST', '/messages/batchModify', {body: {ids: [b], addLabelIds: [label]}});
  const ids = async (q, extra = {}) => (await send(simulator, 'GET', '/messages', {query: {q, ...extra}})).data.messages?.map(item => item.id) ?? [];
  assert.deepEqual(await ids('"[SYNTHETIC] Fabric read pass"'), [c, a], 'the phrase, in any case, in the subject or the text; words apart do not match; newest first');
  assert.deepEqual(await ids('subject:"[SYNTHETIC] Fabric read pass"'), [a]);
  assert.deepEqual(await ids('from:"ann@example.org"'), [a], 'mail in the spam is left out');
  assert.deepEqual(await ids('from:"Ann"'), [a], 'a sender\'s name matches too');
  assert.deepEqual(await ids('to:"team@example.org"'), [c]);
  assert.deepEqual(await ids('label:"work stuff"'), [b]);
  assert.deepEqual(await ids(`label:"${label}"`), [b]);
  assert.deepEqual(await ids('has:attachment'), [d]);
  assert.deepEqual(await ids('-has:attachment from:"bob@example.org"'), [c, b]);
  assert.deepEqual(await ids(`after:${Date.parse('2026-10-21T09:00:00Z') / 1000} before:${Date.parse('2026-10-23T09:00:00Z') / 1000}`), [c, b], 'after is inclusive, before is not');
  assert.deepEqual(await ids('"Écho"', {includeSpamTrash: 'true'}), [e], 'an encoded subject is decoded for search');
  for (const q of ['in:anywhere', 'is:unread', '"open', 'a OR b', 'after:2026/10/21', 'has:drive', '{x y}']) {
    assert.deepEqual(reasonOf(await send(simulator, 'GET', '/messages', {query: {q}})), [400, 'notSimulated'], q);
  }
  const empty = await send(simulator, 'GET', '/messages', {query: {q: '"nothing like this"'}});
  assert.deepEqual([empty.status, empty.data], [200, {resultSizeEstimate: 0}], 'an empty search has no messages key');
  // Pages: maxResults 1 to 500, an opaque pageToken.
  const pages = [];
  let token;
  do {
    const page = await send(simulator, 'GET', '/messages', {query: {maxResults: 2, ...(token ? {pageToken: token} : {})}});
    pages.push(page.data.messages.map(item => item.id));
    assert.equal(page.data.resultSizeEstimate, 4);
    token = page.data.nextPageToken;
  } while (token);
  assert.deepEqual(pages, [[d, c], [b, a]]);
  assert.deepEqual((await send(simulator, 'GET', '/messages')).data.messages[0], {id: d, threadId: d}, 'each entry is {id, threadId}');
  for (const query of [{maxResults: 0}, {maxResults: 501}, {maxResults: 'x'}, {pageToken: 'not-a-token'}]) {
    assert.deepEqual(reasonOf(await send(simulator, 'GET', '/messages', {query})), [400, 'invalidArgument'], JSON.stringify(query));
  }
});

test('the full format: a multipart message is a tree of parts; body.data holds each part\'s decoded bytes; an attachment has an attachmentId and no data', async () => {
  const simulator = sim();
  const id = simulator.deliver(raw(['From: carol@example.org', `To: ${OWNER}`, 'Subject: Invoice', 'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="b1"'],
    ['--b1', 'Content-Type: multipart/alternative; boundary="b2"', '', '--b2', 'Content-Type: text/plain; charset=UTF-8', 'Content-Transfer-Encoding: quoted-printable', '', 'Caf=C3=A9 at 9.', '--b2',
      'Content-Type: text/html; charset=UTF-8', '', '<p>Café at 9.</p>', '--b2--', '--b1', 'Content-Type: application/pdf; name="invoice.pdf"', 'Content-Disposition: attachment; filename="invoice.pdf"',
      'Content-Transfer-Encoding: base64', '', Buffer.from('%PDF-1.4 fake').toString('base64'), '--b1--'].join('\r\n'))).id;
  const {payload, snippet} = (await getMessage(simulator, id)).data;
  assert.deepEqual([payload.partId, payload.mimeType, payload.body, payload.parts.map(part => [part.partId, part.mimeType])], ['', 'multipart/mixed', {size: 0}, [['0', 'multipart/alternative'], ['1', 'application/pdf']]]);
  const [plain, html] = payload.parts[0].parts;
  assert.deepEqual([plain.partId, plain.filename, Buffer.from(plain.body.data, 'base64url').toString('utf8'), plain.body.size], ['0.0', '', 'Café at 9.', 11]);
  assert.deepEqual([html.partId, Buffer.from(html.body.data, 'base64url').toString('utf8')], ['0.1', '<p>Café at 9.</p>']);
  const attachment = payload.parts[1];
  assert.deepEqual([attachment.filename, attachment.body.size, typeof attachment.body.attachmentId, attachment.body.data], ['invoice.pdf', 13, 'string', undefined]);
  assert.equal(snippet, 'Café at 9.');
});

test('test data: deliver, seedDraft, editDraft and remove change the mailbox as the owner or a sender would; the profile counts it', async () => {
  const simulator = sim();
  const message = simulator.deliver(raw(['From: ann@example.org', `To: ${OWNER}`, 'Subject: Hi']));
  assert.deepEqual((await getMessage(simulator, message.id, {format: 'minimal'})).data.labelIds, ['INBOX', 'UNREAD'], 'arrived mail is in the inbox, unread');
  const draft = simulator.seedDraft(raw(['To: bob@example.org', 'Subject: Mine']));
  const edited = simulator.editDraft(draft.id, raw(['To: bob@example.org', 'Subject: Mine, edited']));
  assert.deepEqual([edited.id, edited.message.id === draft.message.id], [draft.id, false]);
  const profile = await send(simulator, 'GET', '/profile');
  assert.deepEqual([profile.data.emailAddress, profile.data.messagesTotal, profile.data.threadsTotal, typeof profile.data.historyId], [OWNER, 2, 2, 'string']);
  const label = (await send(simulator, 'POST', '/labels', {body: {name: 'Gone soon'}})).data.id;
  const filter = (await send(simulator, 'POST', '/settings/filters', {body: {criteria: {from: 'a@example.org'}, action: {addLabelIds: [label]}}})).data.id;
  simulator.remove('message', message.id);
  simulator.remove('draft', draft.id);
  simulator.remove('filter', filter);
  simulator.remove('label', label);
  assert.deepEqual([reasonOf(await getMessage(simulator, message.id)), reasonOf(await send(simulator, 'GET', `/drafts/${draft.id}`)), reasonOf(await send(simulator, 'GET', `/settings/filters/${filter}`)),
    reasonOf(await send(simulator, 'GET', `/labels/${label}`))], Array(4).fill([404, 'notFound']));
  assert.throws(() => simulator.remove('message', message.id), /No message/);
  assert.throws(() => simulator.editDraft('r1', raw(['To: a@example.org'])), /No draft/);
  assert.deepEqual(simulator.writes().length, 2, 'test data records no call');
});

test('the simulator imports only node built-ins: never lib/, catalog/, an action file or the scope facts', () => {
  const source = readFileSync(new URL('./fixtures/provider-simulators/gmail.mjs', import.meta.url), 'utf8');
  const specifiers = [...source.matchAll(/(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)(['"`])([^'"`]+)\1/g)].map(match => match[2]);
  assert.ok(specifiers.length > 0);
  assert.deepEqual(specifiers.filter(specifier => !specifier.startsWith('node:')), []);
});

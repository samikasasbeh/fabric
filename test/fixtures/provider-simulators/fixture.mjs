// F10.11 part b (docs/F10.11-BUILD-MAP.md part b): a provider simulator for the fake app the action runtime's tests drive. It is written
// from this comment alone and imports only node built-ins, never the fixture's action, permission, proxy or map files nor any lib/ module,
// so a runtime bug and a simulator bug cannot cancel out. Test data only: nothing in lib/ imports it.
//
// Two services:
//   https://api.fixture.test        a REST app (JSON in and out)
//   https://rpc.fixture.test/api    its RPC twin, Slack style: every answer is HTTP 200 with {ok, error}
//
// REST routes (a route is named "METHOD /template", as the switches below take it):
//   GET    /accounts/{account}/profile    the account: {id, email, name}
//   GET    /items                         newest first, 2 a page. ?pageToken pages by {nextPageToken, hasMore}; ?page=N pages by a Link
//                                         header (rel="next", same origin and path). Filters: ?kind, ?labelIds (repeated, any of),
//                                         ?updatedAfter (RFC 3339, strictly later). Answer {items, nextPageToken?, hasMore}
//   GET    /items/{item_id}               the item, or 404. PATCH sets name, labels and in_trash; DELETE removes it (204)
//   POST   /items                         creates an item from {parent: {id}, properties}: {id, parent, properties}
//   DELETE /items/{item_id}/labels/{name} takes the label of that name off the item (204), or 404 when it is not on it
//   GET    /items/{item_id}/history       answers, though no row lets an action step reach it
//   POST   /items/search                  {query?, kind?, start_cursor?}: names that contain the query (any case), newest first, 2 a page,
//                                         as {results: [{id, title}], next_cursor, has_more}. Changes nothing
//   POST   /items/export                  {kind?, label?}: really writes an export record; {exportId, count}
//   GET    /labels                        {labels}, ?type filters; GET /labels/{label_id}; POST /labels {name}; PATCH /labels/{label_id}
//   GET    /drafts/{draft_id}             {id, raw}; POST /drafts/{draft_id}/send {raw, sender} sends it once: the raw must equal the
//                                         draft's (else 400), a sent item appears and the draft is gone (404 after)
//   GET    /events/{event_id}             the event with an etag header; PATCH needs If-Match equal to it (else 412) and moves the etag
//   GET    /files/{+path}                 {path, content (base64), sha}, or 404. PUT {message, content, sha?}: a sha that is not the
//                                         current one, or none for an existing file, answers 409 and changes nothing; 201 creates, 200 updates
//   POST   /messages                      {to, text}: a message to people, {id, to, text}
//   GET    /keys, GET /keys/{key_id}      the key list carries ids and names only; one key's answer carries the CANARY secret
//   PUT    /items/{item_id}/share, POST /hooks, DELETE /hooks/{hook_id}
//                                         locked: they answer 200 only so a test can assert they were never called
// RPC routes: GET /messages.list, POST /messages.history and POST /canvases.read read; POST /messages.post, POST /conversations.start
// (opens a direct channel for {users}, the resolving write), POST /messages.unschedule and POST /admin.invite (locked) write. A missing
// channel, canvas or scheduled message answers {ok: false, error}.
//
// The network contract is lib/network.mjs's seam: `request` takes its options and answers {status, headers, data}. Refused before
// sending, with sent false: a URL that is not https on 443 or carries credentials, an origin outside allowedOrigins, an origin this
// simulator does not serve, an unsupported method or response handling, an unsafe header, a body that is not a string or Buffer, a
// body over 1 MiB. After sending, with sent true: an answer over maxBytes, a redirect unless redirect is 'report' (then {status,
// headers, data: null, redirected} or, for 304, notModified), and drop(). Only the response headers asked for come back (the
// seam's default list when none are named). Without "Authorization: Bearer <token>" a REST route answers 401 {error: 'unauthorized'}
// and an RPC route 200 {ok: false, error: 'not_authed'}, changing nothing.
//
// Every request that reaches the simulator is recorded in `calls`, without its Authorization header: {method, origin, path, route,
// query, headers, body, write, locked, status}. writes() and reads() are the calls to write and read routes; state() is a copy of the
// state. Switches, each for the next call to one route unless {times} says how many: fail(route, {status, headers?, data?}) answers
// that instead and changes nothing; drop(route) applies the call, then throws as a lost answer (sent true); swallow(route) answers as
// if applied but changes nothing (a readback then sees the old value); oversize(route, bytes) pads the answer to at least `bytes`;
// hold(route) returns {reached, release()}: calls to the route wait, recorded, until release().
import {createHash} from 'node:crypto';

export const REST_ORIGIN = 'https://api.fixture.test';
export const RPC_BASE = 'https://rpc.fixture.test/api';
/** The secret only GET /keys/{key_id} answers with: a test that finds it anywhere else found a leak. */
export const CANARY = 'canary-secret-9f2b7e01d4c3';
const RPC_ORIGIN = new URL(RPC_BASE).origin;
const DEFAULT_RESPONSE_HEADERS = ['content-type', 'etag', 'retry-after', 'x-ratelimit-remaining'];
const UNSAFE_HEADER = /^(host|connection|transfer-encoding|content-length|upgrade|proxy-.*|forwarded|x-forwarded-.*)$/i;
const PAGE = 2;

const notSent = message => Object.assign(new Error(message), {sent: false});
const lost = message => Object.assign(new Error(message), {sent: true});
const sha = text => createHash('sha256').update(text).digest('hex').slice(0, 40);
const b64 = text => Buffer.from(text, 'utf8').toString('base64');
const ok = (data, headers = {}) => ({status: 200, headers, data});
const missing = () => ({status: 404, data: {error: 'not_found'}});
const rpcFail = error => ({status: 200, data: {ok: false, error}});

function initialState(clock) {
  const at = day => new Date(Date.UTC(2026, 9, day, 9)).toISOString();
  return {
    account: {id: 'acct-1', email: 'owner@fixture.test', name: 'Fixture Owner'},
    items: [
      {id: 'I1', name: 'Plan A', kind: 'note', labels: ['L2'], in_trash: false, updated: at(1)},
      {id: 'I2', name: 'Budget plan', kind: 'task', labels: [], in_trash: false, updated: at(5)},
      {id: 'I3', name: 'Trip', kind: 'note', labels: ['L2'], in_trash: false, updated: at(10)},
      {id: 'I4', name: 'Plan B', kind: 'task', labels: ['L3'], in_trash: false, updated: at(21)},
      {id: 'I5', name: 'Notes', kind: 'task', labels: [], in_trash: false, updated: at(22)}],
    labels: [{id: 'L1', name: 'TRASH', type: 'system'}, {id: 'L2', name: 'Work', type: 'user'}, {id: 'L3', name: 'Later', type: 'user'}],
    drafts: {D1: {id: 'D1', raw: b64('To: friend@fixture.test\r\nSubject: Hello\r\n\r\nSee you soon.')}},
    events: {E1: {id: 'E1', summary: 'Review', start: '2026-10-28T10:00:00Z', end: '2026-10-28T10:30:00Z', version: 1, requestId: null}},
    files: {'docs/a.md': {path: 'docs/a.md', content: b64('old'), sha: sha('old')}},
    messages: [], exports: [], shares: [], hooks: [],
    keys: {K1: {id: 'K1', name: 'Deploy key', secret: CANARY}},
    rpc: {users: {U1: {id: 'U1', name: 'Ada'}, U2: {id: 'U2', name: 'Grace'}},
      channels: {C1: {id: 'C1', name: 'general', messages: [{ts: '1761210000.000100', user: 'U1', text: 'Welcome'}]}},
      canvases: {F1: {id: 'F1', title: 'Roadmap', content: 'Ship step 11.'}}, scheduled: {Q1: {id: 'Q1', channel: 'C1', text: 'Later'}}},
    created: String(clock()),
  };
}

const etagOf = event => `"${event.version}"`;
const byNewest = (a, b) => a.updated < b.updated ? 1 : a.updated > b.updated ? -1 : 0;
const page = (list, start) => ({slice: list.slice(start, start + PAGE), next: start + PAGE < list.length ? start + PAGE : null});

/** The routes, each {method, template, write, locked, handle(ctx)}; ctx is {params, query, body, headers, state, now, origin}. */
const REST = [
  {method: 'GET', template: '/accounts/{account}/profile', handle: ({state}) => ok({...state.account})},
  {method: 'GET', template: '/items', handle({state, query}) {
    let list = state.items.filter(item => !item.in_trash).sort(byNewest);
    if (query.has('kind')) list = list.filter(item => item.kind === query.get('kind'));
    const labels = query.getAll('labelIds');
    if (labels.length) list = list.filter(item => item.labels.some(label => labels.includes(label)));
    if (query.has('updatedAfter')) list = list.filter(item => item.updated > query.get('updatedAfter'));
    if (query.has('page')) {
      const number = Math.max(1, Number(query.get('page')) || 1), {slice, next} = page(list, (number - 1) * PAGE);
      return ok({items: slice, hasMore: next !== null}, next === null ? {} : {link: `<${REST_ORIGIN}/items?page=${number + 1}>; rel="next"`});
    }
    const start = query.has('pageToken') ? Number(/^p([0-9]+)$/.exec(query.get('pageToken'))?.[1] ?? NaN) : 0;
    if (!Number.isSafeInteger(start)) return {status: 400, data: {error: 'bad_page_token'}};
    const {slice, next} = page(list, start);
    return ok({items: slice, ...(next === null ? {} : {nextPageToken: `p${next}`}), hasMore: next !== null});
  }},
  {method: 'GET', template: '/items/{item_id}', handle: ({state, params}) => { const item = state.items.find(entry => entry.id === params.item_id); return item ? ok({...item}) : missing(); }},
  {method: 'PATCH', template: '/items/{item_id}', write: true, handle({state, params, body, now}) {
    const item = state.items.find(entry => entry.id === params.item_id);
    if (!item) return missing();
    for (const field of ['name', 'labels', 'in_trash']) if (body && Object.hasOwn(body, field)) item[field] = structuredClone(body[field]);
    item.updated = now;
    return ok({...item});
  }},
  {method: 'DELETE', template: '/items/{item_id}', write: true, handle({state, params}) {
    const index = state.items.findIndex(entry => entry.id === params.item_id);
    if (index < 0) return missing();
    state.items.splice(index, 1);
    return {status: 204, data: null};
  }},
  {method: 'POST', template: '/items', write: true, handle({state, body, now}) {
    const id = `I${state.items.length + 1}`, item = {id, name: String(body?.properties?.Name ?? id), kind: 'row', labels: [], in_trash: false, updated: now, parent: body?.parent ?? null, properties: body?.properties ?? {}};
    state.items.push(item);
    return ok({id, parent: item.parent, properties: item.properties});
  }},
  {method: 'DELETE', template: '/items/{item_id}/labels/{name}', write: true, handle({state, params, now}) {
    const item = state.items.find(entry => entry.id === params.item_id), label = state.labels.find(entry => entry.name === params.name);
    if (!item || !label || !item.labels.includes(label.id)) return missing();
    item.labels = item.labels.filter(id => id !== label.id);
    item.updated = now;
    return {status: 204, data: null};
  }},
  {method: 'GET', template: '/items/{item_id}/history', handle: ({params}) => ok({id: params.item_id, history: []})},
  {method: 'POST', template: '/items/search', handle({state, body}) {
    const words = String(body?.query ?? '').toLowerCase();
    let list = state.items.filter(item => !item.in_trash && item.name.toLowerCase().includes(words)).sort(byNewest);
    if (body?.kind !== undefined) list = list.filter(item => item.kind === body.kind);
    const start = body?.start_cursor === undefined ? 0 : Number(/^c([0-9]+)$/.exec(String(body.start_cursor))?.[1] ?? NaN);
    if (!Number.isSafeInteger(start)) return {status: 400, data: {error: 'bad_cursor'}};
    const {slice, next} = page(list, start);
    return ok({results: slice.map(item => ({id: item.id, title: item.name})), next_cursor: next === null ? null : `c${next}`, has_more: next !== null});
  }},
  {method: 'POST', template: '/items/export', write: true, handle({state, body, now}) {
    const items = state.items.filter(item => (body?.kind === undefined || item.kind === body.kind) && (body?.label === undefined || item.labels.includes(body.label)));
    const record = {id: `X${state.exports.length + 1}`, at: now, ids: items.map(item => item.id)};
    state.exports.push(record);
    return ok({exportId: record.id, count: items.length});
  }},
  {method: 'GET', template: '/labels', handle: ({state, query}) => ok({labels: state.labels.filter(label => !query.has('type') || label.type === query.get('type')).map(label => ({...label}))})},
  {method: 'GET', template: '/labels/{label_id}', handle: ({state, params}) => { const label = state.labels.find(entry => entry.id === params.label_id); return label ? ok({...label}) : missing(); }},
  {method: 'POST', template: '/labels', write: true, handle({state, body}) {
    if (typeof body?.name !== 'string' || !body.name) return {status: 400, data: {error: 'name_required'}};
    if (state.labels.some(label => label.name.toLowerCase() === body.name.toLowerCase())) return {status: 409, data: {error: 'label_exists'}};
    const label = {id: `L${state.labels.length + 1}`, name: body.name, type: 'user'};
    state.labels.push(label);
    return ok({...label});
  }},
  {method: 'PATCH', template: '/labels/{label_id}', write: true, handle({state, params, body}) {
    const label = state.labels.find(entry => entry.id === params.label_id);
    if (!label) return missing();
    if (typeof body?.name === 'string') label.name = body.name;
    return ok({...label});
  }},
  {method: 'GET', template: '/drafts/{draft_id}', handle: ({state, params}) => state.drafts[params.draft_id] ? ok({...state.drafts[params.draft_id]}) : missing()},
  {method: 'POST', template: '/drafts/{draft_id}/send', write: true, handle({state, params, body, now}) {
    const draft = state.drafts[params.draft_id];
    if (!draft) return missing();
    if (body?.raw !== draft.raw) return {status: 400, data: {error: 'raw_changed'}};
    const id = `S${state.items.filter(item => item.kind === 'sent').length + 1}`;
    state.items.push({id, name: `Sent ${draft.id}`, kind: 'sent', labels: [], in_trash: false, updated: now, raw: draft.raw});
    delete state.drafts[params.draft_id];
    return ok({id, draftId: draft.id});
  }},
  {method: 'GET', template: '/events/{event_id}', handle({state, params}) {
    const event = state.events[params.event_id];
    if (!event) return missing();
    const {version, ...shown} = event;
    void version;
    return ok(shown, {etag: etagOf(event)});
  }},
  {method: 'PATCH', template: '/events/{event_id}', write: true, handle({state, params, body, headers}) {
    const event = state.events[params.event_id];
    if (!event) return missing();
    if (headers['if-match'] !== etagOf(event)) return {status: 412, data: {error: 'precondition_failed'}};
    for (const field of ['start', 'end', 'summary', 'requestId']) if (body && Object.hasOwn(body, field)) event[field] = body[field];
    event.version++;
    const {version, ...shown} = event;
    void version;
    return ok(shown, {etag: etagOf(event)});
  }},
  {method: 'GET', template: '/files/{+path}', handle: ({state, params}) => state.files[params.path] ? ok({...state.files[params.path], encoding: 'base64'}) : missing()},
  {method: 'PUT', template: '/files/{+path}', write: true, handle({state, params, body}) {
    const current = state.files[params.path];
    if (typeof body?.content !== 'string' || typeof body?.message !== 'string') return {status: 422, data: {error: 'content_and_message_required'}};
    if (current ? body.sha !== current.sha : body.sha !== undefined) return {status: 409, data: {error: 'sha_does_not_match'}};
    const text = Buffer.from(body.content, 'base64').toString('utf8'), file = {path: params.path, content: body.content, sha: sha(text)};
    state.files[params.path] = file;
    return {status: current ? 200 : 201, data: {content: {path: file.path, sha: file.sha}, commit: {message: body.message}}};
  }},
  {method: 'POST', template: '/messages', write: true, handle({state, body, now}) {
    const message = {id: `M${state.messages.length + 1}`, to: body?.to ?? null, text: body?.text ?? null, at: now};
    state.messages.push(message);
    return ok({...message});
  }},
  {method: 'GET', template: '/keys', handle: ({state}) => ok({keys: Object.values(state.keys).map(({id, name}) => ({id, name}))})},
  {method: 'GET', template: '/keys/{key_id}', handle: ({state, params}) => state.keys[params.key_id] ? ok({...state.keys[params.key_id]}) : missing()},
  {method: 'PUT', template: '/items/{item_id}/share', write: true, locked: true, handle: ({state, params, body}) => { state.shares.push({item: params.item_id, to: body?.to ?? null}); return ok({shared: true}); }},
  {method: 'POST', template: '/hooks', write: true, locked: true, handle: ({state, body}) => { state.hooks.push({id: `H${state.hooks.length + 1}`, url: body?.url ?? null}); return ok({id: state.hooks.at(-1).id}); }},
  {method: 'DELETE', template: '/hooks/{hook_id}', write: true, locked: true, handle: ({state, params}) => { state.hooks = state.hooks.filter(hook => hook.id !== params.hook_id); return ok({deleted: true}); }},
];
const RPC = [
  {method: 'GET', template: '/messages.list', handle: ({state, query}) => { const channel = state.rpc.channels[query.get('channel') ?? 'C1']; return channel ? ok({ok: true, messages: structuredClone(channel.messages)}) : rpcFail('channel_not_found'); }},
  {method: 'POST', template: '/messages.history', handle: ({state, body}) => { const channel = state.rpc.channels[body?.channel]; return channel ? ok({ok: true, messages: structuredClone(channel.messages).reverse(), has_more: false}) : rpcFail('channel_not_found'); }},
  {method: 'POST', template: '/canvases.read', handle: ({state, body}) => { const canvas = state.rpc.canvases[body?.canvas_id]; return canvas ? ok({ok: true, title: canvas.title, content: canvas.content}) : rpcFail('canvas_not_found'); }},
  {method: 'POST', template: '/messages.post', write: true, handle({state, body, now}) {
    const channel = state.rpc.channels[body?.channel];
    if (!channel) return rpcFail('channel_not_found');
    const ts = `${Math.floor(Date.parse(now) / 1000)}.${String(channel.messages.length).padStart(6, '0')}`;
    channel.messages.push({ts, user: 'U0', text: String(body?.text ?? '')});
    return ok({ok: true, channel: channel.id, ts});
  }},
  {method: 'POST', template: '/conversations.start', write: true, handle({state, body}) {
    const user = String(body?.users ?? '');
    if (!state.rpc.users[user]) return rpcFail('user_not_found');
    const id = `D${user}`;
    state.rpc.channels[id] ??= {id, name: user, messages: []};
    return ok({ok: true, channel: {id}});
  }},
  {method: 'POST', template: '/messages.unschedule', write: true, handle({state, body}) {
    if (!state.rpc.scheduled[body?.scheduled_message_id]) return rpcFail('invalid_scheduled_message_id');
    delete state.rpc.scheduled[body.scheduled_message_id];
    return ok({ok: true});
  }},
  {method: 'POST', template: '/admin.invite', write: true, locked: true, handle: () => ok({ok: true})},
];

function segmentsOf(template) {
  return (template === '/' ? [] : template.slice(1).split('/')).map(part => /^\{\+\w+\}$/.test(part) ? {rest: part.slice(2, -1)} : /^\{\w+\}$/.test(part) ? {param: part.slice(1, -1)} : {literal: part});
}
const COMPILED = new Map([[REST_ORIGIN, REST], [RPC_ORIGIN, RPC]].map(([origin, routes]) => [origin, routes.map(route => ({...route, key: `${route.method} ${route.template}`, parts: segmentsOf(route.template)}))]));
/** The route a method and decoded path take, with its parameters; literals win over parameters. */
function routeOf(origin, method, path) {
  const segments = path === '/' ? [] : path.slice(1).split('/').map(segment => { try { return decodeURIComponent(segment); } catch { return segment; } });
  let best = null;
  for (const route of COMPILED.get(origin) ?? []) {
    if (route.method !== method) continue;
    const params = {};
    let score = 0, matched = true;
    for (let index = 0; index < route.parts.length; index++) {
      const part = route.parts[index];
      if (part.rest) { if (index >= segments.length) matched = false; else params[part.rest] = segments.slice(index).join('/'); break; }
      if (index >= segments.length) { matched = false; break; }
      if (part.literal !== undefined) { if (part.literal !== segments[index]) { matched = false; break; } score += 2; }
      else { params[part.param] = segments[index]; score += 1; }
    }
    if (matched && !route.parts.some(part => part.rest) && route.parts.length !== segments.length) matched = false;
    if (matched && (!best || score > best.score)) best = {route, params, score};
  }
  return best;
}

export class FixtureSimulator {
  /** clock() gives the time item updates and messages carry; token is the bearer token the account sends. */
  constructor({clock = () => Date.parse('2026-10-23T09:00:00.000Z'), token = 'fixture-token'} = {}) {
    this.clock = clock;
    this.token = token;
    this.calls = [];
    this.switches = new Map();
    this.holds = new Map();
    this.data = initialState(clock);
    this.request = this.request.bind(this);
  }
  state() { return structuredClone(this.data); }
  writes() { return this.calls.filter(call => call.write); }
  reads() { return this.calls.filter(call => call.route && !call.write); }
  #switch(kind, route, extra = {}, {times = 1} = {}) {
    if (!Number.isSafeInteger(times) && times !== Infinity) throw new Error('times is a whole number or Infinity.');
    this.switches.set(route, {kind, left: times, ...extra});
    return this;
  }
  fail(route, answer, options) { return this.#switch('fail', route, {answer: structuredClone(answer)}, options); }
  drop(route, options) { return this.#switch('drop', route, {}, options); }
  swallow(route, options) { return this.#switch('swallow', route, {}, options); }
  oversize(route, bytes, options) { return this.#switch('oversize', route, {bytes}, options); }
  hold(route) {
    let reach, release;
    const reached = new Promise(resolve => { reach = resolve; }), released = new Promise(resolve => { release = resolve; });
    const gate = {reached, released, reach, release: () => { this.holds.delete(route); release(); }};
    this.holds.set(route, gate);
    return {reached, release: gate.release};
  }
  /** The switch for one call to `route`, used up as it is taken. */
  #take(route) {
    const entry = this.switches.get(route);
    if (!entry) return null;
    if (--entry.left <= 0) this.switches.delete(route);
    return entry;
  }

  async request({url, method = 'GET', headers = {}, body, allowedOrigins, maxBytes = 2 * 1024 * 1024, responseType = 'json', redirect = 'error', responseHeaders = DEFAULT_RESPONSE_HEADERS, timeoutMs = 15000}) {
    let target;
    try { target = new URL(url); } catch { throw notSent('Invalid request URL.'); }
    if (target.protocol !== 'https:' || target.username || target.password || target.hash || (target.port && target.port !== '443')) throw notSent('Only credential-free HTTPS URLs on port 443 are allowed.');
    if (!Array.isArray(allowedOrigins) || !allowedOrigins.includes(target.origin)) throw notSent('Request origin is outside the connection grant.');
    if (!['json', 'buffer'].includes(responseType) || !['error', 'report'].includes(redirect) || !Array.isArray(responseHeaders)) throw notSent('Unsupported response handling.');
    if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000 || !Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 10 * 1024 * 1024) throw notSent('Invalid request limits.');
    if (!/^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/.test(method)) throw notSent('Unsupported HTTP method.');
    const lower = {};
    for (const [name, value] of Object.entries(headers)) {
      if (UNSAFE_HEADER.test(name) || !/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(name) || typeof value !== 'string' || /[\r\n]/.test(value)) throw notSent('Unsafe request header.');
      lower[name.toLowerCase()] = value;
    }
    if (body !== undefined && !(typeof body === 'string' || Buffer.isBuffer(body))) throw notSent('Request body must be serialized.');
    if (body !== undefined && Buffer.byteLength(body) > 1024 * 1024) throw notSent('Request body is too large.');
    if (!COMPILED.has(target.origin)) throw notSent('Provider DNS lookup failed or timed out.');
    const rpc = target.origin === RPC_ORIGIN;
    if (rpc && !target.pathname.startsWith('/api/')) throw notSent('Provider DNS lookup failed or timed out.');
    // Sent from here on: the call is recorded, without its Authorization header.
    const path = rpc ? target.pathname.slice('/api'.length) : target.pathname, found = routeOf(target.origin, method, path);
    const text = body === undefined ? undefined : Buffer.isBuffer(body) ? body.toString('utf8') : body;
    let parsed = null;
    if (text !== undefined) { try { parsed = JSON.parse(text); } catch { parsed = rpc ? Object.fromEntries(new URLSearchParams(text)) : text; } }
    const query = {};
    for (const [name, value] of target.searchParams) query[name] = Object.hasOwn(query, name) ? [query[name]].flat().concat(value) : value;
    const {authorization, ...kept} = lower;
    const call = {method, origin: target.origin, path, route: found?.route.key ?? null, query, headers: kept, body: parsed, write: found?.route.write === true, locked: found?.route.locked === true, status: null};
    this.calls.push(call);
    const gate = found ? this.holds.get(found.route.key) : null;
    if (gate) { gate.reach(); await gate.released; }
    const chosen = found ? this.#take(found.route.key) : null;
    let answer;
    if (authorization !== `Bearer ${this.token}`) answer = rpc ? rpcFail('not_authed') : {status: 401, data: {error: 'unauthorized'}};
    else if (!found) answer = rpc ? rpcFail('unknown_method') : {status: 404, data: {error: 'not_found'}};
    else if (chosen?.kind === 'fail') answer = structuredClone(chosen.answer);
    else {
      const state = chosen?.kind === 'swallow' ? structuredClone(this.data) : this.data;
      answer = found.route.handle({params: found.params, query: target.searchParams, body: rpc && method === 'GET' ? Object.fromEntries(target.searchParams) : parsed, headers: lower, state, now: new Date(this.clock()).toISOString(), origin: target.origin});
      if (chosen?.kind === 'drop') throw lost('Provider connection failed.');
      if (chosen?.kind === 'oversize') answer = {...answer, data: {...answer.data, padding: 'x'.repeat(Math.max(0, chosen.bytes))}};
    }
    call.status = answer.status;
    const headersOut = Object.fromEntries(Object.entries(answer.headers ?? {}).map(([name, value]) => [name.toLowerCase(), String(value)]));
    if (answer.status >= 300 && answer.status < 400) {
      if (redirect !== 'report') throw lost('Provider redirects are not followed.');
      const shown = {};
      for (const key of responseHeaders) if (key !== 'location' && headersOut[key] !== undefined) shown[key] = headersOut[key];
      if (answer.status !== 304 && headersOut.location) { try { const next = new URL(headersOut.location, target); if (next.origin === target.origin) shown.location = next.href; } catch {} }
      return {status: answer.status, headers: shown, data: null, ...(answer.status === 304 ? {notModified: true} : {redirected: true})};
    }
    const bytes = answer.data === null || answer.data === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(answer.data), 'utf8');
    if (bytes.length > maxBytes) throw lost('Provider response exceeded the size limit.');
    if (bytes.length) headersOut['content-type'] ??= 'application/json; charset=utf-8';
    const shown = {};
    for (const key of responseHeaders) if (headersOut[key] !== undefined) shown[key] = headersOut[key];
    if (shown.location !== undefined) { try { const next = new URL(shown.location, target); if (next.origin === target.origin) shown.location = next.href; else delete shown.location; } catch { delete shown.location; } }
    // A fresh parse of the bytes, so nothing the caller holds shares memory with the simulator's state.
    return {status: answer.status, headers: shown, data: responseType === 'buffer' ? bytes : bytes.length ? JSON.parse(bytes.toString('utf8')) : null};
  }
}

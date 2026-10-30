// F10.19 part 1 (docs/F10.19-BUILD-MAP.md part 1 item 5): a Notion API simulator for the Notion actions' tests. It is written from Notion's
// API reference for Notion-Version 2026-03-11 (developers.notion.com/reference: pages, page markdown, move a page, blocks, databases, data
// sources and their query filter, search, comments, users, errors and request limits) and from this comment, and it imports only node
// built-ins: never lib/, catalog/, Notion's action file or the OAuth simulator of the same name (test/fixtures/oauth-simulators.mjs, a
// different file), so an action bug and a simulator bug cannot cancel out. Test data only: nothing in lib/ imports it, and nothing here calls
// Notion.
//
// The service: https://api.notion.com/v1 (ORIGIN and BASE). One integration (a bot user) installed by one owner {id, name, email}, holding
// capabilities from read_content, update_content, insert_content, read_comments, insert_comments and user_email (all six by default).
// Routes (named "METHOD /template" below the base, as the switches take them), each with the capability it needs:
//   GET    /users/me, /users (paged), /users/{user_id}               none; a person's email only with user_email
//   POST   /search                                                   read_content
//   GET    /pages/{page_id}, /pages/{page_id}/markdown               read_content
//   POST   /pages                                                    insert_content
//   PATCH  /pages/{page_id}, /pages/{page_id}/markdown               update_content
//   POST   /pages/{page_id}/move                                     update_content
//   DELETE /blocks/{block_id}                                        update_content
//   GET    /databases/{database_id}, /data_sources/{data_source_id}  read_content
//   POST   /data_sources/{data_source_id}/query                      read_content
//   GET    /comments (block_id), /comments/{comment_id}              read_comments
//   POST   /comments, DELETE /comments/{comment_id}                  insert_comments
// Errors use Notion's shape {object: 'error', status, code, message, request_id}. A request without "Notion-Version: 2026-03-11" exactly answers
// 400 missing_version (no header) or validation_error (another value), checked first; without "Authorization: Bearer <token>" 401
// unauthorized; a route outside the list 400 invalid_request_url; a body that is not JSON 400 invalid_json; a route needing a capability the
// integration lacks 403 restricted_resource; an object not shared with the integration 404 object_not_found; anything else Notion refuses
// 400 validation_error. Nothing a refused request names changes.
//
// What the simulator models, as Notion documents it:
// - Sharing: the integration sees only the pages and databases shared with it (share(id), unshare(id)), their descendants (child pages,
//   databases, their data sources and rows) and the users. Anything else answers 404 object_not_found.
// - Pages: create under a page (properties holds only title, Notion's rule for a page parent; markdown optional, never with children or
//   content) or a data source (property values typed by its schema, named by name or id). A value names an existing option only (the
//   simulator's own choice: Notion may create a select option; Fabric never asks it to), a read-only or unknown property answers 400. Each
//   rich text list holds at most 100 pieces of at most 2,000 UTF-16 units. Patch takes properties (a list value replaces the whole value),
//   in_trash, icon and cover; any other key, archived among them (gone in this version), answers 400. A row's properties hold every
//   property of its data source, empty ones included.
// - Markdown: get gives {object: 'page_markdown', id, markdown, truncated, unknown_block_ids}. A page's markdown is its text followed by
//   one tag per child page (<page url="...">Title</page>) or database (<database url="...">Title</database>) that is not in the trash, in
//   the order they were made, and one <unknown url="..." alt="block"/> per block unknown(pageId, block) added; those ids are listed in
//   unknown_block_ids, and a get of one of them gives its own markdown. The text is what readBack() makes of what was written, never the
//   same bytes when it holds a mark: [SYNTHETIC] reads \[SYNTHETIC\]. Patch takes one operation, by type:
//     insert_content {content}: appends the content to the page's text (the simulator's own choice when neither after nor position is
//       given; Notion marks the form deprecated);
//     update_content {content_updates: [{old_str, new_str, replace_all_matches?}], allow_deleting_content?}: each update applies in order
//       when old_str occurs exactly once (or every time with replace_all_matches), with or without Notion's backslashes, as the live run
//       of 2026-10-30 measured; one that occurs more than once answers 400 and nothing
//       changes; when none occurs the call answers 400 and nothing changes, and when some do the misses come back as warnings. An edit
//       that would drop a child page or database tag answers 400 unless allow_deleting_content is true, which then moves that child to the
//       trash;
//     replace_content and replace_content_range answer 400 not_simulated: no action sends them.
//   It answers the page_markdown as it now stands.
// - Trash: DELETE /blocks/{id} on a page puts it in the trash ({object: 'block', type: 'child_page', in_trash: true}); on a database it
//   trashes the database. A trashed page still reads 200 with in_trash true, and every write to it but {in_trash: false} (restore) answers
//   400, a second delete included (the simulator's own choice). Trashed rows leave queries and trashed objects leave search.
// - Move: POST /pages/{id}/move {parent: {type: 'page_id', page_id}}; a page cannot move under itself or a descendant (400). A
//   data_source_id parent answers 400 not_simulated: no action sends one.
// - Databases and data sources: get; query with filter (and, or, and one condition per property named by name or id: contains or
//   equals on title, rich_text, url, email and phone_number; equals on number, checkbox, select, status and a date's day; contains on
//   multi_select, people and relation), page_size 1 to 100 (default 100), start_cursor, has_more and next_cursor. Rows in the order they
//   were made (the simulator's own choice).
// - Search: query matches titles in any case; filter {property: 'object', value: 'page' | 'data_source'}; most recently edited first (the
//   simulator's own order); paged as queries are.
// - Comments: list by block_id gives the open comments only (resolve(id) closes one), oldest first, paged; create with parent.page_id (a
//   new discussion) or discussion_id (a reply), exactly one; get and delete one.
// - Users: list paged; me is the integration's bot.
// - A cursor is the next item's id; any other start_cursor answers 400.
//
// The network contract is lib/network.mjs's seam: `request` takes its options and answers {status, headers, data}. Refused before sending,
// with sent false: a URL that is not https on 443 or carries credentials, an origin outside allowedOrigins or not Notion's, an unsupported
// method or response handling, an unsafe header, a body that is not a string or Buffer, a body over 1 MiB. After sending, with sent true:
// an answer over maxBytes, and drop(). A path on Notion's origin outside /v1/ answers 400 invalid_request_url. Only the response headers
// asked for come back (the seam's default list when none are named).
//
// Every request that reaches the simulator is recorded in `calls`, without its Authorization header: {method, origin, path (below the base),
// route, query, headers, body, write, status}. writes() and reads() are the calls to write and read routes; state() is a copy of the state.
// Switches, each for the next call to one route unless {times} says how many: fail(route, {status, headers?, data?}) answers that instead and
// changes nothing; drop(route) applies the call, then throws as a lost answer; swallow(route) answers as if applied but changes nothing;
// oversize(route, bytes) pads the answer; hold(route) returns {reached, release()}; limit(route, retryAfter) answers 429 rate_limited with
// that Retry-After. Test data, never recorded: seedPage(), seedDatabase(), seedRow(), seedUser(), seedComment(), unknown(), share(),
// unshare(), capabilities(list), touch(id) (someone else edits the page) and resolve(commentId).
import {createHash} from 'node:crypto';

export const ORIGIN = 'https://api.notion.com';
export const BASE = `${ORIGIN}/v1`;
export const VERSION = '2026-03-11';
const BASE_PATH = '/v1';
const DEFAULT_RESPONSE_HEADERS = ['content-type', 'etag', 'retry-after', 'x-ratelimit-remaining'];
const UNSAFE_HEADER = /^(host|connection|transfer-encoding|content-length|upgrade|proxy-.*|forwarded|x-forwarded-.*)$/i;
export const CAPABILITIES = Object.freeze(['read_content', 'update_content', 'insert_content', 'read_comments', 'insert_comments', 'user_email']);
const PIECES = 100, UNITS = 2000, PAGE_SIZE = 100;
const WRITABLE = ['title', 'rich_text', 'number', 'checkbox', 'select', 'status', 'multi_select', 'date', 'url', 'email', 'phone_number', 'people', 'relation'];
const READ_ONLY = ['formula', 'rollup', 'created_time', 'created_by', 'last_edited_time', 'last_edited_by', 'unique_id', 'button', 'verification', 'files'];
const UUID = /^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i;

const notSent = message => Object.assign(new Error(message), {sent: false});
const lost = message => Object.assign(new Error(message), {sent: true});
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const hex = text => createHash('sha256').update(text).digest('hex');
/** A Notion id as the API writes it: hyphenated, lower case. Undashed or upper-case ids are read the same. */
const canonicalId = value => typeof value === 'string' && UUID.test(value) ? value.replace(/-/g, '').toLowerCase().replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5') : null;
const linkOf = id => `https://www.notion.so/${id.replace(/-/g, '')}`;
/**
 * A page's text as Notion reads it back, from its enhanced markdown reference and the live runs of 2026-10-30, which wrote these forms: blank
 * lines gone; a heading 5 or 6 reads 4, a * bullet -, _italic_ *italic*; an ordered list counts up; a fence names its language in full; a pipe
 * table reads as <table> tags with its divider gone; a backslash before each mark below outside a code fence and a link. * and ` stay, the
 * simulator's own choice: most of them are marks, not text.
 */
const signedLink = (name, read) => `![](https://prod-files-secure.s3.us-west-2.amazonaws.com/workspace/${name}?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=${read}&X-Amz-Signature=${hex(String(read))}&x-id=GetObject)`;
const readBack = text => {
  const lines = text.split('\n').filter(line => line.trim() !== ''), out = [], tableRow = /^\|.*\|$/;
  let fenced = false, number = 0;
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    if (line.startsWith('```')) { fenced = !fenced; out.push(line.replace(/^```js\b/, '```javascript').replace(/^```py\b/, '```python')); continue; }
    if (fenced) { out.push(line); continue; }
    if (tableRow.test(line)) {
      const rows = [];
      while (index < lines.length && tableRow.test(lines[index])) rows.push(lines[index++]);
      index--;
      out.push('<table header-row="true">', ...rows.filter(row => !/^\|[\s|:-]*\|$/.test(row)).flatMap(row => ['<tr>', ...row.slice(1, -1).split('|').map(cell => `<td>${cell.trim()}</td>`), '</tr>']), '</table>');
      continue;
    }
    number = /^\d+\. /.test(line) ? number + 1 : 0;
    const marked = (number ? line.replace(/^\d+/, number) : line).replace(/^#{5,6} /, '#### ').replace(/^\* /, '- ').replace(/(^|\s)_([^_]+)_(?=\s|$)/g, '$1*$2*');
    out.push(marked.split(/(\[[^\]]*\]\([^)]*\))/).map((part, at) => at % 2 ? part : part.replace(/[\\[\]<>{}|^~$]/g, '\\$&')).join(''));
  }
  return out.join('\n');
};
class Refusal extends Error { constructor(status, code, message, headers = {}) { super(message); Object.assign(this, {status, code, headers}); } }
const refuse = (status, code, message, headers) => { throw new Refusal(status, code, message, headers); };
const invalid = message => refuse(400, 'validation_error', message);
const notFound = id => refuse(404, 'object_not_found', `Could not find object with ID: ${id}. Make sure the relevant pages and databases are shared with your integration.`);
const ok = (data, headers = {}) => ({status: 200, headers, data});

/** Rich text as Notion stores and answers it, from the pieces a write sends; at most 100 pieces of at most 2,000 UTF-16 units each. */
function richText(list, where) {
  if (!Array.isArray(list)) invalid(`body.${where} should be an array.`);
  if (list.length > PIECES) invalid(`body.${where}.length should be ≤ ${PIECES}, instead was ${list.length}.`);
  return list.map((piece, index) => {
    const content = record(piece) && record(piece.text) ? piece.text.content : undefined;
    if (typeof content !== 'string') invalid(`body.${where}[${index}].text.content should be a string.`);
    if (content.length > UNITS) invalid(`body.${where}[${index}].text.content.length should be ≤ ${UNITS}, instead was ${content.length}.`);
    return {type: 'text', text: {content, link: null}, annotations: {bold: false, italic: false, strikethrough: false, underline: false, code: false, color: 'default'}, plain_text: content, href: null};
  });
}
const plain = list => (list ?? []).map(piece => piece.plain_text).join('');
const emptyOf = type => ({title: [], rich_text: [], number: null, checkbox: false, select: null, status: null, multi_select: [], date: null, url: null, email: null, phone_number: null,
  people: [], relation: []})[type];

export class NotionApiSimulator {
  /**
   * clock() gives the time changes carry; token is the bearer token the integration's connection sends; owner is the person who installed
   * it, {id?, name, email}; capabilities are the integration's (all six by default).
   */
  constructor({clock = () => Date.parse('2026-10-26T12:00:00.000Z'), token = 'ntn_notion-simulator-token', owner = {name: 'Avery Owner', email: 'avery@example.com'}, capabilities = CAPABILITIES} = {}) {
    if (!record(owner) || typeof owner.name !== 'string' || typeof owner.email !== 'string') throw new Error('owner is {name, email}.');
    this.clock = clock;
    this.token = token;
    this.calls = [];
    this.switches = new Map();
    this.holds = new Map();
    this.held = new Set(capabilities);
    this.data = {next: 1, request: 1, users: {}, pages: {}, databases: {}, sources: {}, comments: {}, shared: [], unknown: {}, order: []};
    this.bot = this.seedUser({name: 'Fabric', type: 'bot'});
    this.owner = this.seedUser({id: owner.id, name: owner.name, email: owner.email});
    this.request = this.request.bind(this);
    this.routes = [
      ['GET', '/users/me', 'none', false, () => ok(this.#user(this.data.users[this.bot.id]))],
      ['GET', '/users', 'none', false, ({query}) => ok(this.#paged(Object.values(this.data.users).map(user => this.#user(user)), query.get('start_cursor'), query.get('page_size'), 'user'))],
      ['GET', '/users/{user_id}', 'none', false, ({params}) => { const user = this.data.users[canonicalId(params.user_id)]; return user ? ok(this.#user(user)) : notFound(params.user_id); }],
      ['POST', '/search', 'read_content', false, context => this.#search(context)],
      ['GET', '/pages/{page_id}', 'read_content', false, ({params}) => ok(this.#page(this.#visiblePage(params.page_id)))],
      ['GET', '/pages/{page_id}/markdown', 'read_content', false, ({params}) => ok(this.#markdownOf(params.page_id))],
      ['POST', '/pages', 'insert_content', true, context => this.#create(context)],
      ['PATCH', '/pages/{page_id}', 'update_content', true, context => this.#update(context)],
      ['PATCH', '/pages/{page_id}/markdown', 'update_content', true, context => this.#editMarkdown(context)],
      ['POST', '/pages/{page_id}/move', 'update_content', true, context => this.#move(context)],
      ['DELETE', '/blocks/{block_id}', 'update_content', true, context => this.#trash(context)],
      ['GET', '/databases/{database_id}', 'read_content', false, ({params}) => ok(this.#database(this.#visible('databases', params.database_id)))],
      ['GET', '/data_sources/{data_source_id}', 'read_content', false, ({params}) => ok(this.#source(this.#visible('sources', params.data_source_id)))],
      ['POST', '/data_sources/{data_source_id}/query', 'read_content', false, context => this.#query(context)],
      ['GET', '/comments', 'read_comments', false, context => this.#comments(context)],
      ['GET', '/comments/{comment_id}', 'read_comments', false, ({params}) => ok(this.#comment(this.#visibleComment(params.comment_id)))],
      ['POST', '/comments', 'insert_comments', true, context => this.#addComment(context)],
      ['DELETE', '/comments/{comment_id}', 'insert_comments', true, ({state, params}) => { const comment = this.#visibleComment(params.comment_id, state); delete state.comments[comment.id]; return ok(this.#comment(comment)); }],
    ].map(([method, template, capability, write, handle]) => ({method, template, key: `${method} ${template}`, capability, write, handle,
      parts: template.slice(1).split('/').map(part => /^\{(\w+)\}$/.test(part) ? {param: part.slice(1, -1)} : {literal: part})}));
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
  /** The next call to the route answers 429 rate_limited with this Retry-After, in seconds. */
  limit(route, retryAfter = 30, options) { return this.#switch('limit', route, {retryAfter}, options); }
  hold(route) {
    let reach, release;
    const reached = new Promise(resolve => { reach = resolve; }), released = new Promise(resolve => { release = resolve; });
    this.holds.set(route, {reached, released, reach, release: () => { this.holds.delete(route); release(); }});
    return {reached, release: this.holds.get(route).release};
  }
  #take(route) {
    const entry = this.switches.get(route);
    if (!entry) return null;
    if (--entry.left <= 0) this.switches.delete(route);
    return entry;
  }
  /** The integration's capabilities from now on. */
  capabilities(list) {
    if (!Array.isArray(list) || list.some(item => !CAPABILITIES.includes(item))) throw new Error(`capabilities are some of ${CAPABILITIES.join(', ')}.`);
    this.held = new Set(list);
    return this;
  }

  // ---- test data ---------------------------------------------------------------------------------------------------------------------
  #id(kind) { const digest = hex(`${kind}:${this.data.next++}`); return `${digest.slice(0, 8)}-${digest.slice(8, 12)}-4${digest.slice(13, 16)}-8${digest.slice(17, 20)}-${digest.slice(20, 32)}`; }
  #now() { return new Date(this.clock()).toISOString(); }
  /** A user of the workspace: a person (with an email) or a bot. */
  seedUser({id, name, email, type = 'person'} = {}) {
    const user = {id: canonicalId(id) ?? this.#id('user'), name, type, ...(type === 'person' ? {email: email ?? null} : {})};
    this.data.users[user.id] = user;
    return {...user};
  }
  /** A page under another page ({page_id}), or at the workspace's top (parent 'workspace'), with a title and markdown text; `shared` shares it. */
  seedPage({id, title = 'Untitled', parent = 'workspace', markdown = '', shared = false} = {}) {
    const page = this.#newPage({id, parent: parent === 'workspace' ? {type: 'workspace', workspace: true} : {type: 'page_id', page_id: this.#known('pages', parent.page_id).id},
      properties: {title: {id: 'title', type: 'title', title: richText([{text: {content: title}}], 'title')}}, markdown});
    if (shared) this.share(page.id);
    return this.#page(page);
  }
  /**
   * A database under a page with its data sources. Each source is {id?, name, properties}, properties {Name: {type, options?, prefix?}} by
   * name, exactly one of type title; options are option names. Returns {database, sources} as Notion answers them.
   */
  seedDatabase({id, title = 'Database', parent, sources = [], shared = false} = {}) {
    const database = {id: canonicalId(id) ?? this.#id('database'), title: richText([{text: {content: title}}], 'title'), parent: {type: 'page_id', page_id: this.#known('pages', parent.page_id).id},
      sources: [], in_trash: false, created_time: this.#now(), last_edited_time: this.#now()};
    this.data.databases[database.id] = database;
    this.data.order.push(database.id);
    for (const source of sources) {
      const sourceId = canonicalId(source.id) ?? this.#id('source'), properties = {};
      let counter = 0;
      for (const [name, spec] of Object.entries(source.properties)) {
        const propertyId = spec.type === 'title' ? 'title' : spec.id ?? `${'abcdefghij'[counter % 10]}%3B${++counter}`;
        const options = (spec.options ?? []).map((option, index) => ({id: `${propertyId}-o${index}`, name: option, color: 'default', description: null}));
        const config = ['select', 'multi_select'].includes(spec.type) ? {options} : spec.type === 'status' ? {options, groups: []} : spec.type === 'unique_id' ? {prefix: spec.prefix ?? null}
          : spec.type === 'relation' ? {data_source_id: spec.target ?? sourceId, type: 'single_property', single_property: {}} : {};
        properties[name] = {id: propertyId, name, description: '', type: spec.type, [spec.type]: config};
      }
      if (Object.values(properties).filter(property => property.type === 'title').length !== 1) throw new Error('A data source has exactly one title property.');
      this.data.sources[sourceId] = {id: sourceId, name: source.name ?? title, database_id: database.id, properties, unique: 0, created_time: this.#now(), last_edited_time: this.#now()};
      database.sources.push(sourceId);
    }
    if (shared) this.share(database.id);
    return {database: this.#database(database), sources: database.sources.map(sourceId => this.#source(this.data.sources[sourceId]))};
  }
  /** A row of a data source, from property values as POST /v1/pages takes them, keyed by name or id. */
  seedRow({id, dataSource, properties = {}, markdown = ''} = {}) {
    const source = this.#known('sources', dataSource);
    return this.#page(this.#newPage({id, parent: {type: 'data_source_id', data_source_id: source.id, database_id: source.database_id}, properties: this.#rowValues(source, properties, null), markdown}));
  }
  /** A comment on a page by `user` (the owner by default): a new discussion, or a reply in `discussion`. */
  seedComment({page, text, discussion, user = this.owner.id, resolved = false} = {}) {
    const target = this.#known('pages', page);
    const comment = {id: this.#id('comment'), page_id: target.id, discussion_id: discussion ?? this.#id('discussion'), rich_text: richText([{text: {content: text}}], 'rich_text'),
      created_time: this.#now(), last_edited_time: this.#now(), created_by: user, resolved};
    this.data.comments[comment.id] = comment;
    return this.#comment(comment);
  }
  /** An uploaded file on a page: its link is signed anew on every read of the page's markdown, as the live run of 2026-10-30 measured. */
  uploadFile(pageId, name) {
    const page = this.data.pages[canonicalId(pageId)];
    (page.files ??= []).push(name);
    return this;
  }
  /** A block of a page that Notion could not render in its markdown, with its own markdown when read by its id. */
  unknown(pageId, {markdown = ''} = {}) {
    const page = this.#known('pages', pageId), id = this.#id('block');
    this.data.unknown[id] = {id, page_id: page.id, markdown};
    return id;
  }
  /** Shares a page or a database with the integration, as the owner does in Notion's page picker. */
  share(id) { const key = canonicalId(id); if (!this.data.pages[key] && !this.data.databases[key]) throw new Error(`No page or database ${id}.`); if (!this.data.shared.includes(key)) this.data.shared.push(key); return this; }
  unshare(id) { const key = canonicalId(id); this.data.shared = this.data.shared.filter(item => item !== key); return this; }
  /** Someone else edits the page: its last edited time and editor move. */
  touch(id) { const page = this.#known('pages', id); page.last_edited_time = this.#now(); page.last_edited_by = this.owner.id; return this.#page(page); }
  /** Someone resolves a comment's discussion: it leaves the comment list. */
  resolve(commentId) { const comment = this.data.comments[canonicalId(commentId)]; if (!comment) throw new Error(`No comment ${commentId}.`); comment.resolved = true; return this; }

  // ---- shared pieces -----------------------------------------------------------------------------------------------------------------
  #known(kind, id, state = this.data) { const item = state[kind][canonicalId(id)]; if (!item) throw new Error(`No ${kind} ${id}.`); return item; }
  #newPage({id, parent, properties, markdown}, state = this.data) {
    const now = this.#now(), page = {id: canonicalId(id) ?? this.#id('page'), parent, properties, text: markdown, in_trash: false, created_time: now, last_edited_time: now,
      created_by: this.bot.id, last_edited_by: this.bot.id};
    state.pages[page.id] = page;
    state.order.push(page.id);
    return page;
  }
  /** The object an id names, as a parent chain sees it: a page, a database or a data source. */
  #node(state, id) { return state.pages[id] ? ['pages', state.pages[id]] : state.databases[id] ? ['databases', state.databases[id]] : state.sources[id] ? ['sources', state.sources[id]] : null; }
  /** The ids above an object, nearest first. */
  #ancestors(state, kind, item) {
    const chain = [];
    for (let current = [kind, item]; current;) {
      const [type, node] = current, parent = type === 'sources' ? node.database_id : node.parent?.page_id ?? node.parent?.data_source_id ?? null;
      if (!parent || chain.includes(parent)) break;
      chain.push(parent);
      current = this.#node(state, parent);
    }
    return chain;
  }
  #shared(state, kind, item) { return [item.id, ...this.#ancestors(state, kind, item)].some(id => state.shared.includes(id)); }
  /** An object of one kind the integration can see, else 404 object_not_found. */
  #visible(kind, id, state = this.data) {
    const item = state[kind][canonicalId(id)];
    if (!item || !this.#shared(state, kind, item)) notFound(id);
    return item;
  }
  #visiblePage(id, state) { return this.#visible('pages', id, state); }
  #visibleComment(id, state = this.data) {
    const comment = state.comments[canonicalId(id)];
    if (!comment || !state.pages[comment.page_id] || !this.#shared(state, 'pages', state.pages[comment.page_id])) notFound(id);
    return comment;
  }
  #writable(page) { if (page.in_trash) invalid('Can\'t edit block that is archived. You must unarchive the block before editing.'); return page; }
  #user(user) {
    const base = {object: 'user', id: user.id, type: user.type, name: user.name, avatar_url: null};
    return user.type === 'bot' ? {...base, bot: {owner: {type: 'user', user: {object: 'user', id: this.owner.id}}, workspace_name: 'Simulated workspace'}}
      : {...base, person: this.held.has('user_email') && user.email ? {email: user.email} : {}};
  }
  #titleOf(item, kind) { if (kind === 'pages') return plain(Object.values(item.properties).find(property => property.type === 'title')?.title); return plain(item.title); }
  #page(page) {
    return {object: 'page', id: page.id, created_time: page.created_time, last_edited_time: page.last_edited_time, created_by: {object: 'user', id: page.created_by},
      last_edited_by: {object: 'user', id: page.last_edited_by}, cover: null, icon: null, parent: structuredClone(page.parent), in_trash: page.in_trash, is_archived: false, is_locked: false,
      url: linkOf(page.id), public_url: null, properties: this.#rendered(page)};
  }
  /** A page's properties as Notion answers them: a row's computed ones filled from the page. */
  #rendered(page) {
    const out = structuredClone(page.properties);
    for (const property of Object.values(out)) {
      if (property.type === 'created_time') property.created_time = page.created_time;
      if (property.type === 'last_edited_time') property.last_edited_time = page.last_edited_time;
      if (property.type === 'created_by') property.created_by = {object: 'user', id: page.created_by};
      if (property.type === 'last_edited_by') property.last_edited_by = {object: 'user', id: page.last_edited_by};
    }
    return out;
  }
  #database(database) {
    return {object: 'database', id: database.id, title: structuredClone(database.title), parent: structuredClone(database.parent), in_trash: database.in_trash, is_inline: false,
      created_time: database.created_time, last_edited_time: database.last_edited_time, url: linkOf(database.id),
      data_sources: database.sources.map(id => ({id, name: this.data.sources[id]?.name ?? ''}))};
  }
  #source(source, state = this.data) {
    const database = state.databases[source.database_id];
    return {object: 'data_source', id: source.id, title: richText([{text: {content: source.name}}], 'title'), parent: {type: 'database_id', database_id: source.database_id},
      database_parent: structuredClone(database?.parent ?? null), in_trash: Boolean(database?.in_trash), created_time: source.created_time, last_edited_time: source.last_edited_time,
      properties: structuredClone(source.properties), url: linkOf(source.id)};
  }
  #comment(comment) {
    return {object: 'comment', id: comment.id, parent: {type: 'page_id', page_id: comment.page_id}, discussion_id: comment.discussion_id, created_time: comment.created_time,
      last_edited_time: comment.last_edited_time, created_by: {object: 'user', id: comment.created_by}, rich_text: structuredClone(comment.rich_text),
      display_name: {type: 'integration', resolved_name: 'Fabric'}};
  }
  /** One page of a list: start_cursor is the id of the first item to give, page_size 1 to 100. */
  #paged(items, cursor, size, type) {
    const pageSize = size === null || size === undefined ? PAGE_SIZE : Number(size);
    if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > PAGE_SIZE) invalid(`page_size should be a number between 1 and ${PAGE_SIZE}.`);
    let start = 0;
    if (cursor !== null && cursor !== undefined) {
      start = items.findIndex(item => item.id === cursor);
      if (start < 0) invalid('start_cursor provided is invalid.');
    }
    const results = items.slice(start, start + pageSize), more = start + pageSize < items.length;
    return {object: 'list', results, next_cursor: more ? items.at(start + pageSize).id : null, has_more: more, type, [type]: {}};
  }
  #body(body) { if (body === undefined) return {}; if (!record(body)) invalid('body should be an object.'); return body; }
  #only(body, allowed) { for (const key of Object.keys(body)) if (!allowed.includes(key)) invalid(`body.${key} should be not present.`); }

  // ---- pages -------------------------------------------------------------------------------------------------------------------------
  /** A data source property by name or id. */
  #propertyOf(source, key) { return source.properties[key] ?? Object.values(source.properties).find(property => property.id === key) ?? null; }
  /** Property values a write sends for a row, checked against the data source's schema; `current` holds the values they change. */
  #rowValues(source, given, current, state = this.data) {
    if (!record(given)) invalid('body.properties should be an object.');
    const values = current ? structuredClone(current) : Object.fromEntries(Object.values(source.properties).map(property => [property.name, this.#emptyValue(source, property)]));
    for (const [key, value] of Object.entries(given)) {
      const property = this.#propertyOf(source, key);
      if (!property) invalid(`${key} is not a property that exists.`);
      if (!WRITABLE.includes(property.type)) invalid(`${property.name} is a ${property.type} property, which cannot be written.`);
      values[property.name] = {id: property.id, type: property.type, [property.type]: this.#typed(property, value, state)};
    }
    return values;
  }
  #emptyValue(source, property) {
    const base = {id: property.id, type: property.type};
    if (WRITABLE.includes(property.type)) return {...base, [property.type]: emptyOf(property.type), ...(property.type === 'relation' ? {has_more: false} : {})};
    if (property.type === 'unique_id') return {...base, unique_id: {prefix: property.unique_id.prefix, number: ++source.unique}};
    if (property.type === 'formula') return {...base, formula: {type: 'number', number: null}};
    if (property.type === 'rollup') return {...base, rollup: {type: 'number', number: null, function: 'sum'}};
    if (property.type === 'files') return {...base, files: []};
    if (property.type === 'verification') return {...base, verification: {state: 'unverified', verified_by: null, date: null}};
    return {...base, [property.type]: {}};
  }
  /** One typed value as a write sends it, checked by its property's type. */
  #typed(property, value, state) {
    const type = property.type, inner = record(value) && Object.hasOwn(value, type) ? value[type] : undefined;
    if (inner === undefined) invalid(`body.properties.${property.name}.${type} should be defined.`);
    const option = name => {
      const found = property[type].options.find(item => item.name === name);
      if (!found) invalid(`Invalid ${type} option "${name}" for ${property.name}.`);
      return {id: found.id, name: found.name, color: found.color};
    };
    if (type === 'title' || type === 'rich_text') return richText(inner, `properties.${property.name}.${type}`);
    if (type === 'number') { if (inner !== null && (typeof inner !== 'number' || !Number.isFinite(inner))) invalid(`${property.name} should be a number.`); return inner; }
    if (type === 'checkbox') { if (typeof inner !== 'boolean') invalid(`${property.name} should be a boolean.`); return inner; }
    if (type === 'select' || type === 'status') { if (inner === null) return null; if (!record(inner) || typeof inner.name !== 'string') invalid(`${property.name} should name an option.`); return option(inner.name); }
    if (type === 'multi_select') { if (!Array.isArray(inner) || inner.some(item => !record(item) || typeof item.name !== 'string')) invalid(`${property.name} should be a list of options.`); return inner.map(item => option(item.name)); }
    if (type === 'date') {
      if (inner === null) return null;
      const day = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})?)?$/;
      if (!record(inner) || typeof inner.start !== 'string' || !day.test(inner.start) || (inner.end !== undefined && inner.end !== null && (typeof inner.end !== 'string' || !day.test(inner.end)))) invalid(`${property.name} should be a date.`);
      return {start: inner.start, end: inner.end ?? null, time_zone: null};
    }
    if (type === 'url' || type === 'email' || type === 'phone_number') { if (inner !== null && typeof inner !== 'string') invalid(`${property.name} should be a string.`); return inner; }
    if (type === 'people') {
      if (!Array.isArray(inner) || inner.some(item => !record(item) || !state.users[canonicalId(item.id)])) invalid(`${property.name} should be a list of users.`);
      return inner.map(item => ({object: 'user', id: canonicalId(item.id)}));
    }
    if (!Array.isArray(inner) || inner.some(item => !record(item) || !canonicalId(item.id))) invalid(`${property.name} should be a list of pages.`);
    return inner.map(item => ({id: canonicalId(item.id)}));
  }
  /** A page parent's title value: properties holds title only, Notion's rule when the parent is a page. */
  #titleValue(properties) {
    if (properties === undefined) return {id: 'title', type: 'title', title: []};
    if (!record(properties) || Object.keys(properties).some(key => key !== 'title')) invalid('Title is the only valid property when the parent is a page.');
    const value = properties.title;
    return {id: 'title', type: 'title', title: richText(record(value) && !Array.isArray(value) ? value.title : value, 'properties.title.title')};
  }
  #create({state, body}) {
    const given = this.#body(body);
    this.#only(given, ['parent', 'properties', 'markdown', 'children', 'content', 'icon', 'cover', 'template', 'position']);
    if (given.markdown !== undefined && (given.children !== undefined || given.content !== undefined)) invalid('body.markdown should not be given with children or content.');
    if (given.markdown !== undefined && typeof given.markdown !== 'string') invalid('body.markdown should be a string.');
    if (given.children !== undefined || given.content !== undefined || given.template !== undefined || given.position !== undefined) refuse(400, 'not_simulated', 'The simulator takes markdown text only.');
    const parent = given.parent;
    if (!record(parent)) invalid('body.parent should be defined.');
    let page;
    if (parent.page_id !== undefined && parent.data_source_id === undefined) {
      const above = this.#writable(this.#visiblePage(parent.page_id, state));
      page = this.#newPage({parent: {type: 'page_id', page_id: above.id}, properties: {title: this.#titleValue(given.properties)}, markdown: given.markdown ?? ''}, state);
    } else if (parent.data_source_id !== undefined && parent.page_id === undefined) {
      const source = this.#visible('sources', parent.data_source_id, state);
      page = this.#newPage({parent: {type: 'data_source_id', data_source_id: source.id, database_id: source.database_id}, properties: this.#rowValues(source, given.properties ?? {}, null, state),
        markdown: given.markdown ?? ''}, state);
    } else invalid('body.parent should name exactly one of page_id and data_source_id.');
    return ok(this.#page(page));
  }
  #update({state, params, body}) {
    const given = this.#body(body), page = this.#visiblePage(params.page_id, state);
    this.#only(given, ['properties', 'in_trash', 'icon', 'cover']);
    if (given.in_trash !== undefined && typeof given.in_trash !== 'boolean') invalid('body.in_trash should be a boolean.');
    const restoring = given.in_trash === false;
    if (page.in_trash && !(restoring && Object.keys(given).length === 1)) this.#writable(page);
    let properties = page.properties;
    if (given.properties !== undefined) {
      if (page.parent.type === 'data_source_id') properties = this.#rowValues(state.sources[page.parent.data_source_id], given.properties, page.properties, state);
      else properties = {title: this.#titleValue(given.properties)};
    }
    page.properties = properties;
    if (given.in_trash !== undefined) page.in_trash = given.in_trash;
    page.last_edited_time = this.#now();
    page.last_edited_by = this.bot.id;
    return ok(this.#page(page));
  }
  /** The children of a page that its markdown names, in the order they were made: pages and databases, out of the trash. */
  #children(state, page) {
    return state.order.map(id => this.#node(state, id)).filter(node => node && node[0] !== 'sources' && node[1].parent?.page_id === page.id && !node[1].in_trash)
      .map(([kind, item]) => ({id: item.id, tag: `<${kind === 'pages' ? 'page' : 'database'} url="${linkOf(item.id)}">${this.#titleOf(item, kind)}</${kind === 'pages' ? 'page' : 'database'}>`}));
  }
  #render(state, page) {
    const unknown = Object.values(state.unknown).filter(block => block.page_id === page.id);
    return [page.text, ...this.#children(state, page).map(child => child.tag), ...unknown.map(block => `<unknown url="${linkOf(block.id)}" alt="block"/>`)].filter(part => part !== '').join('\n');
  }
  #markdownOf(id, state = this.data) {
    const block = state.unknown[canonicalId(id)];
    if (block) {
      const page = state.pages[block.page_id];
      if (!page || !this.#shared(state, 'pages', page)) notFound(id);
      return {object: 'page_markdown', id: block.id, markdown: block.markdown, truncated: false, unknown_block_ids: []};
    }
    const page = this.#visiblePage(id, state), unknown = Object.values(state.unknown).filter(item => item.page_id === page.id).map(item => item.id);
    const files = (page.files ?? []).map(name => signedLink(name, this.fileReads = (this.fileReads ?? 0) + 1));
    return {object: 'page_markdown', id: page.id, markdown: this.#render(state, {...page, text: [readBack(page.text), ...files].filter(Boolean).join('\n')}), truncated: unknown.length > 0, unknown_block_ids: unknown};
  }
  #editMarkdown({state, params, body}) {
    const given = this.#body(body), page = this.#writable(this.#visiblePage(params.page_id, state));
    this.#only(given, ['type', 'insert_content', 'update_content', 'replace_content', 'replace_content_range', 'markdown_version', 'allow_async']);
    if (given.allow_async !== undefined || (given.markdown_version !== undefined && given.markdown_version !== 'v1')) refuse(400, 'not_simulated', 'The simulator answers synchronously, in markdown v1.');
    const operation = given[given.type];
    if (!['insert_content', 'update_content', 'replace_content', 'replace_content_range'].includes(given.type) || !record(operation)) invalid('body.type should name one operation, with its object.');
    let warnings = [];
    if (given.type === 'insert_content') {
      this.#only(operation, ['content', 'after', 'position']);
      if (typeof operation.content !== 'string') invalid('body.insert_content.content should be a string.');
      if (operation.after !== undefined || operation.position !== undefined) refuse(400, 'not_simulated', 'The simulator appends at the end only.');
      page.text = page.text === '' ? operation.content : `${page.text}\n${operation.content}`;
    } else if (given.type === 'update_content') {
      this.#only(operation, ['content_updates', 'allow_deleting_content']);
      const updates = operation.content_updates;
      if (!Array.isArray(updates) || updates.length < 1 || updates.length > 100) invalid('body.update_content.content_updates should hold 1 to 100 updates.');
      const children = this.#children(state, page);
      let markdown = this.#render(state, page), matched = 0;
      for (const [index, update] of updates.entries()) {
        if (!record(update) || typeof update.old_str !== 'string' || update.old_str === '' || typeof update.new_str !== 'string') invalid(`body.update_content.content_updates[${index}] should be {old_str, new_str}.`);
        const find = markdown.includes(update.old_str) ? update.old_str : update.old_str.replace(/\\([\\*~`$[\]<>{}|^])/g, '$1'), count = markdown.split(find).length - 1;
        if (count === 0) { warnings.push({code: 'old_str_not_found', message: `content_updates[${index}]: old_str was not found.`}); continue; }
        if (count > 1 && update.replace_all_matches !== true) invalid(`content_updates[${index}]: old_str matched ${count} times; give more context or set replace_all_matches.`);
        markdown = update.replace_all_matches === true ? markdown.split(find).join(update.new_str) : markdown.replace(find, () => update.new_str);
        matched++;
      }
      if (matched === 0) invalid('No content_updates matched the page\'s content.');
      const dropped = children.filter(child => !markdown.includes(child.tag));
      if (dropped.length && operation.allow_deleting_content !== true) invalid(`This edit would delete child pages or databases: ${dropped.map(child => child.id).join(', ')}. Set allow_deleting_content to delete them.`);
      for (const child of dropped) { const [, item] = this.#node(state, child.id); item.in_trash = true; }
      const kept = children.filter(child => !dropped.includes(child)).map(child => child.tag), unknown = Object.values(state.unknown).filter(block => block.page_id === page.id);
      page.text = markdown.split('\n').filter(line => !kept.includes(line) && !unknown.some(block => line === `<unknown url="${linkOf(block.id)}" alt="block"/>`)).join('\n');
    } else refuse(400, 'not_simulated', `The simulator does not apply ${given.type}.`);
    page.last_edited_time = this.#now();
    page.last_edited_by = this.bot.id;
    return ok({...this.#markdownOf(page.id, state), ...(warnings.length ? {warnings} : {})});
  }
  #move({state, params, body}) {
    const given = this.#body(body), page = this.#writable(this.#visiblePage(params.page_id, state));
    this.#only(given, ['parent']);
    const parent = given.parent;
    if (!record(parent)) invalid('body.parent should be defined.');
    if (parent.type === 'data_source_id') refuse(400, 'not_simulated', 'The simulator moves pages under pages only.');
    if (parent.type !== 'page_id' || typeof parent.page_id !== 'string' || Object.keys(parent).some(key => !['type', 'page_id'].includes(key))) invalid('body.parent should be {type: "page_id", page_id}.');
    const target = this.#writable(this.#visiblePage(parent.page_id, state));
    if (target.id === page.id || this.#ancestors(state, 'pages', target).includes(page.id)) invalid('A page cannot be moved under itself or one of its descendants.');
    page.parent = {type: 'page_id', page_id: target.id};
    state.order = [...state.order.filter(id => id !== page.id), page.id];
    page.last_edited_time = this.#now();
    page.last_edited_by = this.bot.id;
    return ok(this.#page(page));
  }
  #trash({state, params}) {
    const id = canonicalId(params.block_id);
    if (state.databases[id]) {
      const database = this.#visible('databases', id, state);
      if (database.in_trash) invalid('Can\'t edit block that is archived.');
      database.in_trash = true;
      return ok({object: 'block', id: database.id, type: 'child_database', child_database: {title: plain(database.title)}, in_trash: true, has_children: false});
    }
    const page = this.#writable(this.#visiblePage(params.block_id, state));
    page.in_trash = true;
    page.last_edited_time = this.#now();
    page.last_edited_by = this.bot.id;
    return ok({object: 'block', id: page.id, parent: structuredClone(page.parent), type: 'child_page', child_page: {title: this.#titleOf(page, 'pages')}, in_trash: true, has_children: false,
      created_time: page.created_time, last_edited_time: page.last_edited_time});
  }

  // ---- search and queries ------------------------------------------------------------------------------------------------------------
  #search({state, body}) {
    const given = this.#body(body);
    this.#only(given, ['query', 'filter', 'sort', 'start_cursor', 'page_size']);
    if (given.query !== undefined && typeof given.query !== 'string') invalid('body.query should be a string.');
    if (given.sort !== undefined) refuse(400, 'not_simulated', 'The simulator orders search results its own way.');
    let kinds = ['pages', 'sources'];
    if (given.filter !== undefined) {
      if (!record(given.filter) || given.filter.property !== 'object' || !['page', 'data_source'].includes(given.filter.value)) invalid('body.filter.value should be "page" or "data_source".');
      kinds = given.filter.value === 'page' ? ['pages'] : ['sources'];
    }
    const needle = (given.query ?? '').toLowerCase();
    const found = kinds.flatMap(kind => Object.values(state[kind]).map(item => ({kind, item})))
      .filter(({kind, item}) => this.#shared(state, kind, item) && !(kind === 'pages' ? item.in_trash : state.databases[item.database_id]?.in_trash))
      .filter(({kind, item}) => (kind === 'pages' ? this.#titleOf(item, 'pages') : item.name).toLowerCase().includes(needle))
      .sort((a, b) => a.item.last_edited_time < b.item.last_edited_time ? 1 : a.item.last_edited_time > b.item.last_edited_time ? -1 : a.item.id < b.item.id ? -1 : 1)
      .map(({kind, item}) => kind === 'pages' ? this.#page(item) : this.#source(item, state));
    return ok(this.#paged(found, given.start_cursor, given.page_size, 'page_or_data_source'));
  }
  #query({state, params, body}) {
    const given = this.#body(body), source = this.#visible('sources', params.data_source_id, state);
    this.#only(given, ['filter', 'sorts', 'start_cursor', 'page_size', 'filter_properties']);
    if (given.sorts !== undefined || given.filter_properties !== undefined) refuse(400, 'not_simulated', 'The simulator gives rows in the order they were made.');
    const test = given.filter === undefined ? () => true : this.#condition(source, given.filter, 0);
    const rows = state.order.map(id => state.pages[id]).filter(page => page && page.parent.data_source_id === source.id && !page.in_trash && test(page)).map(page => this.#page(page));
    return ok(this.#paged(rows, given.start_cursor, given.page_size, 'page_or_data_source'));
  }
  /** A query filter as a test of one row: and, or, or one condition on a property by name or id. */
  #condition(source, filter, depth) {
    if (!record(filter) || depth > 2) invalid('body.filter should be a filter object.');
    for (const join of ['and', 'or']) {
      if (Object.hasOwn(filter, join)) {
        if (Object.keys(filter).length !== 1 || !Array.isArray(filter[join]) || filter[join].length > 100) invalid(`body.filter.${join} should be a list of filters.`);
        const tests = filter[join].map(item => this.#condition(source, item, depth + 1));
        return join === 'and' ? page => tests.every(check => check(page)) : page => tests.some(check => check(page));
      }
    }
    const property = typeof filter.property === 'string' ? this.#propertyOf(source, filter.property) : null;
    if (!property) invalid(`Could not find property with name or id: ${filter.property}.`);
    const type = property.type, rule = filter[type];
    if (Object.keys(filter).length !== 2 || !record(rule) || Object.keys(rule).length !== 1) invalid(`body.filter.${type} should be a ${type} filter.`);
    const [operator, wanted] = Object.entries(rule)[0], value = page => page.properties[property.name]?.[type];
    const text = ['title', 'rich_text'].includes(type) ? page => plain(value(page)) : page => value(page) ?? '';
    if (['title', 'rich_text', 'url', 'email', 'phone_number'].includes(type) && ['contains', 'equals'].includes(operator) && typeof wanted === 'string') {
      return operator === 'contains' ? page => text(page).toLowerCase().includes(wanted.toLowerCase()) : page => text(page) === wanted;
    }
    if (type === 'number' && operator === 'equals' && typeof wanted === 'number') return page => value(page) === wanted;
    if (type === 'checkbox' && operator === 'equals' && typeof wanted === 'boolean') return page => value(page) === wanted;
    if (['select', 'status'].includes(type) && operator === 'equals' && typeof wanted === 'string') return page => value(page)?.name === wanted;
    if (type === 'multi_select' && operator === 'contains' && typeof wanted === 'string') return page => (value(page) ?? []).some(option => option.name === wanted);
    if (['people', 'relation'].includes(type) && operator === 'contains' && typeof wanted === 'string') return page => (value(page) ?? []).some(item => item.id === canonicalId(wanted));
    if (type === 'date' && operator === 'equals' && typeof wanted === 'string') return page => (value(page)?.start ?? '').slice(0, 10) === wanted.slice(0, 10);
    return invalid(`body.filter.${type}.${operator} is not a filter the simulator takes for a ${type} property.`);
  }

  // ---- comments ----------------------------------------------------------------------------------------------------------------------
  #comments({state, query}) {
    const blockId = query.get('block_id');
    if (!blockId) invalid('block_id should be defined.');
    const page = this.#visiblePage(blockId, state);
    const open = Object.values(state.comments).filter(comment => comment.page_id === page.id && !comment.resolved)
      .sort((a, b) => a.created_time < b.created_time ? -1 : a.created_time > b.created_time ? 1 : 0).map(comment => this.#comment(comment));
    return ok(this.#paged(open, query.get('start_cursor'), query.get('page_size'), 'comment'));
  }
  #addComment({state, body}) {
    const given = this.#body(body);
    this.#only(given, ['parent', 'discussion_id', 'rich_text', 'attachments', 'display_name']);
    if ((given.parent === undefined) === (given.discussion_id === undefined)) invalid('Give exactly one of parent and discussion_id.');
    if (given.attachments !== undefined) refuse(400, 'not_simulated', 'The simulator takes text comments only.');
    let pageId, discussion;
    if (given.parent !== undefined) {
      if (!record(given.parent) || typeof given.parent.page_id !== 'string') invalid('body.parent should be {page_id}.');
      pageId = this.#writable(this.#visiblePage(given.parent.page_id, state)).id;
      discussion = this.#id('discussion');
    } else {
      const thread = Object.values(state.comments).find(comment => comment.discussion_id === given.discussion_id);
      if (!thread || !this.#shared(state, 'pages', state.pages[thread.page_id])) notFound(given.discussion_id);
      pageId = this.#writable(state.pages[thread.page_id]).id;
      discussion = thread.discussion_id;
    }
    const comment = {id: this.#id('comment'), page_id: pageId, discussion_id: discussion, rich_text: richText(given.rich_text, 'rich_text'), created_time: this.#now(), last_edited_time: this.#now(),
      created_by: this.bot.id, resolved: false};
    state.comments[comment.id] = comment;
    return ok(this.#comment(comment));
  }

  // ---- the seam ----------------------------------------------------------------------------------------------------------------------
  /** The route a method and a decoded path below the base take, with its parameters; literals win over parameters. */
  #routeOf(method, path) {
    const segments = path === '/' ? [] : path.slice(1).split('/').map(segment => { try { return decodeURIComponent(segment); } catch { return segment; } });
    let best = null;
    for (const route of this.routes) {
      if (route.method !== method || route.parts.length !== segments.length) continue;
      const params = {};
      let score = 0;
      const fits = route.parts.every((part, index) => {
        if (part.literal !== undefined) { score += 2; return part.literal === segments[index]; }
        params[part.param] = segments[index];
        score += 1;
        return segments[index] !== '';
      });
      if (fits && (!best || score > best.score)) best = {route, params, score};
    }
    return best;
  }
  #error(status, code, message, headers = {}) {
    return {status, headers, data: {object: 'error', status, code, message, request_id: `00000000-0000-4000-8000-${String(this.data.request++).padStart(12, '0')}`}};
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
    if (target.origin !== ORIGIN) throw notSent('Provider DNS lookup failed or timed out.');
    // Sent from here on: the call is recorded, without its Authorization header.
    const inBase = target.pathname.startsWith(`${BASE_PATH}/`), path = inBase ? target.pathname.slice(BASE_PATH.length) : target.pathname;
    const found = inBase ? this.#routeOf(method, path) : null;
    const raw = body === undefined ? undefined : Buffer.isBuffer(body) ? body.toString('utf8') : body;
    let parsed, parseFailed = false;
    if (raw !== undefined) { try { parsed = JSON.parse(raw); } catch { parsed = raw; parseFailed = true; } }
    const query = {};
    for (const [name, value] of target.searchParams) query[name] = Object.hasOwn(query, name) ? [query[name]].flat().concat(value) : value;
    const {authorization, ...kept} = lower;
    const call = {method, origin: target.origin, path, route: found?.route.key ?? null, query, headers: kept, body: parsed, write: found?.route.write === true, status: null};
    this.calls.push(call);
    const gate = found ? this.holds.get(found.route.key) : null;
    if (gate) { gate.reach(); await gate.released; }
    const chosen = found ? this.#take(found.route.key) : null;
    let answer;
    if (lower['notion-version'] === undefined) answer = this.#error(400, 'missing_version', 'Notion-Version header failed validation: Notion-Version should be defined.');
    else if (lower['notion-version'] !== VERSION) answer = this.#error(400, 'validation_error', `Notion-Version header failed validation: the only allowed value is "${VERSION}".`);
    else if (authorization !== `Bearer ${this.token}`) answer = this.#error(401, 'unauthorized', 'API token is invalid.');
    else if (!found) answer = this.#error(400, 'invalid_request_url', 'Invalid request URL.');
    else if (chosen?.kind === 'limit') answer = this.#error(429, 'rate_limited', 'You have been rate limited. Please try again in a few minutes.', {'retry-after': String(chosen.retryAfter)});
    else if (found.route.capability !== 'none' && !this.held.has(found.route.capability)) answer = this.#error(403, 'restricted_resource', 'Insufficient permissions for this endpoint.');
    else if (chosen?.kind === 'fail') answer = structuredClone(chosen.answer);
    else if (parseFailed) answer = this.#error(400, 'invalid_json', 'Error parsing JSON body.');
    else {
      const state = chosen?.kind === 'swallow' ? structuredClone(this.data) : this.data;
      try {
        answer = found.route.handle({params: found.params, query: target.searchParams, body: parsed, headers: lower, state});
      } catch (error) {
        if (!(error instanceof Refusal)) throw error;
        answer = this.#error(error.status, error.code, error.message, error.headers);
      }
      if (chosen?.kind === 'drop') { call.status = answer.status; throw lost('Provider connection failed.'); }
      if (chosen?.kind === 'oversize') answer = {...answer, data: {...answer.data, padding: 'x'.repeat(Math.max(0, chosen.bytes))}};
    }
    call.status = answer.status;
    const headersOut = Object.fromEntries(Object.entries(answer.headers ?? {}).map(([name, value]) => [name.toLowerCase(), String(value)]));
    const bytes = answer.data === null || answer.data === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(answer.data), 'utf8');
    if (bytes.length > maxBytes) throw lost('Provider response exceeded the size limit.');
    if (bytes.length) headersOut['content-type'] ??= 'application/json; charset=utf-8';
    const shown = {};
    for (const key of responseHeaders) if (headersOut[key] !== undefined) shown[key] = headersOut[key];
    // A fresh parse of the bytes, so nothing the caller holds shares memory with the simulator's state.
    return {status: answer.status, headers: shown, data: responseType === 'buffer' ? bytes : bytes.length ? JSON.parse(bytes.toString('utf8')) : null};
  }
}

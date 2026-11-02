import { mkdirSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { checkedClock } from '../contracts/repository.mts';
import { LocalAuthority, serializeAuthorityDocument, assertAuthorityDocumentsPresent } from './local-authority.mts';
import { scrubAuthorization } from './redaction.mjs';

const SENSITIVE = /token|password|secret|authorization|cookie|verifier|credential|private.?key/i;
function safeAudit(value, depth = 0) {
  if (depth > 5) return '[truncated]';
  if (Array.isArray(value)) return value.slice(0, 30).map(v => safeAudit(v, depth + 1));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).filter(([k]) => !SENSITIVE.test(k)).map(([k,v]) => [k, safeAudit(v, depth + 1)]));
  if (typeof value === 'string') return scrubAuthorization(value).slice(0, 1000);
  return value;
}

/** Iteration 9 (docs/I07-BUILD-MAP.md section 2.1): events, each client's next sequence, and the seen rows. They sit outside `documents` so a page reads by key. */
const TRIGGER_TABLES = `CREATE TABLE IF NOT EXISTS trigger_events (
  client_id TEXT NOT NULL, seq INTEGER NOT NULL, subscription_id TEXT NOT NULL, dedupe_key TEXT NOT NULL,
  connection_id TEXT NOT NULL, user_record_id TEXT, kind TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, payload TEXT NOT NULL,
  PRIMARY KEY (client_id, seq), UNIQUE (subscription_id, dedupe_key));
CREATE INDEX IF NOT EXISTS trigger_events_expiry ON trigger_events(expires_at);
CREATE INDEX IF NOT EXISTS trigger_events_connection ON trigger_events(connection_id);
CREATE TABLE IF NOT EXISTS trigger_sequences (client_id TEXT PRIMARY KEY, next_seq INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS trigger_seen (
  feed_id TEXT NOT NULL, lens TEXT NOT NULL, item_key TEXT NOT NULL, value_hash TEXT NOT NULL, generation INTEGER NOT NULL,
  seen_at INTEGER NOT NULL, connection_id TEXT NOT NULL, PRIMARY KEY (feed_id, lens, item_key)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS trigger_seen_age ON trigger_seen(feed_id, lens, seen_at);
CREATE INDEX IF NOT EXISTS trigger_seen_connection ON trigger_seen(connection_id);`;
const TRIGGER_TABLE_COUNT = 3;
/** Spec lines 1819 and 1820: what one subscription keeps, and the most one event may hold as stored. */
const EVENTS_KEPT = 1000, EVENT_BYTES = 8192;
const EVENT_NAMES = ['clientId', 'subscriptionId', 'dedupeKey', 'connectionId', 'kind'];
/**
 * One event as its row, checked before any transaction opens. INSERT OR IGNORE skips a row with a missing field as quietly as a duplicate,
 * so a missing field is refused here, where it can be heard. A bad event refuses its whole poll: the engine holds 8,192 bytes to itself first.
 */
function eventRow(event) {
  if (EVENT_NAMES.some(name => typeof event?.[name] !== 'string' || !event[name]) || !Number.isSafeInteger(event.createdAt) || !Number.isSafeInteger(event.expiresAt)) throw new Error('A trigger event names its client, subscription, key, account and kind, with its two times.');
  if (event.itemTime !== undefined && !Number.isFinite(event.itemTime)) throw new Error('A trigger event\'s itemTime is a number.');
  const payload = JSON.stringify(event.payload);
  if (payload === undefined || Buffer.byteLength(payload) > EVENT_BYTES) throw new Error('A trigger event is JSON of at most 8,192 bytes.');
  return {...event, userRecordId: event.userRecordId ?? null, payload};
}
/** Oldest first, so an agent never reads a `desc` page backwards. An equal time keeps its order, and events with no time follow, in theirs. */
const byItemTime = (a, b) => (a.itemTime === undefined) - (b.itemTime === undefined) || (a.itemTime ?? 0) - (b.itemTime ?? 0);
const validLimit = rule => Number.isSafeInteger(rule?.limit) && rule.limit > 0 && typeof rule.evict === 'boolean';

export class Store {
  #authority;
  #where = new Map();
  #triggers = null;
  /** secureDelete: deleted and replaced documents are overwritten in the file, so erased data leaves no bytes behind (tenant stores, and the owner's local store since Iteration 9). */
  constructor({ dataDir, clock = Date.now, localAuthority, secureDelete = false } = {}) {
    this.clock = checkedClock(clock);
    mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    chmodSync(dataDir, 0o700);
    const file = join(dataDir, 'fabric.sqlite');
    this.db = new DatabaseSync(file);
    try {
      chmodSync(file, 0o600);
      assertAuthorityDocumentsPresent(this.db, localAuthority);
      if (secureDelete) this.db.exec('PRAGMA secure_delete=ON;');
      this.db.exec('PRAGMA journal_mode=DELETE; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS documents (collection TEXT NOT NULL, id TEXT NOT NULL, document TEXT NOT NULL, PRIMARY KEY(collection,id));');
      this.read = this.db.prepare('SELECT document FROM documents WHERE collection=? AND id=?');
      this.all = this.db.prepare('SELECT document FROM documents WHERE collection=? ORDER BY rowid');
      this.write = this.db.prepare('INSERT INTO documents(collection,id,document) VALUES(?,?,?) ON CONFLICT(collection,id) DO UPDATE SET document=excluded.document');
      this.remove = this.db.prepare('DELETE FROM documents WHERE collection=? AND id=?');
      this.#authority = new LocalAuthority(this.db, localAuthority);
    } catch (error) { this.db.close(); throw error; }
  }
  get authorityEnabled() { return this.#authority.enabled; }
  connectionGeneration(id) { return this.#authority.lookup('connection', id); }
  policyRevision(id) { return this.#authority.lookup('policy', id); }
  get(collection, id) { const row = this.read.get(String(collection), String(id)); return row ? JSON.parse(row.document) : null; }
  list(collection) { return this.all.all(String(collection)).map(row => JSON.parse(row.document)); }
  /**
   * The documents of one collection whose top-level field equals value, read through an index on that field (made the
   * first time the field is asked for), so only matching documents are parsed. Developer environments read one
   * person's records this way; a store nobody asks keeps its single table.
   */
  listWhere(collection, field, value) {
    if (typeof field !== 'string' || !/^[A-Za-z][A-Za-z0-9]{0,63}$/.test(field)) throw new Error('A field name is a plain name.');
    let query = this.#where.get(field);
    if (!query) {
      this.db.exec(`CREATE INDEX IF NOT EXISTS documents_by_${field} ON documents(collection, json_extract(document, '$.${field}'))`);
      query = this.db.prepare(`SELECT document FROM documents WHERE collection=? AND json_extract(document, '$.${field}')=? ORDER BY rowid`);
      this.#where.set(field, query);
    }
    return query.all(String(collection), String(value)).map(row => JSON.parse(row.document));
  }
  /**
   * The prepared trigger statements, or null while this file lacks the tables, so a store nobody subscribes on keeps its single table. Only a
   * yes is remembered: another handle on this file can make the tables later.
   */
  #triggerReads() {
    if (this.#triggers) return this.#triggers;
    const found = this.db.prepare("SELECT count(*) AS tables FROM sqlite_master WHERE type='table' AND name IN ('trigger_events','trigger_sequences','trigger_seen')").get().tables;
    if (found !== TRIGGER_TABLE_COUNT) return null;
    const prepare = text => this.db.prepare(text);
    this.#triggers = {
      nextSequence: prepare('SELECT next_seq FROM trigger_sequences WHERE client_id=?'),
      takeSequence: prepare('INSERT INTO trigger_sequences(client_id,next_seq) VALUES(?,?) ON CONFLICT(client_id) DO UPDATE SET next_seq=excluded.next_seq'),
      addEvent: prepare('INSERT OR IGNORE INTO trigger_events(client_id,seq,subscription_id,dedupe_key,connection_id,user_record_id,kind,created_at,expires_at,payload) VALUES(?,?,?,?,?,?,?,?,?,?)'),
      staleGap: prepare("DELETE FROM trigger_events WHERE subscription_id=? AND dedupe_key=? AND kind='trigger.gap' AND payload<>?"),
      keptFrom: prepare('SELECT seq FROM trigger_events WHERE subscription_id=? ORDER BY seq DESC LIMIT 1 OFFSET ?'),
      pruneEvents: prepare('DELETE FROM trigger_events WHERE subscription_id=? AND seq<?'),
      putSeen: prepare('INSERT INTO trigger_seen(feed_id,lens,item_key,value_hash,generation,seen_at,connection_id) VALUES(?,?,?,?,?,?,?) ON CONFLICT(feed_id,lens,item_key) DO UPDATE SET value_hash=excluded.value_hash,generation=excluded.generation,seen_at=excluded.seen_at,connection_id=excluded.connection_id'),
      countSeen: prepare('SELECT count(*) AS rows FROM trigger_seen WHERE feed_id=? AND lens=?'),
      evictSeen: prepare('DELETE FROM trigger_seen WHERE feed_id=? AND lens=? AND item_key IN (SELECT item_key FROM trigger_seen WHERE feed_id=? AND lens=? ORDER BY seen_at, item_key LIMIT ?)'),
      readSeen: prepare('SELECT value_hash, generation FROM trigger_seen WHERE feed_id=? AND lens=? AND item_key=?'),
      eventPage: prepare('SELECT seq, subscription_id, dedupe_key, connection_id, user_record_id, kind, created_at, expires_at, payload FROM trigger_events WHERE client_id=? AND seq>? AND expires_at>? ORDER BY seq LIMIT ?'),
      dropSubscription: prepare('DELETE FROM trigger_events WHERE subscription_id=?'),
      dropAccountEvents: prepare('DELETE FROM trigger_events WHERE connection_id=?'),
      dropAccountSeen: prepare('DELETE FROM trigger_seen WHERE connection_id=?'),
      dropFeed: prepare('DELETE FROM trigger_seen WHERE feed_id=?'),
      dropLens: prepare('DELETE FROM trigger_seen WHERE feed_id=? AND lens=?'),
      sweep: prepare('DELETE FROM trigger_events WHERE expires_at<=?'),
    };
    return this.#triggers;
  }
  /** The statements, making the tables the first time a write needs them. They land with their indexes or not at all: three tables read as done for good. */
  #triggerTables() {
    if (!this.#triggerReads()) this.#atomically(() => this.db.exec(TRIGGER_TABLES));
    return this.#triggerReads();
  }
  /** One commit around synchronous work. Private on purpose: this is no general transaction API, and guarantees.transactions stays false. */
  #atomically(work) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const value = work(); this.db.exec('COMMIT'); return value; }
    catch (error) { if (this.db.isTransaction) this.db.exec('ROLLBACK'); throw error; }
  }
  /**
   * Stores one poll's events and seen rows in one commit, with no await. The feed's cursor document follows with `put`, so a crash between the
   * two replays the poll, finds the seen rows current and fires nothing. Each `itemKey` is already hashed, and `seen_at` is this store's clock.
   * A duplicate takes no sequence, so a client's numbers stay contiguous and a hole in them is exactly what retention or the cap removed. A
   * lens past its limit loses its oldest rows when `evict` is true, or is reported when false. Answers {added: {<clientId>: count}, overLimit: [{lens, count}]}.
   */
  appendPoll({ feedId, seen = [], seenLimits = {}, events = [] }) {
    if (this.db.isTransaction) throw new Error('A poll is stored in its own transaction.');
    if (typeof feedId !== 'string' || !feedId) throw new Error('A poll names its feed.');
    const limits = Object.entries(seenLimits);
    if (!limits.every(([, rule]) => validLimit(rule))) throw new Error('A seen limit is {limit, evict}: a positive integer and true or false.');
    const rows = events.map(eventRow).sort(byItemTime), at = this.clock(), added = new Map(), written = new Set(), overLimit = [], sql = this.#triggerTables();
    this.#atomically(() => {
      for (const row of rows) {
        // A replay keeps a gap's key, and what was written since the first attempt lies past its end. So a gap stored again takes a new number in the first one's place: an agent that read the first still hears.
        if (row.kind === 'trigger.gap') sql.staleGap.run(row.subscriptionId, row.dedupeKey, row.payload);
        const seq = sql.nextSequence.get(row.clientId)?.next_seq ?? 1;
        const inserted = sql.addEvent.run(row.clientId, seq, row.subscriptionId, row.dedupeKey, row.connectionId, row.userRecordId, row.kind, row.createdAt, row.expiresAt, row.payload).changes > 0;
        if (!inserted) continue;
        sql.takeSequence.run(row.clientId, seq + 1);
        added.set(row.clientId, (added.get(row.clientId) ?? 0) + 1);
        written.add(row.subscriptionId);
      }
      for (const row of seen) sql.putSeen.run(feedId, row.lens, row.itemKey, row.valueHash, row.generation, at, row.connectionId);
      for (const id of written) {
        const oldest = sql.keptFrom.get(id, EVENTS_KEPT - 1);
        if (oldest) sql.pruneEvents.run(id, oldest.seq);
      }
      for (const [lens, {limit, evict}] of limits) {
        const count = sql.countSeen.get(feedId, lens).rows;
        if (count <= limit) continue;
        if (evict) sql.evictSeen.run(feedId, lens, feedId, lens, count - limit);
        else overLimit.push({lens, count});
      }
    });
    return {added: Object.fromEntries(added), overLimit};
  }
  /** The seen rows of these hashed keys, as a Map of key to {valueHash, generation}. A key with no row is not in it. */
  seenRows(feedId, lens, keys) {
    const sql = this.#triggerReads(), found = new Map();
    if (!sql) return found;
    for (const key of keys) {
      const row = sql.readSeen.get(feedId, lens, key);
      if (row) found.set(key, {valueHash: row.value_hash, generation: row.generation});
    }
    return found;
  }
  /** One page of a client's events after a sequence, by primary key, oldest first. An expired event reads as gone before the sweep reaches it. */
  listEvents(clientId, after, limit) {
    if (!Number.isSafeInteger(after) || after < 0 || !Number.isSafeInteger(limit) || limit < 1) throw new Error('A page of events starts at a whole sequence and holds at least one.');
    const sql = this.#triggerReads();
    if (!sql) return [];
    return sql.eventPage.all(clientId, after, this.clock(), limit).map(row => ({sequence: row.seq, subscriptionId: row.subscription_id, dedupeKey: row.dedupe_key, connectionId: row.connection_id,
      userRecordId: row.user_record_id, kind: row.kind, createdAt: row.created_at, expiresAt: row.expires_at, payload: JSON.parse(row.payload)}));
  }
  /** The last sequence a client was given, or 0. It never falls: rows go, numbers do not come back. */
  latestSequence(clientId) {
    const row = this.#triggerReads()?.nextSequence.get(clientId);
    return row ? row.next_seq - 1 : 0;
  }
  /** Each delete answers how many rows went. None of them touches a client's sequence. */
  deleteSubscriptionEvents(id) { return this.#triggerReads()?.dropSubscription.run(id).changes ?? 0; }
  deleteConnectionTriggerData(connectionId) {
    const sql = this.#triggerReads();
    return sql ? this.#atomically(() => sql.dropAccountEvents.run(connectionId).changes + sql.dropAccountSeen.run(connectionId).changes) : 0;
  }
  deleteFeedSeen(feedId) { return this.#triggerReads()?.dropFeed.run(feedId).changes ?? 0; }
  deleteLensSeen(feedId, lens) { return this.#triggerReads()?.dropLens.run(feedId, lens).changes ?? 0; }
  /** Deletes events whose own expires_at has come, and never makes a table. Seen rows stay: a key must last as long as its cursor. */
  sweepEvents(now) { return this.#triggerReads()?.sweep.run(now).changes ?? 0; }
  put(collection, object) {
    collection = String(collection);
    const serialized = this.authorityEnabled && ['connections','permissions','browserDevices','persistentSessions'].includes(collection) ? serializeAuthorityDocument(object,collection) : null;
    if (!object || typeof object.id !== 'string' || !object.id || object.id.length > 256) throw new Error('A bounded document id is required.');
    const document = serialized ?? JSON.stringify(object);
    return this.#authority.mutate(collection,object.id,document,()=>{
      this.write.run(collection, object.id, document);
      return this.get(collection, object.id);
    });
  }
  delete(collection, id) {
    collection=String(collection);id=String(id);
    return this.#authority.mutate(collection,id,null,()=>this.remove.run(collection,id).changes>0);
  }
  audit(event) {
    // Callers must pass metadata only: request/response bodies and free-form secrets do not belong in the audit journal.
    const safe = safeAudit(event);
    return this.put('activity', { ...safe, id: randomUUID(), createdAt: new Date(this.clock()).toISOString() });
  }
  close() { this.db.close(); }
}

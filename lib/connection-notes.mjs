// F10.19 part 2 (docs/F10.19-BUILD-MAP.md section 2, the account note; spec lines 1176-1177): how many pages a Notion account shared with
// Fabric, as an agent's last full Search saw them. Notion's sign-in names no pages, so the account row says "Pages you shared (N)" only after
// a succeeded Search with no words, no kind and no cursor: N is the number of results (at most 100) and `more` says Notion had more. The
// note lives in its own collection, `connectionNotes`, by connection id, never on the connection record, so the account's generation, health
// fields, bindings and grants never move. This file is the only one that reads or writes the collection: the runtime calls notePages() when
// a read job succeeds, the account rows read pagesLevel(), and a disconnect calls forgetPages(). An end user's erasure removes the note with
// the user's other records (END_USER_COLLECTIONS). Agents never read it.
import {stampOwner} from './tenant/deployment.mjs';

export const NOTES = 'connectionNotes';
/** The action whose answer counts an app's shared pages, by app. */
export const NOTE_SOURCES = Object.freeze({notion: Object.freeze({action: 'search'})});
/** Search reads 100 a page, so a note counts at most 100. */
const MAX_PAGES = 100;
/** The inputs that narrow a Search: with any of them, its results are not every shared page. */
const NARROWING = Object.freeze(['query', 'kind', 'cursor']);
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);

/**
 * After a succeeded job of an app's note source (Search with no query, kind or cursor): writes the account's note,
 * {id, connectionId, appId, pages, more, at}, stamped with the job's owner in a developer environment. `entry` is the action's app and
 * key, {appId, key}; `output` the job's checked output. Any other job writes nothing. Returns the note written, or null.
 */
export function notePages(store, job, entry, output, at) {
  const source = Object.hasOwn(NOTE_SOURCES, entry?.appId ?? '') ? NOTE_SOURCES[entry.appId] : null;
  if (!source || entry.key !== source.action || job?.status !== 'succeeded' || typeof job.connectionId !== 'string') return null;
  const args = record(job.args) ? job.args : {};
  if (NARROWING.some(name => Object.hasOwn(args, name))) return null;
  if (!record(output) || !Array.isArray(output.results) || output.results.length > MAX_PAGES || typeof output.hasMore !== 'boolean') return null;
  const owner = job.userRecordId ? {subjectId: job.ownership?.owner?.id, userRecordId: job.userRecordId} : null;
  const note = {id: job.connectionId, connectionId: job.connectionId, appId: entry.appId, pages: output.results.length, more: output.hasMore, at, ...(owner ? stampOwner({}, owner) : {})};
  store.put(NOTES, note);
  return note;
}

/** The account's note, {pages, more}, when one was written for this connection of this app; otherwise null. */
export function pagesNote(store, connection) {
  if (typeof connection?.id !== 'string') return null;
  const note = store.get(NOTES, connection.id);
  if (!record(note) || note.connectionId !== connection.id || note.appId !== connection.appId || !Number.isSafeInteger(note.pages) || note.pages < 0 || typeof note.more !== 'boolean') return null;
  return {pages: note.pages, more: note.more};
}

/** A held level with the note's count: a `pages` grant with a note reads {level: 'pages', pages, more}; any other level is unchanged. */
export const withPages = (held, note) => held === 'pages' && note ? {level: 'pages', pages: note.pages, more: note.more} : held;

/** The held level an account row shows: `held` with this account's note when it has one. */
export const pagesLevel = (store, connection, held) => withPages(held, held === 'pages' ? pagesNote(store, connection) : null);

/** A disconnect: the account's note goes with it. */
export function forgetPages(store, connectionId) {
  if (typeof connectionId === 'string' && store.get(NOTES, connectionId)) store.delete(NOTES, connectionId);
}

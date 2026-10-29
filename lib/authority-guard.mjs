// Opt-in local lifecycle guard. Presence and generation are separate: a deleted
// connection retains a counter, but cannot authorize a late callback.
function changed() {
  const error = new Error('Connection authority changed while work was pending. Start a new request.');
  error.code = 'connection_changed';
  throw error;
}

export function captureConnectionAuthority(store, id) {
  if (!store.authorityEnabled) return null;
  if (!store.get('connections', id)) changed();
  return Object.freeze({id, generation: store.connectionGeneration(id)});
}

export function assertConnectionAuthority(store, snapshot) {
  if (!store.authorityEnabled) return null;
  if (!snapshot || typeof snapshot.id !== 'string' || !Number.isSafeInteger(snapshot.generation) || snapshot.generation < 1) changed();
  const current = store.get('connections', snapshot.id);
  if (!current || store.connectionGeneration(snapshot.id) !== snapshot.generation) changed();
  return current;
}

// F10.4 (T7): a renewal keeps authRevision and the generation, so a stale-result guard also compares which sign-in wrote
// the record. Records and flows from before sign-in revisions existed compare as null.
export function sameSignIn(a, b) {
  return (a?.signInRevision ?? null) === (b?.signInRevision ?? null);
}

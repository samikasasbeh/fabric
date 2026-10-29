// F03.0b cross-tenant matrix (docs/F03-DEVELOPER-LAYER.md, "The adversarial cross-tenant matrix"), strengthened after
// the F03.0 security review. Cells (organization x environment) share every guessable id; each cell holds two end
// users. Every operation runs as every actor (cell and user) against every other target, and passes only if:
//   1. its answer for another target equals its answer for a target that never existed (N2: no existence oracle,
//      no counts, no shared-value leaks);
//   2. no cell's store ends up holding another cell's data (no copy-in), and no other user's data reaches the actor;
//   3. no other cell's files, the platform catalog, the registry or the root files change;
//   4. the same actor on its own data succeeds (refusing everything cannot pass).
import {createHash} from 'node:crypto';
import {existsSync, readdirSync, readFileSync, statSync} from 'node:fs';
import path from 'node:path';
import {endUser, stampOwner} from '../../lib/tenant/deployment.mjs';

export const ORGS = Object.freeze(['acme', 'beta']);
export const ENVIRONMENTS = Object.freeze(['development', 'production']);
export const USERS = Object.freeze(['u1', 'u2']);
/** Ids every cell reuses, so anything keyed without the environment collides. */
export const SHARED = Object.freeze({connection: 'conn-1', approval: 'appr-1', session: 'sess-1', idempotency: 'idem-1', subject: 'google-sub-123', email: 'same@example.com'});
const SWEPT = Object.freeze(['connections', 'approvals', 'connectSessions', 'activity']);
const short = text => createHash('sha256').update(text).digest('hex').slice(0, 10);

const digest = target => {
  const files = [];
  const walk = folder => { for (const entry of readdirSync(folder, {withFileTypes: true})) { const full = path.join(folder, entry.name); if (entry.isDirectory()) walk(full); else if (!entry.name.includes('.lock')) files.push(`${full}:${createHash('sha256').update(readFileSync(full)).digest('hex')}`); } };
  if (existsSync(target)) { if (statSync(target).isDirectory()) walk(target); else files.push(`${target}:${createHash('sha256').update(readFileSync(target)).digest('hex')}`); }
  return files.sort().join('\n');
};

/** One cell per organization and environment, each seeded with the same ids, unique ids, and two end users. */
export function buildCells(stores, root) {
  const cells = [];
  for (const organizationId of ORGS) for (const environmentId of ENVIRONMENTS) {
    const scope = {organizationId, projectId: 'agent', environmentId}, handle = stores.open(scope), marker = `cell:${handle.scopeKey}`, tag = short(handle.scopeKey);
    const users = Object.fromEntries(USERS.map((user, index) => [user, endUser({subjectId: `ext-${user}`, userRecordId: `usr_${(tag + 'abcdefghijklmnopqrstuvwxyz').replace(/[^a-z2-7]/g, 'a').slice(0, 25)}${'ab'[index]}`})]));
    for (const user of USERS) {
      handle.repository.put('connections', stampOwner({id: `${SHARED.connection}-${user}`, appId: 'gmail', identity: {subject: SHARED.subject, email: SHARED.email}, marker, userMarker: `${marker}/${user}`}, users[user]));
      handle.vault.set(`${SHARED.connection}-${user}`, {accessToken: `synthetic-${marker}-${user}`});
    }
    handle.repository.put('connections', {id: SHARED.connection, appId: 'gmail', identity: {subject: SHARED.subject, email: SHARED.email}, marker});
    handle.repository.put('connections', {id: `unique-${tag}`, appId: 'gmail', marker});
    handle.repository.put('approvals', {id: SHARED.approval, idempotencyKey: SHARED.idempotency, marker});
    handle.repository.put('connectSessions', {id: SHARED.session, marker});
    handle.repository.audit({type: 'connection.connected', connectionId: SHARED.connection, marker});
    handle.vault.set(SHARED.connection, {accessToken: `synthetic-${marker}`});
    cells.push({scope, key: handle.scopeKey, marker, folder: handle.folder, handle, users, uniqueIds: {connection: `unique-${tag}`}});
  }
  // A target that never existed: its ids are guessable-looking but absent everywhere.
  const ghost = {key: 'ghost', marker: 'cell:ghost', users: {}, uniqueIds: {connection: 'unique-never-existed'}};
  return Object.assign(cells, {root, ghost});
}

/**
 * Runs every operation as every actor (cell and user) against every other cell.
 * @param {{cells: any[], operations: {name: string, run: (actor: any, target: any) => unknown}[]}} input
 * @returns {{attempts: number, violations: string[], controlFailures: string[]}}
 */
export function runMatrix({cells, operations}) {
  const violations = [], controlFailures = [];
  let attempts = 0;
  const observe = fn => { try { return {value: fn()}; } catch (error) { return {error: error.code || error.message}; } };
  const shared = cells.root ? [path.join(cells.root, 'platform'), path.join(cells.root, 'registry'), path.join(cells.root, 'tenant-root.json')] : [];
  const sweep = (operation, actorKey) => {
    for (const cell of cells) for (const collection of SWEPT) {
      let documents;
      try { documents = cell.handle.repository.list(collection); } catch (error) { violations.push(`${operation}: ${cell.key}'s ${collection} holds a foreign row (${error.code}) after ${actorKey}`); continue; }
      const text = JSON.stringify(documents);
      for (const other of cells) if (other !== cell && text.includes(`"${other.marker}"`)) violations.push(`${operation}: ${cell.key}'s ${collection} holds ${other.key}'s data after ${actorKey}`);
    }
  };
  for (const operation of operations) for (const cell of cells) for (const user of USERS) {
    const actor = {...cell, user: cell.users[user], userName: user}, actorKey = `${cell.key}/${user}`;
    // Control: on its own cell the actor must reach its own data.
    const own = observe(() => operation.run(actor, cell));
    if (own.error || !JSON.stringify(own.value ?? null).includes(cell.marker)) controlFailures.push(`${operation.name}: ${actorKey} cannot reach its own data (${own.error || 'no own marker'})`);
    const baseline = JSON.stringify(observe(() => operation.run(actor, cells.ghost)));
    for (const target of cells) {
      if (target === cell) continue;
      attempts++;
      const watched = [...cells.filter(other => other !== cell).map(other => other.folder), ...shared];
      const before = watched.map(digest);
      const result = observe(() => operation.run(actor, target));
      const seen = JSON.stringify(result);
      if (seen !== baseline) violations.push(`${operation.name}: ${actorKey} got a different answer for ${target.key} than for a target that never existed`);
      for (const other of cells) if (other !== cell && seen.includes(`"${other.marker}"`)) violations.push(`${operation.name}: ${actorKey} saw ${other.key}'s data`);
      for (const name of USERS) if (name !== user && seen.includes(`"${cell.marker}/${name}"`)) violations.push(`${operation.name}: ${actorKey} saw ${name}'s data in its own environment`);
      const after = watched.map(digest);
      watched.forEach((folder, index) => { if (before[index] !== after[index]) violations.push(`${operation.name}: ${actorKey} changed ${path.basename(folder)} while targeting ${target.key}`); });
      sweep(operation.name, actorKey);
    }
  }
  return {attempts, violations, controlFailures};
}

/** Every route the tenant router exposes must have a matrix row; returns the routes without one. */
export function uncoveredRoutes(routes, operations) {
  const covered = new Set(operations.map(operation => operation.route).filter(Boolean));
  return routes.filter(route => !covered.has(route));
}

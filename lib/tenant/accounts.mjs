// F03.5a (docs/F03-DEVELOPER-LAYER.md sections 5.5 and 5.7): what a developer's server sees and does about its end
// users' accounts. A user-asserting route resolves the end user first and the account second; an environment-wide
// route resolves the owner from the stored record and fails closed without one. An account of another end user,
// another environment, or none at all gets the same not_found. Disconnect goes through the environment's sign-in
// adapter, whose revocation policy (N9) decides whether the provider is asked: Fabric's shared Google app never is (D4).
import {TenantError, notFound, invalid} from './errors.mjs';
import {endUser, ownedBy, ownershipOf, stampOwner, tenantDeployment} from './deployment.mjs';
import {developerAccountRow, signInOf, tenantApps} from './views.mjs';
import {developerParty, partyFields} from './party.mjs';
import {ConnectionManager} from '../connections.mjs';
import {current} from '../connection-notices.mjs';
import {pagesNote} from '../connection-notes.mjs';

const SUBJECT = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;
const ACCOUNT_REF = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DEFAULTS = 'defaultAccounts';
/** Present accounts: neither disconnected nor waiting for the person's confirmation. */
export const present = connection => !['revoked', 'pending_confirmation'].includes(connection?.status);

/** The external id a route names, checked against the identity contract's rule (D6). */
export function externalId(value) {
  if (typeof value !== 'string' || !SUBJECT.test(value)) throw new TenantError(400, 'invalid_external_user_id', 'externalUserId must be 1 to 128 characters: letters, digits and . _ : @ -');
  return value;
}

/** Stable paging over items sorted by (createdAt, id): the cursor names the last item seen, so deletions never shift a page. */
export function pageOf(items, {after, limit}) {
  const size = limit === undefined || limit === null || limit === '' ? 50 : Number(limit);
  if (!Number.isSafeInteger(size) || size < 1 || size > 100) throw invalid('limit must be 1 to 100.');
  const sorted = [...items].sort((a, b) => a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  let start = 0;
  if (after !== undefined && after !== null && after !== '') {
    let mark;
    try { mark = JSON.parse(Buffer.from(String(after), 'base64url').toString('utf8')); } catch { throw invalid('The cursor is not valid.'); }
    if (!Array.isArray(mark) || mark.length !== 2 || mark.some(part => typeof part !== 'string')) throw invalid('The cursor is not valid.');
    start = sorted.findIndex(item => item.createdAt > mark[0] || (item.createdAt === mark[0] && item.id > mark[1]));
    if (start < 0) start = sorted.length;
  }
  const page = sorted.slice(start, start + size), last = page.at(-1);
  return {page, pageInfo: {count: page.length, totalCount: sorted.length, ...(start + size < sorted.length ? {endCursor: Buffer.from(JSON.stringify([last.createdAt, last.id])).toString('base64url')} : {})}};
}

export class TenantAccounts {
  /** @param {{stores: any, registry: any, providerApps: any, adapterFor: (scope: any, providerId: string) => {adapter: any, connections: any, env: any}}} deps */
  constructor(deps) { Object.assign(this, deps); }

  /** The environment's active end user for an external id, or null. */
  user(env, externalUserId) {
    const subjectId = externalId(externalUserId);
    return env.repository.list('endUsers').find(user => user.status === 'active' && user.subjectId === subjectId) ?? null;
  }
  ownerOf(user) { return endUser({subjectId: user.subjectId, userRecordId: user.id}); }
  /** One end user's present accounts, in the order they were stored. */
  accountsOf(env, owner) {
    const deployment = tenantDeployment(env.scope);
    return env.repository.list('connections').filter(connection => present(connection) && ownedBy(connection, owner, deployment));
  }
  #defaultId(owner, appId) { return `${owner.userRecordId}.${appId}`; }
  /** The app's default account for this user: the one the developer chose while it is present, else the first ready one. */
  #defaultRef(env, owner, appId, accounts) {
    const sameApp = accounts.filter(account => account.appId === appId), stored = env.repository.get(DEFAULTS, this.#defaultId(owner, appId));
    const chosen = stored && ownedBy(stored, owner, tenantDeployment(env.scope)) ? sameApp.find(account => account.id === stored.accountRef) : null;
    return (chosen || sameApp.find(account => account.status === 'ready') || sameApp[0])?.id ?? null;
  }
  /** Rows for one user's accounts, optionally one app's; the developer's row unless another is asked for (the person's own, F03.10).
   *  The most urgent notice of each account's current sign-in is its attention line (F10.4). */
  rows(env, owner, appId, build = developerAccountRow) {
    const all = this.accountsOf(env, owner);
    return all.filter(account => !appId || account.appId === appId).map(account => build(account, {isDefault: this.#defaultRef(env, owner, account.appId, all) === account.id, notice: current(env.repository, account)[0] ?? null,
      pages: pagesNote(env.repository, account)}));
  }
  #row(env, owner, connection) {
    return developerAccountRow(connection, {isDefault: present(connection) && this.#defaultRef(env, owner, connection.appId, this.accountsOf(env, owner)) === connection.id, notice: current(env.repository, connection)[0] ?? null,
      pages: pagesNote(env.repository, connection)});
  }
  /** One present account of this owner, or not_found whatever the reason. */
  #mine(env, owner, accountRef) {
    if (typeof accountRef !== 'string' || !ACCOUNT_REF.test(accountRef)) throw notFound();
    const connection = env.repository.get('connections', accountRef);
    if (!connection || !present(connection) || !ownedBy(connection, owner, tenantDeployment(env.scope))) throw notFound();
    return connection;
  }
  /** The end user a route names, or not_found. */
  #named(env, externalUserId) {
    const user = this.user(env, externalUserId);
    if (!user) throw notFound();
    return this.ownerOf(user);
  }
  /** Environment-wide routes: the owner comes from the stored record, and that end user must still be active. */
  #stored(env, accountRef) {
    if (typeof accountRef !== 'string' || !ACCOUNT_REF.test(accountRef)) throw notFound();
    const connection = env.repository.get('connections', accountRef);
    if (!connection || !present(connection)) throw notFound();
    let stored;
    try { stored = ownershipOf(connection, tenantDeployment(env.scope)); } catch { throw notFound(); }
    const user = env.repository.get('endUsers', stored.userRecordId);
    if (!user || user.status !== 'active' || user.subjectId !== stored.subjectId) throw notFound();
    return {connection, owner: this.ownerOf(user)};
  }

  /** One present account of this owner by ref (the executions routes), or not_found. */
  ownedAccount(env, owner, accountRef) { return this.#mine(env, owner, accountRef); }
  /**
   * The account to act on when none is named: the developer's stored default while it is present, else the only one.
   * Several accounts and no default is a question for the developer, never a guess.
   */
  chosenAccount(env, owner, appId) {
    const accounts = this.accountsOf(env, owner).filter(account => account.appId === appId), stored = env.repository.get(DEFAULTS, this.#defaultId(owner, appId));
    const chosen = stored && ownedBy(stored, owner, tenantDeployment(env.scope)) ? accounts.find(account => account.id === stored.accountRef) : null;
    if (chosen) return chosen;
    if (accounts.length === 1) return accounts[0];
    if (!accounts.length) throw new TenantError(409, 'connection_required', 'This person has no account for this app yet; send them a Connect link.', {appId});
    throw new TenantError(409, 'account_choice_required', 'This person has several accounts for this app and no default; name one with accountRef or set a default.', {accountRefs: accounts.map(account => account.id)});
  }

  // ---- user-asserting routes -------------------------------------------------------------------
  /** GET /v1/users/:ext/accounts?appId= : an unknown user has an empty list. */
  list(caller, externalUserId, {appId} = {}) {
    const env = this.stores.open(caller.scope), user = this.user(env, externalUserId);
    if (appId !== undefined && appId !== null && (typeof appId !== 'string' || !tenantApps().some(app => app.id === appId))) throw invalid('appId is not an app of this catalog.');
    return {accounts: user ? this.rows(env, this.ownerOf(user), appId || undefined) : []};
  }
  /** GET /v1/users/:ext/accounts/:accountRef */
  get(caller, externalUserId, accountRef) {
    const env = this.stores.open(caller.scope), owner = this.#named(env, externalUserId);
    return this.#row(env, owner, this.#mine(env, owner, accountRef));
  }
  /** POST /v1/users/:ext/accounts/:accountRef/disconnect */
  async disconnect(caller, externalUserId, accountRef, body) {
    const env = this.stores.open(caller.scope), owner = this.#named(env, externalUserId), connection = this.#mine(env, owner, accountRef);
    return this.#disconnectChecked(env, owner, connection, body, developerParty(caller));
  }
  /** F03.10: one of this owner's present accounts disconnected from Fabric's hosted page; the row is the person's own. */
  async disconnectFor(env, owner, accountRef, body, party, {row} = {}) {
    return this.#disconnectChecked(env, owner, this.#mine(env, owner, accountRef), body, party, row);
  }
  /** POST /v1/users/:ext/accounts/:accountRef/check: an identity check at the provider, then the row. */
  async check(caller, externalUserId, accountRef) {
    // Pinned across the refresh and identity calls: a rotated refresh token is saved to a vault that is still open.
    return this.stores.hold(caller.scope, async env => {
      const owner = this.#named(env, externalUserId), connection = this.#mine(env, owner, accountRef);
      const providerId = connection.providerId ?? signInOf(connection.appId)?.providerId;
      let connections;
      try { ({connections} = this.adapterFor(caller.scope, providerId, connection.providerApp)); } catch (error) { throw new TenantError(422, 'setup_required', error.message); }
      try { await connections.check(connection.id, owner); } catch { /* the stored status already says what went wrong */ }
      const stored = env.repository.get('connections', connection.id);
      if (!stored || !present(stored) || !ownedBy(stored, owner, tenantDeployment(env.scope))) throw notFound();
      return this.#row(env, owner, stored);
    });
  }
  /** PUT /v1/users/:ext/apps/:appId/default-account */
  setDefault(caller, externalUserId, appId, body) {
    const env = this.stores.open(caller.scope), owner = this.#named(env, externalUserId);
    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(key => key !== 'accountRef')) throw invalid('Send the accountRef only.');
    const connection = this.#mine(env, owner, body.accountRef);
    if (connection.appId !== appId) throw notFound();
    env.repository.put(DEFAULTS, stampOwner({id: this.#defaultId(owner, appId), appId, accountRef: connection.id, updatedAt: this.registry.now()}, owner));
    env.repository.audit({type: 'tenant.default_account_set', userRecordId: owner.userRecordId, appId, accountRef: connection.id, byKey: caller.keyId});
    return {appId, accountRef: connection.id};
  }

  // ---- environment-wide routes -----------------------------------------------------------------
  /** GET /v1/accounts?externalUserId=&appId=&after=&limit= */
  listAll(caller, {externalUserId, appId, after, limit} = {}) {
    const env = this.stores.open(caller.scope), deployment = tenantDeployment(env.scope);
    const only = externalUserId === undefined || externalUserId === null || externalUserId === '' ? null : externalId(externalUserId);
    const users = new Map(env.repository.list('endUsers').filter(user => user.status === 'active' && (!only || user.subjectId === only)).map(user => [user.id, user]));
    const rows = [];
    for (const connection of env.repository.list('connections')) {
      if (!present(connection) || (appId && connection.appId !== appId)) continue;
      let stored;
      try { stored = ownershipOf(connection, deployment); } catch { continue; }
      const user = users.get(stored.userRecordId);
      if (!user || user.subjectId !== stored.subjectId) continue;
      rows.push({connection, owner: this.ownerOf(user), createdAt: connection.createdAt ?? '', id: connection.id});
    }
    const {page, pageInfo} = pageOf(rows, {after, limit});
    return {accounts: page.map(({connection, owner}) => ({...this.#row(env, owner, connection), externalUserId: owner.subjectId})), pageInfo};
  }
  /** GET /v1/accounts/:accountRef */
  getAny(caller, accountRef) {
    const env = this.stores.open(caller.scope), {connection, owner} = this.#stored(env, accountRef);
    return {...this.#row(env, owner, connection), externalUserId: owner.subjectId};
  }
  /** POST /v1/accounts/:accountRef/disconnect */
  async disconnectAny(caller, accountRef, body) {
    const env = this.stores.open(caller.scope), {connection, owner} = this.#stored(env, accountRef);
    return this.#disconnectChecked(env, owner, connection, body, developerParty(caller));
  }

  // ---- disconnect ------------------------------------------------------------------------------
  async #disconnectChecked(env, owner, connection, body = {}, party, row) {
    if (body === undefined) body = {};
    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(key => !['remote', 'confirmSiblings'].includes(key))) throw invalid('Send remote and confirmSiblings only.');
    for (const field of ['remote', 'confirmSiblings']) if (body[field] !== undefined && typeof body[field] !== 'boolean') throw invalid(`${field} must be true or false.`);
    if (body.remote === true) {
      // N9: the provider is asked only where the environment's policy allows it: never on Fabric's shared apps where the revocation
      // removes the whole grant (Google), nor where the provider offers no revoke.
      const signIn = signInOf(connection.appId), name = signIn?.definition.displayName ?? 'the provider';
      const policy = signIn ? this.providerApps.revocationPolicy(signIn.definition, connection.providerApp?.kind === 'developer' ? connection.providerApp : {kind: 'shared'}) : 'none';
      if (policy !== 'provider') throw new TenantError(422, 'remote_unavailable', policy === 'local_only' ? 'Revoking the whole grant at the provider is not available on Fabric\'s shared sign-in apps. Disconnect without remote to remove Fabric\'s copy.' : `${name} offers no revoke Fabric can ask for. Disconnect without remote to remove Fabric's copy.`);
      // F10.4 (F03 N9): a grant-wide revoke on the developer's own app never signs out another person here.
      if (signIn.definition.revocation.covers === 'grant' && this.#heldByAnother(env, owner, connection)) throw new TenantError(422, 'remote_unavailable', `Another person here signed in with the same ${name} account on this sign-in app, so revoking at ${name} would sign them out too. Disconnect without remote to remove Fabric's copy.`);
    }
    // Pinned across the provider's revoke and the audit after it, so both write to a store that is still open.
    return this.stores.hold(env.scope, async () => {
      const result = await this.disconnectRecord(env, owner, connection, {remote: body.remote, confirmSiblings: body.confirmSiblings, row});
      env.repository.audit({type: 'tenant.account_disconnected', userRecordId: owner.userRecordId, accountRef: connection.id, appId: connection.appId, remoteRevoked: result.remoteRevoked, ...partyFields(party)});
      return result;
    });
  }
  /** F03 N9: whether another person here holds the same provider account on the same sign-in app, so a revoke of the whole grant
   *  would sign them out too. Their waiting sign-ins count: they hold tokens of the same grant. */
  #heldByAnother(env, owner, connection) {
    const providerOf = item => item.providerId ?? signInOf(item.appId)?.providerId, appKey = item => item?.providerApp?.kind === 'developer' ? `developer:${item.providerApp.id}` : 'shared';
    const deployment = tenantDeployment(env.scope);
    return env.repository.list('connections').some(other => other.id !== connection.id && other.status !== 'revoked' && providerOf(other) === providerOf(connection) && appKey(other) === appKey(connection)
      && other.identity?.id === connection.identity?.id && !ownedBy(other, owner, deployment));
  }
  /**
   * Disconnects one account of this owner: local erasure always happens; the provider is asked only where the
   * environment's revocation policy allows it. Without a usable sign-in app the account is still erased here.
   */
  async disconnectRecord(env, owner, connection, {remote, confirmSiblings, row = developerAccountRow} = {}) {
    const providerId = connection.providerId ?? signInOf(connection.appId)?.providerId, signIn = signInOf(connection.appId);
    const policy = signIn ? this.providerApps.revocationPolicy(signIn.definition, connection.providerApp?.kind === 'developer' ? connection.providerApp : {kind: 'shared'}) : 'none';
    // T1 (F10.4): where the revocation removes the whole grant, only an explicit remote: true reaches the provider. A plain
    // disconnect, a deleted person and every other path disconnect here only.
    if (signIn?.definition.revocation?.covers === 'grant' && remote !== true) remote = false;
    let result;
    try {
      // The account's own provider app (D8): never the environment's current default.
      const {adapter} = this.adapterFor(env.scope, providerId, connection.providerApp);
      // N9: a token another account here still holds is erased here only, never revoked at the provider.
      const options = {remote: this.providerApps.tokenHeldElsewhere(env, connection) ? false : remote};
      result = await adapter.revoke(connection.id, owner, {...options, confirmSiblings});
    } catch (error) {
      // F10.4: the revoke would also sign out this person's other accounts of the same grant (the adapter lists only theirs), and
      // nothing changed: the developer confirms, or disconnects here only. The accounts are named by accountRef.
      if (error?.code === 'confirm_required') throw new TenantError(409, 'confirm_required', error.message, {siblings: (error.siblings ?? []).map(item => ({accountRef: item.connectionId, appId: item.appId, displayName: item.displayName}))});
      // No sign-in app to ask (or it failed before erasing): erase Fabric's copy directly.
      const stored = env.repository.get('connections', connection.id);
      if (stored && stored.status !== 'revoked') new ConnectionManager({store: env.repository, vault: env.vault, deployment: tenantDeployment(env.scope)}).revoke(connection.id, owner);
      const name = signIn?.definition.displayName ?? 'the provider';
      result = {remoteRevoked: false, message: policy === 'local_only' ? (connection.providerApp?.kind === 'developer' ? `Disconnected here. Revoking at ${name} would sign this account out of everything that uses this app's grant, so Fabric did not ask; remove it in ${name} account settings if needed.` : `Disconnected here. Removing Fabric in your ${name} account would also sign this ${name} account out of every other app that uses Fabric's shared ${name} sign-in.`)
        : `Disconnected here. Fabric could not ask ${name} to revoke access; remove it in ${name} account settings if needed.`};
    }
    const stored = env.repository.get('connections', connection.id) ?? {...connection, status: 'revoked'};
    return {account: row(stored), remoteRevoked: result.remoteRevoked === true, message: String(result.message || 'Disconnected.'),
      ...(result.affected?.length ? {affected: result.affected.map(item => ({accountRef: item.connectionId, appId: item.appId}))} : {})};
  }
}

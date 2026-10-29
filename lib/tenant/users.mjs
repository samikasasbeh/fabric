// F03.5a (docs/F03-DEVELOPER-LAYER.md section 5.5): a developer's end users. Listing pages stably by creation time;
// deleting one is irreversible: every account is disconnected (the provider is asked only where N9 allows), open
// links and sign-ins are closed, every record the user owns is erased, and a tombstone keeps only the usr_ id. The
// environment's store overwrites what it deletes (secure_delete), so the erased data leaves no bytes in Fabric's files.
import {notFound} from './errors.mjs';
import {ownedBy, tenantDeployment} from './deployment.mjs';
import {pageOf, present} from './accounts.mjs';

/** Collections that can hold an end user's records, by owner, by usr_ id, or by one of their accounts. */
export const END_USER_COLLECTIONS = Object.freeze(['connectSessions', 'oauthFlows', 'connections', 'jobs', 'permissions', 'backgroundPolicies', 'proxyResponses', 'heartbeats', 'clientGrants', 'continuations', 'protocolRequests', 'defaultAccounts', 'idempotencyKeys', 'connectionNotes', 'subscriptions', 'actionPrepared', 'actionRecords']);
// subscriptions is reserved for triggers (Iteration 9, section 8): listed now so the delete cascade and its test hold from day one.
// actionPrepared and actionRecords (F10.11 part h): an action job's prepared bytes and the records Fabric made, each stamped with its owner.
// connectionNotes (F10.19): a Notion account's page count, stamped with its owner (lib/connection-notes.mjs).
// Usage records (usageEvents) are not here on purpose: they hold only the usr_ id and keep the month's history (D11).


export class ExternalUsers {
  /** @param {{stores: any, registry: any, accounts: import('./accounts.mjs').TenantAccounts}} deps */
  constructor(deps) { Object.assign(this, deps); }

  #summary(user, accounts) {
    return {externalUserId: user.subjectId, createdAt: user.createdAt, ...(user.lastConnectedAt ? {lastConnectedAt: user.lastConnectedAt} : {}), accounts};
  }
  /** GET /v1/users?after=&limit=&q= ; q matches the start of an external id. */
  list(caller, {q, after, limit} = {}) {
    const env = this.stores.open(caller.scope), prefix = typeof q === 'string' ? q.slice(0, 128) : '';
    // Paged on (createdAt, external id): unique among active users, and the cursor carries nothing the developer lacks.
    const users = env.repository.list('endUsers').filter(user => user.status === 'active' && (!prefix || user.subjectId.startsWith(prefix))).map(user => ({createdAt: user.createdAt, id: user.subjectId, user}));
    const {page, pageInfo} = pageOf(users, {after, limit});
    return {users: page.map(({user}) => this.#summary(user, this.accounts.accountsOf(env, this.accounts.ownerOf(user)).length)), pageInfo};
  }
  /** GET /v1/users/:externalUserId */
  get(caller, externalUserId) {
    const env = this.stores.open(caller.scope), user = this.accounts.user(env, externalUserId);
    if (!user) throw notFound();
    return {user: this.#summary(user, this.accounts.rows(env, this.accounts.ownerOf(user)))};
  }
  /** DELETE /v1/users/:externalUserId */
  async delete(caller, externalUserId) {
    // Pinned across every provider revoke, so the steps after them still write to an open store and vault.
    return this.stores.hold(caller.scope, env => this.#delete(caller, env, externalUserId));
  }
  async #delete(caller, env, externalUserId) {
    // A delete that stopped part way (status deleting) can be finished by asking again.
    const user = this.accounts.user(env, externalUserId) ?? env.repository.list('endUsers').find(record => record.status === 'deleting' && record.subjectId === externalUserId);
    if (!user) throw notFound();
    const repository = env.repository, owner = this.accounts.ownerOf(user), deployment = tenantDeployment(env.scope);
    const mine = record => ownedBy(record, owner, deployment) || record?.userRecordId === user.id || record?.tenant?.userRecordId === user.id;
    // 1. The user leaves the active set first: a new link for the same external id makes a new end user.
    repository.put('endUsers', {...user, status: 'deleting'});
    // 2. Open links and sign-ins close before any provider call, so no callback can land an account for this user.
    for (const session of repository.list('connectSessions').filter(mine)) { repository.delete('connectSessions', session.id); this.registry.removeRoute('sessionRoutes', session.id); }
    for (const flow of repository.list('oauthFlows').filter(mine)) { repository.delete('oauthFlows', flow.id); env.vault.delete(`oauth:${flow.id}`); this.registry.removeRoute('flowRoutes', flow.id); }
    // Agent tokens stop working at once: their routes go before anything slower runs; the grants are erased in step 4.
    for (const grant of repository.list('clientGrants').filter(mine)) this.registry.removeRoute('agentTokenRoutes', grant.id);
    // 3. Every account is disconnected under N9 and erased. A sign-in already past its flow may still land one; look again.
    const accounts = [], seen = new Set();
    for (let pass = 0; pass < 3; pass++) {
      const left = repository.list('connections').filter(record => ownedBy(record, owner, deployment));
      if (!left.length) break;
      for (const connection of left) {
        seen.add(connection.id);
        if (connection.status !== 'revoked') {
          const result = await this.accounts.disconnectRecord(env, owner, connection);
          if (present(connection)) accounts.push({accountRef: connection.id, appId: connection.appId, remoteRevoked: result.remoteRevoked, message: result.message});
        }
        env.vault.delete(connection.id); repository.delete('connections', connection.id);
      }
    }
    // 4. Everything else the user owns, or that belongs to one of their accounts.
    for (const collection of END_USER_COLLECTIONS) {
      for (const record of repository.list(collection)) {
        if (mine(record) || (typeof record.connectionId === 'string' && seen.has(record.connectionId)) || (collection === 'backgroundPolicies' && seen.has(record.id))) repository.delete(collection, record.id);
      }
    }
    // F10.4: the user's connection notices name their accounts, so they go too. The rest of the activity stays, as before.
    for (const id of seen) for (const notice of repository.listWhere('activity', 'connectionId', id)) if (notice.type === 'connection.health') repository.delete('activity', notice.id);
    // 5. The tombstone: only the usr_ id, so a re-created user with the same external id inherits nothing.
    repository.put('endUsers', {id: user.id, status: 'deleted', deletedAt: this.registry.now()});
    repository.audit({type: 'tenant.user_deleted', userRecordId: user.id, accounts: accounts.length, byKey: caller.keyId});
    return {deleted: true, accounts};
  }
}

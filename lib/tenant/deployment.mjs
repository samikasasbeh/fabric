// F03.2: who owns a record. The single-owner runtime derives ownership from its one owner and stores nothing. A
// developer environment stores ownership on every end-user record (the end user's external id and Fabric's usr_
// record id) and fails closed without it. Matching needs both ids, so a deleted end user re-created with the same
// external id never sees the old records.
const USER_RECORD = /^usr_[a-z2-7]{26}$/;
const SUBJECT = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;

export class OwnershipError extends Error {
  constructor(message) { super(message); this.name = 'OwnershipError'; this.code = 'not_found'; }
}

export const LOCAL_DEPLOYMENT = Object.freeze({kind: 'local'});
/** A developer environment's deployment; its scope is the environment's TenantScope. */
export function tenantDeployment(scope) {
  if (!scope || scope.kind !== 'tenant') throw new Error('A tenant deployment needs a tenant scope.');
  return Object.freeze({kind: 'tenant', scope});
}

/** A validated end-user owner: the developer's external id (subjectId) and Fabric's usr_ record id. */
export function endUser({subjectId, userRecordId} = {}) {
  if (typeof subjectId !== 'string' || !SUBJECT.test(subjectId) || typeof userRecordId !== 'string' || !USER_RECORD.test(userRecordId)) throw new Error('An end-user owner needs a subjectId and a usr_ record id.');
  return Object.freeze({subjectId, userRecordId});
}

/** The record with its owner stamped, in the OwnedRecord shape plus userRecordId beside it. */
export function stampOwner(record, owner) {
  const checked = endUser(owner);
  return {...record, ownership: {owner: {kind: 'product_user', id: checked.subjectId}}, userRecordId: checked.userRecordId};
}

/** The owner stored on a tenant record, or an error: a tenant record without both ids is never usable. */
export function ownershipOf(record, deployment) {
  if (deployment.kind === 'local') return null;
  const id = record?.ownership?.owner?.kind === 'product_user' ? record.ownership.owner.id : null;
  if (typeof id !== 'string' || !SUBJECT.test(id) || typeof record.userRecordId !== 'string' || !USER_RECORD.test(record.userRecordId)) throw new OwnershipError('This record has no owner and cannot be used.');
  return {subjectId: id, userRecordId: record.userRecordId};
}

/** True when the record belongs to this end user (both ids). Local deployments have one owner, so always true. */
export function ownedBy(record, owner, deployment) {
  if (deployment.kind === 'local') return true;
  if (!owner) return false;
  let stored;
  try { stored = ownershipOf(record, deployment); } catch { return false; }
  return stored.subjectId === owner.subjectId && stored.userRecordId === owner.userRecordId;
}

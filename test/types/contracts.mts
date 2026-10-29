// Compile-only regression fixtures. Never executed against a provider.
import type {Principal, LocalScope, LocalClientPrincipal, OwnedRecord} from '../../contracts/identity.mts';
import type {ApprovalRecord, ExecutionRequest, DispatchContext} from '../../contracts/execution.mts';
import type {CertificationAssessment} from '../../contracts/certification.mts';

const local: LocalScope = {schemaVersion: 1, kind: 'local', localOwnerId: 'owner'};
const principal: Principal = {schemaVersion: 1, kind: 'local_owner', id: 'owner', scope: local};
const ownership: OwnedRecord = {schemaVersion: 1, scope: local, owner: {kind: 'local_owner', id: 'owner'}};
const request: ExecutionRequest = {schemaVersion: 1, id: 'request', scope: local, principal,
  policyRevision: 1,
  access: {kind: 'connection', id: 'account', generation: 1},
  capability: {appId: 'example', id: 'read', version: 1, definitionHash: 'a'.repeat(64), effect: 'read'},
  args: {query: 'example'}, idempotencyKey: 'key', createdAt: '2026-10-11T00:00:00Z', deadline: '2026-10-11T01:00:00Z'};
const context: DispatchContext = {request, now: request.createdAt, current: {scope: local, principal, ownerPrincipal: principal,
  connection: {id: 'account', generation: 1, appId: 'example', status: 'active', ownership}, capability: {reference: request.capability, status: 'active'}, policy: {revision: 1, decision: 'ask'}}};
void context;
// @ts-expect-error Requests are immutable; mutations require a newly accepted request.
request.args.query = 'changed';
// @ts-expect-error Connection authority requires an exact generation.
const missingGeneration: ExecutionRequest['access'] = {kind: 'connection', id: 'account'};
// @ts-expect-error Local principals cannot silently become tenant developers.
const localDeveloper: Principal = {schemaVersion: 1, kind: 'developer', id: 'developer', scope: local};
// @ts-expect-error Agents must declare a delegator and a grant reference.
const undelegated: Principal = {schemaVersion: 1, kind: 'agent', id: 'agent', scope: {schemaVersion: 1, kind: 'tenant', organizationId: 'org', projectId: 'project', environmentId: 'dev'}};
// @ts-expect-error A metadata assessment never authorizes publication.
const publish: CertificationAssessment['publicationAuthorized'] = true;
void [missingGeneration, localDeveloper, undelegated, publish];

const localClient: LocalClientPrincipal = {schemaVersion: 1, kind: 'local_client', id: 'authenticated-grant', scope: local, delegatedBy: {kind: 'local_owner', id: 'owner'}};
const clientRequest: ExecutionRequest = {...request, principal: localClient};
const clientContext: DispatchContext = {...context, request: clientRequest, current: {...context.current, principal: localClient, ownerPrincipal: principal}};
// @ts-expect-error Local clients are not human approvers.
const clientApprover: ApprovalRecord['approver'] = localClient;
// @ts-expect-error Local-client grant identities require a local owner delegator.
const undelegatedClient: Principal = {schemaVersion: 1, kind: 'local_client', id: 'grant', scope: local};
// @ts-expect-error A client cannot delegate another client.
const clientChain: LocalClientPrincipal = {...localClient, delegatedBy: {kind: 'local_client', id: 'other-grant'}};
// @ts-expect-error Local clients cannot become tenant principals.
const tenantClient: LocalClientPrincipal = {...localClient, scope: {schemaVersion: 1, kind: 'tenant', organizationId: 'org', projectId: 'project', environmentId: 'dev'}};
// @ts-expect-error Local clients cannot claim workspace context.
const workspaceClient: LocalClientPrincipal = {...localClient, workspaceId: 'workspace'};
// @ts-expect-error Local clients cannot claim a tenant product-user subject.
const subjectClient: LocalClientPrincipal = {...localClient, subjectId: 'subject'};
// @ts-expect-error The local client id is the grant ID; a second delegation ID is forbidden.
const separateGrant: LocalClientPrincipal = {...localClient, delegationId: 'different-grant'};
// @ts-expect-error A local-client principal cannot be a connection owner.
const clientOwnership: OwnedRecord = {schemaVersion: 1, scope: local, owner: {kind: 'local_client', id: localClient.id}};
// @ts-expect-error The delegator is part of the immutable principal.
localClient.delegatedBy.id = 'different-owner';
void [clientContext, clientApprover, undelegatedClient, clientChain, tenantClient, workspaceClient, subjectClient, separateGrant, clientOwnership];

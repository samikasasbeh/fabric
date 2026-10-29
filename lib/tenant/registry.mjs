// F03.1: the platform registry of customers, projects, environments, service clients and keys. It lives beside the
// platform catalog under the tenant data root, and both the operator command and the developer server use it. Creating
// an environment record also creates its sealed environment folder (F03.0).
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import path from 'node:path';
import {createHash, randomBytes} from 'node:crypto';
import {Store} from '../store.mjs';
import {ID_PREFIXES, validName, validEmail, assertRecordId, TenantRecordError} from '../../contracts/tenant.mts';
import {resolveTenantRoot, EnvironmentError, DESIGNATION_FILE} from './environments.mjs';

const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';
/** A prefix plus 26 lowercase base32 characters (130 random bits). */
/** A stable digest of pending branding (sorted keys), for review-bound approval. */
export function brandingDigest(pending) {
  const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
  return createHash('sha256').update(JSON.stringify(canonical(pending))).digest('hex').slice(0, 32);
}

export function newId(kind) {
  const bytes = randomBytes(26);
  return `${ID_PREFIXES[kind]}${[...bytes].map(byte => BASE32[byte & 31]).join('')}`;
}
const COLLECTIONS = Object.freeze(['organizations', 'projects', 'environments', 'serviceClients', 'serviceKeys', 'sessionRoutes', 'flowRoutes', 'projectLogos', 'clientIds', 'agentTokenRoutes']);
const MARKER = 'tenant-registry.json';
/** The project fields end users see on Fabric's pages (L10). */
const BRANDING_FIELDS = Object.freeze(['appName', 'supportEmail', 'dataUse', 'logo', 'brand']);
const shownBranding = project => Object.fromEntries(BRANDING_FIELDS.filter(field => project[field] !== undefined && project[field] !== null).map(field => [field, project[field]]));

export class TenantRegistry {
  #store; #clock;
  /** @param {{root: string, forbiddenRoots?: string[], clock?: () => number}} options */
  constructor({root, forbiddenRoots, clock = Date.now} = {}) {
    const dir = path.join(resolveTenantRoot(root, forbiddenRoots), 'registry');
    mkdirSync(dir, {recursive: true, mode: 0o700});
    if (existsSync(path.join(dir, DESIGNATION_FILE))) throw new EnvironmentError('designation_mismatch', 'The registry folder cannot be a developer environment.');
    const marker = path.join(dir, MARKER);
    if (!existsSync(marker)) {
      if (existsSync(path.join(dir, 'fabric.sqlite'))) throw new EnvironmentError('designation_mismatch', 'This folder holds data but is not the tenant registry.');
      writeFileSync(marker, `${JSON.stringify({kind: 'tenant-registry', createdAt: new Date(clock()).toISOString()})}\n`, {flag: 'wx', mode: 0o600});
    } else if (JSON.parse(readFileSync(marker, 'utf8')).kind !== 'tenant-registry') throw new EnvironmentError('designation_mismatch', 'This folder is not the tenant registry.');
    this.#store = new Store({dataDir: dir, clock, secureDelete: true}); this.#clock = clock;
  }
  now() { return new Date(this.#clock()).toISOString(); }
  #collection(collection) { if (!COLLECTIONS.includes(collection)) throw new TenantRecordError(`${collection} is not a registry collection.`); return collection; }
  get(collection, id) { return this.#store.get(this.#collection(collection), id); }
  list(collection) { return this.#store.list(this.#collection(collection)); }
  put(collection, record) { return this.#store.put(this.#collection(collection), record); }
  audit(event) { return this.#store.audit(event); }
  /** Routes only: a used sign-in route is removed so it can never be replayed. */
  removeRoute(collection, id) { if (!['sessionRoutes', 'flowRoutes', 'agentTokenRoutes'].includes(collection)) throw new TenantRecordError('Only routes can be removed.'); return this.#store.delete(collection, id); }
  /**
   * N8: one provider client, one environment. A client id is held only by Fabric (seeded) or by the one environment that
   * proved it first; pending registrations live in each environment and never block anyone. Check and set in one
   * synchronous call, so two proofs can never both win. Returns 'claimed', 'mine' or 'taken'.
   */
  claimClientId(hash, owner, extra = {}) {
    if (typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash) || typeof owner !== 'string' || !owner) throw new TenantRecordError('A client id claim needs its hash and owner.');
    const existing = this.#store.get('clientIds', hash);
    if (existing) return existing.owner === owner ? 'mine' : 'taken';
    this.#store.put('clientIds', {id: hash, owner, state: owner === 'fabric' ? 'fabric' : 'proven', ...extra, provenAt: this.now()});
    return 'claimed';
  }
  /** The owner of a proven client id, or null. */
  clientIdOwner(hash) { return this.#store.get('clientIds', hash)?.owner ?? null; }
  /** Releases a client id, only by the environment that holds it. */
  releaseClientId(hash, owner) {
    const existing = this.#store.get('clientIds', hash);
    if (existing && existing.owner === owner && owner !== 'fabric') this.#store.delete('clientIds', hash);
  }
  activity() { return this.#store.list('activity'); }
  close() { this.#store.close(); }

  createOrganization({name}) {
    const organization = {id: newId('organization'), name: validName(name), status: 'active', createdAt: this.now()};
    this.put('organizations', organization); this.audit({type: 'tenant.organization_created', organizationId: organization.id});
    return organization;
  }
  createProject({organizationId, name, appName = name, supportEmail = null}) {
    const organization = this.get('organizations', assertRecordId(organizationId, 'organization'));
    if (!organization) throw new TenantRecordError('No such organization.');
    const project = {id: newId('project'), organizationId, name: validName(name), appName: validName(appName, 'appName'), supportEmail: validEmail(supportEmail), createdAt: this.now()};
    // The operator gives the name and help address here, so they count as reviewed.
    project.reviewedBranding = shownBranding(project);
    this.put('projects', project); this.audit({type: 'tenant.project_created', organizationId, projectId: project.id});
    return project;
  }
  /** One development and at most one production environment per project; production starts disabled. */
  createEnvironment({projectId, kind}, stores) {
    const project = this.get('projects', assertRecordId(projectId, 'project'));
    if (!project) throw new TenantRecordError('No such project.');
    if (!['development', 'production'].includes(kind)) throw new TenantRecordError('kind must be development or production.');
    if (this.list('environments').some(environment => environment.projectId === projectId && environment.kind === kind)) throw new TenantRecordError(`This project already has a ${kind} environment.`);
    const environment = {id: newId('environment'), projectId, organizationId: project.organizationId, kind, status: 'active', productionEnabled: false, openerOrigins: [], redirectOrigins: [], eventDestinations: [], createdAt: this.now()};
    this.put('environments', environment);
    stores?.open(this.scopeOf(environment));
    this.audit({type: 'tenant.environment_created', organizationId: project.organizationId, projectId, environmentId: environment.id, kind});
    return environment;
  }
  enableProduction(environmentId) {
    const environment = this.get('environments', assertRecordId(environmentId, 'environment'));
    if (!environment || environment.kind !== 'production') throw new TenantRecordError('No such production environment.');
    // L10: branding changed while production was off was never reviewed. Whatever differs from the last reviewed
    // branding moves to pending before production goes live, so production end users see only what the operator approved.
    const project = environment.productionEnabled ? null : this.get('projects', environment.projectId);
    if (project) {
      const reviewed = project.reviewedBranding ?? {appName: project.name}, live = shownBranding(project), held = {};
      for (const field of BRANDING_FIELDS) if (brandingDigest(live[field] ?? null) !== brandingDigest(reviewed[field] ?? null)) held[field] = live[field] ?? null;
      if (Object.keys(held).length) {
        const next = {...project, reviewedBranding: reviewed, pendingBranding: {...held, ...(project.pendingBranding || {})}};
        for (const field of Object.keys(held)) { if (reviewed[field] === undefined) delete next[field]; else next[field] = reviewed[field]; }
        this.put('projects', next); this.audit({type: 'tenant.branding_held', projectId: project.id, fields: Object.keys(held)});
      }
    }
    const enabled = {...environment, productionEnabled: true};
    this.put('environments', enabled); this.audit({type: 'tenant.production_enabled', environmentId});
    return enabled;
  }
  /** Branding end users see in production changes only with the operator's approval (L10): true once production is live. */
  brandingNeedsReview(projectId) { return this.list('environments').some(environment => environment.projectId === projectId && environment.kind === 'production' && environment.productionEnabled); }
  /** What a project's pending branding is, and its digest: the operator reviews exactly this and approves with the digest. */
  pendingBranding(projectId) {
    const project = this.get('projects', assertRecordId(projectId, 'project'));
    if (!project) throw new TenantRecordError('No such project.');
    if (!project.pendingBranding) return null;
    const logo = project.pendingBranding.logo ? this.get('projectLogos', `${projectId}.${project.pendingBranding.logo.hash}`) : null;
    return {pending: project.pendingBranding, digest: brandingDigest(project.pendingBranding), ...(logo ? {logoBytes: Buffer.from(logo.data, 'base64')} : {})};
  }
  /**
   * The operator approves a project's pending branding: the name, logo, support email and data-use note end users will
   * see. Bound to the digest the operator reviewed, so nothing sent after the review can ride along with the approval.
   */
  approveBranding(projectId, digest) {
    const project = this.get('projects', assertRecordId(projectId, 'project'));
    if (!project) throw new TenantRecordError('No such project.');
    if (!project.pendingBranding) throw new TenantRecordError('This project has no branding waiting for review.');
    if (digest !== brandingDigest(project.pendingBranding)) throw new TenantRecordError('The pending branding changed since it was reviewed (or no digest was given); review it again.');
    const {pendingBranding, ...rest} = project, approved = {...rest};
    for (const [field, value] of Object.entries(pendingBranding)) { if (value === null) delete approved[field]; else approved[field] = value; }
    approved.reviewedBranding = shownBranding(approved);
    this.put('projects', approved); this.audit({type: 'tenant.branding_approved', projectId, fields: Object.keys(pendingBranding), digest});
    this.pruneLogos(projectId, project);
    return approved;
  }
  /**
   * Keeps only a project's approved and pending logos: the logos `before` (the project record before a change) named
   * that the project no longer names are deleted, by id. Never lists the collection, which holds every project's logo
   * bytes, so one tenant's upload does not cost more as other tenants add logos (N1).
   */
  pruneLogos(projectId, before) {
    const project = this.get('projects', projectId), keep = new Set([project?.logo?.hash, project?.pendingBranding?.logo?.hash].filter(Boolean));
    for (const hash of new Set([before?.logo?.hash, before?.pendingBranding?.logo?.hash])) if (hash && !keep.has(hash)) this.#store.delete('projectLogos', `${projectId}.${hash}`);
  }
  setStatus(collection, id, status) {
    if (!['organizations', 'environments'].includes(collection) || !['active', 'suspended'].includes(status)) throw new TenantRecordError('Only organizations and environments can be suspended or reactivated.');
    const record = this.get(collection, id);
    if (!record) throw new TenantRecordError('No such record.');
    this.put(collection, {...record, status}); this.audit({type: `tenant.${status}`, collection, id});
  }
  /** The isolation key of an environment record. */
  scopeOf(environment) { return {organizationId: environment.organizationId, projectId: environment.projectId, environmentId: environment.id}; }
}

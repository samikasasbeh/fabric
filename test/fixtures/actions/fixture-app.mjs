// F10.9 part a (docs/F10.9-BUILD-MAP.md part a): the fixture app of the action format tests, app id `fixture`, and its RPC twin
// `fixture-rpc`, as data in this folder, with helpers that load them through the shipped validators. Not a real provider; nothing in lib/
// reads it.
//   permissions/<app>.json   version 2 rows: a read row with a reviewed-read POST and a POST that is not one, an unavailable member and a
//                            typed operation; a read row whose member is marked sensitive: 'secrets'; a write row that stays in the account;
//                            a write row with body routes into the delete row and the locked row; an audience write row with one bindContent
//                            member of each kind and a conditional scope; a delete row; a locked row. The twin is shaped like Slack.
//   proxy/<app>.json         a REST proxy file and its RPC twin.
//   maps/fixture.json        the method and path of the typed operation, so templatesFor() places it.
//   options/fixture.json     a version 1 option source; choices/fixture.json the version 2 choice sources (section 9), and
//                            choices/gmail.json a Gmail choices file for part i's tests (no app ships one).
//   answers/github-repos.json  a GitHub-style answer of two repositories that carry temp_clone_token.
//   actions/fixture.json     one action file that uses every field the fixture app can hold (parts f to j validate it), with the ids
//                            and the certified definition hash part g computes.
// fixtureSignIn() is the fixture app's reviewed sign-in (F10.11 part b). registry.mjs holds the fixture transform registry and its pins.
import {readFileSync} from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import {validatePermissionGroups} from '../../../lib/permission-groups.mjs';
import {validateProxyConfig} from '../../../lib/proxy-config.mjs';
import {actionIds} from '../../../lib/actions.mjs';
import {validateAuthDefinition} from '../../../contracts/auth-definition.mts';
import {v1Definition} from '../auth-v1/urls.mjs';

const read = file => JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8'));
export const FIXTURE_APPS = Object.freeze(['fixture', 'fixture-rpc']);
/** The origins the fixture apps' proxy settings may use, as catalog/apps.json lists them for a shipped app. */
export const ORIGINS = Object.freeze({fixture: Object.freeze(['https://api.fixture.test']), 'fixture-rpc': Object.freeze(['https://rpc.fixture.test'])});
/** A fresh copy of one fixture app's rows file. */
export const fixtureRows = (appId = 'fixture') => read(`./permissions/${appId}.json`);
/** Both fixture apps' rows, validated, keyed by app as PERMISSION_GROUPS keys the shipped ones. `change` edits the fixture app's rows file
 *  before it is validated (F10.11 part e: a test that marks a member or moves one gives the changed rows here). */
export const fixtureGroups = (change = rows => rows) => new Map(FIXTURE_APPS.map(appId => [appId, validatePermissionGroups(appId === 'fixture' ? change(fixtureRows(appId)) : fixtureRows(appId))]));
/** A fresh copy of one fixture app's proxy file. */
export const fixtureProxy = (appId = 'fixture') => read(`./proxy/${appId}.json`);
/** Both fixture apps' proxy settings, validated against their rows, keyed by app. */
export const fixtureConfigs = (groups = fixtureGroups()) => new Map(FIXTURE_APPS.map(appId => [appId, validateProxyConfig(fixtureProxy(appId), {groups, allowedOrigins: [...ORIGINS[appId]]})]));
export const fixtureMap = () => read('./maps/fixture.json');
export const fixtureOptions = () => read('./options/fixture.json');
export const fixtureChoices = () => read('./choices/fixture.json');
export const fixtureActions = () => read('./actions/fixture.json');
/** The GitHub-style answer to GET /user/repos: a fresh list of two repository objects. */
export const reposAnswer = () => read('./answers/github-repos.json').answer;
/**
 * Part g: every stored id must equal the computed one, so a test that builds or edits an action writes its computed id, and its certified
 * definition hash, as an author does, through actionIds(). A file actionIds() refuses comes back unchanged, so the validator refuses it with
 * the same words. The id tests call validateActionFile() on the file as written.
 */
export function withIds(file, deps) {
  let ids;
  try { ids = actionIds(file, deps); } catch { return file; }
  return {...file, actions: file.actions.map(action => {
    const computed = ids.get(`${action.key} v${action.version}`);
    return {...action, id: computed.id, ...(action.certified ? {certified: {...action.certified, definitionHash: computed.definitionHash}} : {})};
  })};
}

/**
 * The fixture app's reviewed sign-in, version 2: one required scope and an identity that yields only id. F10.11 part b moved it here from
 * test/actions-validator.test.mjs and test/app-template-check.test.mjs, which each kept a copy; `appId` names the app it carries.
 */
export const fixtureSignIn = (appId = 'fixture') => validateAuthDefinition({...v1Definition('github'), schemaVersion: 2, providerId: 'fixture', displayName: 'Fixture',
  credentialEnvironment: {clientId: 'FABRIC_FIXTURE_CLIENT_ID', clientSecret: 'FABRIC_FIXTURE_CLIENT_SECRET'},
  apps: [{appId, accessProbe: null, access: {default: 'full', grant: 'scope', levels: {full: {required: ['fixture:all'], optional: [], inContext: []}, read: null}}, neverRequest: []}],
  scopeImplications: {}, consentPolicy: {testing: 'full', production: 'required'}});

/**
 * Part l: schemas/action.schema.json, compiled with ajv in strict mode as the schema tests run it. The schema documents the format for
 * editors and reviewers and validateActionFile() stays the authority, so every file a test accepts must pass it.
 */
export const actionSchema = () => new Ajv2020({strict: true, allErrors: true}).compile(read('../../../schemas/action.schema.json'));

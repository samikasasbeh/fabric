// F10.12 part 2 (docs/F10.12-BUILD-MAP.md part 2): the live-test command. It starts a throwaway certification Fabric on port 4320 in the
// folder the owner names, runs one app's live tests (catalog/live-tests/<appId>.json) the way an agent sends them, and writes evidence
// that is safe to commit. The owner approves every card on Fabric's own approve page; the guard (lib/live-guard.mjs) refuses anything
// outside the owner's test areas before it leaves the machine.
//
//   node --env-file-if-exists=.env scripts/live-certify.mjs <appId> --folder <absolute path> [--record <name>=<value>]... [--resume <runId> [--from <test>]]
//   node scripts/live-certify.mjs [<appId>] --check      checks plan structure offline; starts nothing and sends nothing
//
// The folder and the port never come from the environment: FABRIC_DATA_DIR and FABRIC_PORT are ignored. This file holds the owner
// principal only to bind each test's client grant (section 8, question 3): it reaches Fabric through createApp, start, close, the guard,
// protocol.createClient, protocol.revokeClient, the client calls and read-only lookups, and never approves, sets a row or resets
// (test/f10-12-churn.test.mjs pins this).
import {randomBytes} from 'node:crypto';
import {existsSync, readFileSync, readdirSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createInterface} from 'node:readline/promises';
import {createApp, lockDataDir} from '../server.mjs';
import {CERTIFICATION_PORT, certificationFolderRefusal} from '../lib/certification.mjs';
import {createGuard, newRunId, signInFile, LIMITS, RULES} from '../lib/live-guard.mjs';
import {checkPlan, checkPlanShape, evidenceRecords, openRunState, runDateOf, runLiveTests, writeEvidence, writeIntrospection} from '../lib/live-certify.mjs';
import {loadActionCatalog} from '../lib/action-catalog.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {definitionFor, reviewedProviderIds} from '../lib/providers/definitions.mjs';
import {INTROSPECTION} from '../lib/providers/oauth2.mjs';
import {consentDue} from '../lib/connection-notices.mjs';
import {validatePrincipal} from '../contracts/identity.mts';
import {GOOGLE_APPS, PATHS_FILE, SCOPES_FILE, methodMap} from './google-method-paths.mjs';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
/** Where the plans live: catalog/live-tests/<appId>.json. */
export const PLANS = path.join(ROOT, 'catalog', 'live-tests');
/** The one owner of every certification Fabric: fixed, so a folder the harness made always opens again with `require`. */
export const CERTIFICATION_OWNER = validatePrincipal({schemaVersion: 1, kind: 'local_owner', id: 'fabric-certification', scope: {schemaVersion: 1, kind: 'local', localOwnerId: 'fabric-certification'}});
export const USAGE = 'Usage: node --env-file-if-exists=.env scripts/live-certify.mjs <appId> --folder <absolute path> [--record <name>=<value>]... [--resume <runId> [--from <test>]]\n       node scripts/live-certify.mjs [<appId>] --check';
const APP = /^[a-z][a-z0-9-]{1,63}$/, NAME = /^[A-Za-z][A-Za-z0-9]{0,39}$/, RUN_ID = /^[A-Z2-7]{8}$/, TEST_ID = /^[A-Za-z][A-Za-z0-9-]{0,15}$/, EMAIL = /^[^\s@]+@[^\s@]+$/;
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);

/** The command line, closed: every flag known, the folder absolute, a value for every flag that takes one. */
export function parseArgs(argv) {
  const options = {appId: null, folder: null, records: {}, resume: null, from: null, check: false, leave: false};
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index], value = () => { const next = argv[++index]; if (next === undefined || next.startsWith('--')) throw new Error(`${arg} needs a value.`); return next; };
    if (arg === '--check') options.check = true;
    else if (arg === '--leave') options.leave = true;
    else if (arg === '--folder') options.folder = value();
    else if (arg === '--record') {
      const text = value(), cut = text.indexOf('='), name = text.slice(0, cut), given = text.slice(cut + 1);
      if (cut < 1 || !NAME.test(name) || !given || given.length > 1024) throw new Error('Give each recorded value as --record <name>=<value>.');
      if (Object.hasOwn(options.records, name)) throw new Error(`${name} is recorded twice.`);
      options.records[name] = given;
    } else if (arg === '--resume') { options.resume = value(); if (!RUN_ID.test(options.resume)) throw new Error('A run id is 8 base32 characters.'); }
    else if (arg === '--from') { options.from = value(); if (!TEST_ID.test(options.from)) throw new Error('--from names a test, such as C6.'); }
    else if (arg.startsWith('-')) throw new Error(`${arg} is not an option of this command.`);
    else if (options.appId === null) { if (!APP.test(arg)) throw new Error(`${arg} is not an app id.`); options.appId = arg; }
    else throw new Error(`Name one app; ${arg} is a second one.`);
  }
  if (options.check) {
    if (options.folder || options.resume || options.from || Object.keys(options.records).length) throw new Error('--check takes an app id at most.');
    return options;
  }
  if (!options.appId) throw new Error('Name the app whose live tests to run, such as google-calendar.');
  if (!options.folder) throw new Error('Give the live-test folder with --folder <absolute path>. FABRIC_DATA_DIR is never used.');
  if (!path.isAbsolute(options.folder)) throw new Error('Give --folder as an absolute path.');
  if (options.from && !options.resume) throw new Error('--from goes with --resume <runId>.');
  if (options.resume && Object.keys(options.records).length) throw new Error('A resumed run keeps the values it recorded; give no --record.');
  return options;
}

/**
 * The port the runner gets: the fabric/0.1 client calls on a grant this run holds, and read-only lookups. Every read is a copy. Nothing
 * in it approves, decides, sets or resets a row, or promotes an action. `app` is createApp()'s object (or {store, runtime, protocol, origin}); `owner` binds the
 * grants and nothing else.
 */
export function harnessPort(app, {owner = CERTIFICATION_OWNER} = {}) {
  const tokens = new Map(), issued = [];
  const readyAccount = appId => app.store.list('connections').filter(item => item.appId === appId && item.status === 'ready').sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt))[0] ?? null;
  const copy = value => value === undefined || value === null ? null : structuredClone(value);
  const body = item => item.body === null || item.body === undefined ? {} : {body: item.body};
  return Object.freeze({
    /** A client call (calls.create, calls.get or proxy.request) on one of this run's grants, with its request id. */
    async call(grantId, method, params, requestId) {
      const token = tokens.get(grantId);
      if (!token) throw new Error('That grant is not one this run holds.');
      return copy(await app.protocol.handle(`Bearer ${token}`, {protocol: 'fabric/0.1', id: requestId, method, params}));
    },
    /** The exact requests a waiting card would send: an action's stored prepared bytes, or a proxy job's request. */
    prepared(jobId) {
      const job = app.store.get('jobs', jobId);
      if (job?.kind === 'proxy') return [{method: job.proxy.method, url: job.proxy.url, ...body(job.proxy)}];
      const content = app.store.get('actionPrepared', jobId)?.content;
      if (!record(content)) return [];
      return [...(content.reads ?? []).filter(item => item.template === undefined), ...(content.resolving ? [content.resolving] : []), ...(content.perform ?? [])].map(item => ({method: item.method, url: item.url, ...body(item)}));
    },
    job: jobId => copy(app.store.get('jobs', jobId)),
    /** The stored job whose request id this is, the latest when a request was sent again. */
    jobFor(requestId) {
      const found = app.store.list('jobs').filter(job => job?.source?.requestId === requestId).sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt));
      return copy(found.at(-1));
    },
    rowMode: (connectionId, row) => app.runtime.proxyPolicy.view(connectionId).find(item => item.row === `group:${row}`)?.mode ?? null,
    /** The app's ready account, the oldest when there are several: its id and the address its sign-in gave. */
    account(appId) {
      const ready = readyAccount(appId);
      if (!ready) return null;
      const email = [ready.identity?.email, ready.identity?.displayName].find(value => typeof value === 'string' && EMAIL.test(value)) ?? null;
      return {connectionId: ready.id, email: email?.toLowerCase() ?? null};
    },
    /** A client grant of the named actions on the account and the named rows as proxy rows. Its token stays here. */
    grant({name, connectionId, actions = [], rows = [], expiresInSeconds}) {
      const {client, token} = app.protocol.createClient({name, bindings: actions.map(capabilityId => ({connectionId, capabilityId})), ...(rows.length ? {proxy: [{connectionId, rows: rows.map(row => `group:${row}`)}]} : {}), expiresInSeconds}, owner);
      tokens.set(client.id, token);
      issued.push(client.id);
      return {id: client.id, actions: client.bindings.map(binding => binding.capabilityId), rows: [...rows], expiresAt: client.expiresAt};
    },
    revokeGrant(id) {
      tokens.delete(id);
      try { app.protocol.revokeClient(id); } catch (error) { if (error?.code !== 'not_found') throw error; }
    },
    /** This port's grants still active. */
    grants: () => issued.filter(id => app.store.get('clientGrants', id)?.status === 'active'),
    link: jobId => `${app.origin}/approve/${jobId}`,
    appLink: appId => `${app.origin}/connectors/${appId}`,
    /** F10.19: the token introspection of the app's ready account (the one account() names), through its own sign-in, as {active, scope}
     *  only; null for an app whose provider has none, or with no ready account. It changes nothing at the provider or here. */
    async introspect(appId) {
      const providerId = providerOf(appId), ready = readyAccount(appId);
      if (!providerId || !Object.hasOwn(INTROSPECTION, providerId) || !ready) return null;
      const answer = await app.connections.providers.resolve({providerId, appId}).introspect(ready.id);
      return {active: answer?.active === true, scope: typeof answer?.scope === 'string' ? answer.scope : null};
    },
  });
}

/** The owner's facts: the address from the account (typedAddress() when its sign-in reads none), the time zone from the plan's read (inside
 *  a setup test, on a grant of its read rows that is revoked at once) or this machine's, and the run date in that zone. */
export async function readOwner(port, plan, {guard, clock = Date.now, prompt = async () => ''}) {
  const account = port.account(plan.appId);
  if (!account) throw new Error(`No ready ${plan.appId} account: connect one first.`);
  const email = account.email ?? await typedAddress(plan.appId, prompt);
  let timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  if (plan.timeZone) {
    guard.begin('setup');
    let grant = null;
    try {
      grant = port.grant({name: `Live test setup ${guard.runId}`, connectionId: account.connectionId, rows: plan.readRows, expiresInSeconds: 600});
      const answer = await port.call(grant.id, 'proxy.request', {connectionId: account.connectionId, request: {method: 'GET', path: plan.timeZone.path}}, `${guard.runId}.setup.1`);
      if (answer.error || answer.result?.status !== 'succeeded') throw new Error(`Fabric could not read the time zone (${answer.error?.code ?? answer.result?.status}).`);
      timeZone = plan.timeZone.pointer === '' ? answer.result.result?.response?.body : plan.timeZone.pointer.slice(1).split('/').reduce((value, part) => value?.[part.replace(/~1/g, '/').replace(/~0/g, '~')], answer.result.result?.response?.body);
    } finally {
      if (grant) port.revokeGrant(grant.id);
      guard.end();
    }
  }
  return {email, timeZone, runDate: runDateOf(clock(), timeZone)};
}

/**
 * The address the owner types once at a new run's start, for an app whose reviewed sign-in reads none (GitHub and Slack: docs/F10.17-BUILD-MAP.md
 * section 9, docs/F10.21-BUILD-MAP.md question 16). An app whose sign-in reads one (Gmail, Calendar, Notion) never takes a typed address, so
 * the guard sends only to the address the provider gave. Anything but one address refuses before a test runs.
 */
async function typedAddress(appId, prompt) {
  const providerId = providerOf(appId), definition = providerId ? definitionFor(providerId) : null;
  if (!definition || definition.identity.email !== null) throw new Error(`The ${appId} account has no email address Fabric can read, so the guard cannot know the owner.`);
  const typed = String(await prompt(`${definition.displayName} gives Fabric no email address. Type the address you use with ${definition.displayName}; the guard keeps it as this run's owner, and the evidence never holds it.`) ?? '').trim().toLowerCase();
  if (!EMAIL.test(typed) || typed.length > 320) throw new Error('That is not one email address, so the guard cannot know the owner. Nothing was sent.');
  return typed;
}

/** A resumed run's owner, never asked again: the account's address, else the one the run's guard saved when the owner typed it, with the
 *  zone, date and recorded values the run state kept. */
export function resumedOwner(port, plan, guard, data) {
  const email = port.account(plan.appId)?.email ?? guard.owner()?.email;
  if (!email) throw new Error(`The ${plan.appId} account has no email address Fabric can read, and this run saved none, so the guard cannot know the owner.`);
  return {email, timeZone: data.timeZone, runDate: data.runDate, recorded: data.recorded};
}

/** The provider whose reviewed sign-in carries an app. */
const providerOf = appId => reviewedProviderIds().find(id => definitionFor(id).apps.some(item => item.appId === appId)) ?? null;

/**
 * F10.19 (spec line 1174, B6): for an app whose provider has a token introspection (Notion), asks it once through the port, says whether its
 * scope lists the capabilities the sign-in attests, and writes docs/live-evidence/<appId>/introspection.json under `root` (writeIntrospection()).
 * Any other app: nothing is asked and nothing written. Returns the record, or null.
 */
export async function introspectOnce(port, plan, {runId, at, root = ROOT, emails = [], say = () => {}} = {}) {
  const providerId = providerOf(plan.appId);
  if (!providerId || !Object.hasOwn(INTROSPECTION, providerId)) return null;
  const answer = await port.introspect(plan.appId);
  if (!answer) throw new Error(`No ready ${plan.appId} account to introspect: connect one first.`);
  const attested = definitionFor(providerId).apps.find(item => item.appId === plan.appId)?.attestedCapabilities ?? [];
  const named = typeof answer.scope === 'string' ? answer.scope.split(/[\s,]+/).filter(Boolean) : [];
  const record = {schemaVersion: 1, appId: plan.appId, runId, at, active: answer.active === true, scope: typeof answer.scope === 'string' ? answer.scope : null,
    listsCapabilities: attested.some(name => named.includes(name))};
  writeIntrospection(root, plan.appId, record, {emails});
  say(`${plan.appId} token introspection: ${record.active ? 'active' : 'not active'}; its scope ${record.listsCapabilities ? 'lists' : 'does not list'} the integration's capabilities.`);
  return record;
}
const googleApp = appId => GOOGLE_APPS.includes(appId);

/** GitHub: before a connect link, the live tokens Muse counted elsewhere for this scope set, and the counts the guard will hold it to. */
async function githubCount(app, guard, folder, {say, prompt, clock}) {
  const provider = app.connections.providers.resolve({providerId: 'github', appId: 'github'}), {scopes, userScopes} = provider.plan({appId: 'github', writeAccess: true});
  const set = [...new Set([...scopes, ...userScopes])].sort(), file = signInFile(folder);
  const log = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')).signIns.filter(entry => entry.providerId === 'github') : [];
  const hour = log.filter(entry => clock() - Date.parse(entry.at) < 60 * 60_000).length, here = log.filter(entry => entry.scopes.join(' ') === set.join(' ')).length;
  let elsewhere = null;
  while (elsewhere === null) {
    const answer = String(await prompt(`How many GitHub tokens for these permissions are live elsewhere (S7.13's paper log)? Type a number.`) ?? '').trim();
    if (/^(0|[1-9][0-9]?)$/.test(answer)) elsewhere = Number(answer);
  }
  guard.setElsewhere('github', set, elsewhere);
  say(`GitHub sign-in: ${hour} of ${LIMITS.githubHourly} this hour, ${here} live in this folder, ${elsewhere} elsewhere. Refused at ${LIMITS.githubTokens} in total.`);
}

/** The preconditions, each with a prompt and a wait: a ready account (reused when there is one), a stored map for a Google app, and a
 *  consent that is not about to end. */
async function preconditions(app, port, plan, {guard, folder, say, prompt, clock}) {
  const appId = plan.appId, providerId = providerOf(appId);
  while (!port.account(appId)) {
    if (providerId === 'github') await githubCount(app, guard, folder, {say, prompt, clock});
    say(`Connect ${appId} first: ${port.appLink(appId)}`);
    await prompt('Press Enter once it is connected.');
  }
  while (googleApp(appId) && !app.store.get('applicationMaps', appId)) {
    say(`Discover it on the app page first: ${port.appLink(appId)}`);
    await prompt('Press Enter once it is discovered.');
  }
  const provider = providerId ? app.connections.providers.resolve({providerId, appId}) : null;
  while (consentDue(app.store.get('connections', port.account(appId).connectionId), {consentDays: provider?.consentDays, now: clock()})) {
    say(`Sign in again first; a renewal keeps your settings: ${port.appLink(appId)}`);
    await prompt('Press Enter once you have signed in again.');
  }
}

/** --check: each plan (or the named app's) against the shipped action catalog, rows, proxy settings and guard rules. Offline. */
function checkPlans(appId, {plans, say}) {
  const files = existsSync(plans) ? readdirSync(plans).filter(name => name.endsWith('.json')).sort() : [];
  const chosen = appId ? files.filter(name => name === `${appId}.json`) : files;
  if (!chosen.length) {
    say(appId ? `No live test plan for ${appId} yet.` : 'No app has a live test plan yet.');
    return appId ? 1 : 0;
  }
  const read = file => JSON.parse(readFileSync(path.join(ROOT, file), 'utf8'));
  const maps = new Map(GOOGLE_APPS.map(id => [id, methodMap(read(PATHS_FILE), read(SCOPES_FILE), id)]).filter(([, map]) => map));
  const catalog = loadActionCatalog({maps});
  let failed = 0;
  for (const name of chosen) {
    const id = name.slice(0, -'.json'.length);
    try {
      const plan = JSON.parse(readFileSync(path.join(plans, name), 'utf8'));
      if (!record(plan) || plan.appId !== id) throw new Error(`${name} must be named after its appId.`);
      if (catalog.refused.has(id)) throw new Error(`the action file of ${id} does not load: ${catalog.refused.get(id)}`);
      const checked = checkPlan(plan, {entries: [...catalog.entries.values()].filter(item => item.appId === id).map(item => item.entry), superseded: [...catalog.superseded.keys()],
        groups: PERMISSION_GROUPS.get(id), config: PROXY_CONFIGS.get(id), rules: RULES});
      say(`${id}: ${checked.plan.tests.length} tests check, calling ${checked.actions.size} actions.`);
    } catch (error) {
      failed++;
      say(`${id}: ${error.message}`);
    }
  }
  return failed ? 1 : 0;
}

/** A line typed at the terminal. */
async function ask(words) {
  const terminal = createInterface({input: process.stdin, output: process.stdout});
  try { return await terminal.question(`${words} `); } finally { terminal.close(); }
}

/**
 * The command. Order: the arguments; --check alone; the folder (certificationFolderRefusal()) and the plan's structure and recorded
 * values, before anything opens; the folder lock; the guard and createApp() on port 4320 with a designated store (new for an empty
 * folder, require after) and the fixed owner; start; the preconditions; checkPlan(); the owner's facts; runLiveTests() with its stop
 * steps; the evidence; every grant of the run revoked; close; the lock released. `deps`, `plans` and `evidenceRoot` are test seams.
 * Returns the exit code.
 */
export async function main(argv = process.argv.slice(2), {say = line => console.log(line), prompt = ask, deps = {}, plans = PLANS, evidenceRoot = ROOT, clock = Date.now} = {}) {
  const create = deps.createApp ?? createApp, lock = deps.lockDataDir ?? lockDataDir;
  let args;
  try { args = parseArgs(argv); } catch (error) { say(error.message); say(USAGE); return 2; }
  if (args.check) return checkPlans(args.appId, {plans, say});
  const refusal = certificationFolderRefusal(args.folder, {root: ROOT});
  if (refusal) { say(refusal); return 2; }
  let plan;
  try {
    const file = path.join(plans, `${args.appId}.json`);
    if (!existsSync(file)) throw new Error(`No live test plan for ${args.appId} yet.`);
    plan = checkPlanShape(JSON.parse(readFileSync(file, 'utf8')));
    if (plan.appId !== args.appId) throw new Error(`${args.appId}.json must be named after its appId.`);
  } catch (error) { say(error.message); return 2; }
  if (!args.resume) {
    const missing = Object.keys(plan.recorded).filter(name => !Object.hasOwn(args.records, name)), extra = Object.keys(args.records).filter(name => !Object.hasOwn(plan.recorded, name));
    if (missing.length || extra.length) {
      say(missing.length ? `Give each value the plan records: ${missing.map(name => `--record ${name}=<value> (${plan.recorded[name]})`).join(' ')}` : `The plan records no ${extra.join(' or ')}.`);
      return 2;
    }
  }
  const release = await lock(args.folder);
  let app = null, port = null;
  try {
    const key = randomBytes(32), runId = args.resume ?? newRunId();
    const guard = createGuard({appId: plan.appId, runId, folder: args.folder, key, clock});
    app = await create({dataDir: args.folder, port: CERTIFICATION_PORT, localAuthority: {mode: existsSync(path.join(args.folder, 'fabric.sqlite')) ? 'require' : 'new', ownerPrincipal: CERTIFICATION_OWNER},
      certification: {guard}});
    await app.start();
    say(`A Fabric for live tests runs at ${app.origin} (run ${runId}). Approve each card there; nothing else needs you unless the run asks.`);
    port = harnessPort(app);
    await preconditions(app, port, plan, {guard, folder: args.folder, say, prompt, clock});
    if (!app.actions) throw new Error('The action catalog did not load, so no action can run.');
    const entries = [...app.actions.entries.values()].filter(item => item.appId === plan.appId).map(item => item.entry);
    const checked = checkPlan(plan, {entries, superseded: [...app.actions.superseded.keys()], groups: PERMISSION_GROUPS.get(plan.appId), config: PROXY_CONFIGS.get(plan.appId), rules: RULES});
    let state;
    if (args.resume) {
      state = openRunState(args.folder, plan.appId, runId);
      guard.setOwner(resumedOwner(port, plan, guard, state.data));
    } else {
      const facts = await readOwner(port, plan, {guard, clock, prompt});
      guard.setOwner({...facts, recorded: args.records});
      state = openRunState(args.folder, plan.appId, runId, {runDate: facts.runDate, timeZone: facts.timeZone, recorded: args.records});
      // F10.19: a new run of an app with a token introspection asks it once, before its first test (N0 records what it says).
      await introspectOnce(port, plan, {runId, at: new Date(clock()).toISOString(), root: evidenceRoot, emails: [facts.email], say});
    }
    say(`Run date ${state.data.runDate} in ${state.data.timeZone}: every date of this run falls on days 7 to 13 after it.`);
    const run = await runLiveTests(port, checked, {guard, state, prompt, say, clock, from: args.from ?? undefined, leave: args.leave});
    const map = app.store.get('applicationMaps', plan.appId);
    const evidence = evidenceRecords(run, {key, entries, trace: id => guard.trace(id), job: id => port.job(id), maps: new Map(map ? [[plan.appId, map]] : [])});
    writeEvidence(evidenceRoot, plan.appId, evidence, {emails: [port.account(plan.appId)?.email, guard.owner()?.email].filter(Boolean)});
    say(`Evidence: docs/live-evidence/${plan.appId}/actions.json. Commit it only with the owner's OK.`);
    for (const item of run.left) say(`Still there: ${item}`);
    if (run.stopped) say(`To resume: node --env-file-if-exists=.env scripts/live-certify.mjs ${plan.appId} --folder ${args.folder} --resume ${runId} --from ${run.stopped.test}`);
    return run.stopped ? 1 : 0;
  } catch (error) {
    say(String(error?.message ?? error));
    return 1;
  } finally {
    if (port) for (const id of port.grants()) port.revokeGrant(id);
    if (app) await app.close();
    await release();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = await main();

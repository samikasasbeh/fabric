import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {templateChecks, gatePasses, signInFor, TEMPLATE_APPS, CASE_KINDS, requiredKinds} from '../scripts/app-template-check.mjs';
import {dataHash, defaultsTable} from '../scripts/defaults-golden.mjs';
import {validateActionFile} from '../lib/actions.mjs';
import {fixtureGroups, fixtureConfigs, fixtureMap, fixtureChoices, fixtureActions, fixtureSignIn} from './fixtures/actions/fixture-app.mjs';
import {TRANSFORMS, PINS} from './fixtures/actions/registry.mjs';

// F10.1 template check skeleton. The ratchet holds which exit-gate checks pass for each of the five template apps:
// a check that starts failing again fails here, and so does one that starts passing without the ratchet being updated.
const RATCHET = JSON.parse(readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'access', 'template-ratchet.json'), 'utf8'));
const CHECKS = ['auth-definition', 'closure', 'rows', 'row-scope-data', 'defaults', 'actions', 'live-evidence', 'sign-in-evidence'];

test('every template app matches the recorded ratchet, check by check', () => {
  assert.deepEqual(Object.keys(RATCHET.apps).sort(), [...TEMPLATE_APPS].sort());
  for (const appId of TEMPLATE_APPS) {
    const checks = templateChecks(appId);
    assert.deepEqual(checks.map(item => item.id), CHECKS, appId);
    assert.deepEqual(Object.fromEntries(checks.map(item => [item.id, item.pass])), RATCHET.apps[appId], `${appId}: update test/fixtures/access/template-ratchet.json on purpose when a check changes`);
    for (const item of checks) if (!item.pass) assert.ok(item.reason && item.reason !== 'passes', `${appId} ${item.id} says why it fails`);
    // F10.21 listed churn: Slack passes checks 1 to 5 once its reviewed actions pass; its live checks wait for the operator's setup and do not gate.
    // F10.14 and F10.16 listed churn: Calendar and Gmail pass all eight on 2026-10-29, live evidence and sign-in evidence included.
    const grade = ['slack', 'google-calendar', 'gmail'].includes(appId);
    assert.equal(gatePasses(checks), grade, `${appId} is ${grade ? 'Muse-grade' : 'not Muse-grade yet'}`);
  }
  // Slack's live checks wait for the operator's setup and do not gate; every other app's checks all gate.
  assert.deepEqual(templateChecks('slack').filter(item => !item.required).map(item => item.id), ['live-evidence', 'sign-in-evidence']);
  assert.ok(templateChecks('gmail').every(item => item.required));
  assert.throws(() => templateChecks('dropbox'), /not one of the template apps/);
});

test('the checks can pass: a version 2 definition with a closed full level, signed defaults and version 2 rows', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-template-'));
  try {
    const groups = {schemaVersion: 2, appId: 'demo', groups: [
      {id: 'demo.read', label: 'Read', effect: 'read', defaultMode: 'allow', operations: ['demo.list', 'demo.get'], requests: []},
      {id: 'demo.purge', label: 'Purge', effect: 'delete', defaultMode: 'deny', operations: ['demo.purge'], requests: [], unavailable: {'demo.purge': 'not-requested'}},
      {id: 'demo.admin', label: 'Administer', effect: 'write', defaultMode: 'ask', operations: ['demo.admin'], requests: []}]};
    const facts = {apps: {demo: {methods: {'demo.list': ['read'], 'demo.get': ['read', 'all'], 'demo.purge': ['all'], 'demo.admin': ['admin']}}}};
    // The in-context scope names its row, in the version 2 {scope, rows} shape.
    const definition = {schemaVersion: 2, providerId: 'demo', consentPolicy: {testing: 'full', production: 'required'}, authorization: {identityScopes: ['openid']},
      apps: [{appId: 'demo', access: {default: 'full', grant: 'scope', levels: {full: {required: ['read'], optional: [], inContext: [{scope: 'admin', rows: ['demo.admin']}]}, read: null}}, neverRequest: ['all']}]};
    mkdirSync(path.join(root, 'catalog', 'permissions'), {recursive: true});
    mkdirSync(path.join(root, 'test', 'fixtures', 'access'), {recursive: true});
    writeFileSync(path.join(root, 'catalog', 'permissions', 'demo.json'), JSON.stringify(groups));
    // F10.7 (docs/F10.7-BUILD-MAP.md decision 2): a sign-off binds the hash of the defaults table the data gives now. This root is a
    // temporary folder; only Sami's approval signs the shipped golden.
    const golden = path.join(root, 'test', 'fixtures', 'access', 'defaults.golden.json'), current = dataHash('demo', defaultsTable({appId: 'demo', definition, groups, facts}));
    const sign = (signedOff, recorded = current) => writeFileSync(golden, JSON.stringify({schema: 1, apps: {demo: {dataHash: recorded, signedOff}}}));
    sign({by: 'Test signer', date: '2026-10-18', dataHash: current});
    const run = (overrides = {}) => Object.fromEntries(templateChecks('demo', {root, definitions: [overrides.definition || definition], groups: overrides.groups || groups, scopeFacts: facts}).map(item => [item.id, item]));
    let checks = run();
    for (const id of ['auth-definition', 'closure', 'rows', 'row-scope-data', 'defaults']) assert.equal(checks[id].pass, true, `${id}: ${checks[id].reason}`);
    for (const id of ['actions', 'live-evidence', 'sign-in-evidence']) assert.equal(checks[id].pass, false, id);

    // Adversarial: a member that can never work but is not marked unavailable fails the closure.
    const unmarked = structuredClone(groups); delete unmarked.groups[1].unavailable;
    assert.match(run({groups: unmarked}).closure.reason, /1 member\(s\) can never work and are not marked unavailable/);
    // A granted scope nothing uses is unjustified; a member lacking a requestable scope is missing.
    const wide = structuredClone(definition); wide.apps[0].access.levels.full.optional = ['spare'];
    assert.match(run({definition: wide}).closure.reason, /unjustified scopes: spare/);
    const narrowFacts = structuredClone(definition); narrowFacts.apps[0].access.levels.full.required = ['other'];
    assert.match(run({definition: narrowFacts}).closure.reason, /2 member\(s\) lack a scope/);
    // Without its in-context scope, the administer member lacks a scope.
    const noInContext = structuredClone(definition); noInContext.apps[0].access.levels.full.inContext = [];
    assert.match(run({definition: noInContext}).closure.reason, /1 member\(s\) lack a scope/);
    // A sign-off counts only while it binds the table the data gives now, and an unsigned or missing golden never passes.
    sign({by: 'Test signer', date: '2026-10-18', dataHash: '0'.repeat(64)});
    assert.equal(run().defaults.reason, 'the table changed since the owner signed the defaults');
    sign({by: 'Test signer', date: '2026-10-18', dataHash: '0'.repeat(64)}, '0'.repeat(64));
    assert.equal(run().defaults.reason, 'the data changed since the owner signed the defaults');
    sign(null);
    assert.deepEqual([run().defaults.pass, run().defaults.reason], [false, 'the defaults table is not signed yet']);
    sign({by: '', date: '2026-10-18', dataHash: current});
    assert.equal(run().defaults.pass, false, 'a sign-off with no name is no sign-off');
    rmSync(golden);
    assert.equal(run().defaults.reason, 'no owner-signed defaults table yet');
    // Any changed default leaves the old sign-off behind.
    sign({by: 'Test signer', date: '2026-10-18', dataHash: current});
    const stricter = structuredClone(groups); stricter.groups[2].defaultMode = 'deny';
    assert.equal(run({groups: stricter}).defaults.reason, 'the data changed since the owner signed the defaults');
    // A definition without a consent policy or never-request list is not version 2 enough.
    const loose = structuredClone(definition); delete loose.consentPolicy;
    assert.equal(run({definition: loose})['auth-definition'].pass, false);
    const noNever = structuredClone(definition); delete noNever.apps[0].neverRequest;
    assert.equal(run({definition: noNever})['auth-definition'].reason, 'the app has no never-request list');
    // Notion-style page grants need no consent policy.
    const pages = structuredClone(loose); pages.apps[0].access.grant = 'pages';
    assert.equal(run({definition: pages})['auth-definition'].pass, true);
  } finally { rmSync(root, {recursive: true, force: true}); }
  assert.equal(signInFor('google-calendar').definition.providerId, 'google');
  assert.throws(() => signInFor('nothing', []), /No reviewed sign-in definition carries nothing/);
});

// F10.6 (docs/F10.6-BUILD-MAP.md part j, open question 11): its own check, after `rows`. Every member of every row has Discovery
// facts, row scope data or an unavailable marker, read by one member key (correction 5).
test('row-scope-data: a member with no facts, no row sets and no marker fails the check, and passes once it is marked', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-template-rows-'));
  try {
    const groups = {schemaVersion: 2, appId: 'demo', groups: [
      {id: 'demo.read', label: 'Read', effect: 'read', defaultMode: 'allow', operations: ['demo.list'], requests: ['GET /extra']},
      {id: 'demo.purge', label: 'Purge', effect: 'delete', defaultMode: 'deny', operations: ['demo.purge'], requests: [], unavailable: {'demo.purge': 'not-requested'}}]};
    const facts = {apps: {demo: {methods: {'demo.list': ['read'], 'demo.purge': ['all']}}}};
    const definition = {schemaVersion: 2, providerId: 'demo', consentPolicy: {testing: 'full', production: 'full'}, authorization: {identityScopes: []},
      apps: [{appId: 'demo', access: {default: 'full', grant: 'scope', levels: {full: {required: ['read'], optional: [], inContext: []}, read: null}}, neverRequest: ['all']}]};
    mkdirSync(path.join(root, 'catalog', 'permissions'), {recursive: true});
    const check = rows => {writeFileSync(path.join(root, 'catalog', 'permissions', 'demo.json'), JSON.stringify(rows)); return templateChecks('demo', {root, definitions: [definition], groups: rows, scopeFacts: facts}).find(item => item.id === 'row-scope-data');};
    const missing = check(groups);
    assert.equal(missing.pass, false); assert.match(missing.reason, /GET \/extra|1 member/);
    const marked = structuredClone(groups); marked.groups[0].memberScopeSets = {'GET /extra': [['read']]};
    assert.equal(check(marked).pass, true);
    const unavailable = structuredClone(groups); unavailable.groups[0].unavailable = {'GET /extra': 'no-oauth-scope'};
    assert.equal(check(unavailable).pass, true);
  } finally { rmSync(root, {recursive: true, force: true}); }
});

// F10.9 part l (docs/F10.9-BUILD-MAP.md part l; F10.8 map part m): check 5 reads the app's action file through validateActionFile(),
// with the app's choice sources and the pins of lib/transforms/pins.json, and recomputes the code of every transform the file names.
// Check 6 takes the ids the validator computes, pins included, never a raw id field, and a live record counts only when it carries the
// pins of the action's transforms. Check 5 stays false whatever the file holds until the app has its own provider simulator (steps 13 to 21).
// The fixture app's sign-in lives in test/fixtures/actions/fixture-app.mjs since F10.11 part b.
const FIXTURE_SIGN_IN = fixtureSignIn;

test('check 5 reads the action file through the validator and its transform pins; check 6 takes the ids the validator computes', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-template-actions-'));
  try {
    const groups = fixtureGroups(), definition = FIXTURE_SIGN_IN();
    const deps = {groups, configs: fixtureConfigs(groups), maps: new Map([['fixture', fixtureMap()]]), transforms: TRANSFORMS, pins: PINS};
    const actionsDir = path.join(root, 'catalog', 'actions'), choicesDir = path.join(root, 'catalog', 'choices'), evidenceDir = path.join(root, 'docs', 'live-evidence', 'fixture');
    for (const folder of [actionsDir, choicesDir, evidenceDir]) mkdirSync(folder, {recursive: true});
    writeFileSync(path.join(choicesDir, 'fixture.json'), JSON.stringify(fixtureChoices()));
    const writeActions = file => writeFileSync(path.join(actionsDir, 'fixture.json'), typeof file === 'string' ? file : JSON.stringify(file));
    const writeEvidence = records => writeFileSync(path.join(evidenceDir, 'actions.json'), JSON.stringify(records));
    // The code each named transform gives now: by default exactly its pin, as when nothing changed since it was pinned.
    let codeOf = id => PINS[id];
    const run = (given = deps) => Object.fromEntries(templateChecks('fixture', {root, definitions: [definition], groups: groups.get('fixture'), scopeFacts: {apps: {}},
      actionDeps: given, codeHashes: ids => Object.fromEntries(ids.map(id => [id, codeOf(id)]))}).map(item => [item.id, item]));
    const reasons = (checks = run()) => [checks.actions.pass, checks.actions.reason, checks['live-evidence'].pass, checks['live-evidence'].reason];

    // No file: today's reasons.
    assert.deepEqual(reasons(), [false, 'no action file yet (F10.13 to F10.21)', false, 'no actions to certify yet']);
    // A valid reviewed file, its transforms pinned and unchanged: what is left is the app's own simulator (steps 13 to 21; F10.11 listed churn:
    // the reason names it) and live evidence (F10.12).
    const file = {...fixtureActions(), reviewStatus: 'reviewed'}, entries = validateActionFile(file, {...deps, choices: new Map([['fixture', fixtureChoices().sources]])}).actions;
    writeActions(file);
    assert.deepEqual(reasons(), [false, 'no provider simulator for fixture yet (steps 13 to 21)', false, `${entries.length} of ${entries.length} actions have no passing live record for their id and the current pins of their transforms`]);
    // Check 5 counts reviewed actions only (I8): the same file as a candidate says so, though its ids are the same (review state is not hashed).
    writeActions({...file, reviewStatus: 'candidate'});
    assert.deepEqual(reasons(), [false, 'the action file is a candidate: no reviewer has marked it reviewed yet (I8)', false, `${entries.length} of ${entries.length} actions have no passing live record for their id and the current pins of their transforms`]);
    writeActions(file);
    // Check 6 counts a record only under the id the validator computed, with the pins of every transform the action names.
    const pinsOf = entry => Object.fromEntries(entry.transforms.map(id => [id, PINS[id]]));
    const records = Object.fromEntries(entries.map(entry => [entry.id, {passed: true, transforms: pinsOf(entry)}]));
    writeEvidence(records);
    assert.equal(run()['live-evidence'].pass, true, 'every action has a passing record');
    const named = entries.find(entry => entry.transforms.length);
    writeEvidence({...records, [named.id]: {passed: true, transforms: {...pinsOf(named), [named.transforms[0]]: 'f'.repeat(64)}}});
    assert.equal(run()['live-evidence'].reason, `1 of ${entries.length} actions have no passing live record for their id and the current pins of their transforms`, 'a record made under another pin');
    writeEvidence({...records, [named.id]: {passed: true}});
    assert.equal(run()['live-evidence'].pass, false, 'a record without the transform pins');
    writeEvidence(records);
    // A transform whose code changed since it was pinned fails check 5, by name; its pin, and so every id, is unchanged.
    const changed = named.transforms[0];
    codeOf = id => id === changed ? 'e'.repeat(64) : PINS[id];
    assert.match(run().actions.reason, new RegExp(`^the code of ${changed.replace(/[.@]/g, '\\$&')} changed since it was pinned: run node scripts/transform-pins\\.mjs --check`));
    codeOf = id => PINS[id];
    // A transform the pins file does not hold: the validator refuses the file, and check 5 says why.
    const {[changed]: dropped, ...fewer} = PINS;
    void dropped;
    assert.match(run({...deps, pins: fewer}).actions.reason, new RegExp(`^the action file does not pass the validator: .*${changed.replace(/[.@]/g, '\\$&')}.*no pin`));
    // Without the app's map none of its steps can be placed (templatesFor() has nothing for an app with a typed operation): valid in
    // shape, never runnable, so check 5 says so.
    assert.match(run({...deps, maps: new Map()}).actions.reason, /^7 of 7 actions cannot be placed: fixture is reviewed by operation id, and the check has no method table for it/);

    // A file the validator refuses: check 5 gives the validator's words, and check 6 has no ids, though the raw id fields have passing
    // records: an id is what the content hashes to, never what a file says.
    const stale = structuredClone(file);
    stale.actions[1].description = 'Renames an item or changes its label, as written by another hand.';
    writeActions(stale);
    assert.match(run().actions.reason, /^the action file does not pass the validator: Actions for fixture: update-item v1: id is fixture\.action\.update-item\.v1\.[a-f0-9]{24}, but its content hashes to /);
    assert.deepEqual([run()['live-evidence'].pass, run()['live-evidence'].reason], [false, 'the action file does not pass the validator, so no action has an id to certify']);
    // A file that is not JSON, and a choices file the choice source validator refuses, are reasons too.
    writeActions('{not json');
    assert.equal(run().actions.reason, 'the action file catalog/actions/fixture.json is not JSON');
    writeActions(file);
    writeFileSync(path.join(choicesDir, 'fixture.json'), JSON.stringify({...fixtureChoices(), schemaVersion: 1}));
    assert.match(run().actions.reason, /^the choice sources do not pass their validator: Choice sources for fixture: a choice source file holds exactly schemaVersion 2/);
  } finally { rmSync(root, {recursive: true, force: true}); }
});

// Check of part l: check 5 reads only the app's own files, as loadActions() and loadChoiceSources() do (a file not named after its appId
// is refused), so another app's actions are never certified as this app's; and a choice source file that is not JSON is a reason, never
// a crash of the whole check.
test('check of part l: check 5 reads an action or choice source file only when it is named after its appId, and a choice source file that is not JSON is a reason', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-template-own-'));
  try {
    const groups = fixtureGroups(), file = {...fixtureActions(), reviewStatus: 'reviewed'};
    const deps = {groups, configs: fixtureConfigs(groups), maps: new Map([['fixture', fixtureMap()]]), transforms: TRANSFORMS, pins: PINS};
    const actionsDir = path.join(root, 'catalog', 'actions'), choicesDir = path.join(root, 'catalog', 'choices');
    for (const folder of [actionsDir, choicesDir, path.join(root, 'docs', 'live-evidence', 'fixture-rpc')]) mkdirSync(folder, {recursive: true});
    const run = (appId, given = deps) => Object.fromEntries(templateChecks(appId, {root, definitions: [FIXTURE_SIGN_IN(appId)], groups: groups.get(appId), scopeFacts: {apps: {}},
      actionDeps: given, codeHashes: ids => Object.fromEntries(ids.map(id => [id, PINS[id]]))}).map(item => [item.id, item]));

    // fixture-rpc's action file holds the fixture app's actions, which pass the validator as the fixture app's, with passing records
    // under their ids in fixture-rpc's evidence: neither check reads them as fixture-rpc's.
    const ownDeps = {...deps, choices: new Map([['fixture', fixtureChoices().sources]]), identities: new Map([['fixture', FIXTURE_SIGN_IN()]])};
    const entries = validateActionFile(file, ownDeps).actions;
    writeFileSync(path.join(actionsDir, 'fixture-rpc.json'), JSON.stringify(file));
    writeFileSync(path.join(root, 'docs', 'live-evidence', 'fixture-rpc', 'actions.json'),
      JSON.stringify(Object.fromEntries(entries.map(entry => [entry.id, {passed: true, transforms: Object.fromEntries(entry.transforms.map(id => [id, PINS[id]]))}]))));
    const misnamed = run('fixture-rpc', ownDeps);
    assert.deepEqual([misnamed.actions.pass, misnamed.actions.reason, misnamed['live-evidence'].pass, misnamed['live-evidence'].reason],
      [false, 'the action file catalog/actions/fixture-rpc.json is not named after its appId: an action file holds its own app\'s actions (as loadActions() requires)',
        false, 'the action file does not pass the validator, so no action has an id to certify']);

    // The fixture app's own action file, beside a choice source file that names another app, or that is not JSON.
    writeFileSync(path.join(actionsDir, 'fixture.json'), JSON.stringify(file));
    writeFileSync(path.join(choicesDir, 'fixture.json'), JSON.stringify(fixtureChoices()));
    assert.equal(run('fixture').actions.reason, 'no provider simulator for fixture yet (steps 13 to 21)');
    writeFileSync(path.join(choicesDir, 'fixture.json'), JSON.stringify({...fixtureChoices(), appId: 'fixture-rpc'}));
    assert.equal(run('fixture').actions.reason, 'the choice source file catalog/choices/fixture.json is not named after its appId: a choice source file holds its own app\'s sources (as loadChoiceSources() requires)');
    writeFileSync(path.join(choicesDir, 'fixture.json'), '{not json');
    assert.equal(run('fixture').actions.reason, 'the choice source file catalog/choices/fixture.json is not JSON');
  } finally { rmSync(root, {recursive: true, force: true}); }
});

// F10.13 part 1 (docs/F10.13-BUILD-MAP.md part 1): check 5 passes only with the app's provider simulator case list,
// test/fixtures/provider-simulators/<appId>.cases.json: it names this app, a simulator and test files that exist under the root, and
// exactly the file's actions, each with every kind it needs (succeeds, refused and provider-refusal for every action; unverified and
// lost-answer too for one that is not a read). test/fixtures/provider-simulators/cases.mjs runs the same list, so the two cannot disagree.
test('F10.13 part 1: check 5 passes only with the app\'s simulator case list, and each way a list falls short has its own words', () => {
  // The root sits inside another folder that holds a real file, so a path that climbs out of the root names something that exists.
  const outer = mkdtempSync(path.join(tmpdir(), 'fabric-template-cases-')), root = path.join(outer, 'repo');
  try {
    mkdirSync(root);
    writeFileSync(path.join(outer, 'outside.test.mjs'), '// outside the root\n');
    const groups = fixtureGroups(), definition = FIXTURE_SIGN_IN();
    const deps = {groups, configs: fixtureConfigs(groups), maps: new Map([['fixture', fixtureMap()]]), transforms: TRANSFORMS, pins: PINS};
    for (const folder of ['catalog/actions', 'catalog/choices', 'test/fixtures/provider-simulators']) mkdirSync(path.join(root, folder), {recursive: true});
    writeFileSync(path.join(root, 'catalog', 'choices', 'fixture.json'), JSON.stringify(fixtureChoices()));
    const file = {...fixtureActions(), reviewStatus: 'reviewed'}, entries = validateActionFile(file, {...deps, choices: new Map([['fixture', fixtureChoices().sources]])}).actions;
    writeFileSync(path.join(root, 'catalog', 'actions', 'fixture.json'), JSON.stringify(file));
    const run = () => templateChecks('fixture', {root, definitions: [definition], groups: groups.get('fixture'), scopeFacts: {apps: {}}, actionDeps: deps,
      codeHashes: ids => Object.fromEntries(ids.map(id => [id, PINS[id]]))}).find(item => item.id === 'actions');
    const casesFile = path.join(root, 'test', 'fixtures', 'provider-simulators', 'fixture.cases.json');
    const writeCases = list => writeFileSync(casesFile, typeof list === 'string' ? list : JSON.stringify(list));
    const result = () => { const check = run(); return [check.pass, check.reason]; };

    // The kinds: three for a read, all five for an action that changes something.
    assert.deepEqual(CASE_KINDS, ['succeeds', 'refused', 'provider-refusal', 'unverified', 'lost-answer']);
    const read = entries.find(entry => entry.effect === 'read'), write = entries.find(entry => entry.effect === 'write');
    assert.deepEqual([requiredKinds(read), requiredKinds(write), requiredKinds(entries.find(entry => entry.effect === 'delete'))],
      [['succeeds', 'refused', 'provider-refusal'], CASE_KINDS, CASE_KINDS]);
    // No list: the reason step 11 gave.
    assert.deepEqual(result(), [false, 'no provider simulator for fixture yet (steps 13 to 21)']);
    // A complete list passes once its simulator and test files exist.
    const complete = {schemaVersion: 1, appId: 'fixture', simulator: 'test/fixtures/provider-simulators/fixture.mjs', tests: ['test/provider-simulator-fixture.test.mjs'],
      cases: Object.fromEntries(entries.map(entry => [`${entry.key} v${entry.version}`, requiredKinds(entry)]))};
    writeCases(complete);
    assert.deepEqual(result(), [false, 'the simulator case list names a simulator that is not a file under the root: test/fixtures/provider-simulators/fixture.mjs']);
    writeFileSync(path.join(root, 'test', 'fixtures', 'provider-simulators', 'fixture.mjs'), '// the simulator\n');
    assert.deepEqual(result(), [false, 'the simulator case list names a test file that is not a file under the root: test/provider-simulator-fixture.test.mjs']);
    writeFileSync(path.join(root, 'test', 'provider-simulator-fixture.test.mjs'), '// the tests\n');
    assert.deepEqual(result(), [true, 'passes']);
    // Each way a list falls short, in its own words.
    const key = `${write.key} v${write.version}`, change = edit => { const list = structuredClone(complete); edit(list); writeCases(list); return result(); };
    assert.deepEqual(change(list => { list.cases[key] = list.cases[key].filter(kind => kind !== 'lost-answer'); }), [false, `the simulator case list gives ${key} no lost-answer case`]);
    assert.deepEqual(change(list => { list.cases[`${read.key} v${read.version}`] = ['succeeds', 'refused']; }), [false, `the simulator case list gives ${read.key} v${read.version} no provider-refusal case`]);
    assert.deepEqual(change(list => { list.cases[key] = [...list.cases[key], 'flaky']; }), [false, `the simulator case list gives ${key} a kind that is not one of succeeds, refused, provider-refusal, unverified, lost-answer`]);
    assert.deepEqual(change(list => { list.cases[key] = [...list.cases[key], 'succeeds']; }), [false, `the simulator case list gives ${key} a kind that is not one of succeeds, refused, provider-refusal, unverified, lost-answer`], 'a kind twice');
    assert.deepEqual(change(list => { list.cases['ghost v1'] = ['succeeds', 'refused', 'provider-refusal']; }), [false, 'the simulator case list names 1 action the action file does not hold: ghost v1']);
    assert.deepEqual(change(list => { list.cases[`${key.split(' ')[0]} v9`] = list.cases[key]; delete list.cases[key]; }),
      [false, `the simulator case list names 1 action the action file does not hold: ${key.split(' ')[0]} v9`], 'the same key at another version');
    assert.deepEqual(change(list => { delete list.cases[key]; }), [false, `the simulator case list leaves out 1 action of the action file: ${key}`]);
    assert.deepEqual(change(list => { list.appId = 'fixture-rpc'; }), [false, 'the simulator case list test/fixtures/provider-simulators/fixture.cases.json names fixture-rpc, not fixture: a case list holds its own app\'s cases']);
    assert.deepEqual(change(list => { list.simulator = 'test/fixtures/provider-simulators/missing.mjs'; }), [false, 'the simulator case list names a simulator that is not a file under the root: test/fixtures/provider-simulators/missing.mjs']);
    assert.deepEqual(change(list => { list.simulator = '../outside.test.mjs'; }), [false, 'the simulator case list names a simulator that is not a file under the root: ../outside.test.mjs']);
    assert.deepEqual(change(list => { list.tests = ['../outside.test.mjs']; }), [false, 'the simulator case list names a test file that is not a file under the root: ../outside.test.mjs']);
    assert.deepEqual(change(list => { list.simulator = 'test/fixtures'; }), [false, 'the simulator case list names a simulator that is not a file under the root: test/fixtures'], 'a folder is not a file');
    assert.deepEqual(change(list => { list.tests = [...list.tests, 'test/missing.test.mjs']; }), [false, 'the simulator case list names a test file that is not a file under the root: test/missing.test.mjs']);
    assert.deepEqual(change(list => { list.tests = []; }), [false, 'the simulator case list names no test file']);
    assert.deepEqual(change(list => { list.tests = ['test/fixtures/provider-simulators/fixture.mjs']; }), [false, 'the simulator case list names a test file that is not a file under the root: test/fixtures/provider-simulators/fixture.mjs'], 'a test file ends in .test.mjs');
    assert.deepEqual(change(list => { list.notes = 'x'; }), [false, 'the simulator case list test/fixtures/provider-simulators/fixture.cases.json holds exactly schemaVersion 1, appId, simulator, tests and cases']);
    assert.deepEqual(change(list => { list.cases = []; }), [false, 'the simulator case list test/fixtures/provider-simulators/fixture.cases.json holds exactly schemaVersion 1, appId, simulator, tests and cases']);
    writeCases('{not json');
    assert.deepEqual(result(), [false, 'the simulator case list test/fixtures/provider-simulators/fixture.cases.json is not JSON']);
    // The action file's own reasons come first: a candidate file with a complete list still waits for its review.
    writeCases(complete);
    writeFileSync(path.join(root, 'catalog', 'actions', 'fixture.json'), JSON.stringify({...file, reviewStatus: 'candidate'}));
    assert.deepEqual(result(), [false, 'the action file is a candidate: no reviewer has marked it reviewed yet (I8)']);
  } finally { rmSync(outer, {recursive: true, force: true}); }
});

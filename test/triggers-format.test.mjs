import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {validateActionFile, pollHash} from '../lib/actions.mjs';
import {placeRegistration, REGISTRATION_PHASES} from '../lib/action-placement.mjs';
import {validateTriggerFile, triggerIds, checkEvent, REGISTRATION_MEMBERS} from '../lib/triggers.mjs';
import {fixtureActions, fixtureChoices, fixtureConfigs, fixtureGroups, fixtureMap, withIds} from './fixtures/actions/fixture-app.mjs';
import {TRANSFORMS, PINS} from './fixtures/actions/registry.mjs';
import {googleMap} from './fixtures/access/google-maps.mjs';

// F10.9 part k (docs/F10.9-BUILD-MAP.md section 8 and section 4): the trigger format, design only: a file shape, a JSON Schema and a pure
// validator, with no engine, scheduler, receiver or socket. test/fixtures/triggers holds the worked examples that can be tested in F10.9
// (R8): the Calendar watch, the GitHub repository webhook and, since F10.10 counts a reviewed-read POST built from reads as a read, Notion's
// row trigger, whose poll is one. Calendar places through F10.7's synthetic map with the paths the section 8 example writes; since F10.11
// part a recorded Google's own method paths, one test also places it, and Gmail's forwarding member, on those.
const fixture = appId => JSON.parse(readFileSync(new URL(`./fixtures/triggers/${appId}.json`, import.meta.url), 'utf8'));
const json = file => JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8'));
const KEYS = ['appId', 'pinnedParameters', 'reviewStatus', 'schemaVersion', 'specVersion', 'triggers'];

test('the three trigger fixtures name their app, its read rows and transforms of the fixture registry', () => {
  for (const [appId, method] of [['google-calendar', 'watch'], ['github', 'webhook'], ['notion', 'webhook']]) {
    const file = fixture(appId);
    assert.deepEqual(Object.keys(file).sort(), KEYS, appId);
    assert.deepEqual([file.schemaVersion, file.appId, file.specVersion, file.triggers.length], [1, appId, 'fabric/0.2', 1], appId);
    const [trigger] = file.triggers, rows = new Set(PERMISSION_GROUPS.get(appId).groups.filter(group => group.effect === 'read').map(group => group.id));
    assert.equal(trigger.delivery.method, method, appId);
    assert.equal(trigger.delivery.fallback, 'polling', `${appId} names its polling fallback`);
    assert.equal(trigger.delivery.admission.trust, 'doorbell', appId);
    for (const id of trigger.rows) assert.ok(rows.has(id), `${appId}: ${id} is a read row`);
    const named = JSON.stringify(trigger).match(/"(?:transform|compare)":"[^"]+"/g)?.map(text => text.split(':"')[1].slice(0, -1)) ?? [];
    for (const id of named) assert.ok(TRANSFORMS.has(id), `${appId}: ${id}`);
  }
});

// ---- the dependencies ------------------------------------------------------------------------------------------------------------------
const SYNTHETIC = json('./fixtures/access/f10-7-bindings.before.json').maps;
// F10.7's synthetic Calendar map, with the paths the section 8 example writes for the change feed and the watch: not read from Google.
const CALENDAR_PATHS = {'calendar.events.list': '/calendars/{calendarId}/events', 'calendar.events.watch': '/calendars/{calendarId}/events/watch'};
const CALENDAR_MAP = {...SYNTHETIC['google-calendar'], operations: SYNTHETIC['google-calendar'].operations.map(operation => CALENDAR_PATHS[operation.id] ? {...operation, path: CALENDAR_PATHS[operation.id]} : operation)};
const GMAIL_MAP = {...SYNTHETIC.gmail, operations: SYNTHETIC.gmail.operations.map(operation => operation.id === 'gmail.users.getProfile' ? {...operation, method: 'GET'} : operation)};
const FIXTURE = (() => {
  const groups = fixtureGroups();
  return {groups, configs: fixtureConfigs(groups), choices: new Map([['fixture', fixtureChoices().sources]])};
})();
const DEPS = {groups: new Map([...PERMISSION_GROUPS, ...FIXTURE.groups]), configs: new Map([...PROXY_CONFIGS, ...FIXTURE.configs]),
  maps: new Map([['google-calendar', CALENDAR_MAP], ['gmail', GMAIL_MAP], ['fixture', fixtureMap()]]), transforms: TRANSFORMS, pins: PINS, choices: FIXTURE.choices,
  identities: new Map([['google-calendar', definitionFor('google')], ['gmail', definitionFor('google')], ['github', definitionFor('github')], ['notion', definitionFor('notion')], ['slack', definitionFor('slack')]]),
  actions: new Map([['fixture', fixtureActions()]])};
/** The file with each trigger's computed id written, as an author writes it (triggerIds()); a file triggerIds() refuses comes back unchanged. */
function withTriggerIds(file, deps = DEPS) {
  let ids;
  try { ids = triggerIds(file, deps); } catch { return file; }
  return {...file, triggers: file.triggers.map(trigger => ({...trigger, id: ids.get(`${trigger.key} v${trigger.version}`)}))};
}
const valid = (file, deps = DEPS) => validateTriggerFile(withTriggerIds(file, deps), deps);
const entryOf = (file, deps) => valid(file, deps).triggers[0];
const refused = (file, pattern, deps = DEPS, message) => assert.throws(() => valid(file, deps), pattern, message);
/** A fresh copy of a fixture, its one trigger changed in place by `edit(trigger, file)`. */
const edited = (appId, edit) => { const file = fixture(appId); edit(file.triggers[0], file); return file; };
const closed = (properties, required = Object.keys(properties)) => ({type: 'object', properties, required, additionalProperties: false});
const words = (max = 200) => ({type: 'string', minLength: 1, maxLength: max});
const OK = {status: [200], require: []};
// F10.21 listed churn: a Slack step requires /ok true (apiSuccessRequire), the trigger's poll step included.
const SLACK_OK = {status: [200], require: [{equals: {pointer: '/ok', value: {const: true}}}]};
const ZEROS = '0'.repeat(24);
const COMMON = {backfill: {default: 0, max: 25}, retention: {days: 7}, bounds: {pages: 10, items: 500, pollSeconds: 10}};
const ITEM_EVENT = {schema: closed({id: words(64), name: words(200), updated: words(64)}), id: {concat: [{item: '/id'}, {const: ':'}, {item: '/updated'}], max: 200}, occurredAt: {item: '/updated'},
  fields: {id: {item: '/id'}, name: {item: '/name'}, updated: {item: '/updated'}}, summary: [{label: 'Item', expr: {item: '/name'}, truncate: 120}]};
/** A fixture trigger that polls GET /items with its own step and a high-water mark. */
const ownSteps = (edit = () => {}) => {
  const trigger = {id: `fixture.trigger.item-changed.v1.${ZEROS}`, key: 'item-changed', version: 1, name: 'An item changed', description: 'Tells you when one of your items changes.',
    delivery: {method: 'polling', intervalSeconds: {default: 120, min: 60}},
    inputSchema: closed({kind: {type: 'string', enum: ['all', 'open']}}), resource: ['kind'],
    poll: {source: {steps: [{id: 'list', method: 'GET', path: '/items', query: {kind: {input: '/kind'}, updatedAfter: {cursor: 'since'}},
      page: {next: {pointer: '/nextPageToken'}, into: {query: 'pageToken'}, items: '/items', max: 3}, maxResponseBytes: 262_144, expect: OK}]},
    items: {step: 'list', pointer: ''}, itemId: {item: '/id'}, itemVersion: '/updated', itemTime: {pointer: '/updated', format: 'rfc3339'}, order: 'desc',
    cursors: [{name: 'since', kind: 'high-water-time@1', next: {max: 'itemTime'}, compare: 'time.rfc3339ToEpochSeconds@1', overlapSeconds: 60}],
    resync: {statusIn: []}, minIntervalSeconds: 60},
    dedupe: {kind: 'id+version'}, event: structuredClone(ITEM_EVENT), ...structuredClone(COMMON), rows: ['fixture.items.read']};
  edit(trigger);
  return {schemaVersion: 1, appId: 'fixture', specVersion: 'fabric/0.2', reviewStatus: 'candidate', pinnedParameters: {account: 'me'}, triggers: [trigger]};
};
/** A fixture trigger that reuses List items' poll block. */
const fromAction = (edit = () => {}) => {
  const trigger = {id: `fixture.trigger.listed-item.v1.${ZEROS}`, key: 'listed-item', version: 1, name: 'A listed item changed', description: 'Polls List items for changes.',
    delivery: {method: 'polling', intervalSeconds: {default: 300, min: 60}}, inputSchema: closed({}), resource: [],
    poll: {source: {action: {key: 'list-items', version: 1}, args: {kind: {const: 'all'}}}},
    dedupe: {kind: 'id+version'}, event: structuredClone(ITEM_EVENT), ...structuredClone(COMMON), rows: ['fixture.items.read']};
  edit(trigger);
  return {schemaVersion: 1, appId: 'fixture', specVersion: 'fabric/0.2', reviewStatus: 'candidate', pinnedParameters: {account: 'me'}, triggers: [trigger]};
};
/** A Slack trigger on a live connection, one cursor per chosen channel through resource.each. */
const slack = (edit = () => {}) => {
  const trigger = {id: `slack.trigger.new-channel-message.v1.${ZEROS}`, key: 'new-channel-message', version: 1, name: 'New message in chosen channels', description: 'Tells you about new messages in the channels you choose.',
    delivery: {method: 'live', transport: 'slack-socket-mode', fallback: 'polling',
      admission: {scheme: 'socket-authenticated', route: {pointers: ['/payload/team_id', '/payload/authorizations/0/user_id'], to: 'identity'}, events: ['message.channels', 'message.groups'],
        wake: {pointer: '/payload/event/channel', in: {input: '/channels'}}, collapse: {pointer: '/payload/event_id'}, trust: 'doorbell'}},
    inputSchema: closed({channels: {type: 'array', minItems: 1, maxItems: 20, items: words(64)}}), resource: {each: '/channels', as: 'channel'},
    poll: {source: {steps: [{id: 'history', method: 'GET', path: '/conversations.history', query: {channel: {var: 'channel'}, oldest: {cursor: 'ts'}, limit: {const: 100}},
      page: {next: {pointer: '/response_metadata/next_cursor'}, into: {query: 'cursor'}, items: '/messages', max: 10}, expect: SLACK_OK}]},
    items: {step: 'history', pointer: ''}, itemId: {concat: [{var: 'channel'}, {const: ':'}, {item: '/ts'}], max: 200}, itemVersion: null, itemTime: {pointer: '/ts', format: 'slack-ts'}, order: 'desc',
    cursors: [{name: 'ts', kind: 'high-water-ts@1', next: {max: 'itemTime'}, compare: 'time.slackTs@1'}], resync: {statusIn: []}, minIntervalSeconds: 60},
    dedupe: {kind: 'id'},
    event: {schema: closed({channel: words(64), ts: words(32), user: words(64)}, ['channel', 'ts']), id: {concat: [{var: 'channel'}, {const: ':'}, {item: '/ts'}], max: 200}, occurredAt: {item: '/ts'},
      fields: {channel: {var: 'channel'}, ts: {item: '/ts'}, user: {when: {present: {item: '/user'}}, then: {item: '/user'}}}, summary: [{label: 'Message', expr: {item: '/text'}, truncate: 120}]},
    backfill: {default: 0, max: 25}, retention: {hours: 24}, bounds: {pages: 10, items: 500, pollSeconds: 10}, rows: ['slack.messages.read']};
  edit(trigger);
  return {schemaVersion: 1, appId: 'slack', specVersion: 'fabric/0.2', reviewStatus: 'candidate', pinnedParameters: {}, triggers: [trigger]};
};

// ---- the worked examples (R8) ---------------------------------------------------------------------------------------------------------
test('part k: the Calendar watch and the GitHub repository webhook pass validateTriggerFile(), placed on read rows and registration members, with their computed ids (R8)', () => {
  const calendar = validateTriggerFile(fixture('google-calendar'), DEPS), github = validateTriggerFile(fixture('github'), DEPS);
  assert.ok(Object.isFrozen(calendar) && Object.isFrozen(calendar.triggers[0]));
  const [watch] = calendar.triggers, [hook] = github.triggers;
  assert.deepEqual(watch.placements.map(placement => [placement.stepId, placement.phase, placement.groupId, placement.member]), [
    ['watch', 'register', 'google-calendar.access.grant', 'calendar.events.watch'], ['stop', 'teardown', 'google-calendar.access.grant', 'calendar.channels.stop'],
    ['changes', 'poll', 'google-calendar.events.read', 'calendar.events.list']]);
  assert.deepEqual(hook.placements.map(placement => [placement.stepId, placement.phase, placement.groupId]), [
    ['hook', 'register', 'github.access.grant'], ['unhook', 'teardown', 'github.access.grant'], ['issues', 'poll', 'github.issues.read']]);
  assert.deepEqual([watch.rows, hook.rows, watch.unplaced, hook.unplaced], [['google-calendar.events.read'], ['github.issues.read'], false, false]);
  assert.deepEqual(watch.transforms, ['text.truncate@1', 'time.rfc3339ToEpochSeconds@1']);
  assert.deepEqual(hook.transforms, ['ids.linkPage@1', 'text.truncate@1', 'time.rfc3339ToEpochSeconds@1']);
  // The ids the fixtures carry are the computed ones; the trigger comes back as written.
  assert.match(watch.id, /^google-calendar\.trigger\.event-changed\.v1\.[a-f0-9]{24}$/);
  assert.deepEqual([watch.id, hook.id], [triggerIds(fixture('google-calendar'), DEPS).get('event-changed v1'), triggerIds(fixture('github'), DEPS).get('issue-activity v1')]);
  assert.deepEqual(watch.trigger, fixture('google-calendar').triggers[0]);
  // checkRequest() positions for I07's engine: each cursor slot.
  assert.deepEqual([watch.rawAt.changes, hook.rawAt.issues], [['/query/syncToken'], ['/query/since', '/headers/If-None-Match']]);
  // Without the map, Calendar's steps cannot be placed: valid in shape, never runnable.
  const unmapped = validateTriggerFile(fixture('google-calendar'), {...DEPS, maps: new Map()}).triggers[0];
  assert.deepEqual([unmapped.unplaced, unmapped.rows], [true, null]);
  // A fixture trigger with its own poll steps, and one that reuses a read action's poll block.
  assert.deepEqual(entryOf(ownSteps()).rows, ['fixture.items.read']);
  const reused = entryOf(fromAction());
  assert.deepEqual([reused.rows, reused.sources], [['fixture.items.read'], [{key: 'list-items', version: 1, id: fixtureActions().actions[0].id, pollHash: validateActionFile(fixtureActions(), {...DEPS, choices: FIXTURE.choices}).actions[0].pollHash}]]);
  assert.equal(entryOf(slack()).key, 'new-channel-message');
});

test('part k: the Calendar watch and the GitHub repository webhook pass schemas/trigger.schema.json under ajv; a file the schema does not describe fails it', () => {
  const ajv = new Ajv2020({strict: true, allErrors: true});
  addFormats(ajv);
  const check = ajv.compile(json('../schemas/trigger.schema.json'));
  for (const file of [fixture('google-calendar'), fixture('github'), fixture('notion'), ownSteps(), fromAction(), slack()]) assert.ok(check(file), `${file.appId}: ${JSON.stringify(check.errors)}`);
  for (const [label, file] of [['an unknown file field', {...fixture('github'), extra: 1}], ['an unknown trigger field', edited('github', trigger => { trigger.extra = 1; })],
    ['an unknown delivery method', edited('github', trigger => { trigger.delivery.method = 'email'; })], ['trust other than doorbell', edited('github', trigger => { trigger.delivery.admission.trust = 'verified-payload'; })],
    ['an expression with an unknown key', edited('github', trigger => { trigger.event.fields.state = {query: '/state'}; })]]) {
    assert.equal(check(file), false, label);
  }
});

test('part k and F10.10: the Notion fixture validates with its computed id: its poll is a reviewed-read POST built from inputs, constants and its cursor, so a read', () => {
  const [rows] = validateTriggerFile(fixture('notion'), DEPS).triggers;
  assert.equal(rows.id, triggerIds(fixture('notion'), DEPS).get('row-changed v1'));
  assert.match(rows.id, /^notion\.trigger\.row-changed\.v1\.[a-f0-9]{24}$/);
  assert.notEqual(rows.id.slice(-24), '0'.repeat(24));
  assert.deepEqual(rows.placements.map(placement => [placement.stepId, placement.phase, placement.member, placement.groupId, placement.reviewedRead, placement.fromReads, placement.effect]),
    [['rows', 'poll', 'POST /v1/data_sources/{data_source_id}/query', 'notion.content.read', true, true, 'read']]);
  assert.deepEqual([rows.rows, rows.unplaced, rows.status], [['notion.content.read'], false, 'candidate']);
  // checkRequest() positions for I07's engine: the cursor slot and the provider's next page cursor in the body.
  assert.deepEqual(rows.rawAt.rows, ['/body/filter/last_edited_time/on_or_after', '/body/start_cursor']);
  // A job key in its body makes the poll a write (the write-poll cases below keep their words).
  refused(edited('notion', trigger => { trigger.poll.source.steps[0].body.object.key = {jobKey: 'poll'}; }), /Triggers for notion: row-changed v1: poll\.source\.steps\[0\] \(rows\): a poll step's computed effect is write: a trigger polls with reads only, and a reviewed-read POST is a read only when everything it sends is built from reads \(F10\.10, I5\)/);
});

// F10.11 part a: the former todo, on Google's own method paths (test/fixtures/access/google-method-paths.json) through googleMap().
test('F10.11 part a: on Google\'s own paths the Calendar watch places with its id unchanged, and Gmail settings.forwardingAddresses.create as a register step lands on its locked member and is refused', () => {
  const google = {...DEPS, maps: new Map([...DEPS.maps, ['google-calendar', googleMap('google-calendar')], ['gmail', googleMap('gmail')]])};
  const [watch] = validateTriggerFile(fixture('google-calendar'), google).triggers;
  assert.deepEqual(watch.placements.map(placement => [placement.stepId, placement.phase, placement.groupId, placement.member, placement.template]), [
    ['watch', 'register', 'google-calendar.access.grant', 'calendar.events.watch', 'POST /calendars/{calendarId}/events/watch'],
    ['stop', 'teardown', 'google-calendar.access.grant', 'calendar.channels.stop', 'POST /channels/stop'],
    ['changes', 'poll', 'google-calendar.events.read', 'calendar.events.list', 'GET /calendars/{calendarId}/events']]);
  assert.deepEqual([watch.unplaced, watch.rows, watch.id], [false, ['google-calendar.events.read'], fixture('google-calendar').triggers[0].id], 'the id is content only, so the recorded paths do not move it');
  const gmail = edited('google-calendar', (trigger, file) => {
    Object.assign(file, {appId: 'gmail', pinnedParameters: {userId: 'me'}});
    trigger.id = `gmail.trigger.event-changed.v1.${ZEROS}`;
    trigger.delivery.register.step = {id: 'forward', method: 'POST', path: '/gmail/v1/users/{userId}/settings/forwardingAddresses', body: {object: {forwardingEmail: {const: 'someone@example.test'}}}, expect: OK};
  });
  refused(gmail, /delivery\.register\.step \(forward\): POST \/gmail\/v1\/users\/\{userId\}\/settings\/forwardingAddresses lands on gmail\.users\.settings\.forwardingAddresses\.create, which is not a reviewed register member: gmail has none \(R6, T4\)/, google);
  assert.ok(PERMISSION_GROUPS.get('gmail').groups.find(group => group.id === 'gmail.access.grant').operations.includes('gmail.users.settings.forwardingAddresses.create'), 'the member it lands on sits in Gmail\'s locked row');
});

// ---- registration (R6) ---------------------------------------------------------------------------------------------------------------
test('part k: REGISTRATION_MEMBERS is the reviewed allowlist: five members, each in its app\'s locked row, with its destination, secret and registration id slots (R6)', () => {
  assert.deepEqual(Object.keys(REGISTRATION_MEMBERS), ['google-calendar', 'github']);
  assert.deepEqual(Object.entries(REGISTRATION_MEMBERS).flatMap(([appId, members]) => members.map(entry => [appId, entry.member, entry.role, entry.destination])), [
    ['google-calendar', 'calendar.events.watch', 'register', '/address'], ['google-calendar', 'calendar.calendarList.watch', 'register', '/address'], ['google-calendar', 'calendar.channels.stop', 'teardown', null],
    ['github', 'POST /repos/{owner}/{repo}/hooks', 'register', '/config/url'], ['github', 'DELETE /repos/{owner}/{repo}/hooks/{hook_id}', 'teardown', null]]);
  assert.deepEqual(REGISTRATION_MEMBERS['google-calendar'][2].ids, [{body: '/id'}, {body: '/resourceId'}]);
  assert.deepEqual(REGISTRATION_MEMBERS.github[1].ids, [{path: 'hook_id'}]);
  assert.ok(Object.isFrozen(REGISTRATION_MEMBERS) && Object.isFrozen(REGISTRATION_MEMBERS.github[0]));
  for (const [appId, members] of Object.entries(REGISTRATION_MEMBERS)) {
    const locked = PERMISSION_GROUPS.get(appId).groups.find(group => group.locked === 'fabric');
    for (const {member} of members) assert.ok([...locked.operations, ...locked.requests].includes(member), `${appId}: ${member} sits in ${locked.id}`);
  }
  // placeRegistration() places only on the members given for the phase, in the locked row; a read placement never lands there.
  assert.deepEqual(REGISTRATION_PHASES, ['register', 'teardown']);
  const github = {definition: PERMISSION_GROUPS.get('github'), config: PROXY_CONFIGS.get('github'), where: 'step'};
  const hook = {id: 'hook', method: 'POST', path: '/repos/{owner}/{repo}/hooks'};
  assert.equal(placeRegistration(hook, {...github, phase: 'register', members: ['POST /repos/{owner}/{repo}/hooks']}).groupId, 'github.access.grant');
  assert.throws(() => placeRegistration(hook, {...github, phase: 'teardown', members: ['DELETE /repos/{owner}/{repo}/hooks/{hook_id}']}), /step: POST \/repos\/\{owner\}\/\{repo\}\/hooks lands on POST \/repos\/\{owner\}\/\{repo\}\/hooks, which is not a reviewed teardown member/);
  assert.throws(() => placeRegistration(hook, {...github, phase: 'poll', members: []}), /a registration step's phase is register or teardown/);
  assert.throws(() => placeRegistration({id: 'list', method: 'GET', path: '/repos/{owner}/{repo}/issues'}, {...github, phase: 'register', members: ['GET /repos/{owner}/{repo}/issues']}),
    /step: GET \/repos\/\{owner\}\/\{repo\}\/issues is a registration member, which sits in its app's locked row, and github\.issues\.read is not locked \(R6\)/, 'an allowlist that named an unlocked member');
  assert.throws(() => placeRegistration({...hook, path: '/repos/{owner}/{repo}/Hooks'}, {...github, phase: 'register', members: ['POST /repos/{owner}/{repo}/hooks']}), /step: the literal Hooks is written hooks in the reviewed template/);
  assert.equal(placeRegistration(hook, {...github, map: null, definition: PERMISSION_GROUPS.get('google-calendar'), config: PROXY_CONFIGS.get('google-calendar'), phase: 'register', members: []}).unplaced, true, 'an app reviewed by operation id, without its map');
  // An organisation hook is unavailable (admin:org_hook is never asked for, open question 4), so not even an allowlist could place it.
  assert.throws(() => placeRegistration({id: 'org', method: 'POST', path: '/orgs/{org}/hooks'}, {...github, phase: 'register', members: ['POST /orgs/{org}/hooks']}), /step: POST \/orgs\/\{org\}\/hooks lands on POST \/orgs\/\{org\}\/hooks, which is unavailable/);
});

test('part k: registration steps (R6): only a reviewed member of their role, a destination of exactly {receiver}, inputs only in the path and only from resource, a secret only from {secret}', () => {
  for (const [label, file, pattern] of [
    ['Calendar acl.insert as a register step', edited('google-calendar', trigger => { trigger.delivery.register.step.path = '/acl/insert'; delete trigger.delivery.register.step.params; }),
      /event-changed v1: delivery\.register\.step \(watch\): POST \/acl\/insert lands on calendar\.acl\.insert, which is not a reviewed register member: a trigger's register step runs only on calendar\.events\.watch or calendar\.calendarList\.watch \(R6, T4\)/],
    ['GitHub collaborators as a register step', edited('github', trigger => { Object.assign(trigger.delivery.register.step, {method: 'PUT', path: '/repos/{owner}/{repo}/collaborators/{username}', params: {...trigger.delivery.register.step.params, username: {const: 'someone'}}}); }),
      /lands on PUT \/repos\/\{owner\}\/\{repo\}\/collaborators\/\{username\}, which is not a reviewed register member/],
    ['GitHub hook config as a register step', edited('github', trigger => { Object.assign(trigger.delivery.register.step, {method: 'PATCH', path: '/repos/{owner}/{repo}/hooks/{hook_id}/config', params: {...trigger.delivery.register.step.params, hook_id: {const: '1'}}}); }),
      /lands on PATCH \/repos\/\{owner\}\/\{repo\}\/hooks\/\{hook_id\}\/config, which is not a reviewed register member/],
    ['a teardown step on a register member', edited('github', trigger => { trigger.delivery.teardown.step = {...trigger.delivery.register.step, id: 'unhook'}; }),
      /delivery\.teardown\.step \(unhook\): POST \/repos\/\{owner\}\/\{repo\}\/hooks lands on POST \/repos\/\{owner\}\/\{repo\}\/hooks, which is not a reviewed teardown member/],
    ['a constant URL at the destination', edited('github', trigger => { trigger.delivery.register.step.body.object.config.object.url = {const: 'https://example.test/hook'}; }),
      /issue-activity v1: delivery\.register\.step \(hook\): the destination \/config\/url holds exactly \{receiver: 'github'\}: a constant URL or an input never chooses where the owner's events go \(R6, T4\)/],
    ['an input at the destination', edited('github', trigger => { trigger.delivery.register.step.body.object.config.object.url = {input: '/owner'}; }), /the destination \/config\/url holds exactly \{receiver: 'github'\}/],
    ['another app\'s receiver', edited('github', trigger => { trigger.delivery.register.step.body.object.config.object.url = {receiver: 'notion'}; }), /the destination \/config\/url holds exactly \{receiver: 'github'\}/],
    ['a receiver anywhere else', edited('github', trigger => { trigger.delivery.register.step.body.object.name = {receiver: 'github'}; }), /delivery\.register\.step \(hook\): \{receiver\} sits only at the destination \/config\/url/],
    ['an input in a registration body', edited('github', trigger => { trigger.delivery.register.step.body.object.name = {input: '/repo'}; }),
      /delivery\.register\.step \(hook\)\.body: a registration body holds only constants, \{receiver\}, \{secret\}, \{kept\} and \{subscriptionKey\}: never an input \(R6\)/],
    ['an input in a registration path that is not in resource', edited('github', trigger => { trigger.resource = ['owner']; }),
      /delivery\.register\.step \(hook\)\.params\.repo: a registration path takes only inputs the trigger lists in resource, or constants \(R6\)/],
    ['a constant secret', edited('github', trigger => { trigger.delivery.register.step.body.object.config.object.secret = {const: 'abc'}; }),
      /delivery\.register\.step \(hook\): the secret \/config\/secret holds exactly \{secret: <name>\}: Fabric generates it and keeps it in the vault/],
    ['a secret anywhere else', edited('github', trigger => { trigger.delivery.register.step.body.object.name = {secret: 'hook'}; }), /delivery\.register\.step \(hook\): \{secret\} sits only at the secret \/config\/secret/],
    ['an admission secret of another name', edited('github', trigger => { trigger.delivery.admission.secret = 'other'; }), /delivery\.admission\.secret is hook, the \{secret\} the register step sends/],
    ['a kept value in a register step', edited('google-calendar', trigger => { trigger.delivery.register.step.body.object.id = {kept: 'channelId'}; }),
      /delivery\.register\.step \(watch\): a register step reads no kept value: it makes them/],
    ['a register step with a query', edited('github', trigger => { trigger.delivery.register.step.query = {x: {const: '1'}}; }), /delivery\.register\.step \(hook\): a registration step holds id, method, path and expect, and may hold params and body/],
    ['a register path in another case', edited('github', trigger => { trigger.delivery.register.step.path = '/repos/{owner}/{repo}/Hooks'; }), /delivery\.register\.step \(hook\): the literal Hooks is written hooks in the reviewed template/],
    ['a kept value that names a secret', edited('github', trigger => { trigger.delivery.register.keep.token = '/config/secret'; }), /delivery\.register\.keep\.token: the pointer \/config\/secret reads secret, a field that carries a secret, so it is refused wherever it appears \(R11\)/],
  ]) refused(file, pattern, DEPS, label);
  // Gmail has no registration member: Sami chose polling (docs/MASTER-PLAN.md:246).
  const gmail = edited('google-calendar', (trigger, file) => {
    Object.assign(file, {appId: 'gmail', pinnedParameters: {userId: 'me'}});
    trigger.id = `gmail.trigger.event-changed.v1.${ZEROS}`;
    trigger.delivery.register.step = {id: 'forward', method: 'POST', path: '/gmail/v1/users/{userId}/settings/forwardingAddresses/create', body: {object: {forwardingEmail: {const: 'someone@example.test'}}}, expect: OK};
  });
  refused(gmail, /delivery\.register\.step \(forward\): POST \/gmail\/v1\/users\/\{userId\}\/settings\/forwardingAddresses\/create lands on gmail\.users\.settings\.forwardingAddresses\.create, which is not a reviewed register member: gmail has none \(R6, T4\)/);
});

test('part k: registration ids (R6): a teardown acts only on what its own register step made, and a registration targets only a resource the trigger polls', () => {
  for (const [label, file, pattern] of [
    ['a teardown hook_id from an input listed in resource', edited('github', trigger => {
      trigger.inputSchema.properties.hookId = words(20);
      trigger.inputSchema.required.push('hookId');
      trigger.resource.push('hookId');
      trigger.poll.source.steps[0].query.hook = {input: '/hookId'};
      trigger.delivery.teardown.step.params.hook_id = {input: '/hookId'};
    }), /delivery\.teardown\.step \(unhook\)\.params\.hook_id: hook_id is a registration id slot: it holds exactly \{kept: <name>\} of a value register\.keep takes, so a teardown acts only on what this subscription made \(R6, T4\)/],
    ['a teardown hook_id constant', edited('github', trigger => { trigger.delivery.teardown.step.params.hook_id = {const: '1'}; }), /params\.hook_id: hook_id is a registration id slot/],
    // The slot is found by its place in the reviewed template, so neither the file's pinned parameters, a literal segment nor another
    // parameter name fills it with anything but a kept value.
    ['a teardown hook_id from pinnedParameters', edited('github', (trigger, file) => { delete trigger.delivery.teardown.step.params.hook_id; file.pinnedParameters = {hook_id: '12345'}; }),
      /delivery\.teardown\.step \(unhook\): the registration id slot hook_id is a path parameter the step fills in params with exactly \{kept: <name>\}: never a literal, a pinned parameter or a constant \(R6, T4\)/],
    ['a teardown hook_id written as a literal', edited('github', trigger => { delete trigger.delivery.teardown.step.params.hook_id; trigger.delivery.teardown.step.path = '/repos/{owner}/{repo}/hooks/12345'; }),
      /delivery\.teardown\.step \(unhook\): the registration id slot hook_id is a path parameter the step fills in params/],
    ['a teardown hook_id under another name, from a constant', edited('github', trigger => {
      delete trigger.delivery.teardown.step.params.hook_id;
      Object.assign(trigger.delivery.teardown.step, {path: '/repos/{owner}/{repo}/hooks/{id}'});
      trigger.delivery.teardown.step.params.id = {const: '12345'};
    }), /delivery\.teardown\.step \(unhook\)\.params\.id: hook_id is a registration id slot: it holds exactly \{kept: <name>\}/],
    ['a teardown hook_id under another name, from a resource input', edited('github', trigger => {
      delete trigger.delivery.teardown.step.params.hook_id;
      Object.assign(trigger.delivery.teardown.step, {path: '/repos/{owner}/{repo}/hooks/{id}'});
      trigger.delivery.teardown.step.params.id = {input: '/repo'};
    }), /delivery\.teardown\.step \(unhook\)\.params\.id: hook_id is a registration id slot/],
    ['a channels.stop /id from a subscription key', edited('google-calendar', trigger => { trigger.delivery.teardown.step.body.object.id = {subscriptionKey: 'channel'}; }),
      /delivery\.teardown\.step \(stop\): \/id is a registration id slot: it holds exactly \{kept: <name>\} of a value register\.keep takes/],
    ['a channels.stop /id constant', edited('google-calendar', trigger => { trigger.delivery.teardown.step.body.object.id = {const: 'abc'}; }), /\/id is a registration id slot/],
    ['a channels.stop /resourceId kept but never taken', edited('google-calendar', trigger => { trigger.delivery.teardown.step.body.object.resourceId = {kept: 'other'}; }),
      /delivery\.teardown\.step \(stop\): \/resourceId reads the kept value other, which register\.keep does not take/],
    ['a resource input no poll step reads', edited('google-calendar', trigger => { trigger.poll.source.steps[0].params.calendarId = {const: 'primary'}; }),
      /event-changed v1: resource: calendarId is read by no poll step: a registration targets exactly the resource the owner's read rows let the trigger poll \(R6\)/],
    ['a resource.as variable no poll step reads', slack(trigger => { trigger.poll.source.steps[0].query.channel = {const: 'C1'}; trigger.poll.itemId = {item: '/ts'}; trigger.event.id = {item: '/ts'}; trigger.event.fields.channel = {const: 'C1'}; }),
      /new-channel-message v1: resource: channel, which resource\.each binds, is read by no poll step/],
    ['a route from no kept value', edited('github', trigger => { trigger.delivery.admission.route.equals = {kept: 'other'}; }), /delivery\.admission\.route: a push is routed only by an id kept at registration \(other is not kept\) or the signed-in identity/],
  ]) refused(file, pattern, DEPS, label);
  // The slot goes by its place, not its name: a kept value under another parameter name is the same request.
  const renamed = edited('github', trigger => {
    delete trigger.delivery.teardown.step.params.hook_id;
    Object.assign(trigger.delivery.teardown.step, {path: '/repos/{owner}/{repo}/hooks/{id}'});
    trigger.delivery.teardown.step.params.id = {kept: 'hookId'};
  });
  assert.equal(entryOf(renamed).placements[1].member, 'DELETE /repos/{owner}/{repo}/hooks/{hook_id}');
});

// ---- the rest of the format ----------------------------------------------------------------------------------------------------------
test('part k: poll, seed and enrich steps follow the action rules: a reviewed read row, never Other, locked, a write or unavailable', () => {
  const step = change => ownSteps(trigger => {
    const [own] = trigger.poll.source.steps;
    for (const [key, value] of Object.entries(change)) { if (value === undefined) delete own[key]; else own[key] = value; }
  });
  for (const [label, file, pattern] of [
    ['a poll step in a locked row', step({method: 'PUT', path: '/items/{item_id}/share', params: {item_id: {const: 'x'}}, page: undefined, query: {updatedAfter: {cursor: 'since'}}}), /a row Fabric locks: no action step ever runs there \(T4\)/],
    ['a poll step in Other', step({path: '/nowhere'}), /poll\.source\.steps\[0\] \(list\): GET \/nowhere lands in Other reads/],
    ['a poll step that writes', step({method: 'POST', path: '/labels', page: undefined, query: undefined, body: {object: {since: {cursor: 'since'}}}}), /poll\.source\.steps\[0\] \(list\): a poll step's computed effect is write/],
    ['a poll step on an unavailable member', step({path: '/items/{item_id}/history', params: {item_id: {const: 'x'}}}), /which is unavailable/],
    ['a seed step in Other', ownSteps(trigger => { trigger.poll.seed = {step: {id: 'seed', method: 'GET', path: '/nowhere', expect: OK}, cursor: {name: 'since', pointer: '/now'}}; }), /poll\.seed\.step \(seed\): GET \/nowhere lands in Other reads/],
    ['an enrich step that writes', ownSteps(trigger => { trigger.poll.enrich = {max: 25, steps: [{id: 'more', method: 'POST', path: '/labels', body: {object: {id: {item: '/id'}}}, expect: OK}]}; }), /poll\.enrich\.steps\[0\] \(more\): a enrich step's computed effect is write|an enrich step's computed effect is write/],
  ]) refused(file, pattern, DEPS, label);
  // A seed read and an enrich read per item pass.
  const extended = ownSteps(trigger => {
    trigger.poll.seed = {step: {id: 'seed', method: 'GET', path: '/labels', expect: OK}, cursor: {name: 'since', pointer: '/now'}};
    trigger.poll.enrich = {max: 25, steps: [{id: 'more', method: 'GET', path: '/items/{item_id}', params: {item_id: {item: '/id'}}, maxResponseBytes: 65_536, expect: OK}]};
  });
  assert.deepEqual(entryOf(extended).placements.map(placement => [placement.stepId, placement.phase]), [['list', 'poll'], ['seed', 'seed'], ['more', 'enrich']]);
  refused(ownSteps(trigger => { trigger.poll.seed = {step: {id: 'seed', method: 'GET', path: '/labels', expect: OK}, cursor: {name: 'other', pointer: '/now'}}; }), /poll\.seed\.cursor\.name names other, which is not a cursor of the poll/);
  refused(ownSteps(trigger => { trigger.poll.seed = {step: {id: 'seed', method: 'GET', path: '/labels', expect: OK}, cursor: {name: 'since', pointer: '/access_token'}}; }), /poll\.seed\.cursor: the pointer \/access_token reads access_token/);
});

test('part k: refused: cursors, delivery, admission, fallback, backfill, events, bounds, intervals, Slack channels and unbound variables', () => {
  for (const [label, file, pattern] of [
    ['a cursor named as an input', edited('github', trigger => { trigger.inputSchema.properties.updated = words(64); trigger.poll.source.steps[0].query.extra = {input: '/updated'}; }), /poll\.cursors\[0\]\.name updated is also an input: a cursor never comes from an input \(spec line 1663\)/],
    ['a webhook with registration api and no teardown', edited('github', trigger => { delete trigger.delivery.teardown; }), /issue-activity v1: delivery: a webhook with registration api holds register, teardown, admission and fallback/],
    ['a watch without teardown', edited('google-calendar', trigger => { delete trigger.delivery.teardown; }), /event-changed v1: delivery: a watch holds register, renew, teardown, admission and fallback/],
    ['a watch without renew', edited('google-calendar', trigger => { delete trigger.delivery.renew; }), /delivery: a watch holds register, renew, teardown, admission and fallback/],
    ['a register step that keeps no id', edited('github', trigger => { trigger.delivery.register.keep = {}; }), /delivery\.register\.keep takes 1 to 8 values from the register response/],
    ['renew.at 0', edited('google-calendar', trigger => { trigger.delivery.renew.at = 0; }), /delivery\.renew\.at is above 0 and at most 0\.9/],
    ['renew.at 0.95', edited('google-calendar', trigger => { trigger.delivery.renew.at = 0.95; }), /delivery\.renew\.at is above 0 and at most 0\.9/],
    ['renew from a value never kept', edited('google-calendar', trigger => { trigger.delivery.renew.lifetime.kept = 'other'; }), /delivery\.renew\.lifetime reads the kept value other, which register\.keep does not take/],
    ['a push definition without admission', edited('github', trigger => { delete trigger.delivery.admission; }), /delivery: a webhook with registration api holds register, teardown, admission and fallback/],
    ['an unknown admission scheme', edited('github', trigger => { trigger.delivery.admission.scheme = 'basic'; }), /delivery\.admission\.scheme: a webhook with registration api is admitted by hmac-sha256-header/],
    ['trust other than doorbell', edited('github', trigger => { trigger.delivery.admission.trust = 'verified-payload'; }), /delivery\.admission\.trust is doorbell: a push only wakes the same cursor poll, and its payload is never stored or trusted \(spec line 1657\)/],
    ['a webhook without a polling fallback', edited('github', trigger => { delete trigger.delivery.fallback; }), /delivery: a webhook with registration api holds register, teardown, admission and fallback/],
    ['a watch with another fallback', edited('google-calendar', trigger => { trigger.delivery.fallback = 'none'; }), /delivery\.fallback is polling: every push names its polling fallback, as reviewed data/],
    ['a live trigger without a fallback', slack(trigger => { delete trigger.delivery.fallback; }), /delivery: a live trigger holds transport, admission and fallback, and may hold alternative/],
    ['a live trigger that carries an open step', slack(trigger => { trigger.delivery.open = {step: {id: 'open', method: 'POST', path: '/apps.connections.open', expect: OK}}; }), /delivery: a live trigger holds no step: the engine opens the socket with the operator's app-level token/],
    ['backfill.max 26', edited('github', trigger => { trigger.backfill.max = 26; }), /issue-activity v1: backfill is \{default: 0, max\}, with a max of 0 to 25/],
    ['a backfill default of 1', edited('github', trigger => { trigger.backfill.default = 1; }), /backfill is \{default: 0, max\}/],
    ['an open event schema', edited('github', trigger => { trigger.event.schema.additionalProperties = true; }), /issue-activity v1: event\.schema: \$event: objects require properties and additionalProperties:false/],
    ['a worst-case event above 8,192 bytes', edited('github', trigger => { trigger.event.schema.properties.title.maxLength = 2000; }), /issue-activity v1: event\.schema: a worst-case event is [\d,]+ bytes; at most 8,192 \(spec line 1687\)/],
    ['an unbounded string in the event', edited('github', trigger => { delete trigger.event.schema.properties.url.maxLength; }), /a worst-case event is unbounded; at most 8,192/],
    ['event fields that miss a property', edited('github', trigger => { delete trigger.event.fields.url; }), /event\.fields names exactly the properties of event\.schema/],
    ['a whole list in an event field', edited('github', trigger => { trigger.event.schema.properties.labels = {type: 'array', maxItems: 3, items: words(50)}; trigger.event.fields.labels = {item: '/labels'}; }),
      /issue-activity v1: event\.fields\.labels: copies step data whole: a raw step-data value sits only at a string, integer, number or boolean of event\.schema, and this one sits at an array \(I6, I9\)/],
    ['an input that is never used', edited('github', trigger => { trigger.inputSchema.properties.note = words(); }), /issue-activity v1: the input \/note is never used: every input reaches a poll, seed or enrich request/],
    ['eleven pages', edited('github', trigger => { trigger.bounds.pages = 11; }), /bounds is \{pages, items, pollSeconds\}: at most 10 pages, 500 items and 10 seconds per poll \(spec lines 1681-1682\)/],
    ['501 items', edited('github', trigger => { trigger.bounds.items = 501; }), /at most 10 pages, 500 items and 10 seconds per poll/],
    ['eleven seconds', edited('github', trigger => { trigger.bounds.pollSeconds = 11; }), /at most 10 pages, 500 items and 10 seconds per poll/],
    ['a poll step paging past bounds.pages', edited('github', trigger => { trigger.bounds.pages = 5; }), /poll\.source\.steps\[0\] \(issues\) pages up to 10 times, past bounds\.pages 5/],
    ['intervalSeconds.min 29', ownSteps(trigger => { trigger.delivery.intervalSeconds.min = 29; }), /delivery\.intervalSeconds is \{default, min\}: a min of 30 to 86,400 seconds and a default from min to 86,400/],
    ['a Slack trigger without a channel list', slack(trigger => { trigger.resource = []; trigger.poll.source.steps[0].query.channel = {const: 'C1'}; trigger.poll.itemId = {item: '/ts'}; trigger.event.id = {item: '/ts'}; trigger.event.fields.channel = {const: 'C1'}; }),
      /new-channel-message v1: resource: a Slack trigger names its channels: resource is \{each: '\/<list input>', as\} over a required list of at most 20 \(spec line 1674\)/],
    ['a Slack trigger above its maximum', slack(trigger => { trigger.inputSchema.properties.channels.maxItems = 21; }), /a Slack trigger names its channels: resource is \{each: '\/<list input>', as\} over a required list of at most 20/],
    ['Slack events kept a week', slack(trigger => { trigger.retention = {days: 7}; }), /retention: Slack events are kept at most 24 hours: \{hours: 1 to 24\} \(spec line 1676\)/],
    ['a var that no resource.as binds', ownSteps(trigger => { trigger.poll.source.steps[0].query.kind = {var: 'kind'}; }), /\{var: 'kind'\} is read only inside the \{each\} that binds it, or in a trigger's poll when its resource\.as binds it/],
    ['a rows list that is not the poll rows', edited('github', trigger => { trigger.rows = ['github.repos.read']; }), /issue-activity v1: rows lists github\.repos\.read, and its poll, seed and enrich steps land in github\.issues\.read/],
    ['resolvedInputs on a trigger', edited('github', trigger => { trigger.resolvedInputs = []; }), /issue-activity v1: a trigger's resource-dependent inputs wait for I07/],
    ['a lookup in a trigger\'s choices', edited('google-calendar', trigger => { trigger.choices[0].lookup = 'calendars'; }), /choices\[0\]: a trigger's choices take no lookup/],
    ['an unknown choice source', edited('google-calendar', trigger => { trigger.choices[0].source = 'nothing'; }), /event-changed v1: choices\[0\] names nothing, which is neither a choice source nor a version 1 option source of google-calendar/],
    ['dedupe by version without one', edited('github', trigger => { trigger.poll.itemVersion = null; }), /dedupe: id\+version needs an itemVersion/],
    ['an itemId that reads no item', edited('github', trigger => { trigger.poll.itemId = {input: '/owner'}; }), /poll\.itemId reads the poll item: each item's id comes from the item, so two items never share one \(section 8\)/],
    ['an unknown key', edited('github', trigger => { trigger.extra = true; }), /issue-activity v1: a trigger holds exactly/],
  ]) refused(file, pattern, DEPS, label);
});

test('part k: a trigger reusing a read action: the action\'s poll block, its arguments, its rows and the resource it keys on', () => {
  for (const [label, file, pattern] of [
    ['an action that does not exist', fromAction(trigger => { trigger.poll.source.action.key = 'nothing'; }), /listed-item v1: poll\.source\.action names nothing v1, which fixture's action file does not hold/],
    ['an action without a poll block', fromAction(trigger => { trigger.poll.source.action.key = 'update-item'; }), /poll\.source\.action: update-item v1 is not a read action with a poll block/],
    ['an argument of no input', fromAction(trigger => { trigger.poll.source.args.nothing = {const: 'x'}; }), /poll\.source\.args\.nothing names no input of list-items v1/],
    ['a required input left out', fromAction(trigger => { delete trigger.poll.source.args.kind; }), /poll\.source\.args: list-items v1 needs kind/],
    ['an argument of the wrong type', fromAction(trigger => { trigger.poll.source.args.kind = {const: 7}; }), /poll\.source\.args\.kind: the constant does not fit list-items v1's kind/],
    ['the action\'s own poll fields beside it', fromAction(trigger => { trigger.poll.itemId = {item: '/id'}; }), /poll is \{source: \{action, args\}\} for a trigger that reuses a read action: its poll block holds the rest/],
  ]) refused(file, pattern, DEPS, label);
  // A resource input is read through an argument the action keys its cursor on (its poll.resourceKey).
  const keyed = () => fromAction(trigger => { trigger.inputSchema = closed({labelId: words(64)}); trigger.resource = ['labelId']; trigger.poll.source.args.labelId = {input: '/labelId'}; });
  refused(keyed(), /listed-item v1: resource: labelId is read by no poll step: a registration targets exactly the resource/);
  const resourceKeyed = {...DEPS, actions: new Map([['fixture', {...fixtureActions(), actions: fixtureActions().actions.map(action => action.key === 'list-items' ? {...action, poll: {...action.poll, resourceKey: ['labelId'], filterInputs: ['kind']}} : action)}]])};
  assert.equal(entryOf(keyed(), resourceKeyed).key, 'listed-item', 'the poll block is outside the action id, so the stored ids still hold');
  // I8: a trigger whose source action is a candidate stays a candidate; every trigger is a candidate in F10.9.
  const reviewed = {...fromAction(), reviewStatus: 'reviewed'};
  assert.deepEqual([entryOf(reviewed).reviewed, entryOf(reviewed).status], [false, 'candidate']);
  const reviewedActions = {...DEPS, actions: new Map([['fixture', {...fixtureActions(), reviewStatus: 'reviewed'}]])};
  assert.deepEqual([entryOf(reviewed, reviewedActions).reviewed, entryOf(reviewed, reviewedActions).status], [true, 'candidate']);
  assert.deepEqual([entryOf(fromAction(), reviewedActions).reviewed, entryOf(ownSteps()).reviewed, entryOf({...ownSteps(), reviewStatus: 'reviewed'}).reviewed], [false, false, true]);
});

test('part k: a trigger id hashes its content, the pins of the transforms it names, and each reused action\'s id and poll hash; lifecycle data never moves it (section 8; open point Minor 2)', () => {
  const idOf = (file, deps = DEPS) => triggerIds(file, deps).get(`${file.triggers[0].key} v${file.triggers[0].version}`);
  const github = idOf(fixture('github')), calendar = idOf(fixture('google-calendar')), reused = idOf(fromAction());
  assert.match(github, /^github\.trigger\.issue-activity\.v1\.[a-f0-9]{24}$/);
  for (const [label, file] of [['reviewStatus', {...fixture('github'), reviewStatus: 'reviewed'}], ['certified', edited('github', trigger => { trigger.certified = {evidence: 'docs/live-evidence/github/triggers.json'}; })],
    ['superseded', {...fixture('github'), superseded: [{id: `github.trigger.issue-activity.v1.${'a'.repeat(24)}`, replacedBy: {key: 'issue-activity', version: 1}, reason: 'change', stopsAfter: '2026-12-31'}]}],
    ['the stored id', edited('github', trigger => { trigger.id = `github.trigger.issue-activity.v1.${ZEROS}`; })]]) {
    assert.equal(idOf(file), github, label);
  }
  assert.notEqual(idOf(edited('github', trigger => { trigger.description = 'Issues.'; })), github, 'its content');
  assert.notEqual(idOf(edited('github', trigger => { trigger.poll.cursors[0].kind = 'high-water-time@1'; trigger.poll.minIntervalSeconds = 120; })), github, 'a poll field');
  // The pin of a transform it names: in an expression, a cursor's compare, Link paging; not one it does not name.
  for (const id of ['text.truncate@1', 'time.rfc3339ToEpochSeconds@1', 'ids.linkPage@1']) assert.notEqual(idOf(fixture('github'), {...DEPS, pins: {...PINS, [id]: 'f'.repeat(64)}}), github, id);
  assert.equal(idOf(fixture('google-calendar'), {...DEPS, pins: {...PINS, 'ids.linkPage@1': 'f'.repeat(64)}}), calendar, 'a pin it does not name');
  refused(fixture('github'), /issue-activity v1: names ids\.linkPage@1, which has no pin, so its id could not bind its code \(decision 4\)/, {...DEPS, pins: Object.fromEntries(Object.entries(PINS).filter(([id]) => id !== 'ids.linkPage@1'))});
  // A reused action's id and poll hash.
  const actionsWith = edit => ({...DEPS, actions: new Map([['fixture', withIds({...fixtureActions(), actions: fixtureActions().actions.map(action => action.key === 'list-items' ? edit(structuredClone(action)) : action)}, {...DEPS, choices: FIXTURE.choices})]])});
  assert.notEqual(idOf(fromAction(), actionsWith(action => ({...action, description: 'Lists items.'}))), reused, 'the reused action\'s id');
  assert.notEqual(idOf(fromAction(), actionsWith(action => ({...action, poll: {...action.poll, minIntervalSeconds: 300}}))), reused, 'the reused action\'s poll hash');
  assert.equal(pollHash(validateActionFile(fixtureActions(), {...DEPS, choices: FIXTURE.choices}).actions[0], PINS), entryOf(fromAction()).sources[0].pollHash);
  assert.notEqual(idOf(fromAction(), {...DEPS, pins: {...PINS, 'time.rfc3339ToEpochSeconds@1': 'f'.repeat(64)}}), reused, 'a pin the reused poll block names');
  // A stored id that is not the computed one is refused, with the id its content hashes to; ids and keys are unique.
  assert.throws(() => validateTriggerFile(edited('github', trigger => { trigger.id = `github.trigger.issue-activity.v1.${ZEROS}`; }), DEPS),
    new RegExp(`issue-activity v1: id is github\\.trigger\\.issue-activity\\.v1\\.${ZEROS}, but its content hashes to ${github.replace(/\./g, '\\.')}: a changed trigger gets a new id`));
  assert.throws(() => validateTriggerFile(edited('github', trigger => { trigger.id = 'github.action.issue-activity.v1.000'; }), DEPS), /issue-activity v1: id is github\.trigger\.issue-activity\.v1\.<24 hex characters>/);
  refused({...fixture('github'), triggers: [fixture('github').triggers[0], fixture('github').triggers[0]]}, /Triggers for github: issue-activity v1 is declared twice/);
  refused({...fixture('github'), superseded: [{id: github, replacedBy: {key: 'issue-activity', version: 1}, reason: 'change', stopsAfter: '2026-12-31'}]}, /superseded\[0\]\.id is the current id of issue-activity v1/);
  refused({...fixture('github'), superseded: [{id: `notion.trigger.x.v1.${ZEROS}`, replacedBy: {key: 'issue-activity', version: 1}, reason: 'change', stopsAfter: '2026-12-31'}]}, /superseded\[0\]\.id is not a trigger id of github/);
  refused(edited('github', trigger => { trigger.certified = {evidence: 'docs/live-evidence/github-2026-10-20.json'}; }), /certified is \{evidence: 'docs\/live-evidence\/github\/triggers\.json'\}/);
});

test('part k: the file and every field of a trigger are closed: each malformed field is refused in its own words', () => {
  const github = fixture('github').triggers[0].id;
  const superseded = entry => ({...fixture('github'), superseded: [{id: `github.trigger.issue-activity.v1.${'a'.repeat(24)}`, replacedBy: {key: 'issue-activity', version: 1}, reason: 'change', stopsAfter: '2026-12-31', ...entry}]});
  const register = change => edited('github', trigger => change(trigger.delivery.register.step, trigger));
  const admissionOf = (appId, change) => edited(appId, trigger => change(trigger.delivery.admission, trigger));
  for (const [label, file, pattern] of [
    // The file.
    ['a file that is a list', [], /Triggers: a trigger file is an object/],
    ['schemaVersion 2', {...fixture('github'), schemaVersion: 2}, /Triggers for github: schemaVersion is 1/],
    ['an app id in capitals', {...fixture('github'), appId: 'GitHub'}, /Triggers for GitHub: appId is an app id/],
    ['an app with no rows', {...fixture('github'), appId: 'nothing'}, /Triggers for nothing: the app has no reviewed permission rows and proxy settings/],
    ['another spec version', {...fixture('github'), specVersion: 'fabric/0.1'}, /Triggers for github: specVersion is fabric\/0\.2/],
    ['an unknown review status', {...fixture('github'), reviewStatus: 'approved'}, /Triggers for github: reviewStatus is reviewed or candidate/],
    ['a pinned parameter from a URL', {...fixture('github'), pinnedParameters: {owner: 'https://x'}}, /pinnedParameters maps names to constant path segments/],
    ['no triggers', {...fixture('github'), triggers: []}, /Triggers for github: triggers holds 1 to 100 triggers/],
    ['an unknown file field', {...fixture('github'), extra: 1}, /a trigger file holds exactly schemaVersion, appId, specVersion, reviewStatus, pinnedParameters and triggers, and may hold superseded/],
    // Superseded ids (R9).
    ['an empty superseded list', {...fixture('github'), superseded: []}, /Triggers for github: superseded holds 1 to 100 entries/],
    ['a superseded entry of another shape', superseded({extra: 1}), /superseded\[0\] is \{id, replacedBy: \{key, version\}, reason, stopsAfter\}/],
    ['a replacement not in the file', superseded({replacedBy: {key: 'other', version: 1}}), /superseded\[0\]\.replacedBy names no trigger of this file/],
    ['an unknown reason', superseded({reason: 'tidy'}), /superseded\[0\]\.reason is safety or change/],
    ['a date that is not real', superseded({stopsAfter: '2026-02-30'}), /superseded\[0\]\.stopsAfter is a real date, YYYY-MM-DD/],
    ['an id listed twice', {...superseded({}), superseded: [...superseded({}).superseded, ...superseded({}).superseded]}, /superseded lists github\.trigger\.issue-activity\.v1\.a{24} twice/],
    // The trigger's own fields.
    ['a trigger that is a list', {...fixture('github'), triggers: [[]]}, /Triggers for github: triggers\[0\] is an object/],
    ['a key in capitals', edited('github', trigger => { trigger.key = 'Issue'; }), /triggers\[0\]: key is 1 to 48 lowercase letters, digits and hyphens/],
    ['version 0', edited('github', trigger => { trigger.version = 0; }), /triggers\[0\]: version is a whole number from 1 to 9999/],
    ['an empty name', edited('github', trigger => { trigger.name = ' '; }), /issue-activity v1: name is 1 to 100 characters on one line/],
    ['a description on two lines', edited('github', trigger => { trigger.description = 'a\nb'; }), /issue-activity v1: description is 1 to 1,000 characters on one line/],
    ['an input schema that is a list', edited('github', trigger => { trigger.inputSchema = {type: 'array', items: words()}; }), /issue-activity v1: inputSchema is a closed object schema/],
    ['a credential-shaped input', edited('github', trigger => { trigger.inputSchema.properties.apiKey = words(); }), /issue-activity v1: the input \$input\.apiKey is named like a credential: a trigger input never carries one \(I3\)/],
    ['an empty filter', edited('github', trigger => { trigger.filter = []; }), /issue-activity v1: filter holds 1 to 8 tests over the item/],
    ['a resource that is not a list input', slack(trigger => { trigger.resource = {each: '/channels', as: 'channels'}; }), /resource\.each names a required list input, and resource\.as a name that is not an input/],
    ['a resource of another shape', edited('github', trigger => { trigger.resource = 'owner'; }), /issue-activity v1: resource is a list of input names, or \{each: '\/<list input>', as\} \(section 8\)/],
    ['an optional resource input', edited('github', trigger => { trigger.inputSchema.required = ['owner']; }), /issue-activity v1: resource lists at most 8 distinct required inputs that pick the resource/],
    // Delivery.
    ['an unknown delivery method', edited('github', trigger => { trigger.delivery = {method: 'email'}; }), /issue-activity v1: delivery\.method is polling, webhook, watch, live or builtin \(spec line 702\)/],
    ['a polling trigger with a register step', ownSteps(trigger => { trigger.delivery.register = {}; }), /item-changed v1: delivery: a polling trigger holds intervalSeconds/],
    ['a built-in schedule without a time zone', fromAction(trigger => { trigger.delivery = {method: 'builtin', kind: 'schedule', intervalSeconds: 300}; }), /listed-item v1: delivery: a built-in schedule is \{kind: 'schedule', intervalSeconds \(30 to 86,400\) or cron, timeZone\}/],
    ['a live trigger on another transport', slack(trigger => { trigger.delivery.transport = 'websocket'; }), /new-channel-message v1: delivery\.transport is slack-socket-mode/],
    ['a live alternative of another shape', slack(trigger => { trigger.delivery.alternative = {method: 'webhook', registration: 'api', admission: {}}; }), /delivery\.alternative is \{method: 'webhook', registration: 'operator', admission\}/],
    ['an operator webhook with a register step', edited('notion', trigger => { trigger.delivery.register = {}; }), /row-changed v1: delivery: a webhook with registration operator holds admission and fallback, and no step/],
    ['an unknown registration', edited('github', trigger => { trigger.delivery.registration = 'manual'; }), /issue-activity v1: delivery\.registration is api or operator/],
    ['a register block of another shape', edited('github', trigger => { trigger.delivery.register.extra = 1; }), /issue-activity v1: delivery\.register is \{step, keep\}/],
    ['a teardown that deletes leftovers', edited('github', trigger => { trigger.delivery.teardown.onFailure = 'retry'; }), /delivery\.teardown is \{step, onFailure: 'record-leftover'\}/],
    ['a renew block of another shape', edited('google-calendar', trigger => { trigger.delivery.renew.extra = 1; }), /event-changed v1: delivery\.renew is \{lifetime, at, order, onMiss\}/],
    ['a lifetime of 30 seconds', edited('google-calendar', trigger => { trigger.delivery.renew.lifetime = {seconds: 30}; }), /delivery\.renew\.lifetime is \{kept, format: 'epoch-ms-string' \| 'rfc3339'\} or \{seconds\} \(60 to 2,592,000\)/],
    ['a renewal that stops the old first', edited('google-calendar', trigger => { trigger.delivery.renew.order = 'stop-old-then-new'; }), /delivery\.renew renews new-then-stop-old, and resyncs on a miss/],
    // Registration steps.
    ['a registration path parameter left open', register(step => { delete step.params.repo; }), /delivery\.register\.step \(hook\): the path parameter repo is filled neither by params nor by pinnedParameters/],
    ['a registration parameter of no path', register(step => { step.params.other = {const: 'x'}; }), /delivery\.register\.step \(hook\)\.params\.other names no parameter of POST \/repos\/\{owner\}\/\{repo\}\/hooks that a step fills/],
    ['a kept value in a register path', register(step => { step.params.repo = {kept: 'hookId'}; }), /delivery\.register\.step \(hook\): a register step reads no kept value: it makes them/],
    ['a register step without its body', register(step => { delete step.body; }), /delivery\.register\.step \(hook\): POST \/repos\/\{owner\}\/\{repo\}\/hooks takes a body with its destination/],
    ['a teardown step without its body', edited('google-calendar', trigger => { delete trigger.delivery.teardown.step.body; }), /delivery\.teardown\.step \(stop\): calendar\.channels\.stop takes a body with its registration ids/],
    ['a step id in capitals', register(step => { step.id = 'Hook'; }), /delivery\.register\.step \(Hook\): a step id is 1 to 32 letters and digits, starting with a lowercase letter/],
    ['a step id used twice', edited('github', trigger => { trigger.delivery.teardown.step.id = 'hook'; }), /delivery\.teardown\.step \(hook\): the step id hook is used twice/],
    // Admission.
    ['an unknown handshake', admissionOf('github', admission => { admission.handshake = 'hello'; }), /delivery\.admission\.handshake is one of github-ping, notion-verification-token, slack-url-verification and google-sync/],
    ['a header in capitals', admissionOf('github', admission => { admission.header = 'X-Hub-Signature-256'; }), /delivery\.admission\.header is a lowercase header name/],
    ['an empty prefix', admissionOf('github', admission => { admission.prefix = ''; }), /delivery\.admission\.prefix is 1 to 32 characters/],
    ['an operator secret of another form', admissionOf('notion', admission => { admission.secret = 'token'; }), /row-changed v1: delivery\.admission\.secret is operator:<name>, a secret the operator keeps/],
    ['a socket that names a secret', slack(trigger => { trigger.delivery.admission.secret = 'socket'; }), /delivery\.admission: a socket is authenticated by the operator's app-level token: it names no secret/],
    ['an identity route that reads a token', admissionOf('notion', admission => { admission.route.pointer = '/access_token'; }), /delivery\.admission\.route\.pointers\[0\]: the pointer \/access_token reads access_token/],
    ['a wake that reads a token', admissionOf('notion', admission => { admission.wake.pointer = '/data/token'; }), /delivery\.admission\.wake: the pointer \/data\/token reads token/],
    ['a collapse that reads a token', slack(trigger => { trigger.delivery.admission.collapse = {pointer: '/payload/token'}; }), /delivery\.admission\.collapse: the pointer \/payload\/token reads token/],
    ['an identity route to somewhere else', admissionOf('notion', admission => { admission.route.to = 'subscription'; }), /delivery\.admission\.route: a push is routed only by an id kept at registration or the signed-in identity: \{pointer, to: 'identity'\}/],
    ['a wake from no input', admissionOf('notion', admission => { admission.wake.equals = {const: 'x'}; }), /delivery\.admission\.wake is \{pointer, equals \| in: \{input\}\}: a push wakes only the subscription whose input it names/],
    ['a collapse of another shape', admissionOf('github', admission => { admission.collapse = {header: 'X-GitHub-Delivery'}; }), /delivery\.admission\.collapse is \{header\} or \{pointer\}/],
    ['an admission of another shape', admissionOf('github', admission => { admission.extra = 1; }), /delivery\.admission is \{scheme, trust, route\} and may hold handshake, header, prefix, secret, wake, collapse and events/],
    ['an unknown event name', slack(trigger => { trigger.delivery.admission.events = ['Message']; }), /delivery\.admission\.events lists 1 to 16 provider event names/],
    // The poll.
    ['an own poll with an unknown field', edited('github', trigger => { trigger.poll.extra = 1; }), /issue-activity v1: poll is \{source, items, itemId, itemVersion, order, cursors, resync, minIntervalSeconds\} and may hold itemTime, seed and enrich/],
    ['four source steps', edited('github', trigger => { const [step] = trigger.poll.source.steps; trigger.poll.source.steps = [{...step, id: 'a', query: {}, headers: {}}, {...step, id: 'b', query: {}, headers: {}}, {...step, id: 'c', query: {}, headers: {}}, step]; }), /poll\.source is \{steps: \[1 to 3 read steps\]\}, or \{action, args\}/],
    ['items from an earlier step', edited('github', trigger => { const [step] = trigger.poll.source.steps; trigger.poll.source.steps = [{...step, id: 'first', query: {}, headers: {}}, step]; trigger.poll.items = {step: 'first', pointer: ''}; }), /poll\.items reads issues, the poll step: the items a poll sees are the list its last step reads/],
    ['items that are not a list', edited('github', trigger => { trigger.poll.items = {object: {all: {step: 'issues', pointer: ''}}}; }), /issue-activity v1: poll\.items is a list/],
    ['an item id that is an object', edited('github', trigger => { trigger.poll.itemId = {object: {id: {item: '/id'}}}; }), /issue-activity v1: poll\.itemId is a string or an integer/],
    ['an item id with a job key', edited('github', trigger => { trigger.poll.itemId = {concat: [{item: '/id'}, {jobKey: 'poll'}], max: 100}; }), /poll\.itemId never reads the clock or a job key/],
    ['an item time in an unknown format', edited('github', trigger => { trigger.poll.itemTime.format = 'iso'; }), /poll\.itemTime is \{pointer, format\}, in one of the formats rfc3339, epoch-ms-string, epoch-seconds and slack-ts/],
    ['an unknown order', edited('github', trigger => { trigger.poll.order = 'newest'; }), /poll\.order is asc, desc or unordered/],
    ['an item version that reads a token', edited('github', trigger => { trigger.poll.itemVersion = '/temp_clone_token'; }), /poll\.itemVersion: the pointer \/temp_clone_token reads temp_clone_token/],
    ['a cursor with no slot', edited('github', trigger => { delete trigger.poll.source.steps[0].query.since; }), /issue-activity v1: the cursor updated has 0 \{cursor\} slots in the poll step issues; a high-water-time@1 cursor has exactly one \(section 8\)/],
    ['no cursors', edited('github', trigger => { delete trigger.poll.source.steps[0].query.since; delete trigger.poll.source.steps[0].headers; trigger.poll.cursors = []; }), /poll\.cursors holds 1 to 4 cursors/],
    ['a poll every 10 seconds', edited('github', trigger => { trigger.poll.minIntervalSeconds = 10; }), /poll\.minIntervalSeconds is 30 to 86,400 \(I7\)/],
    ['a resync on a 500', edited('github', trigger => { trigger.poll.resync.statusIn = [500]; }), /poll\.resync is \{statusIn\}, holding 404, 410, both or neither/],
    ['a seed of another shape', ownSteps(trigger => { trigger.poll.seed = {step: {id: 'seed', method: 'GET', path: '/labels', expect: OK}}; }), /item-changed v1: poll\.seed is \{step, cursor: \{name, pointer\}\}/],
    ['26 enriched items', ownSteps(trigger => { trigger.poll.enrich = {max: 26, steps: [{id: 'more', method: 'GET', path: '/labels', expect: OK}]}; }), /poll\.enrich is \{max, steps\}: 1 to 3 read steps, run for at most 1 to 25 items \(I7\)/],
    ['a read step with forEach', ownSteps(trigger => { trigger.poll.source.steps[0].forEach = {over: {const: ['a']}, max: 1}; }), /poll\.source\.steps\[0\] \(list\): a trigger's read step holds id, method, path and expect, and may hold params, query, headers, body, page and maxResponseBytes/],
    ['an argument of the wrong type', fromAction(trigger => { trigger.inputSchema = closed({count: {type: 'integer', minimum: 0, maximum: 9}}); trigger.poll.source.args.kind = {input: '/count'}; }), /listed-item v1: poll\.source\.args\.kind: its type does not fit list-items v1's kind/],
    ['a reused poll of another shape', fromAction(trigger => { trigger.poll.source.extra = 1; }), /listed-item v1: poll is \{source: \{action, args\}\} for a trigger that reuses a read action/],
    // Dedupe, event and limits.
    ['an unknown dedupe kind', edited('github', trigger => { trigger.dedupe = {kind: 'hash'}; }), /issue-activity v1: dedupe is \{kind: 'id' \| 'id\+version'\} or \{kind: 'content-hash', fields\}/],
    ['dedupe fields on an id', edited('github', trigger => { trigger.dedupe = {kind: 'id', fields: [{item: '/id'}]}; }), /dedupe is \{kind: 'id' \| 'id\+version'\} or \{kind: 'content-hash', fields\}/],
    ['a content hash of nothing', edited('github', trigger => { trigger.dedupe = {kind: 'content-hash', fields: []}; }), /issue-activity v1: dedupe\.fields holds 1 to 8 expressions over the item/],
    ['an event with an unknown field', edited('github', trigger => { trigger.event.extra = 1; }), /issue-activity v1: event is \{schema, id, occurredAt, fields, summary\}/],
    ['an event schema that is a list', edited('github', trigger => { trigger.event.schema = {type: 'array', maxItems: 1, items: words()}; }), /issue-activity v1: event\.schema is a closed object schema/],
    ['an event id that is an object', edited('github', trigger => { trigger.event.id = {object: {id: {item: '/id'}}}; }), /issue-activity v1: event\.id is a string or an integer/],
    ['nine summary lines', edited('github', trigger => { trigger.event.summary = Array.from({length: 9}, () => trigger.event.summary[0]); }), /issue-activity v1: event\.summary holds at most 8 lines/],
    ['a summary line without a label', edited('github', trigger => { delete trigger.event.summary[0].label; }), /event\.summary\[0\] is \{label, expr\} and may hold truncate/],
    ['a summary line that is a boolean', edited('github', trigger => { trigger.event.summary[0].expr = {const: true}; }), /event\.summary\[0\] \(Title\): a summary line shows a string or a number/],
    ['an event field of another type', edited('github', trigger => { trigger.event.fields.number = {const: 'seven'}; }), /issue-activity v1: event\.fields\.number is a string, and event\.schema declares an integer/],
    ['events kept for weeks', edited('github', trigger => { trigger.retention = {weeks: 1}; }), /issue-activity v1: retention is \{days: 1 to 7\} or \{hours: 1 to 24\} \(spec line 1676\)/],
    ['no rows', edited('github', trigger => { trigger.rows = []; }), /issue-activity v1: rows lists the distinct read rows the trigger's poll, seed and enrich steps land in/],
    ['a write row', edited('github', trigger => { trigger.rows = ['github.issues.write']; }), /rows lists the distinct read rows/],
    // The registry holds every transform the trigger names.
  ]) assert.throws(() => valid(file), pattern, label);
  const without = new Map([...TRANSFORMS].filter(([id]) => id !== 'time.rfc3339ToEpochSeconds@1'));
  refused(fixture('github'), /issue-activity v1: names time\.rfc3339ToEpochSeconds@1, which the registry does not hold/, {...DEPS, transforms: without});
  // A built-in schedule, a filter and a content-hash duplicate key pass.
  assert.equal(entryOf(fromAction(trigger => { trigger.delivery = {method: 'builtin', kind: 'schedule', intervalSeconds: 300, timeZone: 'Europe/London'}; })).key, 'listed-item');
  assert.equal(entryOf(fromAction(trigger => { trigger.delivery = {method: 'builtin', kind: 'schedule', cron: '*/5 * * * *', timeZone: 'UTC'}; })).key, 'listed-item');
  assert.equal(entryOf(edited('github', trigger => { trigger.filter = [{equals: [{item: '/state'}, {const: 'open'}]}]; trigger.dedupe = {kind: 'content-hash', fields: [{item: '/id'}, {item: '/state'}]}; })).key, 'issue-activity');
  assert.equal(entryOf(edited('google-calendar', trigger => { trigger.delivery.renew.lifetime = {seconds: 86_400}; })).key, 'event-changed');
  assert.equal(github, triggerIds(fixture('github'), DEPS).get('issue-activity v1'));
});

test('part k check: checkEvent() holds what I07\'s engine builds from one poll item to scalars and the closed event schema, so a raw item value is never a whole provider object (I6, I9)', () => {
  const [entry] = validateTriggerFile(fixture('github'), DEPS).triggers;
  const repository = {id: 1, name: 'fabric', temp_clone_token: 'secret-value'};
  const event = (change = {}) => ({itemId: 101, id: '101:2026-10-20T10:00:00Z', occurredAt: '2026-10-20T10:00:00Z',
    fields: {repository: 'acme/fabric', number: 7, pullRequest: true, state: 'open', title: 'Fix it', updatedAt: '2026-10-20T10:00:00Z', url: 'https://github.com/acme/fabric/issues/7'},
    summary: ['Fix it', 'open'], ...change});
  const built = event();
  assert.equal(checkEvent(entry, built), built, 'returns the event it was given');
  assert.deepEqual(checkEvent(entry, event({summary: [undefined, 3], fields: {repository: 'acme/fabric', number: 7, state: 'open', updatedAt: 'x'}})).summary, [undefined, 3], 'an absent line and a number');
  assert.equal(checkEvent(entry.trigger, built), built, 'the trigger as written');
  for (const [label, value, pattern] of [
    ['an item id that is a whole object', event({itemId: repository}), /issue-activity v1: the item id is an object: an item id is a string or an integer \(I6, I9\)/],
    ['an event id that is a whole object', event({id: repository}), /issue-activity v1: event\.id is an object: an event id is a string or an integer \(I6, I9\)/],
    ['an event time that is a list', event({occurredAt: ['2026']}), /issue-activity v1: event\.occurredAt is a list: an event time is a string or an integer \(I6, I9\)/],
    ['an item id that is a fraction', event({itemId: 1.5}), /the item id is a number: an item id is a string or an integer/],
    ['a summary line that is a whole object', event({summary: [repository, 'open']}), /issue-activity v1: event\.summary\[0\] \(Title\) is an object: a summary line shows a string or a number \(I6, I9\)/],
    ['a summary line that is a boolean', event({summary: ['Fix it', true]}), /event\.summary\[1\] \(State\) is a boolean: a summary line shows a string or a number/],
    ['a summary line that is not a finite number', event({summary: ['Fix it', Infinity]}), /event\.summary\[1\] \(State\) is a number: a summary line shows a string or a number/],
    ['one summary value too few', event({summary: ['Fix it']}), /issue-activity v1: checkEvent\(\) takes one value per summary line: 2, not 1/],
    ['a field that copies a whole object', event({fields: {...built.fields, title: repository}}), /issue-activity v1: event\.fields does not fit event\.schema \(\$event\.title: expected string\)/],
    ['a field the schema does not declare', event({fields: {...built.fields, token: 'x'}}), /issue-activity v1: event\.fields does not fit event\.schema/],
    ['a title past its maximum', event({fields: {...built.fields, title: 'x'.repeat(301)}}), /event\.fields does not fit event\.schema/],
    ['an event of another shape', {...built, raw: repository}, /issue-activity v1: an event is \{itemId, id, occurredAt, fields, summary\}/],
  ]) assert.throws(() => checkEvent(entry, value), pattern, label);
  assert.throws(() => checkEvent({}, built), /checkEvent\(\) takes a trigger, or an entry validateTriggerFile\(\) returned/);
});

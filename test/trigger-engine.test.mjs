import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {PAUSE_REASONS, LIMITS, limitAnswer, PAUSE_ERRORS, WINDOWS, windowOf, BUDGETS, SLACK_HISTORY_TRIGGERS, subscribeRefusal, gapPayload, placeLostAt, retentionMs} from '../lib/trigger-rules.mjs';
import {gate, argsHashOf, authorityOf, runnable} from '../lib/trigger-gate.mjs';
import {TriggerEngine, intervalOf} from '../lib/trigger-engine.mjs';
import {PermissionManager} from '../lib/permissions.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {Store} from '../lib/store.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {CURSOR_KINDS} from '../lib/actions.mjs';
import {validateTriggerFile, triggerIds, triggerPollInputs} from '../lib/triggers.mjs';
import {canonicalHash} from '../lib/compiler.mjs';
import {LOCAL_DEPLOYMENT, tenantDeployment, stampOwner, endUser} from '../lib/tenant/deployment.mjs';
import {REGISTRY_PINS, feedTriggers, triggerHarness} from './fixtures/actions/trigger-fixture.mjs';
import {TOKEN} from './fixtures/actions/runtime-fixture.mjs';
import {forgetTriggers} from '../lib/trigger-data.mjs';
import {createApp} from '../server.mjs';
import {fixtureGroups, fixtureSignIn} from './fixtures/actions/fixture-app.mjs';
import {TRANSFORMS, PINS} from './fixtures/actions/registry.mjs';

// Iteration 9 step 2 (docs/I07-BUILD-MAP.md step 2 and section 2.5): the poll engine. Part 2a: the rules a poll reads, the strictest mode over a
// trigger's read rows and the one gate every check goes through. A gate does no network and no write, so it is safe on every read. Nothing here
// reaches a provider: the fixture app answers from test/fixtures/provider-simulators/fixture.mjs.
const drafts = appId => JSON.parse(readFileSync(new URL(`./fixtures/docs/trigger-drafts/${appId}.json`, import.meta.url), 'utf8')).triggers;
const stepsOf = ({poll}) => [...poll.source.steps, ...(poll.seed ? [poll.seed.step] : []), ...(poll.enrich?.steps ?? [])];

// ---- the rules ---------------------------------------------------------------------------------------------------------------------------
test('lib/trigger-rules.mjs imports nothing, and its tables are frozen', () => {
  assert.doesNotMatch(readFileSync(new URL('../lib/trigger-rules.mjs', import.meta.url), 'utf8'), /^\s*import\b|\bimport\s*\(|\brequire\s*\(/m);
  for (const table of [PAUSE_REASONS, LIMITS, LIMITS.gmail, LIMITS.gmail.reasons, PAUSE_ERRORS, WINDOWS, WINDOWS['github.push'], BUDGETS, BUDGETS.slack, BUDGETS.slack.methods, SLACK_HISTORY_TRIGGERS]) assert.ok(Object.isFrozen(table));
});

test('the pause reasons are the closed list of section 2.5', () => {
  assert.deepEqual([...PAUSE_REASONS], ['owner_paused', 'background_off', 'permission_changed', 'access_missing', 'account_changed', 'client_ended', 'definition_changed', 'provider_refused', 'too_many_items', 'cursor_invalid']);
});

test('a limit 403 reads by the table of its app, and a 403 alone is never a limit', () => {
  const google = field => ({status: 403, headers: {}, data: {error: {errors: [field]}}});
  for (const [label, appId, answer, expected] of [
    ['Gmail, per user', 'gmail', google({reason: 'userRateLimitExceeded'}), true],
    ['Gmail, per day', 'gmail', google({reason: 'dailyLimitExceeded'}), true],
    ['Gmail, rate', 'gmail', google({reason: 'rateLimitExceeded'}), true],
    ['Gmail, one of several errors', 'gmail', {status: 403, headers: {}, data: {error: {errors: [{reason: 'other'}, {reason: 'rateLimitExceeded'}]}}}, true],
    ['Gmail, a policy refusal', 'gmail', google({reason: 'domainPolicy'}), false],
    ['Gmail, no permission', 'gmail', google({reason: 'insufficientPermissions'}), false],
    ['Calendar, usageLimits', 'google-calendar', google({domain: 'usageLimits', reason: 'rateLimitExceeded'}), true],
    ['Calendar, any usageLimits reason', 'google-calendar', google({domain: 'usageLimits', reason: 'quotaExceeded'}), true],
    ['Calendar, a reader\'s calendar', 'google-calendar', google({domain: 'calendar', reason: 'forbidden'}), false],
    ['Calendar reads no Gmail reason', 'google-calendar', google({domain: 'global', reason: 'rateLimitExceeded'}), false],
    ['GitHub, the primary limit spent', 'github', {status: 403, headers: {'x-ratelimit-remaining': '0'}, data: {message: 'API rate limit exceeded'}}, true],
    ['GitHub, a secondary limit by its words', 'github', {status: 403, headers: {'x-ratelimit-remaining': '4000'}, data: {message: 'You have exceeded a secondary rate limit. Please wait.'}}, true],
    ['GitHub, the words in any case', 'github', {status: 403, headers: {}, data: {message: 'You have exceeded a SECONDARY RATE LIMIT'}}, true],
    ['GitHub, a refusal with budget left', 'github', {status: 403, headers: {'x-ratelimit-remaining': '4000'}, data: {message: 'Resource not accessible by integration'}}, false],
    ['GitHub, no headers', 'github', {status: 403, data: {message: 'Forbidden'}}, false],
    ['a 403 with no body', 'gmail', {status: 403, headers: {}, data: null}, false],
    ['a 429 is not this table\'s to read', 'gmail', {status: 429, headers: {}, data: null}, false],
    ['a limit word on a 404', 'github', {status: 404, headers: {}, data: {message: 'secondary rate limit'}}, false],
    ['an app with no table', 'notion', {status: 403, headers: {}, data: {error: {errors: [{reason: 'rateLimitExceeded'}]}}}, false],
    ['the fixture app has none', 'fixture', {status: 403, headers: {'x-ratelimit-remaining': '0'}, data: {message: 'secondary rate limit'}}, false]]) {
    assert.equal(limitAnswer(appId, answer), expected, label);
  }
});

test('the Slack errors that pause are the list of part 2a, and those that back off are not among them', () => {
  assert.deepEqual([...PAUSE_ERRORS], ['channel_not_found', 'not_in_channel', 'thread_not_found', 'method_deprecated', 'deprecated_endpoint', 'token_revoked', 'account_inactive', 'ekm_access_denied']);
  for (const code of ['invalid_cursor', 'internal_error', 'service_unavailable', 'fatal_error', 'request_timeout', 'missing_scope']) assert.ok(!PAUSE_ERRORS.includes(code), code);
});

test('WINDOWS names the seven window snapshots of section 2.4, each a snapshot of a draft, and only two reach a set time', () => {
  assert.deepEqual(Object.keys(WINDOWS).sort(), ['github.push', 'github.release-published', 'github.workflow-run-finished', 'gmail.new-email-matching-search', 'google-calendar.starting-soon', 'slack.mention-search', 'slack.reaction-recent']);
  for (const name of Object.keys(WINDOWS)) {
    const [appId, key] = name.split('.'), trigger = drafts(appId).find(item => item.key === key);
    assert.ok(trigger?.poll.cursors.some(cursor => cursor.kind === 'snapshot@1'), `${name} is a snapshot of its app's drafts`);
  }
  for (const [appId, key, args, expected] of [
    ['gmail', 'new-email-matching-search', {search: {words: 'x'}}, {seconds: 604_800}],
    ['google-calendar', 'starting-soon', {calendarId: 'a', leadMinutes: 30}, {seconds: 1_800}],
    ['github', 'push', {repository: 'a/b'}, {seconds: null}],
    ['github', 'workflow-run-finished', {}, {seconds: null}],
    ['github', 'release-published', {}, {seconds: null}],
    ['slack', 'mention-search', {}, {seconds: null}],
    ['slack', 'reaction-recent', {}, {seconds: null}],
    ['notion', 'new-comment', {}, null],
    ['github', 'toString', {}, null],
    ['fixture', 'feed-listed', {}, null]]) {
    assert.deepEqual(windowOf(appId, key, args), expected, `${appId}.${key}`);
  }
});

test('BUDGETS are half each provider\'s limit, a Slack bucket per method, and they cover every Slack method a draft reads', () => {
  assert.deepEqual(BUDGETS, {gmail: {perMinute: 60}, 'google-calendar': {perMinute: 120}, github: {perMinute: 60, keepRemaining: 500}, notion: {perMinute: 90},
    slack: {methods: {'conversations.history': 25, 'conversations.replies': 25, 'search.messages': 10, 'users.conversations': 25}}});
  const methods = new Set(drafts('slack').flatMap(stepsOf).map(step => step.path.slice(1)));
  assert.deepEqual([...methods].sort(), Object.keys(BUDGETS.slack.methods).sort());
});

test('SLACK_HISTORY_TRIGGERS are exactly the Slack drafts that read history or replies', () => {
  const reads = drafts('slack').filter(trigger => stepsOf(trigger).some(step => ['/conversations.history', '/conversations.replies'].includes(step.path))).map(trigger => `slack.${trigger.key}`);
  assert.deepEqual([...SLACK_HISTORY_TRIGGERS].sort(), reads.sort());
  assert.equal(reads.length, 5);
});

test('subscribeRefusal reads only the arguments and what Fabric holds, by table', () => {
  const channel = 'C0123456789', group = 'G0123456789', direct = 'D0123456789', acls = 'https://www.googleapis.com/auth/calendar.acls';
  for (const [label, appId, key, args, facts, reason] of [
    ['history under distributed', 'slack', 'new-message', {channels: [channel]}, {slackDistribution: 'distributed'}, 'distributed'],
    ['a direct message under distributed', 'slack', 'new-dm', {conversations: [direct]}, {slackDistribution: 'distributed'}, 'distributed'],
    ['replies under distributed', 'slack', 'thread-reply', {threads: [{channel, ts: '1761210000.000100'}]}, {slackDistribution: 'distributed'}, 'distributed'],
    ['reactions under distributed', 'slack', 'reaction-recent', {channels: [channel]}, {slackDistribution: 'distributed'}, 'distributed'],
    ['files under distributed', 'slack', 'file-shared', {channels: [channel]}, {slackDistribution: 'distributed'}, 'distributed'],
    ['search is not paced', 'slack', 'mention-search', {channels: [channel]}, {slackDistribution: 'distributed'}, null],
    ['the conversation list is not paced', 'slack', 'conversation-joined', {kinds: ['im']}, {slackDistribution: 'distributed'}, null],
    ['history when internal', 'slack', 'new-message', {channels: [channel, group]}, {slackDistribution: 'internal'}, null],
    ['history in the Marketplace', 'slack', 'new-message', {channels: [channel]}, {slackDistribution: 'marketplace'}, null],
    ['a channel that is no id', 'slack', 'new-message', {channels: [channel, 'from:@ada']}, {}, 'channel_id'],
    ['a lower-case id', 'slack', 'file-shared', {channels: ['c0123456789']}, {}, 'channel_id'],
    ['an id too short', 'slack', 'reaction-recent', {channels: ['C01234']}, {}, 'channel_id'],
    ['a query in a channel id', 'slack', 'mention-search', {channels: ['C0123456789 in:#x']}, {}, 'channel_id'],
    ['a direct message id on a channel watch', 'slack', 'new-message', {channels: [direct]}, {}, 'channel_id'],
    ['a channel id on a direct message watch', 'slack', 'new-dm', {conversations: [channel]}, {}, 'channel_id'],
    ['a thread in no channel', 'slack', 'thread-reply', {threads: [{channel: 'nope', ts: '1761210000.000100'}]}, {}, 'channel_id'],
    ['a direct message watch', 'slack', 'new-dm', {conversations: [direct]}, {}, null],
    ['an empty search', 'gmail', 'new-email-matching-search', {search: {}}, {}, 'empty_search'],
    ['a search', 'gmail', 'new-email-matching-search', {search: {from: 'a@example.com'}}, {}, null],
    ['the literal primary', 'google-calendar', 'new-event', {calendarId: 'primary'}, {}, 'primary_calendar'],
    ['primary on any calendar watch', 'google-calendar', 'starting-soon', {calendarId: 'primary', leadMinutes: 30}, {}, 'primary_calendar'],
    ['a calendar id', 'google-calendar', 'new-event', {calendarId: 'owner@example.com'}, {}, null],
    ['a lead shorter than twice the interval', 'google-calendar', 'starting-soon', {calendarId: 'a', leadMinutes: 3}, {}, 'lead_too_short'],
    ['a lead of exactly twice the interval', 'google-calendar', 'starting-soon', {calendarId: 'a', leadMinutes: 4}, {}, null],
    ['sharing without the scope', 'google-calendar', 'calendar-sharing-changed', {calendarId: 'a'}, {scopes: []}, 'needs_access'],
    ['sharing with no scopes known', 'google-calendar', 'calendar-sharing-changed', {calendarId: 'a'}, {}, 'needs_access'],
    ['sharing with the scope', 'google-calendar', 'calendar-sharing-changed', {calendarId: 'a'}, {scopes: [acls]}, null],
    ['an app with no rule', 'notion', 'new-row', {dataSourceId: 'x'}, {}, null],
    ['the fixture app', 'fixture', 'feed-updated', {kinds: ['note']}, {}, null]]) {
    const refused = subscribeRefusal(appId, key, args, facts);
    assert.equal(refused?.reason ?? null, reason, label);
    if (reason) assert.ok(refused.words.length > 20 && !/—/.test(refused.words), `${label}: fixed words`);
  }
  // A failed scope check names Add access, not a later failure.
  assert.match(subscribeRefusal('google-calendar', 'calendar-sharing-changed', {calendarId: 'a'}, {scopes: []}).words, /Add access/);
});

// ---- the fixture app ---------------------------------------------------------------------------------------------------------------------
test('the fixture app: one trigger per cursor kind, all active, and the three history triggers share one poll with a lens each', t => {
  const h = triggerHarness(t);
  assert.deepEqual(Object.fromEntries(h.catalog.triggersRefused), {});
  const items = [...h.catalog.triggers.values()];
  assert.ok(items.every(item => item.status === 'active' && !item.entry.unplaced));
  assert.deepEqual([...new Set(items.flatMap(item => item.entry.trigger.poll.cursors.map(cursor => cursor.kind)))].sort(), Object.keys(CURSOR_KINDS).sort());
  const [logged, detail, keys] = ['feed-logged', 'feed-logged-detail', 'feed-logged-keys'].map(h.itemOf);
  assert.equal(new Set([logged.pollHash, detail.pollHash, keys.pollHash]).size, 1, 'one feed');
  assert.equal(new Set([logged.lenses[0], detail.lenses[0], keys.lenses[0]]).size, 3, 'three lenses');
  assert.deepEqual([detail.entry.rows, keys.entry.rows], [['fixture.items.read'], ['fixture.items.read', 'fixture.keys.read']]);
  assert.deepEqual(h.triggerFile.triggers.map(item => item.inputSchema.properties).filter(properties => Object.keys(properties).length).map(Object.keys), [['kinds']], 'only feed-updated takes an input');
});

test('the fixture app: the feed is a member of the read row, a proxied read reaches it, and the rows file stays as a golden test pins it', async t => {
  const h = triggerHarness(t, {designated: true}), job = await h.runtime.createProxyJob({connectionId: h.account, request: {method: 'GET', path: '/feed'}}, h.owner);
  assert.equal(job.status, 'succeeded');
  assert.deepEqual(h.simulator.calls.map(call => [call.route, call.status]), [['GET /feed', 200]]);
  assert.equal(fixtureGroups().get('fixture').groups[0].requests.includes('GET /feed'), false);
});

test('the fixture app: its history transform stops at a whole record and names it, as collections.gmailHistory@1 is to', t => {
  const {run} = triggerHarness(t).catalog.transforms.get('collections.feedHistory@1');
  const record = (id, count) => ({id, messagesAdded: Array.from({length: count}, (_, index) => ({message: {id: `${id}-${index}`, threadId: 'T'}}))});
  assert.deepEqual(run({list: [{id: '1'}, record('2', 1)]}), {items: [{id: '2-0', threadId: 'T', recordId: '2'}]}, 'a record with nothing added gives no item');
  const cut = run({list: [record('1', 200), record('2', 200), record('3', 200), record('4', 1)]});
  assert.deepEqual([cut.items.length, cut.items.at(-1).recordId, cut.throughRecordId], [400, '2', '2']);
  assert.equal(run({list: [record('1', 500)]}).throughRecordId, undefined, 'exactly the limit is no cut');
});

// ---- triggerDecision ---------------------------------------------------------------------------------------------------------------------
const decide = (h, key, options) => h.permissions.triggerDecision(h.connection(), h.entryOf(key), options);
/** A typed read of the feed, which c4 reads: a saved Ask or Never on it caps every step whose template it fits. */
const typedFeed = h => {
  const capability = {id: 'fixture.typed.feed', appId: 'fixture', name: 'Read the feed', driver: 'http', status: 'active', request: {method: 'GET', url: 'https://api.fixture.test/feed'}};
  h.store.put('capabilities', capability);
  return capability;
};
const both = (name, body) => { for (const designated of [false, true]) test(`${name} (${designated ? 'a designated' : 'a plain'} store)`, t => body(t, designated)); };

both('triggerDecision: the shape of part 2a, with generation and policy revision only on a designated store', (t, designated) => {
  const h = triggerHarness(t, {designated}), decision = decide(h, 'feed-logged-keys');
  assert.deepEqual(Object.keys(decision).sort(), ['access', 'bindingHash', 'executable', 'mode', 'policyHash', 'rows', ...(designated ? ['connectionGeneration', 'policyRevision'] : [])].sort());
  assert.deepEqual(decision.rows.map(row => row.row), ['group:fixture.items.read', 'group:fixture.keys.read']);
  assert.ok(decision.rows.every(row => /^[a-f0-9]{64}$/.test(row.policyHash)));
  assert.notEqual(decision.rows[0].policyHash, decision.rows[1].policyHash);
  assert.deepEqual([decide(h, 'feed-logged').mode, decide(h, 'feed-logged').executable, decide(h, 'feed-logged').access], ['allow', true, 'unknown']);
});

both('triggerDecision: the strictest mode over every poll, seed and enrich row, read fresh', (t, designated) => {
  const h = triggerHarness(t, {designated});
  assert.deepEqual([decide(h, 'feed-logged-keys').mode, decide(h, 'feed-logged-keys').executable], ['ask', false], 'an enrich row with a default of Ask cannot pass');
  h.setRow('fixture.keys.read', 'allow');
  assert.equal(decide(h, 'feed-logged-keys').mode, 'allow', 'saved at Allow, it passes');
  h.setRow('fixture.keys.read', 'deny');
  assert.equal(decide(h, 'feed-logged-keys').mode, 'deny');
  assert.equal(decide(h, 'feed-logged').mode, 'allow', 'another trigger on the feed never reads that row');
  h.setRow('fixture.items.read', 'ask');
  assert.equal(decide(h, 'feed-logged').mode, 'ask', 'a read row at Ask is not Allow');
  h.setRow('fixture.items.read', 'deny');
  assert.deepEqual([decide(h, 'feed-logged').mode, decide(h, 'feed-logged').executable], ['deny', false]);
});

test('triggerDecision: a developer\'s ceiling on a row caps it, through base()', t => {
  const h = triggerHarness(t);
  h.permissions.ceilingOf = () => 'ask';
  assert.equal(decide(h, 'feed-logged').mode, 'ask');
});

both('triggerDecision: c4, a typed operation that fits a step caps it by its mode', (t, designated) => {
  const h = triggerHarness(t, {designated}), typed = typedFeed(h), before = decide(h, 'feed-logged');
  assert.equal(before.mode, 'allow', 'with no saved setting a typed read leaves the row as it is');
  h.permissions.set({connectionId: h.account, capabilityId: typed.id, mode: 'ask'});
  assert.equal(decide(h, 'feed-logged').mode, 'ask');
  h.permissions.set({connectionId: h.account, capabilityId: typed.id, mode: 'deny'});
  const never = decide(h, 'feed-logged');
  assert.equal(never.mode, 'deny');
  assert.notDeepEqual(never.rows, before.rows, 'what capped a row is in its hash');
  h.permissions.set({connectionId: h.account, capabilityId: typed.id, mode: 'allow'});
  const back = decide(h, 'feed-logged');
  assert.equal(back.mode, 'allow');
  assert.notEqual(back.policyHash, before.policyHash, 'set and set back still moves the hash');
  if (designated) assert.notEqual(back.policyRevision, before.policyRevision);
});

test('triggerDecision: a step that does not fit a typed operation is not capped by it', t => {
  const h = triggerHarness(t), typed = {...typedFeed(h), id: 'fixture.typed.labels', request: {method: 'GET', url: 'https://api.fixture.test/labels'}};
  h.store.put('capabilities', typed);
  h.permissions.set({connectionId: h.account, capabilityId: typed.id, mode: 'deny'});
  assert.equal(decide(h, 'feed-logged').mode, 'allow');
});

test('triggerDecision: a routed row counts as well as the row it came from', t => {
  const h = triggerHarness(t), entry = h.entryOf('feed-logged');
  const routed = {...entry, placements: entry.placements.map(placement => ({...placement, routedFrom: {groupId: 'fixture.keys.read', member: 'GET /keys', rowEffect: 'read'}}))};
  const decision = h.permissions.triggerDecision(h.connection(), routed);
  assert.equal(decision.mode, 'ask', 'the source row reads Ask');
  assert.deepEqual(decision.rows.map(row => row.row), ['group:fixture.items.read', 'group:fixture.keys.read']);
  h.setRow('fixture.keys.read', 'allow');
  assert.equal(h.permissions.triggerDecision(h.connection(), routed).mode, 'allow');
  assert.notEqual(h.permissions.triggerDecision(h.connection(), routed).bindingHash, decide(h, 'feed-logged').bindingHash, 'a moved step moves the binding');
  // Access is read in the row the step came from, as the proxy reads a routed member.
  const scoped = triggerHarness(t, {rows: file => { file.groups.find(group => group.id === 'fixture.keys.read').scopeSets = [['keys.read']]; return file; }});
  scoped.store.put('connections', {...scoped.connection(), authMethod: 'oauth', scopes: []});
  const entryOf = scoped.entryOf('feed-logged'), moved = {...entryOf, placements: entryOf.placements.map(placement => ({...placement, routedFrom: {groupId: 'fixture.keys.read', member: 'GET /keys', rowEffect: 'read'}}))};
  assert.deepEqual([decide(scoped, 'feed-logged').access, scoped.permissions.triggerDecision(scoped.connection(), moved).access], ['unknown', 'missing']);
});

test('triggerDecision: the binding holds this trigger, this authorization and each read\'s place', t => {
  const h = triggerHarness(t), before = decide(h, 'feed-tagged').bindingHash, connection = h.connection();
  const places = key => h.entryOf(key).placements.map(({stepId, phase, member, groupId}) => [stepId, phase, member, groupId]);
  assert.deepEqual(places('feed-tagged'), places('feed-listed'), 'the two read one member the same way');
  assert.notEqual(decide(h, 'feed-listed').bindingHash, before, 'only the trigger differs');
  for (const [label, change] of [['createdAt', {createdAt: '2026-10-24T09:00:00.000Z'}], ['authRevision', {authRevision: 'r2'}], ['identity', {identity: {id: 'acct-2'}}]]) {
    h.store.put('connections', {...connection, ...change});
    assert.notEqual(decide(h, 'feed-tagged').bindingHash, before, label);
  }
  h.store.put('connections', connection);
  assert.equal(decide(h, 'feed-tagged').bindingHash, before);
  // A member that gains a body route needs fresh consent, as an action's does: this one sits on a row that loaded with none.
  const definition = h.permissions.groups.get('fixture'), route = {member: 'GET /feed', pointer: '/x', equals: 'y', to: 'fixture.keys.read'};
  h.permissions.groups = new Map([...h.permissions.groups, ['fixture', {...definition, groups: definition.groups.map(group => group.id === 'fixture.items.read' ? {...group, bodyRoutes: [route]} : group)}]]);
  assert.notEqual(decide(h, 'feed-tagged').bindingHash, before, 'a body route on a member it reads');
});

test('triggerDecision: a step on a member marked secrets never runs unattended, even with its row at Allow', t => {
  const h = triggerHarness(t, {rows: file => { file.groups.find(group => group.id === 'fixture.keys.read').sensitive['GET /keys'] = 'secrets'; return file; }});
  h.setRow('fixture.keys.read', 'allow');
  assert.equal(decide(h, 'feed-logged-keys').mode, 'ask');
  assert.equal(decide(h, 'feed-logged').mode, 'allow');
});

test('triggerDecision: register and teardown rows never count, so a push trigger does not refuse itself', t => {
  // A real push trigger on GitHub's rows: its register and teardown steps land in the locked row, and Fabric runs neither.
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-trigger-push-'));
  const store = new Store({dataDir: path.join(root, 'data')});
  t.after(() => { store.close(); rmSync(root, {recursive: true, force: true}); });
  const file = JSON.parse(readFileSync(new URL('./fixtures/triggers/github.json', import.meta.url), 'utf8'));
  const {triggers: [entry]} = validateTriggerFile(file, {groups: PERMISSION_GROUPS, configs: PROXY_CONFIGS, maps: new Map(), transforms: TRANSFORMS, pins: PINS, choices: new Map(), identities: new Map([['github', definitionFor('github')]])});
  assert.deepEqual(entry.placements.map(placement => placement.phase).sort(), ['poll', 'register', 'teardown']);
  store.put('connections', {id: 'github-account', appId: 'github', driver: 'http', authMethod: 'token', authRevision: 'r1', status: 'ready', identity: {id: '1'}, allowedOrigins: ['https://api.github.com'], createdAt: '2026-10-23T09:00:00.000Z'});
  const permissions = new PermissionManager({store});
  permissions.proxy = new ProxyPolicy({store, permissions});
  const decision = permissions.triggerDecision(store.get('connections', 'github-account'), entry);
  assert.deepEqual([decision.mode, decision.rows.map(row => row.row)], ['allow', ['group:github.issues.read']]);
});

test('triggerDecision: nothing to read, or no reviewed address, reads Never', t => {
  const h = triggerHarness(t), entry = h.entryOf('feed-logged');
  const none = h.permissions.triggerDecision(h.connection(), {...entry, placements: entry.placements.filter(placement => placement.phase === 'register')});
  assert.deepEqual([none.mode, none.executable, none.access, none.bindingHash, none.rows], ['deny', false, 'unknown', null, []], 'a trigger with no read of its own, as one that reuses an action is');
  h.store.put('connections', {...h.connection(), allowedOrigins: ['https://other.test']});
  assert.deepEqual([decide(h, 'feed-logged').mode, decide(h, 'feed-logged').bindingHash], ['deny', null]);
  assert.equal(h.permissions.triggerDecision({id: 'gone'}, entry).mode, 'deny');
  const placed = {...entry, placements: entry.placements.map(placement => ({...placement, groupId: null}))};
  h.store.put('connections', {...h.connection(), allowedOrigins: ['https://api.fixture.test']});
  assert.equal(h.permissions.triggerDecision(h.connection(), placed).mode, 'deny', 'a step placed on no row');
});

both('triggerDecision: it reads an account that is not ready, as the gate needs it to', (t, designated) => {
  const h = triggerHarness(t, {designated}), before = decide(h, 'feed-logged');
  h.setRow('fixture.items.read', 'deny');
  h.store.put('connections', {...h.connection(), status: 'reconnect_required'});
  const after = decide(h, 'feed-logged');
  assert.deepEqual([after.mode, after.executable, after.bindingHash], ['deny', false, before.bindingHash]);
  assert.deepEqual([decide(h, 'feed-synced').executable, h.store.get('connections', h.account).status], [false, 'reconnect_required']);
  const allowed = triggerHarness(t, {designated});
  allowed.store.put('connections', {...allowed.connection(), status: 'reconnect_required'});
  assert.deepEqual([decide(allowed, 'feed-logged').mode, decide(allowed, 'feed-logged').executable], ['allow', false], 'Allow, but nothing can be sent while it holds');
});

both('triggerDecision: the hashes read identity.id only, and no cursor', (t, designated) => {
  const h = triggerHarness(t, {designated}), before = decide(h, 'feed-logged');
  h.store.put('connections', {...h.connection(), identity: {...h.connection().identity, displayName: 'New name', email: 'new@fixture.test'}});
  assert.deepEqual(decide(h, 'feed-logged'), before, 'a rename moves nothing');
  h.store.put('triggerFeeds', {id: 'feed-1', connectionId: h.account, cursors: {history: '12'}});
  assert.deepEqual(decide(h, 'feed-logged'), before, 'a cursor is in no hash');
  h.store.put('connections', {...h.connection(), identity: {id: 'acct-2'}});
  assert.notEqual(decide(h, 'feed-logged').bindingHash, before.bindingHash, 'another identity moves the binding');
});

both('triggerDecision: a change and its undo still moves the policy hash', (t, designated) => {
  const h = triggerHarness(t, {designated}), before = decide(h, 'feed-logged');
  h.setRow('fixture.items.read', 'deny');
  h.setRow('fixture.items.read', 'allow');
  const after = decide(h, 'feed-logged');
  assert.equal(after.mode, 'allow');
  assert.notEqual(after.policyHash, before.policyHash);
  assert.notDeepEqual(after.rows, before.rows);
  if (designated) assert.notEqual(after.policyRevision, before.policyRevision);
  assert.equal(after.bindingHash, before.bindingHash);
});

test('triggerDecision: Add access moves the binding, and the rows it holds', t => {
  const h = triggerHarness(t), before = decide(h, 'feed-logged');
  h.store.put('connections', {...h.connection(), authRevision: 'r2'});
  const after = decide(h, 'feed-logged');
  assert.notEqual(after.bindingHash, before.bindingHash);
  assert.notEqual(after.policyHash, before.policyHash);
  assert.notEqual(after.rows[0].policyHash, before.rows[0].policyHash);
});

test('triggerDecision: a projection without authRevision reads the stored account', t => {
  const h = triggerHarness(t), {authRevision, ...projection} = h.connection();
  assert.equal(authRevision, 'r1');
  assert.deepEqual(h.permissions.triggerDecision(projection, h.entryOf('feed-logged')), decide(h, 'feed-logged'));
});

/** The fixture rows as a later review might leave them: GET /feed marked unavailable, with scopes on the enrich member. */
const unavailableFeed = () => fixtureGroups(file => { file.groups[0].requests.push('GET /feed'); file.groups[0].unavailable['GET /feed'] = 'not-requested'; file.groups[0].memberScopeSets = {'GET /items/{item_id}': [['detail.read']]}; return file; });
test('triggerDecision: access is the weakest of the steps, read per member, and each gate reads it again', t => {
  const scoped = 'feed.read', rows = file => { file.groups[0].memberScopeSets = {'GET /feed': [[scoped]], 'GET /items/{item_id}': [['detail.read']]}; return file; };
  const h = triggerHarness(t, {rows});
  h.store.put('connections', {...h.connection(), authMethod: 'oauth', scopes: [scoped]});
  assert.deepEqual([decide(h, 'feed-logged').access, decide(h, 'feed-logged').executable], ['granted', true]);
  assert.deepEqual([decide(h, 'feed-logged-detail').access, decide(h, 'feed-logged-detail').executable], ['missing', false], 'its enrich step needs another scope');
  h.store.put('connections', {...h.connection(), scopes: [scoped, 'detail.read']});
  assert.equal(decide(h, 'feed-logged-detail').access, 'granted');
  // Unknown stands above granted and below missing: a step with no scope data says nothing either way.
  const partial = triggerHarness(t, {rows: file => { file.groups[0].memberScopeSets = {'GET /items/{item_id}': [['detail.read']]}; return file; }});
  partial.store.put('connections', {...partial.connection(), authMethod: 'oauth', scopes: []});
  assert.deepEqual([decide(partial, 'feed-logged').access, decide(partial, 'feed-logged-detail').access], ['unknown', 'missing']);
  partial.store.put('connections', {...partial.connection(), scopes: ['detail.read']});
  assert.equal(decide(partial, 'feed-logged-detail').access, 'unknown');
  // A member its row marks unavailable after the file loaded: unavailable outranks every other state, a missing scope included.
  h.store.put('connections', {...h.connection(), scopes: []});
  h.permissions.groups = unavailableFeed();
  assert.equal(decide(h, 'feed-logged-detail').access, 'unavailable');
});

test('triggerDecision: the memo holds the template list alone, for one account; rows, base() and typed modes are read on every call', t => {
  const h = triggerHarness(t), typed = typedFeed(h), memo = new Map();
  decide(h, 'feed-logged', {memo});
  assert.deepEqual([...memo.keys()], [`${h.account}:typedTemplates`]);
  let lists = 0;
  const {typedTemplates} = h.proxyPolicy;
  h.proxyPolicy.typedTemplates = context => { lists++; return typedTemplates.call(h.proxyPolicy, context); };
  decide(h, 'feed-logged', {memo});
  decide(h, 'feed-logged-detail', {memo});
  assert.equal(lists, 0, 'the list is read once a tick');
  h.setRow('fixture.items.read', 'deny');
  assert.equal(decide(h, 'feed-logged', {memo}).mode, 'deny', 'a row saved after the memo was made is read');
  h.setRow('fixture.items.read', 'allow');
  h.permissions.set({connectionId: h.account, capabilityId: typed.id, mode: 'deny'});
  assert.equal(decide(h, 'feed-logged', {memo}).mode, 'deny', 'so is a typed mode');
  decide(h, 'feed-logged');
  assert.equal(lists, 1, 'a call with no memo reads its own');
});

// ---- the gate --------------------------------------------------------------------------------------------------------------------------
const gateOf = (h, subscription, options) => gate(h.runtime, h.store.get('subscriptions', subscription.id) ?? subscription, options);
const pause = (reason, detail) => ({ok: false, reason, ...(detail ? {detail} : {})});

both('the gate: an approved watch passes, and nothing is written or sent', (t, designated) => {
  const h = triggerHarness(t, {designated}), watch = h.watch('feed-logged');
  const writes = [], {put, audit} = h.store;
  h.store.put = (...args) => { writes.push(args); return put.apply(h.store, args); };
  h.store.audit = (...args) => { writes.push(args); return audit.apply(h.store, args); };
  assert.deepEqual(gateOf(h, watch), {ok: true});
  assert.deepEqual([writes.length, h.simulator.calls.length], [0, 0]);
  h.store.put = put;
  h.store.audit = audit;
});

both('gate step 1: Background at Never pauses before anything else is read', (t, designated) => {
  const h = triggerHarness(t, {designated}), watch = h.watch('feed-logged');
  h.store.put('backgroundPolicies', {id: h.account, connectionId: h.account, mode: 'deny', updatedAt: 'x'});
  assert.deepEqual(gateOf(h, watch), pause('background_off'));
  h.store.put('backgroundPolicies', {id: h.account, connectionId: h.account, mode: 'allow', updatedAt: 'x'});
  assert.deepEqual(gateOf(h, watch), {ok: true});
});

both('gate step 2: a ready account of the trigger\'s app passes; a failed renewal skips; anything else is account_changed', (t, designated) => {
  const h = triggerHarness(t, {designated}), watch = h.watch('feed-logged'), ready = h.connection();
  for (const status of ['unavailable', 'reconnect_required']) {
    h.store.put('connections', {...ready, status});
    assert.deepEqual(gateOf(h, watch), {ok: false, skip: true, detail: status}, status);
  }
  for (const status of ['pending_confirmation', 'expired', 'revoked', 'session_ready', 'anything']) {
    h.store.put('connections', {...ready, status});
    assert.deepEqual(gateOf(h, watch), pause('account_changed'), status);
  }
  h.store.put('connections', ready);
  assert.deepEqual(gate(h.runtime, {...watch, connectionId: h.rpcAccount}), pause('account_changed'), 'an account of another app');
  assert.deepEqual(gate(h.runtime, {...watch, connectionId: 'gone'}), pause('account_changed'), 'an account that is gone');
  h.store.put('connections', {...ready, driver: 'browser'});
  assert.deepEqual(gateOf(h, watch), pause('account_changed'), 'a watch reads an API account only');
});

both('gate: a skip does not end the gate, and a failure after it wins', (t, designated) => {
  const h = triggerHarness(t, {designated}), watch = h.watch('feed-logged'), ready = h.connection();
  h.store.put('connections', {...ready, status: 'reconnect_required'});
  assert.equal(gateOf(h, watch).skip, true);
  assert.equal(h.simulator.calls.length, 0);
  h.grant('client-1', {status: 'revoked'});
  assert.deepEqual(gateOf(h, watch), pause('client_ended'), 'step 8');
  h.grant('client-1');
  h.store.put('connections', ready);
  h.setRow('fixture.items.read', 'deny');
  h.store.put('connections', {...h.connection(), status: 'reconnect_required'});
  assert.deepEqual(gateOf(h, watch), pause('permission_changed'), 'a row at Never pauses while the account needs reconnecting');
});

test('gate step 3: the tenant check, ownedBy()', t => {
  const h = triggerHarness(t), watch = h.watch('feed-logged');
  const scope = {schemaVersion: 1, kind: 'tenant', tenantId: 'ten_a', environmentId: 'env_a'}, runtime = Object.assign(Object.create(h.runtime), {deployment: tenantDeployment(scope)});
  const owner = endUser({subjectId: 'user-1', userRecordId: `usr_${'a'.repeat(26)}`}), other = endUser({subjectId: 'user-2', userRecordId: `usr_${'b'.repeat(26)}`});
  assert.deepEqual(gate(h.runtime, watch), {ok: true}, 'the owner\'s Fabric has one owner');
  assert.deepEqual(gate(runtime, watch), pause('account_changed'), 'a tenant record with no owner is never usable');
  h.store.put('connections', stampOwner(h.connection(), owner));
  assert.deepEqual(gate(runtime, stampOwner(watch, other)), pause('account_changed'), 'another end user');
  assert.deepEqual(gate(runtime, stampOwner(watch, owner)), {ok: true});
});

both('gate step 4: an entry that is gone, unplaced, moved or a candidate is definition_changed', (t, designated) => {
  const h = triggerHarness(t, {designated}), watch = h.watch('feed-logged');
  assert.deepEqual(gate(h.runtime, {...watch, triggerId: 'fixture.trigger.gone.v1.000000000000000000000000'}), pause('definition_changed'), 'an id the catalog no longer holds');
  assert.deepEqual(gate(h.runtime, {...watch, appId: 'fixture-rpc', connectionId: h.rpcAccount}), pause('definition_changed'), 'a trigger of another app than the record says');
  const unplaced = triggerHarness(t, {designated, map: null});
  assert.equal(unplaced.itemOf('feed-logged').entry.unplaced, true);
  assert.deepEqual(gateOf(unplaced, {...watch}), pause('definition_changed'), 'unplaced, with no map');
  unplaced.permissions.certification = true;
  assert.deepEqual(gateOf(unplaced, {...watch}), pause('definition_changed'), 'a certification Fabric never runs a step it cannot place');
  const moved = triggerHarness(t, {designated, codeHashes: ids => Object.fromEntries(ids.map(id => [id, id === 'time.decimalCompare@1' ? 'f'.repeat(64) : h.deps.pins[id]]))});
  assert.deepEqual([moved.itemOf('feed-logged').status, moved.catalog.pinned(moved.itemOf('feed-logged'))], ['candidate', false]);
  const pinned = moved.watch('feed-logged', {status: 'awaiting_approval'});
  assert.deepEqual(gateOf(moved, pinned), pause('definition_changed'), 'a changed pin');
  moved.permissions.certification = true;
  assert.deepEqual(gateOf(moved, pinned), pause('definition_changed'), 'a certification Fabric never runs code that moved');
});

both('gate step 4: a candidate passes only in a certification Fabric', (t, designated) => {
  const h = triggerHarness(t, {designated, reviewed: false}), watch = h.watch('feed-logged');
  assert.equal(h.itemOf('feed-logged').status, 'candidate');
  assert.deepEqual(gateOf(h, watch), pause('definition_changed'));
  h.permissions.certification = true;
  assert.deepEqual(gateOf(h, watch), {ok: true});
});

test('gate step 5: Slack\'s history and replies triggers hold to a distributed install, read at every gate', t => {
  // Two real drafts on Slack's real rows: the operator can change the setting under a running watch, so a check at subscribe alone would miss it.
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-trigger-slack-')), store = new Store({dataDir: path.join(root, 'data')});
  t.after(() => { store.close(); rmSync(root, {recursive: true, force: true}); });
  const deps = {groups: PERMISSION_GROUPS, configs: PROXY_CONFIGS, maps: new Map(), transforms: TRANSFORMS, pins: PINS, choices: new Map(), identities: new Map([['slack', definitionFor('slack')]])};
  const draft = JSON.parse(readFileSync(new URL('./fixtures/docs/trigger-drafts/slack.json', import.meta.url), 'utf8')), file = {...draft, triggers: draft.triggers.filter(item => ['new-message', 'mention-search'].includes(item.key))};
  const ids = triggerIds(file, deps), {triggers: entries} = validateTriggerFile({...file, triggers: file.triggers.map(item => ({...item, id: ids.get(`${item.key} v1`)}))}, deps);
  const items = new Map(entries.map(entry => [entry.id, {appId: 'slack', entry, status: 'active'}]));
  store.put('connections', {id: 'slack-account', appId: 'slack', driver: 'http', authMethod: 'token', authRevision: 'r1', status: 'ready', identity: {id: 'T1:U1'}, allowedOrigins: ['https://slack.com'], createdAt: '2026-10-23T09:00:00.000Z'});
  store.put('clientGrants', {id: 'client-1', status: 'active', expiresAt: '2099-01-01T00:00:00.000Z'});
  const permissions = new PermissionManager({store});
  permissions.proxy = new ProxyPolicy({store, permissions});
  const runtime = slackDistribution => ({store, permissions, deployment: LOCAL_DEPLOYMENT, slackDistribution, clock: () => Date.parse('2026-10-23T09:00:00.000Z'), actions: {triggerOf: id => items.get(id), pinned: () => true}});
  const watch = key => {
    const {entry} = [...items.values()].find(item => item.entry.key === key), subscription = {clientId: 'client-1', appId: 'slack', connectionId: 'slack-account', triggerId: entry.id, status: 'active', args: {channels: ['C0123456789']}};
    return {...subscription, authority: authorityOf(subscription, store.get('connections', 'slack-account'), permissions.triggerDecision(store.get('connections', 'slack-account'), entry))};
  };
  assert.deepEqual(gate(runtime('internal'), watch('new-message')), {ok: true});
  assert.deepEqual(gate(runtime('marketplace'), watch('new-message')), {ok: true});
  assert.deepEqual(gate(runtime('distributed'), watch('new-message')), pause('provider_refused', 'distributed'));
  assert.deepEqual(gate(runtime('distributed'), watch('mention-search')), {ok: true}, 'search is not paced');
});

test('gate step 5: the rule reads Slack\'s triggers only', t => {
  const h = triggerHarness(t), watch = h.watch('feed-logged');
  assert.deepEqual(gate(Object.assign(Object.create(h.runtime), {slackDistribution: 'distributed'}), watch), {ok: true});
});

both('gate step 6: a row not at Allow is permission_changed, and it reads fresh with one memo', (t, designated) => {
  const h = triggerHarness(t, {designated}), memo = new Map();
  h.setRow('fixture.keys.read', 'allow');
  const watch = h.watch('feed-logged-keys');
  assert.deepEqual(gateOf(h, watch, {memo}), {ok: true});
  assert.deepEqual([...memo.keys()], [`${h.account}:typedTemplates`], 'the tick\'s memo reaches the decision');
  h.setRow('fixture.keys.read', 'ask');
  assert.deepEqual(gateOf(h, watch, {memo}), pause('permission_changed'), 'Ask is not Allow, with the tick\'s memo in hand');
  h.setRow('fixture.keys.read', 'deny');
  assert.deepEqual(gateOf(h, watch, {memo}), pause('permission_changed'));
});

test('gate step 6: a default of Ask refuses before approval too', t => {
  const h = triggerHarness(t), waiting = h.watch('feed-logged-keys', {status: 'awaiting_approval'});
  assert.deepEqual(gateOf(h, waiting), pause('permission_changed'));
});

test('gate step 6: a lens is held by its own rows, so two lenses on one feed part', t => {
  const h = triggerHarness(t);
  h.setRow('fixture.keys.read', 'allow');
  const plain = h.watch('feed-logged'), keys = h.watch('feed-logged-keys');
  h.setRow('fixture.keys.read', 'deny');
  assert.deepEqual([gateOf(h, plain), gateOf(h, keys)], [{ok: true}, pause('permission_changed')]);
});

test('gate step 6: access missing or unavailable is access_missing, and unknown passes, or all of Notion is blocked', t => {
  const rows = file => { file.groups[0].memberScopeSets = {'GET /feed': [['feed.read']]}; return file; };
  const h = triggerHarness(t, {rows}), watch = h.watch('feed-logged');
  assert.equal(decide(h, 'feed-logged').access, 'unknown', 'a token account');
  assert.deepEqual(gateOf(h, watch), {ok: true});
  h.store.put('connections', {...h.connection(), authMethod: 'oauth', scopes: []});
  assert.deepEqual(gateOf(h, watch), pause('access_missing'));
  h.permissions.groups = unavailableFeed();
  assert.deepEqual(gateOf(h, watch), pause('access_missing'), 'unavailable');
});

both('gate step 7: authority must equal current, and each field has its reason', (t, designated) => {
  const h = triggerHarness(t, {designated}), watch = h.watch('feed-logged'), {authority} = watch;
  for (const [field, reason] of [['identityId', 'account_changed'], ['bindingHash', 'account_changed'], ['policyHash', 'permission_changed'], ['argsHash', 'permission_changed'], ['triggerId', 'permission_changed'],
    ...(designated ? [['connectionGeneration', 'account_changed'], ['policyRevision', 'permission_changed']] : [])]) {
    assert.deepEqual(gate(h.runtime, {...watch, authority: {...authority, [field]: 'changed'}}), pause(reason), field);
  }
  assert.deepEqual(gate(h.runtime, {...watch, args: {changed: true}}), pause('permission_changed'), 'arguments that are not the ones approved');
  const {authority: gone, ...bare} = watch;
  assert.deepEqual(gate(h.runtime, bare), pause('account_changed'), 'an approved record with no authority');
});

both('gate step 7: a row set and set back pauses, since a change never undoes itself', (t, designated) => {
  const h = triggerHarness(t, {designated}), watch = h.watch('feed-logged');
  h.setRow('fixture.items.read', 'deny');
  h.setRow('fixture.items.read', 'allow');
  assert.deepEqual(gateOf(h, watch), pause('permission_changed'));
});

both('gate step 7 is skipped before approval and at Resume, and nowhere else', (t, designated) => {
  const h = triggerHarness(t, {designated}), waiting = h.watch('feed-logged', {status: 'awaiting_approval'}), active = h.watch('feed-logged');
  assert.equal(waiting.authority, undefined);
  assert.deepEqual(gateOf(h, waiting), {ok: true}, 'before approval there is no authority to compare');
  h.setRow('fixture.items.read', 'deny');
  h.setRow('fixture.items.read', 'allow');
  assert.deepEqual(gateOf(h, active), pause('permission_changed'));
  assert.deepEqual(gateOf(h, {...active, status: 'paused'}), pause('permission_changed'), 'a paused watch outside Resume');
  assert.deepEqual(gateOf(h, active, {resume: true}), {ok: true}, 'Resume is a new approval');
  h.setRow('fixture.items.read', 'deny');
  assert.deepEqual(gateOf(h, active, {resume: true}), pause('permission_changed'), 'Resume still reads the row');
});

both('gate step 8: a client that is gone, revoked or past its time is client_ended', (t, designated) => {
  const h = triggerHarness(t, {designated}), watch = h.watch('feed-logged');
  assert.deepEqual(gate(h.runtime, {...watch, clientId: 'nobody'}), pause('client_ended'));
  h.grant('client-1', {status: 'revoked'});
  assert.deepEqual(gateOf(h, watch), pause('client_ended'));
  h.grant('client-1', {expiresAt: new Date(h.now).toISOString()});
  assert.deepEqual(gateOf(h, watch), pause('client_ended'), 'expiry reads the runtime\'s clock, at the instant itself');
  h.grant('client-1', {expiresAt: 'not a time'});
  assert.deepEqual(gateOf(h, watch), pause('client_ended'));
  h.grant('client-1', {expiresAt: new Date(h.now + 1000).toISOString()});
  assert.deepEqual(gateOf(h, watch), {ok: true});
  h.advance(1000);
  assert.deepEqual(gateOf(h, watch), pause('client_ended'));
});

both('gate: a renewal keeps a watch active: new tokens, health fields and a new sign-in, with the same authorization', (t, designated) => {
  const h = triggerHarness(t, {designated}), watch = h.watch('feed-logged');
  h.store.put('connections', {...h.connection(), expiresAt: 'later', refreshAvailable: true, lastCheckedAt: 'now', updatedAt: 'now', signInRevision: 'new', signedInAt: 'now', error: null});
  assert.deepEqual(gateOf(h, watch), {ok: true});
});

both('gate: a failed renewal then a reconnect on the same identity keeps the watch; another identity pauses it', (t, designated) => {
  const h = triggerHarness(t, {designated}), watch = h.watch('feed-logged'), ready = h.connection();
  h.store.put('connections', {...ready, status: 'reconnect_required', error: 'expired'});
  assert.equal(gateOf(h, watch).skip, true);
  h.store.put('connections', {...ready, status: 'ready', signInRevision: 'again', signedInAt: 'now'});
  assert.deepEqual(gateOf(h, watch), {ok: true});
  h.store.put('connections', {...h.connection(), identity: {id: 'acct-2'}});
  assert.deepEqual(gateOf(h, watch), pause('account_changed'));
});

both('gate: Add access pauses a watch: a new authRevision is a new authorization', (t, designated) => {
  const h = triggerHarness(t, {designated}), watch = h.watch('feed-logged');
  h.store.put('connections', {...h.connection(), authRevision: 'r2', scopes: ['more']});
  assert.deepEqual(gateOf(h, watch), pause('account_changed'));
});

both('gate: a rename pauses nothing with no saved record on the path, and with one it pauses permission_changed', (t, designated) => {
  const h = triggerHarness(t, {designated}), plain = h.watch('feed-logged');
  const rename = () => h.store.put('connections', {...h.connection(), identity: {...h.connection().identity, displayName: 'New name', email: 'new@fixture.test'}});
  rename();
  assert.deepEqual(gateOf(h, plain), {ok: true});
  h.setRow('fixture.keys.read', 'allow');
  const keys = h.watch('feed-logged-keys');
  h.store.put('connections', {...h.connection(), identity: {...h.connection().identity, displayName: 'Newer name'}});
  assert.deepEqual([gateOf(h, plain), gateOf(h, keys)], [{ok: true}, pause('permission_changed')], 'the saved row turned stale and reads Ask, exactly as for actions');
});

test('the gate needs no action module, and neither lib/trigger-gate.mjs nor lib/trigger-rules.mjs imports one', () => {
  const imports = readFileSync(new URL('../lib/trigger-gate.mjs', import.meta.url), 'utf8').match(/from '[^']+'/g) ?? [];
  assert.deepEqual(imports.map(text => text.slice(6, -1)).sort(), ['./app-detail.mjs', './compiler.mjs', './tenant/deployment.mjs', './trigger-rules.mjs']);
});

test('argsHashOf and authorityOf: arguments in any key order hash alike, and generation and revision appear only when the decision holds them', () => {
  assert.equal(argsHashOf({a: 1, b: 2}), argsHashOf({b: 2, a: 1}));
  assert.notEqual(argsHashOf({a: 1}), argsHashOf({a: 2}));
  const subscription = {triggerId: 't', args: {a: 1}}, connection = {identity: {id: 'i', displayName: 'n'}}, decision = {bindingHash: 'b', policyHash: 'p'};
  assert.deepEqual(authorityOf(subscription, connection, decision), {triggerId: 't', bindingHash: 'b', policyHash: 'p', identityId: 'i', argsHash: argsHashOf({a: 1})});
  assert.deepEqual(authorityOf(subscription, connection, {...decision, connectionGeneration: 3, policyRevision: 'r'}), {triggerId: 't', bindingHash: 'b', policyHash: 'p', identityId: 'i', argsHash: argsHashOf({a: 1}), connectionGeneration: 3, policyRevision: 'r'});
});

// ---- what the scheduler reads ------------------------------------------------------------------------------------------------------------
test('a gap has one shape on both sides of the action wall, and its key follows the start of its range', () => {
  const gap = gapPayload('resume', '2026-10-23T09:00:00.000Z', '2026-10-23T10:00:00.000Z');
  assert.deepEqual(gap, {type: 'trigger.gap', id: 'gap|resume|2026-10-23T09:00:00.000Z', occurredAt: '2026-10-23T10:00:00.000Z', fields: {from: '2026-10-23T09:00:00.000Z', to: '2026-10-23T10:00:00.000Z', reason: 'resume'},
    summary: [{label: 'Gap', value: 'This watch was paused. Changes in this time were not read.'}]});
  for (const reason of ['resync', 'resume', 'bound', 'stall', 'overflow', 'window']) assert.ok(gapPayload(reason, 'a', 'b').summary[0].value.length > 20 && !/\u2014/.test(gapPayload(reason, 'a', 'b').summary[0].value), reason);
});

test('how long a trigger keeps an event reads in days or in hours', () => {
  assert.equal(retentionMs({days: 7}), 7 * 86_400_000);
  assert.equal(retentionMs({hours: 24}), 86_400_000);
});

test('the catalog names a subscription\'s lens and any input a poll step reads beyond its resource, and the drafts read none', t => {
  const change = (key, edit) => feedTriggers().map(item => { const copy = structuredClone(item); if (item.key === key) edit(copy); return copy; });
  const h = triggerHarness(t);
  assert.equal(h.catalog.triggerLens(h.entryOf('feed-logged'), {}), h.itemOf('feed-logged').lenses[0]);
  for (const key of ['feed-logged', 'feed-updated', 'feed-posted']) assert.deepEqual(h.catalog.triggerPollInputs(h.entryOf(key)), [], key);
  const outside = triggerHarness(t, {triggers: change('feed-listed', item => {
    item.inputSchema = {type: 'object', properties: {kind: {type: 'string', minLength: 1, maxLength: 20}}, required: ['kind'], additionalProperties: false};
    item.poll.source.steps[0].query.kind = {input: '/kind'};
  })});
  assert.deepEqual(outside.catalog.triggerPollInputs(outside.entryOf('feed-listed')), ['kind'], 'an input outside the resource reaches the request');
  const behind = triggerHarness(t, {triggers: change('feed-updated', item => { item.poll.source.steps[0].query.first = {input: '/kinds/0'}; })});
  assert.deepEqual(behind.catalog.triggerPollInputs(behind.entryOf('feed-updated')), ['kinds'], 'the list behind each is such an input too');
  const named = triggerHarness(t, {triggers: change('feed-listed', item => {
    item.inputSchema = {type: 'object', properties: {kind: {type: 'string', minLength: 1, maxLength: 20}}, required: ['kind'], additionalProperties: false};
    item.resource = ['kind'];
    item.poll.source.steps[0].query.kind = {input: '/kind'};
  })});
  assert.deepEqual(named.catalog.triggerPollInputs(named.entryOf('feed-listed')), [], 'a resource input is the feed\'s own');
});

test('every draft reads its poll from its resource alone', () => {
  for (const appId of ['gmail', 'google-calendar', 'github', 'notion', 'slack']) for (const trigger of drafts(appId)) {
    const {resource} = trigger, inside = Array.isArray(resource) ? resource : [];
    const read = JSON.stringify([trigger.poll.source, trigger.poll.seed ?? null, trigger.poll.cursors, trigger.poll.resync]).match(/"input":"\/([^"/]+)/g) ?? [];
    assert.deepEqual(read.map(text => text.slice(10)).filter(name => !inside.includes(name)), [], `${appId}.${trigger.key}`);
  }
});

test('a poll that reads below a resource input reads the feed\'s own value, so no draft is refused at attach()', () => {
  for (const appId of ['gmail', 'google-calendar', 'github', 'notion', 'slack']) for (const trigger of drafts(appId)) assert.deepEqual(triggerPollInputs({trigger}), [], `${appId}.${trigger.key}`);
  const {poll, resource} = drafts('gmail').find(trigger => trigger.key === 'new-email-matching-search');
  assert.deepEqual([resource, JSON.stringify(poll.source).includes('"input":"/search/subject"')], [['search'], true], 'the one draft that does: its search is an object');
});

test('runnable(): placed, pinned, and active, or a candidate only in a certification Fabric, as gate step 4 reads it', t => {
  const h = triggerHarness(t), watch = h.watch('feed-logged');
  assert.equal(runnable(h.runtime, h.itemOf('feed-logged')), true);
  const candidate = triggerHarness(t, {reviewed: false});
  assert.equal(runnable(candidate.runtime, candidate.itemOf('feed-logged')), false);
  candidate.permissions.certification = true;
  assert.equal(runnable(candidate.runtime, candidate.itemOf('feed-logged')), true);
  const unplaced = triggerHarness(t, {map: null});
  unplaced.permissions.certification = true;
  assert.equal(runnable(unplaced.runtime, unplaced.itemOf('feed-logged')), false);
  const moved = triggerHarness(t, {codeHashes: ids => Object.fromEntries(ids.map(id => [id, id === 'time.decimalCompare@1' ? 'f'.repeat(64) : h.deps.pins[id]]))});
  moved.permissions.certification = true;
  assert.equal(runnable(moved.runtime, moved.itemOf('feed-logged')), false);
  assert.deepEqual(gate(h.runtime, watch), {ok: true});
});

// ---- the scheduler -----------------------------------------------------------------------------------------------------------------------
// Part 2c: attach() and tick() on the fixture app, so these tests run the whole path a watch runs. test/trigger-runtime.test.mjs holds what one poll does;
// these hold what the scheduler does around it, in the order section 2.4 names.
const SECOND = 1000, MINUTE = 60_000, HOUR = 3_600_000, DAY = 86_400_000, INTERVAL = 120_000;
const KINDS = [['feed-synced', {}], ['feed-logged', {}], ['feed-updated', {kinds: ['note']}], ['feed-posted', {}], ['feed-tagged', {}], ['feed-modified', {}], ['feed-listed', {}]];
/** The fixture triggers with one changed, by key. */
const edited = (key, change) => feedTriggers().map(item => { const copy = structuredClone(item); if (item.key === key) change(copy); return copy; });
/** One trigger's copy under a new key, on the same poll. */
const twin = (key, name, change = () => {}) => { const copy = structuredClone(feedTriggers().find(item => item.key === key)); Object.assign(copy, {key: name, id: `fixture.trigger.${name}.v1.${'0'.repeat(24)}`}); change(copy); return copy; };
const pagesOf = (item, pages) => { item.bounds.pages = pages; item.poll.source.steps[0].page.max = pages; };
const DETAIL = () => ({id: 'detail', method: 'GET', path: '/items/{item_id}', params: {item_id: {item: '/id'}}, maxResponseBytes: 65_536, expect: {status: [200], require: []}});

/** The harness with a scheduler on it. start() stores a watch as an approval leaves it and attaches it. `random` is 0 unless a test says otherwise, so an interval is exact. */
function rig(t, options = {}, engineOptions = {}) {
  const h = triggerHarness(t, options), engine = new TriggerEngine({store: h.store, runtime: h.runtime, clock: () => h.now, random: () => 0, ...engineOptions});
  return Object.assign(h, {engine,
    start: (key, {args = {}, ...fields} = {}) => engine.attach(h.watch(key, {args, status: 'starting', ...fields})),
    current: watch => h.store.get('subscriptions', watch.id),
    feedOf: (watch, index = 0) => h.store.get('triggerFeeds', h.current(watch).feeds[index]),
    runsOf: feed => h.store.get('triggerRuns', feed.id)?.runs ?? [],
    /** Ticks a second apart until the watch is active. */
    async settle(watch, most = 400) {
      for (let count = 0; count < most; count++) { await engine.tick(); if (h.current(watch).status === 'active') return count + 1; h.advance(SECOND); }
      throw new Error(`The watch never turned active: ${JSON.stringify(h.current(watch))}`);
    },
    /** One interval on, and one tick. */
    async pass(ms = INTERVAL) { h.advance(ms); await engine.tick(); },
    events: (client = 'client-1') => h.store.listEvents(client, 0, 5000),
    eventsOf: (watch, kind = 'trigger.event') => h.store.listEvents(watch.clientId, 0, 5000).filter(row => row.subscriptionId === watch.id && row.kind === kind),
    gapsOf: watch => h.store.listEvents(watch.clientId, 0, 5000).filter(row => row.subscriptionId === watch.id && row.kind === 'trigger.gap'),
    feedReads: () => h.simulator.calls.filter(call => call.route === 'GET /feed'),
    audits: type => h.store.list('activity').filter(row => row.type === type)});
}
/** The hashed keys of a lens's seen rows. */
const seenKeys = (h, feedId, lens) => { try { return h.store.db.prepare('SELECT item_key FROM trigger_seen WHERE feed_id=? AND lens=?').all(feedId, lens).map(row => row.item_key); } catch { return []; } };
/** A watch that is active on a baselined feed. */
async function running(h, key = 'feed-synced', options) {
  const watch = h.start(key, options);
  await h.settle(watch);
  h.advance(INTERVAL);
  return watch;
}

// attach(): a watch's feeds.
both('attach: a new feed has the shape of section 2.1, keyed on account, poll, resource and epoch, and is due now', (t, designated) => {
  const h = rig(t, {designated}), watch = h.watch('feed-synced', {status: 'starting'}), attached = h.engine.attach(watch), {pollHash} = h.itemOf('feed-synced');
  const id = canonicalHash({kind: 'fabric-trigger-feed', connectionId: h.account, pollHash, resource: [], epoch: 0}).slice(0, 32);
  assert.deepEqual([attached.feeds, attached.pending, attached.status], [[id], [id], 'starting']);
  assert.deepEqual(h.store.get('triggerFeeds', id), {id, appId: 'fixture', connectionId: h.account, pollHash, resource: [], epoch: 0, lenses: h.itemOf('feed-synced').lenses, cursors: {}, page: null, baselined: false, floor: null, draining: false, budgetStops: 0,
    recordFailures: 0, lastGoodAt: null, nextPollAt: h.now, notBefore: null, failures: 0, wait: null, createdAt: new Date(h.now).toISOString()});
  assert.equal(h.simulator.calls.length, 0, 'attaching reads nothing');
});

test('attach: a resource makes one feed per element of each and one per list of values, each feed holding its values by index', t => {
  const h = rig(t, {triggers: [...edited('feed-listed', item => {
    item.inputSchema = {type: 'object', properties: {folder: {type: 'string', minLength: 1, maxLength: 20}, depth: {type: 'integer', minimum: 1, maximum: 9}}, required: ['folder', 'depth'], additionalProperties: false};
    item.resource = ['depth', 'folder'];
    item.poll.source.steps[0].query.folder = {input: '/folder'};
    item.poll.source.steps[0].query.depth = {input: '/depth'};
  })]});
  const each = h.start('feed-updated', {args: {kinds: ['note', 'task']}}), list = h.start('feed-listed', {args: {folder: 'a', depth: 2}}), none = h.start('feed-synced');
  assert.deepEqual(h.current(each).feeds.map(id => h.store.get('triggerFeeds', id).resource), [['note'], ['task']]);
  assert.deepEqual(h.feedOf(list).resource, [2, 'a']);
  assert.deepEqual(h.feedOf(none).resource, []);
  assert.deepEqual(h.current(each).pending, h.current(each).feeds);
});

test('attach: triggers with one poll and one resource value share one feed, and another value has its own', t => {
  const h = rig(t), notes = h.start('feed-updated', {args: {kinds: ['note']}}), both = h.start('feed-updated', {args: {kinds: ['note', 'task']}});
  assert.equal(h.store.list('triggerFeeds').length, 2);
  assert.equal(h.current(both).feeds[0], h.current(notes).feeds[0]);
  const a = h.start('feed-logged'), b = h.start('feed-logged-detail');
  assert.equal(h.current(a).feeds[0], h.current(b).feeds[0], 'the history triggers share a feed');
  assert.deepEqual(h.feedOf(a).lenses.slice().sort(), [...h.itemOf('feed-logged').lenses, ...h.itemOf('feed-logged-detail').lenses, ...h.itemOf('feed-logged-keys').lenses].sort(), 'the catalog\'s lenses, and the watch\'s own');
});

test('attach: a trigger with an enrich step stays out of a list feed\'s lenses until it has a watch, since it writes no rows unwatched', t => {
  const enriched = twin('feed-listed', 'feed-listed-detail', item => { item.poll.enrich = {max: 25, steps: [DETAIL()]}; item.event = {...item.event, fields: {id: {item: '/id'}, name: {step: 'detail', pointer: '/name'}}}; });
  const h = rig(t, {triggers: [...feedTriggers(), enriched]}), plain = h.start('feed-listed');
  assert.deepEqual(h.feedOf(plain).lenses, h.itemOf('feed-listed').lenses);
  const candidate = rig(t, {reviewed: false});
  candidate.permissions.certification = true;
  assert.deepEqual(candidate.feedOf(candidate.start('feed-listed')).lenses, candidate.itemOf('feed-listed').lenses, 'a certification Fabric runs a candidate');
});

test('attach: a poll step that reads an input outside its resource, or the list behind each, is refused: it stops at definition_changed with no feed, and asks for nothing', t => {
  const schema = {type: 'object', properties: {kind: {type: 'string', minLength: 1, maxLength: 20}}, required: ['kind'], additionalProperties: false};
  for (const [key, args, triggers] of [
    ['feed-listed', {kind: 'note'}, edited('feed-listed', item => { item.inputSchema = schema; item.poll.source.steps[0].query.kind = {input: '/kind'}; })],
    ['feed-updated', {kinds: ['note']}, edited('feed-updated', item => { item.poll.source.steps[0].query.first = {input: '/kinds/0'}; })]]) {
    const h = rig(t, {triggers}), watch = h.start(key, {args});
    assert.deepEqual([watch.status, watch.reason, watch.detail, watch.feeds], ['paused', 'definition_changed', 'poll_input', []]);
    assert.equal(h.store.list('triggerFeeds').length, 0);
    assert.deepEqual(h.audits('trigger.paused').map(row => row.reason), ['definition_changed']);
  }
});

test('attach: a trigger that left the catalog stops at definition_changed, and a watch that is gone stays gone', t => {
  const h = rig(t), {catalog} = h, watch = h.watch('feed-synced', {status: 'starting'});
  h.runtime.actions = {...catalog, triggerOf: () => null};
  const stopped = h.engine.attach(watch);
  assert.deepEqual([stopped.status, stopped.reason, stopped.detail], ['paused', 'definition_changed', undefined]);
  assert.equal(h.engine.attach({id: 'gone'}), null);
  assert.equal(h.store.get('subscriptions', 'gone'), null);
});

test('attach: attaching twice changes nothing', t => {
  const h = rig(t), watch = h.start('feed-synced'), feed = h.feedOf(watch);
  assert.deepEqual(h.engine.attach(h.current(watch)).feeds, [feed.id]);
  assert.equal(h.store.list('triggerFeeds').length, 1);
});

// tick(): the whole path.
for (const [key, args] of KINDS) {
  test(`spec 1860 and 1861, ${key}: a baseline emits nothing, even for an item edited just before the subscribe, then one write gives one event and a re-poll none`, async t => {
    const h = rig(t), [first] = h.simulator.seed(3, {at: h.now - 10_000});
    h.advance(5_000);
    h.simulator.touch(first.id, {name: 'Edited just before the subscribe'});
    const watch = h.start(key, {args});
    await h.settle(watch);
    assert.equal(h.current(watch).status, 'active');
    assert.deepEqual(h.current(watch).pending, []);
    assert.equal(h.events().length, 0);
    await h.pass();
    assert.equal(h.events().length, 0, 'the overlap reads the edited item again and finds it current');
    h.advance(MINUTE);
    h.simulator.write({name: 'New'});
    h.advance(SECOND);
    await h.pass();
    assert.equal(h.events().length, 1, 'one write, one event');
    await h.pass();
    assert.equal(h.events().length, 1, 'a re-poll fires nothing');
  });
  test(`${key}: an empty resource's first item is one event`, async t => {
    const h = rig(t), watch = h.start(key, {args});
    await h.settle(watch);
    h.advance(MINUTE);
    h.simulator.write({name: 'First'});
    h.advance(SECOND);
    await h.pass();
    assert.deepEqual(h.eventsOf(watch).map(row => row.kind), ['trigger.event']);
  });
}

both('a tick stores what a poll found: events and seen rows, then the feed, then one run, and it writes no audit row', (t, designated) => (async () => {
  const h = rig(t, {designated}), watch = await running(h);
  const audits = h.store.list('activity').length, before = h.runsOf(h.feedOf(watch)).length;
  h.simulator.write({name: 'New'});
  await h.engine.tick();
  const feed = h.feedOf(watch), runs = h.runsOf(feed), run = runs.at(-1);
  assert.equal(runs.length, before + 1);
  assert.deepEqual([run.at, run.outcome, run.status, run.requests, run.items, run.skipped, run.events], [h.now, 'done', 200, 1, 1, 0, {[watch.id]: 1}]);
  assert.equal(h.store.get('triggerRuns', feed.id).connectionId, h.account);
  assert.ok(feed.cursors.sync, 'the cursor moved');
  assert.equal(feed.lastGoodAt, h.now);
  assert.equal(feed.nextPollAt, h.now + INTERVAL);
  assert.equal(h.store.list('activity').length, audits, 'spec 1872: a poll writes no audit row');
})());

test('the ring of runs holds the last 50, and the oldest go', async t => {
  const h = rig(t), watch = await running(h);
  for (let count = 0; count < 55; count++) await h.pass();
  const runs = h.runsOf(h.feedOf(watch));
  assert.equal(runs.length, 50);
  assert.equal(runs.at(-1).at, h.now);
  assert.equal(runs[0].at, h.now - 49 * INTERVAL);
});

test('a feed is due only when its time has come and a live subscription holds it', async t => {
  const h = rig(t), watch = await running(h), reads = h.feedReads().length;
  h.advance(-SECOND);
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads, 'not yet');
  h.advance(SECOND);
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads + 1, 'on the second it is due');
  for (const status of ['awaiting_approval', 'paused', 'declined', 'expired', 'removed']) {
    h.store.put('subscriptions', {...h.current(watch), status});
    h.advance(INTERVAL);
    await h.engine.tick();
    assert.equal(h.feedReads().length, reads + 1, status);
  }
});

test('feeds are read oldest due first', async t => {
  const h = rig(t), a = await running(h, 'feed-synced'), b = await running(h, 'feed-listed');
  h.store.put('triggerFeeds', {...h.feedOf(a), nextPollAt: h.now - HOUR});
  h.store.put('triggerFeeds', {...h.feedOf(b), nextPollAt: h.now - DAY});
  const reads = h.feedReads().length;
  await h.engine.tick();
  assert.deepEqual(h.feedReads().slice(reads).map(call => call.query.order ?? 'sync'), ['unordered', 'sync']);
});

test('a tick with nothing due reads nothing and writes nothing, and a tick while one runs does nothing', async t => {
  const h = rig(t), watch = await running(h), writes = [], {put} = h.store;
  h.advance(-SECOND);
  h.store.put = (...args) => { writes.push(args); return put.apply(h.store, args); };
  const reads = h.feedReads().length;
  await h.engine.tick();
  assert.deepEqual([writes.length, h.feedReads().length], [0, reads]);
  h.store.put = put;
  h.advance(SECOND);
  const held = h.simulator.hold('GET /feed'), first = h.engine.tick();
  await held.reached;
  await h.engine.tick();
  held.release();
  await first;
  assert.equal(h.feedReads().length, reads + 1, 'the second tick found the first still running');
  assert.equal(h.current(watch).status, 'active');
});

test('a null catalog means no polls and no pause writes: that is a local fault', async t => {
  const h = rig(t), watch = await running(h), writes = [], {put, audit} = h.store, reads = h.feedReads().length, {actions} = h.runtime;
  h.runtime.actions = null;
  h.store.put = (...args) => { writes.push(args); return put.apply(h.store, args); };
  h.store.audit = (...args) => { writes.push(args); return audit.apply(h.store, args); };
  await h.engine.tick();
  assert.equal(h.engine.attach(h.watch('feed-listed', {status: 'starting'})).status, 'starting', 'attaching waits too');
  h.store.put = put;
  h.store.audit = audit;
  assert.deepEqual([writes.length - 1, h.feedReads().length, h.current(watch).status], [0, reads, 'active'], 'the one write is the watch this test stored');
  h.runtime.actions = actions;
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads + 1, 'and the next start recovers');
  const budgeted = rig(t, {}, {budgets: {fixture: {methods: {feed: 5}}}}), other = await running(budgeted);
  budgeted.runtime.actions = null;
  await budgeted.engine.tick();
  assert.equal(budgeted.current(other).status, 'active', 'it never reaches for a catalog it has not got');
  assert.equal((await budgeted.engine.pollNow(other.id)).status, 'active', 'pollNow waits too');
  assert.equal(budgeted.feedReads().length, 1);
});

// Joining a running feed.
test('a joiner receives nothing from before it joined, and the next write once it is active', async t => {
  const h = rig(t), first = await running(h);
  h.simulator.write({name: 'Before'});
  h.advance(SECOND);
  const joiner = h.start('feed-synced');
  assert.equal(h.current(joiner).feeds[0], h.current(first).feeds[0]);
  await h.settle(joiner);
  assert.deepEqual([h.eventsOf(first).length, h.eventsOf(joiner).length], [1, 0], 'the active watch hears of it, and the joiner does not');
  h.advance(INTERVAL);
  h.simulator.write({name: 'After'});
  h.advance(SECOND);
  await h.engine.tick();
  assert.deepEqual([h.eventsOf(first).length, h.eventsOf(joiner).length], [2, 1]);
});

test('a joiner stays starting until a poll that started after it joined finishes: one already in flight does not count', async t => {
  const h = rig(t), first = await running(h), held = h.simulator.hold('GET /feed'), flight = h.engine.tick();
  await held.reached;
  const joiner = h.start('feed-synced');
  held.release();
  await flight;
  assert.deepEqual([h.current(joiner).status, h.current(joiner).pending], ['starting', [h.feedOf(first).id]]);
  h.simulator.write({name: 'Read by the next poll'});
  await h.engine.tick();
  assert.equal(h.current(joiner).status, 'active');
  assert.deepEqual([h.eventsOf(first).length, h.eventsOf(joiner).length], [1, 0], 'the catch-up poll goes to the active watch alone');
});

const LONG = [['an asc feed', 'feed-updated', {kinds: ['note']}], ['a history feed', 'feed-logged', {}], ['a sync walk', 'feed-synced', {}]];
for (const [label, key, args] of LONG) {
  test(`1,000 items of backlog on ${label}: a joiner gets none of it across every catch-up poll, then the next write gives it one`, async t => {
    const h = rig(t, {triggers: edited(key, item => { pagesOf(item, 2); })}), first = await running(h, key, {args});
    h.simulator.seed(1000);
    h.advance(SECOND);
    const joiner = h.start(key, {args}), polls = await h.settle(joiner);
    assert.ok(polls > 2, `its catch-up took ${polls} polls`);
    assert.equal(h.eventsOf(joiner).length, 0);
    assert.equal(h.eventsOf(first).length, 1000, 'the active watch reads the whole backlog, once each');
    h.advance(INTERVAL);
    h.simulator.write({name: 'Next'});
    h.advance(SECOND);
    await h.engine.tick();
    assert.equal(h.eventsOf(joiner).length, 1);
  });
}

test('a window snapshot cut by its bounds on every poll still turns a watch active, and a cut sync walk on an unordered block does not', async t => {
  const windows = (appId, key) => key === 'feed-listed' ? {seconds: null, alerts: false} : null;
  const h = rig(t, {triggers: edited('feed-listed', item => { pagesOf(item, 1); item.poll.source.steps[0].query.limit = {const: 2}; })}, {windows});
  h.simulator.seed(40);
  const listed = h.start('feed-listed');
  await h.engine.tick();
  assert.equal(h.current(listed).status, 'active', 'a window\'s bound is its reach');
  const cut = rig(t, {triggers: edited('feed-synced', item => { pagesOf(item, 1); item.poll.source.steps[0].query.limit = {const: 2}; })});
  cut.simulator.seed(40);
  const synced = cut.start('feed-synced');
  await cut.engine.tick();
  cut.advance(SECOND);
  await cut.engine.tick();
  assert.equal(cut.feedOf(synced).baselined, false);
  assert.equal(cut.current(synced).status, 'starting', 'a cut sync walk has not reached the edge, whatever the block\'s order says');
  await cut.settle(synced);
});

test('a window with no paging that fills its bound may have more behind it, a paged one that ends there says it has none, and a whole list is not read as a window', async t => {
  const windows = (appId, key) => key === 'feed-listed' ? {seconds: null, alerts: false} : null, bound = (item, items) => { item.bounds.items = items; item.poll.source.steps[0].query.limit = {const: 4}; };
  const paged = rig(t, {triggers: edited('feed-listed', item => { pagesOf(item, 2); bound(item, 4); })}, {windows}), watch = paged.start('feed-listed');
  await paged.settle(watch);
  paged.simulator.seed(4);
  await paged.pass();
  assert.deepEqual([paged.eventsOf(watch).length, paged.gapsOf(watch).length], [4, 0], 'its last page proves nothing lies behind it, so all four are told');
  const unpaged = item => { delete item.poll.source.steps[0].page; item.bounds.pages = 1; item.poll.items.pointer = '/items'; bound(item, 4); };
  const single = rig(t, {triggers: edited('feed-listed', unpaged)}, {windows}), one = single.start('feed-listed');
  await single.settle(one);
  single.simulator.seed(4);
  await single.pass();
  assert.deepEqual([single.eventsOf(one).length, single.gapsOf(one).map(row => row.payload.fields.reason)], [0, ['overflow']], 'with no next page to ask for, a full read of new items may hide more');
  const whole = rig(t, {triggers: edited('feed-listed', unpaged)}), list = whole.start('feed-listed');
  await whole.settle(list);
  whole.simulator.seed(4);
  await whole.pass();
  assert.deepEqual([whole.current(list).status, whole.eventsOf(list).length, whole.gapsOf(list).length], ['active', 4, 0], 'a list that is no window reads as it always did');
});

test('a starting watch with one finished feed receives that feed\'s next item while its other feed catches up', async t => {
  const h = rig(t, {triggers: edited('feed-updated', item => { pagesOf(item, 1); delete item.poll.seed; item.poll.source.steps[0].query.limit = {const: 2}; })});
  h.simulator.seed(40, {kind: 'task'});
  const watch = h.start('feed-updated', {args: {kinds: ['note', 'task']}}), [notes, tasks] = h.current(watch).feeds;
  await h.engine.tick();
  assert.deepEqual([h.current(watch).status, h.current(watch).pending], ['starting', [tasks]], 'the empty feed finished and the other did not');
  const {updatedAt} = h.current(watch);
  h.simulator.write({name: 'A note', kind: 'note'});
  h.advance(INTERVAL);
  h.simulator.write({name: 'Another', kind: 'note'});
  h.advance(SECOND);
  await h.engine.tick();
  assert.equal(h.current(watch).status, 'starting');
  assert.equal(h.current(watch).updatedAt, updatedAt, 'a feed no longer pending changes nothing on the watch');
  assert.ok(h.eventsOf(watch).length >= 1, 'the finished feed speaks');
  await h.settle(watch);
  assert.equal(h.store.get('triggerFeeds', notes).baselined, true);
});

test('a new subscription on a running sync feed needs no second walk', async t => {
  const h = rig(t);
  h.simulator.seed(4);
  const first = await running(h), walks = h.feedReads().length, joiner = h.start('feed-synced');
  await h.engine.tick();
  assert.equal(h.current(joiner).status, 'active');
  assert.equal(h.feedReads().length, walks + 1, 'one delta read');
  assert.equal(h.feedReads().at(-1).query.syncToken, h.feedOf(first).cursors.sync);
});

// The gate around a poll.
both('spec 1866: Background at Never pauses before anything is read: no credentials, no token refresh, no network', (t, designated) => (async () => {
  const h = rig(t, {designated}), watch = await running(h), reads = h.simulator.calls.length;
  let credentials = 0;
  const {credentials: real} = h.connections;
  h.connections.credentials = (...args) => { credentials++; return real(...args); };
  h.store.put('backgroundPolicies', {id: h.account, connectionId: h.account, mode: 'deny', updatedAt: 'x'});
  await h.engine.tick();
  assert.deepEqual([credentials, h.simulator.calls.length], [0, reads]);
  assert.deepEqual([h.current(watch).status, h.current(watch).reason], ['paused', 'background_off']);
  assert.deepEqual(h.audits('trigger.paused').map(row => [row.subscriptionId, row.connectionId, row.appId, row.reason]), [[watch.id, h.account, 'fixture', 'background_off']]);
  assert.equal(h.current(watch).revision, 2, 'a pause raises the revision');
  assert.equal(h.current(watch).pausedAt, new Date(h.now).toISOString());
  assert.equal(h.runsOf(h.feedOf(watch)).length, 1, 'no poll ran, so no run is recorded');
})());

test('a pause never resumes on its own: the row back at Allow leaves the watch paused and sends nothing', async t => {
  const h = rig(t), watch = await running(h);
  h.store.put('backgroundPolicies', {id: h.account, connectionId: h.account, mode: 'deny', updatedAt: 'x'});
  await h.engine.tick();
  h.store.put('backgroundPolicies', {id: h.account, connectionId: h.account, mode: 'allow', updatedAt: 'y'});
  const reads = h.simulator.calls.length, audits = h.audits('trigger.paused').length;
  assert.deepEqual(gate(h.runtime, h.current(watch)), {ok: true}, 'the gate would pass it');
  await h.pass();
  await h.pass();
  assert.deepEqual([h.current(watch).status, h.simulator.calls.length, h.audits('trigger.paused').length], ['paused', reads, audits]);
});

test('each failing gate pauses its own watch: a lens with a row at Never stops, and the other reads on', async t => {
  const h = rig(t);
  h.setRow('fixture.keys.read', 'allow');
  const plain = await running(h, 'feed-logged'), keys = await running(h, 'feed-logged-keys');
  h.setRow('fixture.keys.read', 'deny');
  h.simulator.write({name: 'New'});
  await h.engine.tick();
  assert.deepEqual([h.current(plain).status, h.current(keys).status, h.current(keys).reason], ['active', 'paused', 'permission_changed']);
  assert.equal(h.eventsOf(plain).length, 1);
  assert.equal(h.simulator.calls.filter(call => call.route === 'GET /keys').length, 0);
  assert.ok(h.feedOf(plain).lenses.includes(h.itemOf('feed-logged-keys').lenses[0]), 'a history feed keeps a lens that lost its watch: a later one needs no new feed');
});

test('a poll is given only the watches that passed the gate', async t => {
  const h = rig(t);
  h.setRow('fixture.keys.read', 'allow');
  const plain = await running(h, 'feed-logged'), keys = await running(h, 'feed-logged-keys'), {runPoll} = h.catalog, given = [];
  h.runtime.actions = {...h.catalog, runPoll: options => { given.push(options.subscriptions.map(subscription => subscription.id)); return runPoll(options); }};
  h.setRow('fixture.keys.read', 'deny');
  await h.engine.tick();
  assert.deepEqual(given, [[plain.id]]);
  assert.equal(h.current(keys).status, 'paused');
});

test('a skip pauses nothing, sends nothing and backs the feed off; a failure after it still pauses', async t => {
  const h = rig(t), watch = await running(h), reads = h.simulator.calls.length, ready = h.connection();
  h.store.put('connections', {...ready, status: 'reconnect_required'});
  await h.engine.tick();
  assert.deepEqual([h.current(watch).status, h.simulator.calls.length], ['active', reads]);
  const feed = h.feedOf(watch);
  assert.equal(feed.failures, 1);
  assert.ok(feed.nextPollAt >= h.now + 2 * INTERVAL, 'the backoff, past the interval');
  assert.deepEqual([h.runsOf(feed).at(-1).outcome, h.runsOf(feed).at(-1).code], ['skipped', 'reconnect_required']);
  h.store.put('connections', ready);
  h.advance(feed.nextPollAt - h.now);
  h.simulator.write({name: 'Back'});
  await h.engine.tick();
  assert.equal(h.eventsOf(watch).length, 1, 'a reconnect on the same identity carries on');
  assert.equal(h.feedOf(watch).failures, 0);
});

test('a renewal that fails inside a poll\'s credentials step stores nothing, pauses nothing and backs off, and the next gate skips', async t => {
  const h = rig(t), watch = await running(h), ready = h.connection(), {credentials} = h.connections, cursors = h.feedOf(watch).cursors;
  h.simulator.write({name: 'Waiting'});
  h.connections.credentials = async () => { h.store.put('connections', {...ready, status: 'reconnect_required'}); throw new Error('renewal failed'); };
  await h.engine.tick();
  assert.deepEqual([h.current(watch).status, h.feedOf(watch).failures, h.events().length], ['active', 1, 0]);
  assert.deepEqual(h.feedOf(watch).cursors, cursors);
  h.connections.credentials = credentials;
  h.advance(h.feedOf(watch).nextPollAt - h.now);
  const reads = h.simulator.calls.length;
  await h.engine.tick();
  assert.deepEqual([h.simulator.calls.length, h.feedOf(watch).failures], [reads, 2], 'the gate skips');
  h.store.put('connections', ready);
  h.advance(h.feedOf(watch).nextPollAt - h.now);
  await h.engine.tick();
  assert.equal(h.eventsOf(watch).length, 1, 'nothing was lost');
});

both('spec 1867: a row turned to Never mid-poll discards the results and keeps the cursor, with one memo shared across the tick', (t, designated) => (async () => {
  const h = rig(t, {designated}), watch = await running(h), cursors = h.feedOf(watch).cursors, {request} = h.runtime;
  h.simulator.write({name: 'Read, and never reported'});
  h.runtime.request = async (...args) => { const answer = await request(...args); h.setRow('fixture.items.read', 'deny'); return answer; };
  await h.engine.tick();
  assert.deepEqual([h.current(watch).status, h.current(watch).reason], ['paused', 'permission_changed']);
  assert.equal(h.events().length, 0);
  assert.deepEqual(h.feedOf(watch).cursors, cursors, 'the cursor stays');
  assert.equal(h.runsOf(h.feedOf(watch)).at(-1).outcome, 'withheld');
  assert.deepEqual(h.runsOf(h.feedOf(watch)).at(-1).events, {}, 'what a run counts was never stored');
})());

test('the last gate: a row turned to Never at the last answer, with another live watch on the feed, pauses the failed one, drops its events and stores the rest', async t => {
  const h = rig(t);
  h.setRow('fixture.keys.read', 'allow');
  const plain = await running(h, 'feed-logged'), keys = await running(h, 'feed-logged-keys'), {request} = h.runtime;
  const before = h.feedOf(plain).cursors;
  h.simulator.write({name: 'New'});
  h.runtime.request = async (options, ...rest) => { const answer = await request(options, ...rest); if (options.url.includes('/keys')) h.setRow('fixture.keys.read', 'deny'); return answer; };
  await h.engine.tick();
  assert.deepEqual([h.current(plain).status, h.current(keys).status], ['active', 'paused']);
  assert.deepEqual([h.eventsOf(plain).length, h.eventsOf(keys).length], [1, 0]);
  assert.notDeepEqual(h.feedOf(plain).cursors, before, 'the cursor advances for the rest');
  assert.deepEqual(h.runsOf(h.feedOf(plain)).at(-1).events, {[plain.id]: 1}, 'a dropped event is not counted');
});

test('spec 1867, two lenses: a row of one turned to Never mid-poll stops that lens\'s enrich reads, and the other still fires', async t => {
  const h = rig(t, {triggers: edited('feed-logged-keys', item => { item.poll.enrich.steps[0].query = {item: {item: '/id'}}; })});
  h.setRow('fixture.keys.read', 'allow');
  const detail = await running(h, 'feed-logged-detail'), keys = await running(h, 'feed-logged-keys'), {request} = h.runtime;
  h.simulator.write({name: 'One'});
  h.simulator.write({name: 'Two'});
  let turned = false;
  h.runtime.request = async (options, ...rest) => { const answer = await request(options, ...rest); if (!turned && options.url.includes('/keys')) { turned = true; h.setRow('fixture.keys.read', 'deny'); } return answer; };
  await h.engine.tick();
  assert.equal(h.simulator.calls.filter(call => call.route === 'GET /keys').length, 1, 'one read, and the row stopped it');
  assert.equal(h.simulator.calls.filter(call => call.route === 'GET /items/{item_id}').length, 2);
  assert.deepEqual([h.current(detail).status, h.eventsOf(detail).length], ['active', 2]);
  assert.deepEqual([h.current(keys).status, h.current(keys).reason, h.eventsOf(keys).length], ['paused', 'permission_changed', 0]);
});

test('a skip at the last gate stores nothing and backs off', async t => {
  const h = rig(t), watch = await running(h), ready = h.connection(), {request} = h.runtime, cursors = h.feedOf(watch).cursors;
  h.simulator.write({name: 'Read'});
  h.runtime.request = async (...args) => { const answer = await request(...args); h.store.put('connections', {...ready, status: 'unavailable'}); return answer; };
  await h.engine.tick();
  assert.deepEqual([h.current(watch).status, h.events().length, h.feedOf(watch).failures, h.runsOf(h.feedOf(watch)).at(-1).outcome, h.runsOf(h.feedOf(watch)).at(-1).code], ['active', 0, 1, 'skipped', 'unavailable']);
  assert.deepEqual(h.feedOf(watch).cursors, cursors);
});

test('a discarded poll still keeps the provider\'s floor, and a joiner stays starting: nothing it read was stored', async t => {
  const h = rig(t), first = await running(h), joiner = h.start('feed-synced'), ready = h.connection(), {request} = h.runtime;
  h.simulator.pollInterval(300);
  h.runtime.request = async (...args) => { const answer = await request(...args); h.store.put('connections', {...ready, status: 'unavailable'}); return answer; };
  await h.engine.tick();
  assert.equal(h.feedOf(first).notBefore, h.now + 300_000);
  assert.deepEqual([h.current(joiner).status, h.current(joiner).pending], ['starting', [h.feedOf(first).id]]);
});

test('a watch paused during the await loses its events, and a feed with no live watch left stores nothing', async t => {
  const h = rig(t), a = await running(h), b = h.start('feed-synced');
  await h.settle(b);
  h.advance(INTERVAL);
  h.simulator.write({name: 'New'});
  const held = h.simulator.hold('GET /feed'), flight = h.engine.tick();
  await held.reached;
  h.store.put('subscriptions', {...h.current(a), status: 'paused', reason: 'owner_paused'});
  held.release();
  await flight;
  assert.deepEqual([h.eventsOf(a).length, h.eventsOf(b).length], [0, 1]);
  h.advance(INTERVAL);
  h.simulator.write({name: 'Again'});
  const cursors = h.feedOf(b).cursors, second = h.simulator.hold('GET /feed'), last = h.engine.tick();
  await second.reached;
  h.store.put('subscriptions', {...h.current(b), status: 'paused', reason: 'owner_paused'});
  second.release();
  await last;
  assert.equal(h.eventsOf(b).length, 1);
  assert.deepEqual(h.feedOf(b).cursors, cursors, 'nobody is left to hear of it, so the cursor stays');
});

test('authority before a request reads the watches again: one paused at a page ends the poll, and one lens gone drops that lens alone', async t => {
  const h = rig(t, {triggers: edited('feed-synced', item => { item.poll.source.steps[0].query.limit = {const: 2}; })}), watch = await running(h), {request} = h.runtime, cursors = h.feedOf(watch).cursors;
  h.simulator.seed(8);
  h.runtime.request = async (...args) => { const answer = await request(...args); h.store.put('subscriptions', {...h.current(watch), status: 'paused', reason: 'owner_paused'}); return answer; };
  const reads = h.feedReads().length;
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads + 1, 'the next page is never asked for');
  assert.deepEqual(h.feedOf(watch).cursors, cursors);
});

test('spec 1870: a malformed stored cursor pauses each watch on the feed with one audit row, and sends nothing after it', async t => {
  const h = rig(t), a = await running(h), b = h.start('feed-synced');
  await h.settle(b);
  h.advance(INTERVAL);
  h.store.put('triggerFeeds', {...h.feedOf(a), cursors: {sync: 'bad\ncursor'}});
  const reads = h.feedReads().length;
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads);
  assert.deepEqual([a, b].map(watch => [h.current(watch).status, h.current(watch).reason, h.current(watch).detail]), [['paused', 'cursor_invalid', 'sync-token@1'], ['paused', 'cursor_invalid', 'sync-token@1']]);
  assert.deepEqual(h.audits('trigger.paused').map(row => row.reason), ['cursor_invalid', 'cursor_invalid']);
  await h.pass();
  assert.equal(h.feedReads().length, reads, 'no network after it');
});

test('a malformed incoming cursor keeps the old one and pauses the same way', async t => {
  const h = rig(t), watch = await running(h), {sync} = h.feedOf(watch).cursors;
  h.simulator.fail('GET /feed', {status: 200, data: {items: [], nextSyncToken: 'bad\ntoken'}});
  await h.engine.tick();
  assert.deepEqual([h.current(watch).status, h.current(watch).reason, h.feedOf(watch).cursors.sync], ['paused', 'cursor_invalid', sync]);
});

test('a refused resource pauses the whole watch, its other feeds too: the owner approved the list as one', async t => {
  const h = rig(t), watch = h.start('feed-updated', {args: {kinds: ['note', 'task']}});
  await h.settle(watch);
  h.advance(INTERVAL);
  h.simulator.fail('GET /feed', {status: 403, data: {error: 'gone'}});
  await h.engine.tick();
  assert.deepEqual([h.current(watch).status, h.current(watch).reason, h.current(watch).detail], ['paused', 'provider_refused', 'http_403']);
  const reads = h.feedReads().length;
  await h.pass();
  assert.equal(h.feedReads().length, reads, 'neither feed is due now');
});

test('a 301 pauses and is never followed; a 200 that fails expect.require pauses nothing and backs off', async t => {
  const h = rig(t), watch = await running(h);
  h.simulator.fail('GET /feed', {status: 301, headers: {location: 'https://elsewhere.test/feed'}});
  await h.engine.tick();
  assert.deepEqual([h.current(watch).status, h.current(watch).reason, h.current(watch).detail], ['paused', 'provider_refused', 'moved']);
  assert.ok(!h.simulator.calls.some(call => call.origin !== 'https://api.fixture.test'));
  const {sync} = h.feedOf(watch).cursors;
  h.engine.resume(h.current(watch));
  assert.deepEqual([h.feedOf(watch).cursors.sync, h.feedOf(watch).baselined], [sync, true], 'a feed that did not lose its place carries on from it');
  const held = rig(t, {triggers: edited('feed-synced', item => { item.poll.source.steps[0].expect = {status: [200], require: [{present: {pointer: '/items'}}]}; })}), other = await running(held);
  held.simulator.fail('GET /feed', {status: 200, data: {odd: true}});
  await held.engine.tick();
  assert.deepEqual([held.current(other).status, held.feedOf(other).failures, held.runsOf(held.feedOf(other)).at(-1).code], ['active', 1, 'require_failed']);
});

/** A row any one of two scopes opens, as Slack's history row is, on an app whose sign-in holds a success rule, as Slack's does. So losing one scope leaves the row reading as granted. */
const anyOfTwo = () => ({signIn: {...fixtureSignIn(), apiSuccessRequire: [{pointer: '/ok', equals: true}]}, file: {schemaVersion: 1, appId: 'fixture', specVersion: 'fabric/0.2', reviewStatus: 'reviewed', pinnedParameters: {}, actions: []},
  rows: file => { file.groups[0].memberScopeSets = {'GET /feed': [['fixture:all'], ['feed.read']]}; return file; },
  triggers: edited('feed-listed', item => { item.poll.source.steps[0].expect = {status: [200], require: [{equals: {pointer: '/ok', value: {const: true}}}]}; }).filter(item => item.key === 'feed-listed')});

both('a provider\'s missing_scope pauses access_missing itself, since a row another scope opens still reads as granted, and the account narrows', async (t, designated) => {
  const h = rig(t, {...anyOfTwo(), designated});
  h.store.put('connections', {...h.connection(), authMethod: 'oauth', scopes: ['fixture:all', 'feed.read']});
  h.simulator.fail('GET /feed', {status: 200, data: {ok: true, items: []}});
  const watch = await running(h, 'feed-listed'), reads = h.feedReads().length;
  h.simulator.fail('GET /feed', {status: 200, data: {ok: false, error: 'missing_scope', needed: 'fixture:all', provided: 'feed.read'}});
  await h.engine.tick();
  assert.deepEqual([h.feedReads().length, h.connection().scopes], [reads + 1, ['feed.read']], 'the answer was read, and it took the scope away');
  assert.equal(gate(h.runtime, {...h.current(watch), status: 'awaiting_approval'}).ok, true, 'the row alone would pass');
  assert.deepEqual([h.current(watch).status, h.current(watch).reason, h.current(watch).detail], ['paused', 'access_missing', 'missing_scope']);
  assert.deepEqual(h.audits('trigger.paused').map(row => row.reason), ['access_missing']);
});

both('a token that never held the scope narrows nothing, and it still pauses access_missing', async (t, designated) => {
  const h = rig(t, {...anyOfTwo(), designated});
  h.store.put('connections', {...h.connection(), authMethod: 'oauth', scopes: ['feed.read']});
  h.simulator.fail('GET /feed', {status: 200, data: {ok: true, items: []}});
  const watch = await running(h, 'feed-listed');
  h.simulator.fail('GET /feed', {status: 200, data: {ok: false, error: 'missing_scope', needed: 'fixture:all', provided: 'feed.read'}});
  await h.engine.tick();
  assert.deepEqual([h.connection().scopes, h.current(watch).status, h.current(watch).reason], [['feed.read'], 'paused', 'access_missing']);
});

test('a row with no scope left pauses access_missing at the first gate, with no read', async t => {
  const rows = file => { file.groups[0].memberScopeSets = {'GET /feed': [['feed.read']]}; return file; };
  const h = rig(t, {rows});
  h.store.put('connections', {...h.connection(), authMethod: 'oauth', scopes: ['feed.read']});
  const watch = await running(h), reads = h.feedReads().length;
  h.store.put('connections', {...h.connection(), scopes: []});
  h.simulator.write({name: 'New'});
  await h.engine.tick();
  assert.deepEqual([h.current(watch).status, h.current(watch).reason, h.feedReads().length], ['paused', 'access_missing', reads]);
});

test('every gate pause reason reaches the watch, each with one audit row', async t => {
  const pausing = [
    ['client_ended', h => h.grant('client-1', {status: 'revoked'})],
    ['account_changed', h => h.store.put('connections', {...h.connection(), status: 'pending_confirmation'})],
    ['account_changed', h => h.store.put('connections', {...h.connection(), identity: {id: 'acct-2'}})],
    ['account_changed', h => h.store.put('connections', {...h.connection(), authRevision: 'r2'})],
    ['permission_changed', h => { h.setRow('fixture.items.read', 'ask'); }],
    ['background_off', h => h.store.put('backgroundPolicies', {id: h.account, connectionId: h.account, mode: 'deny', updatedAt: 'x'})]];
  for (const [reason, change] of pausing) {
    const h = rig(t), watch = await running(h), reads = h.simulator.calls.length;
    change(h);
    await h.engine.tick();
    assert.deepEqual([h.current(watch).status, h.current(watch).reason, h.simulator.calls.length, h.audits('trigger.paused').length], ['paused', reason, reads, 1], reason);
  }
  const moved = rig(t), watch = await running(moved);
  moved.runtime.actions = {...moved.catalog, triggerOf: () => null};
  await moved.engine.tick();
  assert.deepEqual([moved.current(watch).status, moved.current(watch).reason], ['paused', 'definition_changed'], 'a catalog that loaded and lost this trigger');
});

test('a renewal and a rename pause nothing', async t => {
  const h = rig(t), watch = await running(h);
  h.store.put('connections', {...h.connection(), expiresAt: 'later', lastCheckedAt: 'now', identity: {...h.connection().identity, displayName: 'New name'}});
  h.simulator.write({name: 'New'});
  await h.engine.tick();
  assert.deepEqual([h.current(watch).status, h.eventsOf(watch).length], ['active', 1]);
});

// When a feed runs next.
/** Copies of a watch's baselined feed, all due now and all held by the watch, with `fields` over each. */
function copies(h, watch, count, fields = {}) {
  const feed = h.feedOf(watch), ids = Array.from({length: count}, (_, index) => `${feed.id.slice(0, 20)}${String(index).padStart(4, '0')}`);
  for (const id of ids) h.store.put('triggerFeeds', {...feed, id, nextPollAt: h.now, ...fields});
  h.store.put('subscriptions', {...h.current(watch), feeds: [feed.id, ...ids]});
  return ids;
}
/** A second account on the fixture app, and an active watch on it. */
function otherAccount(h, id, key = 'feed-synced', identity = {id: `acct-${id}`}) {
  h.store.put('connections', {...h.connection(), id, identity});
  const at = new Date(h.now).toISOString(), {appId, entry} = h.itemOf(key), record = {id: `watch-${id}`, clientId: 'client-1', appId, triggerId: entry.id, triggerKey: entry.key, connectionId: id, args: {}, argsHash: argsHashOf({}), revision: 1, status: 'starting',
    approvalDigest: '0'.repeat(64), approvalExpiresAt: at, feeds: [], pending: [], createdAt: at, updatedAt: at, approvedAt: at};
  const connection = h.store.get('connections', id);
  h.store.put('subscriptions', {...record, authority: authorityOf(record, connection, h.permissions.triggerDecision(connection, entry))});
  return h.engine.attach(record);
}

test('spec 1865: a Retry-After of 120 delays the next run by at least 120 seconds, and the wait is durable', async t => {
  const h = rig(t), watch = await running(h);
  h.simulator.fail('GET /feed', {status: 429, headers: {'retry-after': '120'}, data: {error: 'slow'}});
  const asked = h.now;
  await h.engine.tick();
  const feed = h.feedOf(watch), reads = h.feedReads().length;
  assert.ok(feed.wait.until >= asked + 120_000);
  assert.equal(feed.wait.reason, 'limited');
  assert.equal(feed.failures, 1);
  assert.equal(h.current(watch).status, 'active', 'a limit pauses nothing');
  h.advance(119_000);
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads);
  h.store.put('triggerFeeds', {...h.feedOf(watch), nextPollAt: 0});
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads, 'the wait holds on its own, whatever the next time says');
  h.advance(feed.wait.until - h.now);
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads + 1);
  assert.deepEqual([h.feedOf(watch).wait, h.feedOf(watch).failures], [null, 0], 'a poll that lands clears both');
});

test('spec 1865: a Retry-After of 7,200 is honoured in full, past the hour that caps a backoff', async t => {
  const h = rig(t), watch = await running(h);
  h.simulator.fail('GET /feed', {status: 429, headers: {'retry-after': '7200'}, data: {error: 'slow'}});
  const asked = h.now;
  await h.engine.tick();
  assert.ok(h.feedOf(watch).nextPollAt >= asked + 7_200_000);
  assert.ok(h.feedOf(watch).wait.until >= asked + 7_200_000);
  const reads = h.feedReads().length;
  h.advance(7_199_000);
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads);
});

test('a limit with no time named lets the backoff decide, and a 529 reads the same', async t => {
  const h = rig(t), watch = await running(h);
  h.simulator.fail('GET /feed', {status: 529, data: {error: 'overloaded'}});
  await h.engine.tick();
  assert.equal(h.feedOf(watch).nextPollAt, h.now + 240_000);
  assert.deepEqual(h.feedOf(watch).wait, {until: h.now + 240_000, reason: 'limited'});
});

test('a limit answer holds every feed of its connection, and no feed of another', async t => {
  const h = rig(t), a = await running(h, 'feed-synced'), b = await running(h, 'feed-listed'), other = otherAccount(h, 'fixture-account-2');
  await h.settle(other);
  h.advance(INTERVAL);
  h.store.put('triggerFeeds', {...h.feedOf(a), nextPollAt: h.now - DAY});
  h.simulator.fail('GET /feed', {status: 429, headers: {'retry-after': '600'}, data: {error: 'slow'}});
  h.store.put('triggerFeeds', {...h.feedOf(b), nextPollAt: h.now + HOUR});
  await h.engine.tick();
  assert.ok(h.feedOf(a).wait.until >= h.now + 600_000);
  assert.deepEqual(h.feedOf(b).wait, h.feedOf(a).wait, 'the quiet feed waits too');
  assert.equal(h.feedOf(other).wait, null);
  assert.equal(h.feedOf(b).failures, 0, 'only the feed that was answered counts a failure');
});

test('for Slack a wait names its method, and holds only the feeds that use it', async t => {
  const onItems = twin('feed-listed', 'feed-items', item => { item.poll.source.steps[0] = {...item.poll.source.steps[0], path: '/items', query: {}, page: {next: {pointer: '/nextPageToken'}, into: {query: 'pageToken'}, items: '/items', max: 10}}; });
  const h = rig(t, {triggers: [...feedTriggers(), onItems]}), feed = await running(h, 'feed-synced'), items = await running(h, 'feed-items'), {runPoll} = h.catalog;
  h.runtime.actions = {...h.catalog, runPoll: async options => { const result = await runPoll(options); return result.wait ? {...result, wait: {...result.wait, method: 'feed'}} : result; }};
  h.store.put('triggerFeeds', {...h.feedOf(items), nextPollAt: h.now + HOUR});
  h.simulator.fail('GET /feed', {status: 429, headers: {'retry-after': '600'}, data: {error: 'slow'}});
  await h.engine.tick();
  assert.ok(h.feedOf(feed).wait);
  assert.equal(h.feedOf(items).wait, null, 'another method keeps going');
});

test('a wait reached on an enrich read stores the whole records before it, and holds the feed', async t => {
  const h = rig(t), watch = await running(h, 'feed-logged-detail');
  h.simulator.write({name: 'One'});
  h.simulator.write({name: 'Two'});
  const {request} = h.runtime;
  let reads = 0;
  h.runtime.request = async (options, ...rest) => {
    if (options.url.includes('/items/') && ++reads === 2) return {status: 429, headers: {'retry-after': '300'}, data: {error: 'slow'}};
    return request(options, ...rest);
  };
  await h.engine.tick();
  assert.equal(h.eventsOf(watch).length, 1);
  assert.ok(h.feedOf(watch).wait.until >= h.now + 300_000);
  assert.equal(h.feedOf(watch).failures, 1);
});

test('a backoff is min(3600, interval * 2^failures), a failed poll raises the count, and a good poll clears it', async t => {
  const h = rig(t), watch = await running(h);
  for (const seconds of [240, 480, 960, 1920, 3600, 3600]) {
    h.simulator.fail('GET /feed', {status: 503, data: {error: 'down'}});
    await h.engine.tick();
    assert.equal(h.feedOf(watch).nextPollAt, h.now + seconds * 1000, `${seconds} seconds`);
    h.advance(seconds * 1000);
  }
  assert.equal(h.feedOf(watch).failures, 6);
  await h.engine.tick();
  assert.deepEqual([h.feedOf(watch).failures, h.feedOf(watch).nextPollAt], [0, h.now + INTERVAL]);
  assert.equal(h.current(watch).status, 'active');
});

test('jitter is upward only and at most a quarter, so no floor is crossed, on an interval and on a backoff', async t => {
  for (const [random, most] of [[0, 1], [0.999, 1.25]]) {
    const h = rig(t, {}, {random: () => random}), watch = h.start('feed-synced');
    await h.settle(watch);
    const next = h.feedOf(watch).nextPollAt - h.now;
    assert.ok(next >= INTERVAL && next <= INTERVAL * most, `interval, ${next}`);
    assert.equal(next, Math.round(INTERVAL * (1 + random * 0.25)));
    h.advance(next);
    h.simulator.fail('GET /feed', {status: 503, data: {error: 'down'}});
    await h.engine.tick();
    const backoff = h.feedOf(watch).nextPollAt - h.now;
    assert.ok(backoff >= 2 * INTERVAL && backoff <= 2 * INTERVAL * most, `backoff, ${backoff}`);
  }
});

test('an interval is section 2.4\'s greatest number on each draft, and a trigger on its fallback takes its poll\'s', () => {
  const of = (appId, key) => intervalOf(drafts(appId).find(item => item.key === key));
  assert.deepEqual([of('gmail', 'new-inbox-email'), of('gmail', 'new-email-matching-search'), of('slack', 'conversation-joined'), of('google-calendar', 'calendar-sharing-changed')], [120, 300, 600, 900]);
  assert.deepEqual([of('notion', 'schema-changed'), of('github', 'push'), of('google-calendar', 'calendar-list-changed')], [600, 60, 900], 'on their fallback');
  assert.equal(intervalOf({delivery: {method: 'polling', intervalSeconds: {default: 120, min: 60}}, poll: {minIntervalSeconds: 300}}), 300);
  assert.equal(intervalOf({delivery: {method: 'polling', intervalSeconds: {default: 60, min: 200}}, poll: {minIntervalSeconds: 30}}), 200);
});

test('a shared feed runs at the greatest interval of its triggers, never whichever comes first', async t => {
  const h = rig(t, {triggers: [...feedTriggers(), twin('feed-synced', 'feed-synced-slow', item => { item.delivery.intervalSeconds.default = 900; })]}), watch = h.start('feed-synced');
  assert.deepEqual(h.feedOf(watch).pollHash, h.itemOf('feed-synced-slow').pollHash);
  await h.settle(watch);
  assert.equal(h.feedOf(watch).nextPollAt, h.now + 900_000);
});

test('spec line 1804: x-poll-interval of 300 delays the next poll by at least 300 seconds, on a good answer and on a cut walk', async t => {
  const h = rig(t), watch = await running(h);
  h.simulator.pollInterval(300);
  await h.engine.tick();
  const asked = h.now, reads = h.feedReads().length;
  assert.equal(h.feedOf(watch).notBefore, asked + 300_000);
  h.simulator.pollInterval(null);
  h.advance(INTERVAL);
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads, 'past its interval, and short of the floor');
  h.advance(300_000 - INTERVAL);
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads + 1);
  const cut = rig(t, {triggers: edited('feed-synced', item => { pagesOf(item, 1); item.poll.source.steps[0].query.limit = {const: 2}; })}), other = cut.start('feed-synced');
  cut.simulator.seed(10);
  cut.simulator.pollInterval(300);
  await cut.engine.tick();
  const walked = cut.feedReads().length;
  assert.equal(cut.feedOf(other).nextPollAt, cut.now, 'a cut walk runs again at the next tick');
  cut.advance(SECOND);
  await cut.engine.tick();
  assert.equal(cut.feedReads().length, walked, 'unless the provider asked for longer');
  cut.advance(300_000);
  await cut.engine.tick();
  assert.equal(cut.feedReads().length, walked + 1);
});

test('a cut walk runs at the next tick, and a walk that reached the end keeps its interval', async t => {
  const h = rig(t, {triggers: edited('feed-synced', item => { pagesOf(item, 1); item.poll.source.steps[0].query.limit = {const: 2}; })}), watch = h.start('feed-synced');
  h.simulator.seed(3);
  await h.engine.tick();
  assert.equal(h.feedOf(watch).nextPollAt, h.now);
  h.advance(SECOND);
  await h.engine.tick();
  assert.equal(h.feedOf(watch).nextPollAt, h.now + INTERVAL);
});

test('a cut walk comes back at once only if its next poll starts further on: a drain does, and a read that would start from the same place waits its interval', async t => {
  const small = item => { pagesOf(item, 1); item.poll.source.steps[0].query.limit = {const: 2}; }, cases = [
    ['an asc walk, whose mark moved', 'feed-updated', {kinds: ['note']}, {}, 0],
    ['a history walk, whose last whole record moved', 'feed-logged', {}, {}, 0],
    ['a newest-first list, whose mark jumped to the present', 'feed-posted', {}, {}, INTERVAL],
    ['a window, which holds no place at all', 'feed-listed', {}, {windows: (appId, key) => key === 'feed-listed' ? {seconds: null, alerts: false} : null}, INTERVAL]];
  for (const [label, key, args, engine, wait] of cases) {
    const h = rig(t, {triggers: edited(key, small)}, engine), watch = await running(h, key, {args});
    h.simulator.seed(10);
    h.advance(SECOND);
    await h.engine.tick();
    assert.equal(h.runsOf(h.feedOf(watch)).at(-1).outcome, 'cut', label);
    assert.equal(h.feedOf(watch).nextPollAt, h.now + wait, label);
  }
});

test('a time-budget stop that kept its place waits its interval, and one on a walk with a page to come back to does not', async t => {
  const slowed = h => { const {request} = h.runtime; h.runtime.request = input => { h.advance(6000); return request(input); }; };
  const posted = rig(t, {triggers: edited('feed-posted', item => { item.poll.source.steps[0].query.limit = {const: 2}; })}), kept = await running(posted, 'feed-posted');
  posted.simulator.seed(40);
  slowed(posted);
  posted.advance(SECOND);
  const asked = posted.now;
  await posted.engine.tick();
  assert.equal(posted.runsOf(posted.feedOf(kept)).at(-1).outcome, 'cut');
  assert.equal(posted.feedOf(kept).nextPollAt, asked + INTERVAL, 'the mark stayed, so the next read starts where this one did');
  const synced = rig(t, {triggers: edited('feed-synced', item => { item.poll.source.steps[0].query.limit = {const: 2}; })}), walking = await running(synced);
  synced.simulator.seed(40);
  slowed(synced);
  synced.advance(SECOND);
  await synced.engine.tick();
  assert.equal(synced.runsOf(synced.feedOf(walking)).at(-1).outcome, 'cut');
  assert.equal(synced.feedOf(walking).nextPollAt, synced.now, 'its page token is a place to come back to');
});

test('a walk that made no progress waits its interval, however much was left: a repeat of the same record cannot get further', async t => {
  const h = rig(t, {triggers: edited('feed-logged', item => { pagesOf(item, 1); item.poll.enrich = {steps: [DETAIL()], max: 1}; })}), watch = await running(h, 'feed-logged');
  h.simulator.seed(3, {perRecord: 3});
  h.advance(SECOND);
  const asked = h.now;
  await h.engine.tick();
  assert.equal(h.runsOf(h.feedOf(watch)).at(-1).outcome, 'cut');
  assert.equal(h.feedOf(watch).nextPollAt, asked + INTERVAL, 'the first record is not whole yet, so the cursor stayed');
});

test('sleep: 50 missed intervals give one run, and a wake drains over several ticks', async t => {
  const h = rig(t), watch = await running(h), ids = copies(h, watch, 7), reads = h.feedReads().length;
  h.advance(50 * INTERVAL);
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads + 5, 'five of the eight now');
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads + 8, 'and the rest on the next tick');
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads + 8, 'each ran once');
  assert.ok(ids.every(id => h.store.get('triggerFeeds', id).nextPollAt === h.now + INTERVAL), 'each is an interval on from its one run');
});

test('a feed\'s next time is durable before its first request, so a crash in flight does not read it again at once', async t => {
  const h = rig(t), watch = await running(h), held = h.simulator.hold('GET /feed'), flight = h.engine.tick();
  await held.reached;
  assert.equal(h.feedOf(watch).nextPollAt, h.now + INTERVAL);
  held.release();
  await flight;
});

test('spec 1868: 5 polls a tick', async t => {
  const h = rig(t), watch = await running(h);
  copies(h, watch, 9);
  const reads = h.feedReads().length;
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads + 5);
});

test('spec 1868: a tick starts no poll once 30 seconds of it are spent, and what it did not start stays due', async t => {
  const h = rig(t), watch = await running(h), ids = copies(h, watch, 4), {request} = h.runtime;
  h.runtime.request = async (...args) => { h.advance(10_000); return request(...args); };
  const reads = h.feedReads().length, started = h.now;
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads + 3);
  assert.equal(h.now, started + 30_000);
  assert.deepEqual(ids.slice(2).map(id => h.store.get('triggerFeeds', id).nextPollAt), [started, started], 'the two it never started are still due');
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads + 5);
});

test('spec 1868: a poll that starts late in a tick ends with the tick', async t => {
  const h = rig(t), watch = await running(h), {request} = h.runtime, timeouts = [];
  copies(h, watch, 1);
  h.runtime.request = async (options, ...rest) => { timeouts.push(options.timeoutMs); if (timeouts.length === 1) h.advance(28_000); return request(options, ...rest); };
  await h.engine.tick();
  assert.equal(timeouts.length, 2);
  assert.ok(timeouts[1] <= 2_000, `a timeout of ${timeouts[1]} ms, with 2 seconds of the tick left`);
});

test('spec 1871: a tick stays within its time budget at 100 due feeds, and every feed gets its turn', async t => {
  const h = rig(t), watch = await running(h), ids = copies(h, watch, 99), {request} = h.runtime, audits = h.store.list('activity').length;
  h.runtime.request = async (...args) => { h.advance(10_000); return request(...args); };
  for (let count = 0; count < 34; count++) {
    const before = h.now;
    await h.engine.tick();
    assert.ok(h.now - before <= 30_000, `tick ${count} took ${h.now - before} ms`);
    h.advance(SECOND);
  }
  assert.ok(ids.every(id => h.store.get('triggerRuns', id)?.runs.length >= 1));
  assert.equal(h.store.list('activity').length, audits, 'spec 1872: and nothing here wrote an audit row');
});

test('an empty bucket leaves a feed due, marks it behind and takes no slot, so one app\'s backlog never starves another', async t => {
  const budgets = {fixture: {perMinute: 3}}, h = rig(t, {}, {budgets}), watch = await running(h);
  const other = otherAccount(h, 'fixture-account-2');
  await h.settle(other);
  h.advance(MINUTE + INTERVAL);
  const ids = copies(h, watch, 7), reads = h.feedReads().length;
  h.store.put('triggerFeeds', {...h.feedOf(other), nextPollAt: h.now + SECOND});
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads + 3, 'three requests a minute');
  const behind = [h.feedOf(watch), ...ids.map(id => h.store.get('triggerFeeds', id))].filter(feed => feed.behind);
  assert.equal(behind.length, 5, 'the other five stay due, marked behind');
  assert.ok(behind.every(feed => feed.nextPollAt <= h.now));
  h.advance(SECOND);
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads + 4, 'the other account\'s feed takes the slot, with five due before it');
  assert.equal(h.runsOf(h.feedOf(other)).length, 2);
  h.advance(MINUTE);
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads + 7, 'the bucket fills again with time');
  assert.equal([h.feedOf(watch), ...ids.map(id => h.store.get('triggerFeeds', id))].filter(feed => feed.behind).length, 2, 'and a feed read is no longer behind');
});

test('marking a feed behind writes once, not every second', async t => {
  const h = rig(t, {}, {budgets: {fixture: {perMinute: 1}}}), watch = await running(h);
  h.advance(MINUTE + INTERVAL);
  copies(h, watch, 1);
  await h.engine.tick();
  const writes = [], {put} = h.store;
  h.store.put = (...args) => { writes.push(args); return put.apply(h.store, args); };
  h.advance(SECOND);
  await h.engine.tick();
  h.advance(SECOND);
  await h.engine.tick();
  h.store.put = put;
  assert.equal(writes.length, 0);
});

test('a bucket counts every request of a poll, and an app with no budget has none', async t => {
  const h = rig(t, {triggers: edited('feed-synced', item => { item.poll.source.steps[0].query.limit = {const: 2}; })}, {budgets: {fixture: {perMinute: 1}}}), watch = await running(h);
  h.simulator.seed(10);
  h.advance(MINUTE + INTERVAL);
  await h.engine.tick();
  assert.equal(h.runsOf(h.feedOf(watch)).at(-1).requests, 5);
  h.advance(INTERVAL);
  const reads = h.feedReads().length;
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads, 'it spent past its minute, and waits for what it owes');
  assert.equal(h.feedOf(watch).behind, true);
  const free = rig(t), other = await running(free);
  copies(free, other, 4);
  const count = free.feedReads().length;
  await free.engine.tick();
  assert.equal(free.feedReads().length, count + 5);
});

test('Slack counts per workspace and method: two accounts in one workspace share a bucket, and another method or workspace has its own', async t => {
  const onItems = twin('feed-listed', 'feed-items', item => { item.poll.source.steps[0] = {...item.poll.source.steps[0], path: '/items', query: {}, page: {next: {pointer: '/nextPageToken'}, into: {query: 'pageToken'}, items: '/items', max: 10}}; });
  const h = rig(t, {triggers: [...feedTriggers(), onItems]}, {budgets: {fixture: {methods: {feed: 1, items: 1}}}});
  const a = otherAccount(h, 'workspace-a', 'feed-synced', {id: 'T1:U1'}), b = otherAccount(h, 'workspace-b', 'feed-synced', {id: 'T1:U2'}), c = otherAccount(h, 'workspace-c', 'feed-synced', {id: 'T2:U1'}), d = otherAccount(h, 'workspace-d', 'feed-items', {id: 'T1:U3'});
  await h.engine.tick();
  assert.deepEqual([a, b, c, d].map(watch => h.runsOf(h.feedOf(watch)).length), [1, 0, 1, 1]);
  assert.equal(h.feedOf(b).behind, true);
});

test('Slack: a method no bucket names has no bucket', async t => {
  const h = rig(t, {}, {budgets: {fixture: {methods: {'conversations.history': 1}}}}), watch = await running(h);
  copies(h, watch, 2);
  await h.engine.tick();
  assert.equal(h.runsOf(h.feedOf(watch)).length, 2);
});

test('GitHub: no poll while its remaining count is under 500, until its reset', async t => {
  const budgets = {fixture: {perMinute: 60, keepRemaining: 500}}, h = rig(t, {}, {budgets}), watch = await running(h), {sync} = h.feedOf(watch).cursors;
  const reset = Math.floor((h.now + 5 * MINUTE) / 1000);
  h.simulator.fail('GET /feed', {status: 200, headers: {'x-ratelimit-remaining': '499', 'x-ratelimit-reset': String(reset)}, data: {items: [], nextSyncToken: sync, historyId: '1'}});
  await h.engine.tick();
  const reads = h.feedReads().length;
  h.advance(INTERVAL);
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads, 'it holds');
  assert.equal(h.feedOf(watch).behind, true);
  h.advance(reset * 1000 - h.now);
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads + 1, 'the reset ends it');
  h.simulator.fail('GET /feed', {status: 200, headers: {'x-ratelimit-remaining': '500', 'x-ratelimit-reset': String(reset + 3600)}, data: {items: [], nextSyncToken: sync, historyId: '1'}});
  h.advance(INTERVAL);
  await h.engine.tick();
  h.advance(INTERVAL);
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads + 3, 'at 500 it reads on');
  h.simulator.fail('GET /feed', {status: 200, headers: {'x-ratelimit-remaining': '1'}, data: {items: [], nextSyncToken: sync, historyId: '1'}});
  h.advance(INTERVAL);
  await h.engine.tick();
  h.store.put('triggerFeeds', {...h.feedOf(watch), nextPollAt: h.now});
  h.advance(MINUTE - SECOND);
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads + 4, 'a count with no reset holds for a minute');
  h.advance(SECOND);
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads + 5);
});

// A crash, and what stays gone.
/** Makes the next write of a feed's cursors throw, as a crash between the two stores would. */
function crashAtCursor(h) {
  const {put} = h.store;
  let armed = true;
  h.store.put = (collection, document) => {
    if (armed && collection === 'triggerFeeds' && h.store.appended) { armed = false; h.store.put = put; throw new Error('crashed before the cursor moved'); }
    return put.call(h.store, collection, document);
  };
  const {appendPoll} = h.store;
  h.store.appendPoll = poll => { const answer = appendPoll.call(h.store, poll); h.store.appended = true; h.store.appendPoll = appendPoll; return answer; };
}

test('spec 1862: a crash between storing the events and moving the cursor stores no duplicate', async t => {
  const h = rig(t), watch = await running(h), {sync} = h.feedOf(watch).cursors;
  h.simulator.write({name: 'New'});
  crashAtCursor(h);
  await h.engine.tick();
  assert.equal(h.eventsOf(watch).length, 1);
  assert.equal(h.feedOf(watch).cursors.sync, sync, 'the crash left the cursor behind');
  await h.pass();
  assert.notEqual(h.feedOf(watch).cursors.sync, sync, 'the replay moved it');
  assert.equal(h.eventsOf(watch).length, 1, 'and found the seen rows current');
});

test('a crash after a gap was stored: the replay ends that gap at its own read, so what was written while Fabric was down sits inside it', async t => {
  const h = rig(t), watch = await running(h, 'feed-logged');
  h.simulator.expireCursors();
  crashAtCursor(h);
  await h.engine.tick();
  const {to} = h.gapsOf(watch)[0].payload.fields;
  h.advance(9 * HOUR);
  const written = h.now;
  h.simulator.write({name: 'Written while Fabric was down'});
  h.advance(SECOND);
  await h.engine.tick();
  const [gap, ...more] = h.gapsOf(watch);
  assert.deepEqual([gap.payload.fields.reason, more, h.eventsOf(watch)], ['resync', [], []]);
  assert.ok(Date.parse(gap.payload.fields.to) >= written, `written at ${new Date(written).toISOString()}, after the first end ${to}, and the gap reads ${gap.payload.fields.to}`);
});

test('spec 1862: the cursor never moves before the events are stored: a store that fails loses nothing', async t => {
  const h = rig(t), watch = await running(h), {sync} = h.feedOf(watch).cursors, {appendPoll} = h.store;
  h.simulator.write({name: 'New'});
  h.store.appendPoll = () => { h.store.appendPoll = appendPoll; throw new Error('disk full'); };
  await h.engine.tick();
  assert.equal(h.feedOf(watch).cursors.sync, sync);
  await h.pass();
  assert.equal(h.eventsOf(watch).length, 1, 'the next poll reads it again');
});

test('spec 1862: the same after a resync and after a stall: one gap, not two', async t => {
  const h = rig(t), watch = await running(h);
  h.simulator.expireCursors();
  crashAtCursor(h);
  await h.engine.tick();
  assert.equal(h.gapsOf(watch).length, 1, 'the walk replaced the cursor in this run, so its gap was stored with it');
  await h.pass();
  await h.pass();
  assert.equal(h.gapsOf(watch).length, 1, 'the replay computes the same key');
  const stalled = rig(t, {triggers: edited('feed-updated', item => { pagesOf(item, 1); item.poll.source.steps[0].query.limit = {const: 5}; })}), other = await running(stalled, 'feed-updated', {args: {kinds: ['note']}});
  stalled.simulator.seed(20, {spacingMs: 0});
  stalled.advance(2 * SECOND);
  await stalled.engine.tick();
  await stalled.pass();
  await stalled.pass();
  const gaps = stalled.gapsOf(other).length;
  assert.equal(gaps, 1);
  await stalled.pass();
  assert.equal(stalled.gapsOf(other).length, 1);
});

test('one feed\'s fault leaves the rest of the tick', async t => {
  const h = rig(t), a = await running(h, 'feed-synced'), b = await running(h, 'feed-listed'), {appendPoll} = h.store;
  h.store.put('triggerFeeds', {...h.feedOf(a), nextPollAt: h.now - HOUR});
  h.store.appendPoll = () => { h.store.appendPoll = appendPoll; throw new Error('disk full'); };
  await h.engine.tick();
  assert.equal(h.runsOf(h.feedOf(b)).length, 2, 'the second feed still ran');
});

test('a poll that ends after a subscription was removed writes nothing and recreates nothing', async t => {
  const h = rig(t), keeper = await running(h), leaver = h.start('feed-synced'), gone = h.start('feed-synced'), held = h.simulator.hold('GET /feed');
  h.simulator.write({name: 'New'});
  const flight = h.engine.tick();
  await held.reached;
  h.store.put('subscriptions', {...h.current(leaver), status: 'removed'});
  h.engine.detach(h.current(leaver));
  h.store.delete('subscriptions', gone.id);
  held.release();
  await flight;
  assert.equal(h.current(leaver).status, 'removed', 'a removed watch stays removed');
  assert.equal(h.store.get('subscriptions', gone.id), null, 'and a deleted record stays deleted');
  assert.equal(h.current(keeper).status, 'active');
  assert.equal(h.eventsOf(leaver).length, 0);
});

test('a watch that left during the await, whatever its new status, does not turn active', async t => {
  for (const status of ['removed', 'declined', 'expired']) {
    const h = rig(t), first = await running(h), leaver = h.start('feed-synced'), held = h.simulator.hold('GET /feed'), flight = h.engine.tick();
    await held.reached;
    h.store.put('subscriptions', {...h.current(leaver), status});
    held.release();
    await flight;
    assert.deepEqual([h.current(leaver).status, h.current(first).status], [status, 'active']);
  }
});

test('a feed removed during the await stays removed', async t => {
  const h = rig(t), watch = await running(h), id = h.current(watch).feeds[0], held = h.simulator.hold('GET /feed');
  h.simulator.write({name: 'New'});
  const flight = h.engine.tick();
  await held.reached;
  h.store.put('subscriptions', {...h.current(watch), status: 'removed'});
  h.engine.detach(h.current(watch));
  held.release();
  await flight;
  assert.deepEqual([h.store.get('triggerFeeds', id), h.store.get('triggerRuns', id), h.events().length], [null, null, 0]);
});

test('a pause during the await is never overwritten', async t => {
  const h = rig(t), watch = await running(h), held = h.simulator.hold('GET /feed'), flight = h.engine.tick();
  await held.reached;
  h.store.put('subscriptions', {...h.current(watch), status: 'paused', reason: 'owner_paused'});
  held.release();
  await flight;
  assert.deepEqual([h.current(watch).status, h.current(watch).reason], ['paused', 'owner_paused']);
});

test('a watch paused and resumed during the await has started again: that poll does not count for it', async t => {
  const h = rig(t), first = await running(h), joiner = h.start('feed-synced'), held = h.simulator.hold('GET /feed'), flight = h.engine.tick();
  await held.reached;
  h.store.put('subscriptions', {...h.current(joiner), status: 'paused', reason: 'owner_paused', revision: 2, pausedAt: new Date(h.now).toISOString()});
  h.engine.resume(h.current(joiner));
  held.release();
  await flight;
  assert.deepEqual([h.current(joiner).status, h.current(joiner).pending], ['starting', [h.feedOf(first).id]]);
});

test('a trigger that leaves the catalog during a poll stops being read, and the last gate says why', async t => {
  const h = rig(t), watch = await running(h, 'feed-logged-detail'), {catalog} = h, {request} = h.runtime;
  h.simulator.write({name: 'One'});
  h.simulator.write({name: 'Two'});
  h.runtime.request = async (options, ...rest) => { const answer = await request(options, ...rest); if (options.url.includes('/items/')) h.runtime.actions = {...catalog, triggerOf: () => null}; return answer; };
  await h.engine.tick();
  assert.equal(h.simulator.calls.filter(call => call.route === 'GET /items/{item_id}').length, 1);
  assert.deepEqual([h.current(watch).status, h.current(watch).reason, h.events().length], ['paused', 'definition_changed', 0]);
});

test('a joiner attached during the await keeps the lens it added to a running history feed', async t => {
  const h = rig(t), watch = await running(h, 'feed-logged');
  h.store.put('triggerFeeds', {...h.feedOf(watch), lenses: h.itemOf('feed-logged').lenses});
  const held = h.simulator.hold('GET /feed'), flight = h.engine.tick();
  await held.reached;
  const joiner = h.start('feed-logged-detail');
  held.release();
  await flight;
  assert.ok(h.feedOf(watch).lenses.includes(h.itemOf('feed-logged-detail').lenses[0]));
  assert.equal(h.current(joiner).status, 'starting');
});

// detach().
test('detach: a feed with another watch stays; the last one takes the feed, its runs and its seen rows', async t => {
  const h = rig(t), a = await running(h), b = await running(h);
  h.simulator.write({name: 'New'});
  await h.pass();
  const feed = h.feedOf(a), lens = feed.lenses[0], keys = () => h.store.seenRows(feed.id, lens, [...seenKeys(h, feed.id, lens)]).size;
  assert.equal(keys(), 1);
  h.store.put('subscriptions', {...h.current(a), status: 'removed'});
  h.engine.detach(h.current(a));
  assert.deepEqual(h.current(a).feeds, [], 'a removed watch names no feed');
  assert.ok(h.store.get('triggerFeeds', feed.id), 'the other watch holds it');
  h.store.put('subscriptions', {...h.current(b), status: 'paused', reason: 'owner_paused'});
  const c = h.start('feed-synced');
  h.store.put('subscriptions', {...h.current(c), status: 'removed'});
  h.engine.detach(h.current(c));
  assert.ok(h.store.get('triggerFeeds', feed.id), 'a paused watch holds it too, to resume on');
  h.store.put('subscriptions', {...h.current(b), status: 'removed'});
  h.engine.detach(h.current(b));
  assert.deepEqual([h.store.get('triggerFeeds', feed.id), h.store.get('triggerRuns', feed.id), keys()], [null, null, 0]);
});

test('detach: it expects a feed a disconnect already deleted, and a watch that is gone', async t => {
  const h = rig(t), watch = await running(h), held = h.current(watch);
  forgetTriggers(h.store, h.account, h.now);
  assert.deepEqual(h.current(watch).feeds, held.feeds, 'a disconnect leaves the lists');
  h.store.delete('subscriptions', watch.id);
  h.engine.detach(held);
  assert.equal(h.store.get('subscriptions', watch.id), null);
});

test('a lens with a watch on a list feed that goes unwatched stops being tracked, and a resume takes the next epoch', async t => {
  const enriched = twin('feed-listed', 'feed-listed-detail', item => { item.poll.enrich = {max: 25, steps: [DETAIL()]}; item.event = {...item.event, fields: {id: {item: '/id'}, name: {step: 'detail', pointer: '/name'}}}; });
  const h = rig(t, {triggers: [...feedTriggers(), enriched]}), detail = await running(h, 'feed-listed-detail'), feed = h.feedOf(detail), lens = h.itemOf('feed-listed-detail').lenses[0];
  const plain = h.engine.attach(h.watch('feed-listed', {status: 'starting'}));
  assert.equal(h.current(plain).feeds[0], feed.id, 'the plain lens is tracked on the feed the enrich lens made');
  await h.settle(plain);
  h.advance(INTERVAL);
  h.simulator.write({name: 'Seen by the detail lens'});
  await h.engine.tick();
  assert.ok(seenKeys(h, feed.id, lens).length);
  h.store.put('subscriptions', {...h.current(detail), status: 'paused', reason: 'owner_paused', pausedAt: new Date(h.now).toISOString()});
  await h.pass();
  assert.ok(!h.feedOf(plain).lenses.includes(lens), 'it writes no rows unwatched, so it stops being tracked');
  assert.equal(seenKeys(h, feed.id, lens).length, 0, 'and its rows go');
  assert.ok(h.feedOf(plain).lenses.includes(h.itemOf('feed-listed').lenses[0]), 'the plain lens stays, within its limit');
  const resumed = h.engine.resume(h.current(detail));
  assert.notEqual(resumed.feeds[0], feed.id);
  assert.equal(h.store.get('triggerFeeds', resumed.feeds[0]).epoch, feed.epoch + 1);
});

// A lens of its own.
test('a Resume that takes the next epoch leaves no feed behind: the old one goes with its runs and seen rows, unless another watch holds it', async t => {
  const triggers = [...feedTriggers(), twin('feed-synced', 'feed-synced-read', item => { item.poll.enrich = {max: 25, steps: [DETAIL()]}; })];
  const h = rig(t, {triggers}), held = await running(h), watch = h.start('feed-synced-read'), old = h.current(watch).feeds[0];
  await h.settle(watch);
  assert.notEqual(old, h.current(held).feeds[0], 'its first watch took a feed of its own');
  h.grant('client-2');
  const other = h.start('feed-synced-read', {clientId: 'client-2'}), lens = h.itemOf('feed-synced-read').lenses[0], plain = h.itemOf('feed-synced').lenses[0];
  await h.settle(other);
  for (const paused of [watch, other]) h.store.put('subscriptions', {...h.current(paused), status: 'paused', reason: 'owner_paused', pausedAt: new Date(h.now).toISOString()});
  h.store.put('subscriptions', {...h.current(held), feeds: [...h.current(held).feeds, old]});
  await h.pass();
  assert.deepEqual(h.store.get('triggerFeeds', old).lenses.includes(lens), false, 'nothing read it while it was paused, so it left the feed');
  const moved = h.engine.resume(h.current(watch));
  assert.notEqual(moved.feeds[0], old);
  assert.ok(h.store.get('triggerFeeds', old), 'another watch still holds it');
  h.store.put('subscriptions', {...h.current(held), feeds: h.current(held).feeds.filter(id => id !== old)});
  const last = h.engine.resume(h.current(other));
  assert.equal(last.feeds[0], moved.feeds[0]);
  assert.deepEqual([h.store.get('triggerFeeds', old), h.store.get('triggerRuns', old), seenKeys(h, old, plain)], [null, null, []], 'and the last one out takes it with it');
});

test('a lens added to a running feed takes the next epoch and baselines alone, with no false new event', async t => {
  const enriched = twin('feed-synced', 'feed-synced-detail', item => { item.poll.enrich = {max: 25, steps: [DETAIL()]}; item.dedupe = {kind: 'id'}; item.event = {...item.event, fields: {id: {item: '/id'}, name: {step: 'detail', pointer: '/name'}}}; });
  const h = rig(t, {triggers: [...feedTriggers(), enriched]});
  h.simulator.seed(3);
  const first = await running(h), late = h.start('feed-synced-detail');
  assert.notEqual(h.current(late).feeds[0], h.current(first).feeds[0]);
  assert.deepEqual([h.feedOf(late).epoch, h.feedOf(late).baselined], [1, false]);
  await h.settle(late);
  assert.equal(h.eventsOf(late).length, 0);
  h.advance(INTERVAL);
  h.simulator.write({name: 'New'});
  await h.engine.tick();
  assert.deepEqual([h.eventsOf(first).length, h.eventsOf(late).length], [1, 1]);
  const again = h.start('feed-synced-detail');
  assert.equal(h.current(again).feeds[0], h.current(late).feeds[0], 'the lowest epoch that tracks its lens');
});

test('a lens a limit dropped takes the next epoch, and a history feed takes a lens straight in', async t => {
  const h = rig(t), first = await running(h);
  h.store.put('triggerFeeds', {...h.feedOf(first), lenses: []});
  assert.equal(h.feedOf(h.start('feed-synced')).epoch, 1);
  const log = await running(h, 'feed-logged'), [own] = h.itemOf('feed-logged-detail').lenses;
  h.store.put('triggerFeeds', {...h.feedOf(log), lenses: h.itemOf('feed-logged').lenses});
  const detail = h.start('feed-logged-detail');
  assert.equal(h.feedOf(detail).id, h.feedOf(log).id);
  assert.equal(h.feedOf(detail).epoch, 0);
  assert.ok(h.feedOf(detail).lenses.includes(own));
});

test('a lens past its limit pauses only its own watches with too_many_items, and a lens with none is dropped with its rows', async t => {
  const h = rig(t), {appendPoll} = h.store, watch = await running(h, 'feed-logged'), detail = await running(h, 'feed-logged-detail');
  const [plain] = h.itemOf('feed-logged').lenses, [keys] = h.itemOf('feed-logged-keys').lenses;
  h.store.appendPoll = poll => ({...appendPoll.call(h.store, poll), overLimit: [{lens: plain, count: 5001}, {lens: keys, count: 5001}]});
  h.simulator.write({name: 'New'});
  await h.engine.tick();
  h.store.appendPoll = appendPoll;
  assert.deepEqual([h.current(watch).status, h.current(watch).reason, h.current(watch).detail], ['paused', 'too_many_items', 'seen_limit']);
  assert.equal(h.current(detail).status, 'active');
  assert.ok(!h.feedOf(detail).lenses.includes(keys), 'a lens nobody watches leaves the feed');
  assert.ok(h.feedOf(detail).lenses.includes(plain), 'one with a watch stays until a resume or a removal');
  assert.equal(h.eventsOf(detail).length, 1, 'and the feed reads on');
});

test('a lens refused by its transform pauses its own watches, and one with no watch is dropped', async t => {
  const h = rig(t), {runPoll} = h.catalog, watch = await running(h, 'feed-logged'), detail = await running(h, 'feed-logged-detail'), [plain] = h.itemOf('feed-logged').lenses, [keys] = h.itemOf('feed-logged-keys').lenses;
  h.runtime.actions = {...h.catalog, runPoll: async options => ({...await runPoll(options), lensPauses: [{lens: plain, code: 'too_large', reason: 'too_many_items'}, {lens: keys, code: 'too_large', reason: 'too_many_items'}]})};
  await h.engine.tick();
  assert.deepEqual([h.current(watch).status, h.current(watch).reason, h.current(watch).detail], ['paused', 'too_many_items', 'too_large']);
  assert.equal(h.current(detail).status, 'active');
  assert.ok(!h.feedOf(detail).lenses.includes(keys));
});

test('a refusal of one lens\'s enrich read pauses provider_refused, and the other watch still hears', async t => {
  const h = rig(t);
  h.setRow('fixture.keys.read', 'allow');
  const keys = await running(h, 'feed-logged-keys'), plain = await running(h, 'feed-logged');
  h.simulator.write({name: 'New'});
  h.simulator.fail('GET /keys', {status: 403, data: {error: 'no'}});
  await h.engine.tick();
  assert.deepEqual([h.current(keys).status, h.current(keys).reason, h.current(keys).detail], ['paused', 'provider_refused', 'http_403']);
  assert.deepEqual([h.current(plain).status, h.eventsOf(plain).length], ['active', 1]);
});

// resume().
for (const [label, key, args] of LONG) {
  test(`1,000 items of backlog on ${label}: a resumed watch gets none of it, one gap with the paused range, then the next write gives it one`, async t => {
    const h = rig(t, {triggers: edited(key, item => { pagesOf(item, 2); })}), watch = await running(h, key, {args}), pausedAt = new Date(h.now).toISOString();
    h.store.put('subscriptions', {...h.current(watch), status: 'paused', reason: 'owner_paused', pausedAt});
    h.simulator.seed(1000);
    h.advance(HOUR);
    const resumed = h.engine.resume(h.current(watch));
    assert.deepEqual([resumed.status, resumed.reason, resumed.pausedAt, resumed.revision], ['starting', undefined, pausedAt, 2]);
    const polls = await h.settle(watch);
    assert.ok(polls > 2, `its catch-up took ${polls} polls`);
    const [gap, ...more] = h.gapsOf(watch);
    assert.equal(more.length, 0, 'one gap');
    assert.deepEqual([gap.payload.fields.from, gap.payload.fields.to, gap.payload.fields.reason], [pausedAt, new Date(h.now).toISOString(), 'resume']);
    assert.equal(h.eventsOf(watch).length, 0, 'a window the owner forbade is never replayed');
    assert.equal(h.current(watch).pausedAt, undefined, 'and an active watch holds no paused time');
    h.advance(INTERVAL);
    h.simulator.write({name: 'Next'});
    h.advance(SECOND);
    await h.engine.tick();
    assert.deepEqual([h.eventsOf(watch).length, h.gapsOf(watch).length], [1, 1]);
  });
}

test('a resume over a backlog of 3 bounds gives one gap and no paused event, and the gap is kept by the longest retention of its feed', async t => {
  const h = rig(t, {triggers: [...edited('feed-updated', item => { pagesOf(item, 1); item.retention = {hours: 24}; }), twin('feed-updated', 'feed-updated-long', item => { pagesOf(item, 1); })]}), args = {kinds: ['note']}, watch = await running(h, 'feed-updated', {args});
  h.store.put('subscriptions', {...h.current(watch), status: 'paused', reason: 'owner_paused', pausedAt: new Date(h.now).toISOString()});
  h.simulator.seed(1500);
  h.advance(HOUR);
  h.engine.resume(h.current(watch));
  await h.settle(watch);
  assert.deepEqual([h.gapsOf(watch).length, h.eventsOf(watch).length], [1, 0]);
  assert.equal(h.gapsOf(watch)[0].expiresAt, h.now + 7 * DAY);
});

test('a replayed resume stores its gap once: a crash before active runs the last poll again', async t => {
  const h = rig(t), watch = await running(h), {put} = h.store;
  h.store.put('subscriptions', {...h.current(watch), status: 'paused', reason: 'owner_paused', pausedAt: new Date(h.now).toISOString()});
  h.engine.resume(h.current(watch));
  h.store.put = (collection, document) => { if (collection === 'subscriptions' && document.status === 'active') { h.store.put = put; throw new Error('crashed before active'); } return put.call(h.store, collection, document); };
  await h.engine.tick();
  assert.equal(h.current(watch).status, 'starting');
  assert.equal(h.gapsOf(watch).length, 1);
  await h.settle(watch);
  assert.equal(h.gapsOf(watch).length, 1);
});

test('a resume after a disconnect rebuilds the feeds and the pending list the disconnect left', async t => {
  const h = rig(t), watch = await running(h), id = h.current(watch).feeds[0];
  h.simulator.seed(2);
  forgetTriggers(h.store, h.account, h.now);
  assert.equal(h.store.get('triggerFeeds', id), null);
  h.grant();
  const resumed = h.engine.resume(h.current(watch));
  assert.deepEqual([resumed.feeds, resumed.pending, h.feedOf(watch).baselined], [[id], [id], false]);
  await h.settle(watch);
  assert.deepEqual([h.gapsOf(watch).length, h.eventsOf(watch).length], [1, 0]);
});

test('a resume leaves a watch that was removed as it is', t => {
  const h = rig(t), watch = h.watch('feed-synced', {status: 'removed'});
  assert.equal(h.engine.resume(watch).status, 'removed');
  assert.equal(h.store.list('triggerFeeds').length, 0);
  assert.equal(h.engine.resume({id: 'gone'}), null);
});

test('a pause found at a poll reports what no poll read: the gap starts at the last poll that reached the present', async t => {
  const h = rig(t), watch = await running(h, 'feed-logged');
  await h.engine.tick();
  const read = h.now;
  h.advance(30 * SECOND);
  const missed = h.simulator.write({name: 'Written after the last read, before the pause'});
  h.advance(30 * SECOND);
  h.setRow('fixture.items.read', 'deny');
  await h.pass();
  assert.equal(h.current(watch).status, 'paused');
  assert.deepEqual(h.eventsOf(watch), [], 'nothing read it');
  assert.ok(Date.parse(h.current(watch).pausedAt) > read);
  h.setRow('fixture.items.read', 'allow');
  h.store.put('subscriptions', {...h.current(watch), authority: authorityOf(h.current(watch), h.connection(), h.permissions.triggerDecision(h.connection(), h.entryOf('feed-logged')))});
  h.engine.resume(h.current(watch));
  await h.settle(watch);
  assert.deepEqual(h.eventsOf(watch), [], 'a window the owner forbade is never replayed');
  const [gap] = h.gapsOf(watch);
  assert.equal(gap.payload.fields.from, new Date(read).toISOString(), `${missed.id} sits inside the range the agent is told of`);
  assert.equal(gap.dedupeKey, `gap|resume|${gap.payload.fields.from}`);
  assert.equal(h.current(watch).heardTo, undefined, 'an active watch holds no such time');
});

test('a watch paused again before it reached the present keeps when it last heard everything', async t => {
  const h = rig(t), watch = await running(h, 'feed-logged');
  await h.engine.tick();
  const read = h.now;
  h.store.put('backgroundPolicies', {id: h.account, connectionId: h.account, mode: 'deny', updatedAt: 'x'});
  await h.pass();
  assert.equal(h.current(watch).heardTo, read);
  h.store.put('backgroundPolicies', {id: h.account, connectionId: h.account, mode: 'allow', updatedAt: 'y'});
  h.engine.resume(h.current(watch));
  h.store.put('triggerFeeds', {...h.feedOf(watch), readAt: h.now});
  h.store.put('backgroundPolicies', {id: h.account, connectionId: h.account, mode: 'deny', updatedAt: 'z'});
  await h.pass();
  assert.deepEqual([h.current(watch).status, h.current(watch).heardTo], ['paused', read]);
});

test('a feed\'s read time moves only with a poll that reached the present and stored what it read', async t => {
  const h = rig(t, {triggers: edited('feed-synced', item => { pagesOf(item, 2); })}), watch = await running(h), feed = h.feedOf(watch), at = feed.readAt;
  assert.equal(typeof at, 'number');
  h.simulator.seed(1000);
  await h.engine.tick();
  assert.equal(h.feedOf(watch).readAt, at, 'a cut walk has not reached it');
  for (let count = 0; count < 20 && h.feedOf(watch).page; count++) { h.advance(SECOND); await h.engine.tick(); }
  const done = h.runsOf(h.feedOf(watch)).at(-1).at;
  assert.equal(h.feedOf(watch).readAt, done, 'a poll reads to when it started, which is the run\'s time');
  h.advance(INTERVAL);
  h.simulator.hold('GET /feed');
  const running2 = h.engine.tick(), {holds} = h.simulator;
  await holds.get('GET /feed').reached;
  h.setRow('fixture.items.read', 'deny');
  holds.get('GET /feed').release();
  await running2;
  assert.equal(h.current(watch).status, 'paused');
  assert.equal(h.feedOf(watch).readAt, done, 'and one that stored nothing has read nothing');
});

test('a feed has read to when its poll started, since what was written during a poll may sit on a page already read', async t => {
  const h = rig(t), watch = await running(h, 'feed-logged'), {request} = h.runtime, started = h.now;
  h.runtime.request = async (...args) => { h.advance(5 * SECOND); return request(...args); };
  await h.engine.tick();
  assert.ok(h.now > started);
  assert.equal(h.feedOf(watch).readAt, started);
});

test('a pause with several feeds reports from the one read longest ago, and a feed never read says nothing', async t => {
  const h = rig(t), watch = h.start('feed-updated', {args: {kinds: ['note', 'task']}});
  await h.settle(watch);
  const [first, second] = h.current(watch).feeds;
  h.store.put('triggerFeeds', {...h.store.get('triggerFeeds', first), readAt: h.now - 5 * MINUTE});
  h.store.put('triggerFeeds', {...h.store.get('triggerFeeds', second), readAt: h.now - MINUTE});
  h.store.put('backgroundPolicies', {id: h.account, connectionId: h.account, mode: 'deny', updatedAt: 'x'});
  await h.pass();
  assert.equal(h.current(watch).heardTo, h.now - INTERVAL - 5 * MINUTE);
  const fresh = h.start('feed-synced');
  h.store.put('backgroundPolicies', {id: h.account, connectionId: h.account, mode: 'deny', updatedAt: 'y'});
  await h.pass();
  assert.deepEqual([h.current(fresh).status, h.current(fresh).heardTo], ['paused', undefined]);
});

test('a lost place starts at the earlier of the two times, or at the one a feed has', () => {
  for (const [feed, expected] of [[{lastGoodAt: 5, readAt: 3}, 3], [{lastGoodAt: 3, readAt: 5}, 3], [{lastGoodAt: 5, readAt: null}, 5], [{lastGoodAt: null, readAt: 3}, 3], [{lastGoodAt: 5}, 5], [{readAt: 3}, 3], [{}, null]]) assert.equal(placeLostAt(feed), expected, JSON.stringify(feed));
});

test('a place lost partway through a drain reports what the drain had not reached: the gap starts at the last poll that reached the present', async t => {
  const h = rig(t, {triggers: edited('feed-logged', item => { pagesOf(item, 1); })}), watch = await running(h, 'feed-logged');
  await h.engine.tick();
  const read = h.feedOf(watch).readAt;
  h.advance(HOUR);
  h.simulator.seed(1000);
  await h.engine.tick();
  const drained = h.feedOf(watch);
  assert.equal(drained.lastGoodAt, h.now, 'the cursor moved, so lastGoodAt did');
  assert.equal(drained.readAt, read, 'but that poll did not reach the present');
  h.advance(SECOND);
  h.simulator.expireCursors();
  await h.engine.tick();
  const [gap] = h.gapsOf(watch);
  assert.deepEqual([gap.payload.fields.reason, gap.payload.fields.from], ['resync', new Date(read).toISOString()]);
  assert.equal(gap.dedupeKey, `gap|resync|${gap.payload.fields.from}`);
});

test('a Resume of a feed that lost its place partway through a drain tells the other watch from the same time', async t => {
  const h = rig(t), watch = await running(h, 'feed-logged'), other = h.watch('feed-logged', {status: 'active', clientId: 'client-2', feeds: h.current(watch).feeds}), [id] = h.current(watch).feeds;
  h.grant('client-2');
  h.store.put('triggerFeeds', {...h.feedOf(watch), lastGoodAt: h.now, readAt: h.now - HOUR, cursorInvalid: true});
  h.store.put('subscriptions', {...h.current(watch), status: 'paused', reason: 'cursor_invalid', pausedAt: new Date(h.now).toISOString()});
  h.engine.resume(h.current(watch));
  await h.settle(watch);
  assert.equal(h.gapsOf(other)[0].payload.fields.from, new Date(h.now - HOUR).toISOString());
  assert.ok(h.store.get('triggerFeeds', id));
});

test('a lens refused mid-page keeps the gap its Resume owes from its last read, though the other lens carried that poll to the present', async t => {
  const h = rig(t), detail = h.start('feed-logged-detail'), plain = h.start('feed-logged');
  await h.settle(detail);
  await h.settle(plain);
  h.advance(INTERVAL);
  await h.engine.tick();
  const read = h.feedOf(detail).readAt;
  h.advance(20 * SECOND);
  const items = [h.simulator.write({name: 'One'}), h.simulator.write({name: 'Two'})], written = h.now;
  h.simulator.fail('GET /items/{item_id}', {status: 403, data: {error: 'no'}});
  await h.pass();
  assert.deepEqual([h.current(detail).status, h.current(detail).reason, h.eventsOf(plain).map(row => row.payload.id), h.eventsOf(detail)], ['paused', 'provider_refused', items.map(item => item.id), []]);
  assert.ok(h.feedOf(detail).readAt > written, 'the other lens moved the feed past both writes');
  assert.equal(h.current(detail).heardTo, read, 'this watch last heard before them');
  h.advance(HOUR);
  h.engine.resume(h.current(detail));
  await h.settle(detail);
  const [gap] = h.gapsOf(detail);
  assert.ok(Date.parse(gap.payload.fields.from) < written, `each write sits inside the gap: ${gap.payload.fields.from}`);
});

test('a lens past its seen limit keeps its gap from its last read too', async t => {
  const h = rig(t), detail = h.start('feed-logged-detail'), plain = h.start('feed-logged');
  await h.settle(detail);
  await h.settle(plain);
  h.advance(INTERVAL);
  await h.engine.tick();
  const read = h.feedOf(detail).readAt, {appendPoll} = h.store, [lens] = h.itemOf('feed-logged-detail').lenses;
  h.store.appendPoll = options => ({...appendPoll.call(h.store, options), overLimit: [{lens, count: 5001}]});
  h.simulator.write({name: 'One'});
  await h.pass();
  h.store.appendPoll = appendPoll;
  assert.deepEqual([h.current(detail).status, h.current(detail).reason, h.current(detail).heardTo], ['paused', 'too_many_items', read]);
});

test('a real item whose event fails reaches the agent as a gap, with one event for the item beside it and none for it after', async t => {
  const h = rig(t), watch = await running(h), good = h.simulator.write({name: 'Good'}), bad = h.simulator.write({name: 'Bad'}), written = h.now;
  h.simulator.touch(bad.id, {name: {not: 'text'}});
  await h.pass();
  assert.deepEqual(h.eventsOf(watch).map(row => row.payload.id), [good.id]);
  const [gap, ...more] = h.gapsOf(watch);
  assert.deepEqual([gap.payload.fields.reason, more], ['stall', []]);
  assert.ok(Date.parse(gap.payload.fields.from) <= written && Date.parse(gap.payload.fields.to) >= written, 'the write sits inside the gap');
  await h.pass();
  assert.equal(h.gapsOf(watch).length, 1);
});

test('a watch paused again before it reached the present keeps its first paused time', async t => {
  const h = rig(t), watch = await running(h), first = new Date(h.now).toISOString();
  h.store.put('subscriptions', {...h.current(watch), status: 'paused', reason: 'owner_paused', pausedAt: first});
  h.advance(HOUR);
  h.engine.resume(h.current(watch));
  h.store.put('backgroundPolicies', {id: h.account, connectionId: h.account, mode: 'deny', updatedAt: 'x'});
  await h.engine.tick();
  assert.deepEqual([h.current(watch).status, h.current(watch).pausedAt], ['paused', first]);
  h.store.put('backgroundPolicies', {id: h.account, connectionId: h.account, mode: 'allow', updatedAt: 'y'});
  h.advance(HOUR);
  h.engine.resume(h.current(watch));
  await h.settle(watch);
  assert.equal(h.gapsOf(watch)[0].payload.fields.from, first);
});

test('spec 1870: a resume from cursor_invalid starts again from now: it drops the cursors and the page, baselines, and tells any other live watch of the gap, once', async t => {
  const h = rig(t), watch = await running(h), lastGood = h.feedOf(watch).lastGoodAt;
  h.simulator.fail('GET /feed', {status: 200, data: {items: [], nextSyncToken: 'bad\ntoken'}});
  await h.engine.tick();
  assert.equal(h.current(watch).reason, 'cursor_invalid');
  const other = h.start('feed-synced');
  await h.settle(other);
  h.simulator.write({name: 'In the gap'});
  h.advance(SECOND);
  h.engine.resume(h.current(watch));
  assert.deepEqual([h.feedOf(watch).cursors, h.feedOf(watch).page, h.feedOf(watch).baselined], [{}, null, false]);
  assert.equal(h.gapsOf(other).length, 0, 'the watch that kept running hears when the feed has found its place again');
  await h.settle(watch);
  assert.equal(h.gapsOf(other).length, 1);
  assert.equal(h.gapsOf(other)[0].payload.fields.from, new Date(lastGood).toISOString());
  assert.equal(h.gapsOf(other)[0].payload.fields.reason, 'resync');
  assert.deepEqual([h.eventsOf(watch).length, h.eventsOf(other).length], [0, 0], 'the baseline fires nothing');
  assert.equal(h.gapsOf(watch).length, 1, 'and the resumed watch has its own');
  h.advance(INTERVAL);
  h.simulator.write({name: 'After'});
  h.advance(SECOND);
  await h.engine.tick();
  assert.deepEqual([h.eventsOf(watch).length, h.eventsOf(other).length], [1, 1]);
  h.store.put('subscriptions', {...h.current(watch), status: 'paused', reason: 'owner_paused', pausedAt: new Date(h.now).toISOString()});
  h.engine.resume(h.current(watch));
  assert.equal(h.feedOf(watch).baselined, true, 'only a feed that lost its place starts again');
});

test('a Resume that starts a feed over ends the other watch\'s gap when the baseline ends, so a write before that sits inside it', async t => {
  const h = rig(t), a = await running(h);
  h.simulator.fail('GET /feed', {status: 200, data: {items: [], nextSyncToken: 'bad\ntoken'}});
  await h.engine.tick();
  const b = h.start('feed-synced');
  await h.settle(b);
  h.advance(INTERVAL);
  await h.engine.tick();
  h.simulator.fail('GET /feed', {status: 429, headers: {'retry-after': '1800'}, data: {error: 'slow'}});
  await h.pass();
  h.advance(5 * SECOND);
  h.engine.resume(h.current(a));
  h.advance(10 * SECOND);
  const written = h.now;
  h.simulator.write({name: 'Written while the feed had no place'});
  for (let count = 0; count < 16; count++) await h.pass();
  assert.deepEqual([h.current(a).status, h.current(b).status, h.eventsOf(b)], ['active', 'active', []], 'the baseline is silent, and nothing runs twice');
  const [gap, ...more] = h.gapsOf(b);
  assert.deepEqual([gap.payload.fields.reason, more], ['resync', []]);
  assert.ok(Date.parse(gap.payload.fields.to) >= written, `the write at ${new Date(written).toISOString()} sits inside a gap ending ${gap.payload.fields.to}`);
  assert.equal(h.feedOf(b).lostFrom, null, 'once');
});

test('a baseline over several polls owes its gap until the last of them', async t => {
  const h = rig(t, {triggers: edited('feed-synced', item => { item.bounds.pages = 1; item.poll.source.steps[0].page.max = 1; })}), a = await running(h);
  h.simulator.fail('GET /feed', {status: 200, data: {items: [], nextSyncToken: 'bad\ntoken'}});
  await h.engine.tick();
  const b = h.start('feed-synced');
  await h.settle(b);
  h.engine.resume(h.current(a));
  h.simulator.seed(120);
  h.advance(INTERVAL);
  await h.engine.tick();
  assert.deepEqual([h.feedOf(b).baselined, h.gapsOf(b)], [false, []], 'the first page of three has not found the place');
  await h.settle(a);
  assert.deepEqual(h.gapsOf(b).map(row => row.payload.fields.reason), ['resync']);
});

test('a feed with no other watch owes nobody a resync gap, and the resumed watch has only its own', async t => {
  const h = rig(t), a = await running(h);
  h.simulator.fail('GET /feed', {status: 200, data: {items: [], nextSyncToken: 'bad\ntoken'}});
  await h.engine.tick();
  h.engine.resume(h.current(a));
  await h.settle(a);
  assert.deepEqual([h.gapsOf(a).map(row => row.payload.fields.reason), h.feedOf(a).lostFrom], [['resume'], null]);
});

test('a resume reads back a feed\'s bad place once, whichever watch comes first', async t => {
  const h = rig(t), a = await running(h), b = await running(h);
  h.store.put('triggerFeeds', {...h.feedOf(a), cursors: {sync: 'bad\ncursor'}});
  await h.engine.tick();
  h.engine.resume(h.current(a));
  await h.settle(a);
  const {sync} = h.feedOf(a).cursors;
  h.engine.resume(h.current(b));
  assert.deepEqual([h.feedOf(b).cursors.sync, h.feedOf(b).baselined], [sync, true]);
});

test('a resume that lands during a poll\'s await wins: the poll stores nothing over the fresh start', async t => {
  const h = rig(t), a = await running(h), b = await running(h);
  h.store.put('triggerFeeds', {...h.feedOf(a), cursorInvalid: true});
  h.store.put('subscriptions', {...h.current(a), status: 'paused', reason: 'cursor_invalid', pausedAt: new Date(h.now).toISOString()});
  const held = h.simulator.hold('GET /feed'), flight = h.engine.tick();
  await held.reached;
  h.engine.resume(h.current(a));
  held.release();
  await flight;
  assert.deepEqual([h.feedOf(a).cursors, h.feedOf(a).baselined], [{}, false]);
  assert.equal(h.current(b).status, 'active');
});

test('notify wakes each client whose events were stored, once a poll has landed', async t => {
  const h = rig(t), watch = await running(h), woken = [];
  h.grant('client-2');
  h.engine.notify = clientId => { woken.push([clientId, h.feedOf(watch).cursors.sync !== undefined]); };
  await h.engine.tick();
  assert.deepEqual(woken, [], 'nothing new, nobody woken');
  h.simulator.write({name: 'New'});
  h.advance(INTERVAL);
  await h.engine.tick();
  assert.deepEqual(woken, [['client-1', true]]);
  h.store.put('subscriptions', {...h.current(watch), status: 'paused', reason: 'owner_paused', pausedAt: new Date(h.now).toISOString()});
  h.engine.resume(h.current(watch));
  woken.length = 0;
  await h.engine.tick();
  assert.deepEqual(woken.map(([client]) => client), ['client-1'], 'a resume\'s gap wakes too');
});

// pollNow(), start() and stop().
test('pollNow: the same path, ignoring nextPollAt, and it answers the watch as it stands', async t => {
  const h = rig(t), watch = h.start('feed-synced');
  assert.equal((await h.engine.pollNow(watch.id)).status, 'active');
  h.simulator.write({name: 'New'});
  assert.ok(h.feedOf(watch).nextPollAt > h.now);
  await h.engine.pollNow(watch.id);
  assert.equal(h.eventsOf(watch).length, 1);
  assert.equal(await h.engine.pollNow('gone'), null);
});

test('pollNow never ignores the gate: Background at Never pauses, and nothing is sent', async t => {
  const h = rig(t), watch = await running(h), reads = h.feedReads().length;
  h.store.put('backgroundPolicies', {id: h.account, connectionId: h.account, mode: 'deny', updatedAt: 'x'});
  assert.equal((await h.engine.pollNow(watch.id)).reason, 'background_off');
  assert.equal(h.feedReads().length, reads);
  await h.engine.pollNow(watch.id);
  assert.equal(h.feedReads().length, reads, 'a paused watch reads nothing');
});

test('pollNow waits out feed.wait and the x-poll-interval floor', async t => {
  const h = rig(t), watch = await running(h), slept = [];
  h.runtime.wait = async ms => { slept.push(ms); h.advance(ms); };
  h.simulator.pollInterval(300);
  await h.engine.pollNow(watch.id);
  h.simulator.pollInterval(null);
  const floor = h.feedOf(watch).notBefore;
  await h.engine.pollNow(watch.id);
  assert.equal(slept.length, 1);
  assert.equal(h.now, floor, 'it slept to the floor, and no longer');
  h.simulator.fail('GET /feed', {status: 429, headers: {'retry-after': '600'}, data: {error: 'slow'}});
  await h.engine.pollNow(watch.id);
  const {until} = h.feedOf(watch).wait;
  await h.engine.pollNow(watch.id);
  assert.ok(h.now >= until);
  assert.equal(h.feedOf(watch).wait, null);
});

test('pollNow and a tick take turns: neither runs while the other does', async t => {
  const h = rig(t), watch = await running(h), held = h.simulator.hold('GET /feed'), flight = h.engine.tick();
  await held.reached;
  let done = false;
  const now = h.engine.pollNow(watch.id).then(() => { done = true; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(done, false);
  assert.equal(h.feedReads().length, 2, 'the baseline and the one in flight');
  held.release();
  await flight;
  await now;
  assert.equal(h.feedReads().length, 3);
});

test('stop() waits for a running poll, and no poll starts after it', async t => {
  const h = rig(t), watch = await running(h);
  copies(h, watch, 1);
  const held = h.simulator.hold('GET /feed'), flight = h.engine.tick();
  await held.reached;
  let stopped = false;
  const stopping = h.engine.stop().then(() => { stopped = true; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(stopped, false, 'it waits');
  held.release();
  await stopping;
  await flight;
  const reads = h.feedReads().length;
  assert.equal(reads, 2, 'the baseline and the poll it waited for: the second due feed never started');
  h.advance(DAY);
  await h.engine.tick();
  assert.equal(h.feedReads().length, reads, 'a stopped engine does not tick');
});

test('start(): one immediate tick and a one-second timer that keeps nothing alive; stop() clears it', async t => {
  const h = rig(t), watch = h.start('feed-synced');
  h.engine.start();
  assert.equal(h.engine.timer.hasRef(), false);
  await h.engine.running;
  assert.equal(h.current(watch).status, 'active', 'the first tick came at once');
  await h.engine.stop();
  assert.equal(h.engine.timer, null);
});

test('in a certification Fabric start() runs no timer and no tick: polls run only through pollNow', async t => {
  const h = rig(t, {}, {certification: true}), watch = h.start('feed-synced');
  h.engine.start();
  await h.engine.running;
  assert.deepEqual([h.engine.timer, h.feedReads().length, h.current(watch).status], [null, 0, 'starting']);
  assert.equal((await h.engine.pollNow(watch.id)).status, 'active');
  await h.engine.stop();
});

test('credentials never appear in an event, a run, a feed or a seen row', async t => {
  const h = rig(t), watch = await running(h);
  h.simulator.write({name: 'New'});
  await h.engine.tick();
  const feed = h.feedOf(watch), written = JSON.stringify([h.events(), h.store.get('triggerRuns', feed.id), feed, h.current(watch)]);
  assert.equal(written.includes(TOKEN), false);
  assert.equal(JSON.stringify(h.store.db.prepare('SELECT * FROM trigger_seen').all()).includes(TOKEN), false);
});

test('the engine stays outside the action wall, and reaches a trigger only through the catalog', () => {
  const imports = readFileSync(new URL('../lib/trigger-engine.mjs', import.meta.url), 'utf8').match(/from '[^']+'/g) ?? [];
  assert.deepEqual(imports.map(text => text.slice(6, -1)).sort(), ['./compiler.mjs', './retention.mjs', './trigger-gate.mjs', './trigger-rules.mjs']);
});

// server.mjs: no test here listens on a port.
test('createApp builds the engine and starts nothing; listening starts it beside the heartbeats; close() waits for it before the store closes', async t => {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-trigger-server-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const app = await createApp({dataDir: path.join(root, 'data'), port: 0});
  assert.ok(app.triggers instanceof TriggerEngine);
  assert.deepEqual([app.triggers.timer, app.triggers.store, app.triggers.runtime], [null, app.store, app.runtime], 'createApp alone starts nothing');
  app.server.listen = (port, host, ready) => ready();
  await app.start();
  assert.notEqual(app.triggers.timer, null);
  assert.equal(app.store.list('triggerFeeds').length, 0);
  let release, closed = false;
  app.triggers.running = new Promise(resolve => { release = resolve; });
  const closing = app.close().then(() => { closed = true; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(closed, false, 'the store stays open under a running poll');
  assert.equal(app.triggers.timer, null);
  release();
  await closing;
});

test('server.mjs tells the engine when it is a certification Fabric', () => {
  assert.ok(readFileSync(new URL('../server.mjs', import.meta.url), 'utf8').includes('new TriggerEngine({store,runtime,clock,certification:Boolean(certification)})'));
});

// The outcome table, through the scheduler.
test('a 304 is a no-op: the run is recorded, the cursor and the rows stay, and the feed keeps its interval', async t => {
  const h = rig(t), watch = await running(h, 'feed-tagged');
  h.simulator.write({name: 'One'});
  await h.engine.tick();
  await h.pass();
  const {etag} = h.feedOf(watch).cursors;
  assert.ok(etag);
  await h.pass();
  const run = h.runsOf(h.feedOf(watch)).at(-1);
  assert.deepEqual([run.outcome, run.status, h.feedOf(watch).cursors.etag, h.feedOf(watch).failures, h.feedOf(watch).nextPollAt], ['not_modified', 304, etag, 0, h.now + INTERVAL]);
  assert.equal(h.eventsOf(watch).length, 1);
});

test('spec 1864: a 410 re-baselines, stores one gap and keeps its seen rows, and the feed reads on', async t => {
  const h = rig(t), watch = await running(h);
  h.simulator.write({name: 'Old'});
  await h.engine.tick();
  const feed = h.feedOf(watch), rows = seenKeys(h, feed.id, feed.lenses[0]).length;
  h.simulator.expireCursors();
  h.advance(INTERVAL);
  await h.engine.tick();
  assert.deepEqual([h.gapsOf(watch).length, h.eventsOf(watch).length, h.current(watch).status], [1, 1, 'active']);
  assert.equal(seenKeys(h, feed.id, feed.lenses[0]).length, rows);
  h.advance(INTERVAL);
  h.simulator.write({name: 'New'});
  await h.engine.tick();
  assert.deepEqual([h.gapsOf(watch).length, h.eventsOf(watch).length], [1, 2]);
});

test('spec 1864, with a seed: a 404 replaces the cursor in one run, and an item written just after it fires on the next poll', async t => {
  const h = rig(t), watch = await running(h, 'feed-logged');
  h.simulator.expireCursors();
  await h.engine.tick();
  assert.deepEqual([h.gapsOf(watch).length, h.runsOf(h.feedOf(watch)).at(-1).outcome], [1, 'resynced']);
  h.simulator.write({name: 'Just after'});
  await h.pass();
  assert.deepEqual([h.eventsOf(watch).length, h.gapsOf(watch).length], [1, 1]);
});

test('a status outside statusIn pauses and re-baselines nothing', async t => {
  const h = rig(t), watch = await running(h), {sync} = h.feedOf(watch).cursors;
  h.simulator.fail('GET /feed', {status: 404, data: {error: 'gone'}});
  await h.engine.tick();
  assert.deepEqual([h.current(watch).status, h.current(watch).reason, h.feedOf(watch).cursors.sync, h.feedOf(watch).baselined, h.gapsOf(watch).length], ['paused', 'provider_refused', sync, true, 0]);
});

test('A to B to A to B fires each change across polls, and a replay after a crash fires none twice', async t => {
  const h = rig(t, {triggers: edited('feed-listed', item => { item.dedupe = {kind: 'content-hash', fields: [{item: '/name'}]}; })}), [item] = (() => h.simulator.seed(1, {name: 'A'}))(), watch = await running(h, 'feed-listed');
  h.simulator.touch(item.id, {name: 'B'});
  await h.engine.tick();
  h.simulator.touch(item.id, {name: 'A'});
  crashAtCursor(h);
  await h.pass();
  await h.pass();
  assert.equal(h.eventsOf(watch).length, 2);
  h.simulator.touch(item.id, {name: 'B'});
  await h.pass();
  assert.equal(h.eventsOf(watch).length, 3, 'a true return to B has its own key');
  assert.deepEqual(new Set(h.eventsOf(watch).map(row => row.dedupeKey)).size, 3);
});

test('a shorter wait never cuts a longer one that a feed already holds', async t => {
  const h = rig(t), a = await running(h, 'feed-synced'), b = await running(h, 'feed-listed'), until = h.now + DAY;
  h.store.put('triggerFeeds', {...h.feedOf(b), wait: {until, reason: 'limited'}, nextPollAt: h.now + HOUR});
  h.simulator.fail('GET /feed', {status: 429, headers: {'retry-after': '600'}, data: {error: 'slow'}});
  await h.engine.tick();
  assert.ok(h.feedOf(a).wait.until < until);
  assert.equal(h.feedOf(b).wait.until, until);
});

test('attach leaves a watch that is active, or no longer wants its feeds, as it is', async t => {
  const h = rig(t), watch = await running(h), {feeds} = h.current(watch);
  assert.deepEqual([h.engine.attach(h.current(watch)).status, h.current(watch).pending], ['active', []]);
  for (const status of ['removed', 'declined', 'expired', 'awaiting_approval']) {
    const other = h.watch('feed-listed', {status});
    assert.deepEqual([h.engine.attach(other).status, h.current(other).feeds], [status, []], status);
  }
  assert.deepEqual(h.current(watch).feeds, feeds);
});

// What survived the first hand breaks of the scheduler.
const POLL_FIELDS = {floor: '2026-10-23T09:00:01.000Z', draining: true, budgetStops: 2, recordFailures: 3, notBefore: 1, lastGoodAt: 2, cursors: {sync: 's7'}, page: {token: 'p9', walk: 'delta'}, baselined: true};
test('every feed field of a poll\'s return lands on the feed', async t => {
  const h = rig(t), watch = await running(h), {runPoll} = h.catalog;
  h.runtime.actions = {...h.catalog, runPoll: async options => ({...await runPoll(options), ...POLL_FIELDS})};
  await h.engine.tick();
  const feed = h.feedOf(watch);
  assert.deepEqual(Object.fromEntries(Object.keys(POLL_FIELDS).map(name => [name, feed[name]])), POLL_FIELDS);
});

for (const [outcome, fails] of [['limited', true], ['backoff', true], ['skipped', true], ['scope_missing', true], ['done', false], ['not_modified', false], ['resynced', false], ['withheld', false]]) {
  test(`a poll that ends ${outcome} ${fails ? 'backs off' : 'keeps its interval'}, whatever the last gate says`, async t => {
    const h = rig(t), watch = await running(h), {runPoll} = h.catalog;
    h.runtime.actions = {...h.catalog, runPoll: async options => ({...await runPoll(options), outcome})};
    await h.engine.tick();
    assert.deepEqual([h.feedOf(watch).failures, h.feedOf(watch).nextPollAt], fails ? [1, h.now + 2 * INTERVAL] : [0, h.now + INTERVAL]);
  });
}

test('a skip at a mid-poll gate backs off, though the account is back by the last gate', async t => {
  const h = rig(t), watch = await running(h), ready = h.connection(), {credentials} = h.connections, {runPoll} = h.catalog, {sync} = h.feedOf(watch).cursors;
  h.simulator.write({name: 'New'});
  h.connections.credentials = async (...args) => { const answer = await credentials(...args); h.store.put('connections', {...ready, status: 'unavailable'}); return answer; };
  h.runtime.actions = {...h.catalog, runPoll: async options => { const result = await runPoll(options); h.store.put('connections', ready); return result; }};
  await h.engine.tick();
  assert.deepEqual([h.runsOf(h.feedOf(watch)).at(-1).outcome, h.feedOf(watch).failures, h.feedOf(watch).cursors.sync, h.events().length, h.current(watch).status], ['skipped', 1, sync, 0, 'active']);
});

test('a run counts events and never gaps', async t => {
  const h = rig(t), watch = await running(h);
  h.simulator.expireCursors();
  await h.engine.tick();
  assert.equal(h.gapsOf(watch).length, 1);
  assert.deepEqual(h.runsOf(h.feedOf(watch)).at(-1).events, {});
});

test('a wait names a method through any step of a feed: its poll, its seed or an enrich step', async t => {
  const h = rig(t, {triggers: edited('feed-updated', item => { item.poll.seed.step.path = '/items'; item.poll.seed.cursor.pointer = '/items/0/updated'; })}), {runPoll} = h.catalog, args = {kinds: ['note']};
  h.setRow('fixture.keys.read', 'allow');
  const seeded = await running(h, 'feed-updated', {args}), keys = await running(h, 'feed-logged-keys'), plain = await running(h, 'feed-synced');
  const limit = method => { h.runtime.actions = {...h.catalog, runPoll: async options => ({...await runPoll(options), outcome: 'limited', wait: {until: h.now + HOUR, reason: 'limited', method}})}; };
  const clear = () => { for (const watch of [seeded, keys, plain]) h.store.put('triggerFeeds', {...h.feedOf(watch), wait: null, nextPollAt: h.now + HOUR}); };
  const held = async method => {
    clear();
    limit(method);
    h.store.put('triggerFeeds', {...h.feedOf(plain), nextPollAt: 0});
    await h.engine.tick();
    return [seeded, keys].map(watch => h.feedOf(watch).wait !== null);
  };
  assert.deepEqual(await held('items'), [true, false], 'a seed step');
  assert.deepEqual(await held('keys'), [false, true], 'an enrich step');
  assert.deepEqual(await held('feed'), [true, true], 'the poll step');
});

test('I8: a candidate on a shared poll is never run: its lens is not tracked, and its entry never reaches a poll', async t => {
  const candidate = twin('feed-synced', 'feed-synced-draft');
  const h = rig(t, {triggers: [...feedTriggers(), candidate], evidence: entries => Object.fromEntries(entries.filter(entry => entry.key !== 'feed-synced-draft').map(entry => [entry.id, {passed: true, transforms: Object.fromEntries(entry.transforms.map(id => [id, REGISTRY_PINS[id]])), tests: [{test: 'fixture', passed: true, proof: {afterWrite: 1, repoll: 0, resync: {gapEvents: 1, duplicates: 0}}}]}]))});
  assert.deepEqual([h.itemOf('feed-synced').status, h.itemOf('feed-synced-draft').status], ['active', 'candidate']);
  const {runPoll} = h.catalog, seen = [];
  h.runtime.actions = {...h.catalog, runPoll: options => { seen.push(options.entries.map(item => item.entry.key)); return runPoll(options); }};
  const watch = h.start('feed-synced');
  assert.equal(h.feedOf(watch).lenses.length, 1);
  await h.settle(watch);
  assert.deepEqual(seen, [['feed-synced']]);
});

test('a watch pauses once, though a lens stop and a feed pause both name it, and attaching a paused watch that cannot run adds nothing', async t => {
  const h = rig(t), watch = await running(h), {runPoll} = h.catalog, [lens] = h.itemOf('feed-synced').lenses;
  h.runtime.actions = {...h.catalog, runPoll: async options => ({...await runPoll(options), lensPauses: [{lens, code: 'too_large', reason: 'too_many_items'}], pause: {reason: 'provider_refused', detail: 'moved'}})};
  await h.engine.tick();
  assert.deepEqual([h.current(watch).reason, h.current(watch).revision, h.audits('trigger.paused').length], ['too_many_items', 2, 1]);
  const schema = {type: 'object', properties: {kind: {type: 'string', minLength: 1, maxLength: 20}}, required: ['kind'], additionalProperties: false};
  const other = rig(t, {triggers: edited('feed-listed', item => { item.inputSchema = schema; item.poll.source.steps[0].query.kind = {input: '/kind'}; })}), stopped = other.start('feed-listed', {args: {kind: 'note'}});
  other.engine.attach(stopped);
  assert.deepEqual([other.current(stopped).revision, other.audits('trigger.paused').length], [2, 1]);
});

test('a feed with no live watch takes no slot, however long it has been due', async t => {
  for (const status of ['paused', 'removed']) {
    const h = rig(t), held = await running(h), ids = copies(h, held, 5, {nextPollAt: 0});
    h.store.put('subscriptions', {...h.current(held), status, feeds: ids});
    const live = await running(h, 'feed-listed');
    h.advance(INTERVAL);
    await h.engine.tick();
    assert.equal(h.runsOf(h.feedOf(live)).length, 2, status);
  }
});

test('a feed held by its bucket is marked behind even past the five slots', async t => {
  const h = rig(t, {}, {budgets: {fixture: {perMinute: 5}}}), watch = await running(h);
  h.advance(MINUTE + INTERVAL);
  const ids = copies(h, watch, 6);
  await h.engine.tick();
  assert.equal([h.feedOf(watch), ...ids.map(id => h.store.get('triggerFeeds', id))].filter(feed => feed.behind).length, 2);
});

test('a resumed watch\'s gap carries its owner, so an erasure reaches it', async t => {
  const h = rig(t), watch = await running(h, 'feed-synced', {userRecordId: 'usr_owner'});
  h.store.put('subscriptions', {...h.current(watch), status: 'paused', reason: 'owner_paused', pausedAt: new Date(h.now).toISOString()});
  h.engine.resume(h.current(watch));
  await h.settle(watch);
  assert.equal(h.gapsOf(watch)[0].userRecordId, 'usr_owner');
});

// What survived the second.
test('what a poll hands the store goes to the store: a lens past the limit the poll set pauses', async t => {
  const h = rig(t), watch = await running(h, 'feed-listed'), {runPoll} = h.catalog, [lens] = h.itemOf('feed-listed').lenses;
  h.simulator.seed(3);
  h.runtime.actions = {...h.catalog, runPoll: async options => ({...await runPoll(options), seenLimits: {[lens]: {limit: 1, evict: false}}})};
  await h.engine.tick();
  assert.deepEqual([h.current(watch).status, h.current(watch).reason, h.current(watch).detail], ['paused', 'too_many_items', 'seen_limit']);
});

test('a lens past its limit with no watch goes with its rows, and a lens within its limit stays', async t => {
  const other = twin('feed-listed', 'feed-listed-named', item => { item.filter = [{equals: [{item: '/kind'}, {const: 'note'}]}]; });
  const h = rig(t, {triggers: [...feedTriggers(), other]}), {appendPoll} = h.store, [plain] = h.itemOf('feed-listed').lenses, [named] = h.itemOf('feed-listed-named').lenses;
  h.simulator.seed(2);
  const watch = await running(h, 'feed-listed-named'), id = h.current(watch).feeds[0];
  assert.ok(seenKeys(h, id, plain).length);
  h.store.appendPoll = poll => ({...appendPoll.call(h.store, poll), overLimit: [{lens: plain, count: 5001}]});
  await h.engine.tick();
  h.store.appendPoll = appendPoll;
  assert.deepEqual([h.feedOf(watch).lenses, seenKeys(h, id, plain).length, h.current(watch).status], [[named], 0, 'active']);
  assert.ok(seenKeys(h, id, named).length, 'the other lens keeps its rows');
});

test('a feed that goes during an await or before its turn ends a poll quietly, baselined or not', async t => {
  const h = rig(t), watch = h.start('feed-synced'), held = h.simulator.hold('GET /feed'), flight = h.engine.pollNow(watch.id);
  await Promise.race([held.reached, flight]);
  forgetTriggers(h.store, h.account, h.now);
  held.release();
  assert.equal((await flight).status, 'paused');
  assert.equal((await h.engine.pollNow(watch.id)).reason, 'account_changed', 'its list still names the feed that went');
});

test('the template list is read once a tick, across the feeds of an account', async t => {
  const h = rig(t), watch = await running(h), {typedTemplates} = h.proxyPolicy;
  copies(h, watch, 3);
  let lists = 0;
  h.proxyPolicy.typedTemplates = context => { lists++; return typedTemplates.call(h.proxyPolicy, context); };
  await h.engine.tick();
  assert.equal(lists, 1);
});

test('a poll that fails does not stop the next one from taking its turn', async t => {
  const h = rig(t), watch = await running(h), {appendPoll} = h.store;
  h.store.appendPoll = () => { h.store.appendPoll = appendPoll; throw new Error('disk full'); };
  await assert.rejects(h.engine.pollNow(watch.id), /disk full/);
  h.simulator.write({name: 'New'});
  await h.engine.pollNow(watch.id);
  assert.equal(h.eventsOf(watch).length, 1);
});

// What survived the second, around a Resume, detach() and stop().
test('joining marks a feed due and keeps its place in the queue', async t => {
  const h = rig(t), watch = await running(h), {nextPollAt} = h.feedOf(watch);
  h.advance(HOUR);
  h.start('feed-synced');
  assert.equal(h.feedOf(watch).nextPollAt, nextPollAt, 'it stays as overdue as it was');
  const later = rig(t), other = await running(later);
  later.start('feed-synced');
  assert.equal(later.feedOf(other).nextPollAt, later.now, 'a feed not yet due is due now');
});

test('starting over clears everything the old place left, and tells only a watch that hears of this feed', async t => {
  const h = rig(t), watch = await running(h), active = await running(h), joiner = h.start('feed-synced');
  h.store.put('subscriptions', {...h.current(watch), status: 'paused', reason: 'cursor_invalid', pausedAt: new Date(h.now).toISOString()});
  h.store.put('triggerFeeds', {...h.feedOf(active), cursorInvalid: true, page: {token: 'p1', walk: 'delta'}, floor: '2026-10-23T09:00:00.000Z', draining: true, budgetStops: 2, recordFailures: 3});
  h.engine.resume(h.current(watch));
  const {cursors, page, floor, draining, budgetStops, recordFailures, baselined, cursorInvalid} = h.feedOf(active);
  assert.deepEqual({cursors, page, floor, draining, budgetStops, recordFailures, baselined, cursorInvalid}, {cursors: {}, page: null, floor: null, draining: false, budgetStops: 0, recordFailures: 0, baselined: false, cursorInvalid: undefined});
  await h.pass();
  const reasons = watching => h.gapsOf(watching).map(row => row.payload.fields.reason);
  assert.deepEqual([reasons(active), reasons(joiner), reasons(watch)], [['resync'], [], ['resume']], 'a watch still joining has no place to lose, and the resumed one has its own gap');
});

test('a Resume whose route wrote starting first is told of no lost place: its gap comes when it reaches the present', async t => {
  const h = rig(t), watch = await running(h);
  h.store.put('subscriptions', {...h.current(watch), status: 'starting', pending: [], reason: 'cursor_invalid', revision: 2, pausedAt: new Date(h.now).toISOString()});
  h.store.put('triggerFeeds', {...h.feedOf(watch), cursorInvalid: true});
  assert.equal(h.engine.resume(h.current(watch)).revision, 2, 'its route raised the revision');
  assert.equal(h.gapsOf(watch).length, 0);
  await h.settle(watch);
  assert.deepEqual(h.gapsOf(watch).map(row => row.payload.fields.reason), ['resume']);
});

test('a Resume of a watch that is not paused, or with no catalog, touches no feed', async t => {
  const h = rig(t), watch = await running(h), {actions} = h.runtime;
  h.store.put('triggerFeeds', {...h.feedOf(watch), cursorInvalid: true});
  h.store.put('subscriptions', {...h.current(watch), status: 'removed'});
  h.engine.resume(h.current(watch));
  assert.deepEqual([h.feedOf(watch).baselined, h.feedOf(watch).cursorInvalid], [true, true]);
  h.store.put('subscriptions', {...h.current(watch), status: 'paused', reason: 'cursor_invalid'});
  const other = h.start('feed-synced');
  await h.settle(other);
  h.runtime.actions = null;
  assert.equal(h.engine.resume(h.current(watch)).status, 'paused', 'nothing resumes while the catalog is out');
  assert.deepEqual([h.feedOf(other).baselined, h.feedOf(other).cursorInvalid], [true, true]);
  h.runtime.actions = actions;
});

test('detach: a watch is no holder of its own feed, whatever its status, and neither is a record that left with its list', async t => {
  const h = rig(t), watch = await running(h), id = h.current(watch).feeds[0];
  h.engine.detach(h.current(watch));
  assert.equal(h.store.get('triggerFeeds', id), null, 'its route may call this before it writes the status');
  const other = rig(t), a = await running(other), b = await running(other), feed = other.current(a).feeds[0];
  other.store.put('subscriptions', {...other.current(a), status: 'removed'});
  other.engine.detach(other.current(b));
  assert.equal(other.store.get('triggerFeeds', feed), null, 'a removed record that still lists the feed holds nothing');
});

test('stop() ends the timer as well as the tick in hand', async t => {
  t.mock.timers.enable({apis: ['setInterval']});
  const h = rig(t);
  let ticks = 0;
  h.engine.tick = async () => { ticks++; };
  h.engine.start();
  t.mock.timers.tick(2000);
  assert.equal(ticks, 3, 'one now and one a second');
  await h.engine.stop();
  t.mock.timers.tick(5000);
  assert.equal(ticks, 3);
});

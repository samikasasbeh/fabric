import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import {validateAuthDefinition} from '../contracts/auth-definition.mts';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {apiRuleOf, apiVerdict, narrowOnMissingScope} from '../lib/api-success.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {RUN_WORDS} from '../lib/actions-runtime.mjs';
import {validateActionFile} from '../lib/actions.mjs';
import {current} from '../lib/connection-notices.mjs';
import {ORIGIN, IDS} from './fixtures/provider-simulators/slack.mjs';
import {slackRig, slackAction, historyAction, slackFile, OWNER, SCOPES, RULE, SLACK_OK, SLACK_TOKEN as TOKEN} from './fixtures/actions/slack-rig.mjs';
import {actionHarness} from './fixtures/actions/runtime-fixture.mjs';
import {fixtureSignIn, fixtureActions, withIds} from './fixtures/actions/fixture-app.mjs';
import {googleMap} from './fixtures/access/google-maps.mjs';

// F10.21 part 1 a and b (docs/F10.21-BUILD-MAP.md part 1 a and b; spec lines 274, 1209-1212 and 1228): Slack answers its own errors with
// HTTP 200 and {ok: false, error}, so a reviewed provider field, apiSuccessRequire, says which body facts a 2xx must hold. The proxy and the
// action runtime read it through one function (lib/api-success.mjs), from the reviewed definition, so a test runtime cannot drop it; the
// validator holds every Slack step to it; and Slack's missing_scope narrows the account so its row reads "Needs more access".
const ALREADY = {status: [200], require: [{anyOf: [RULE, {equals: {pointer: '/error', value: {const: 'already_reacted'}}}]}]};
const closed = properties => ({type: 'object', properties, required: Object.keys(properties), additionalProperties: false});
const words = (max = 200) => ({type: 'string', minLength: 1, maxLength: max});
const READ_HINTS = {readOnly: true, destructive: false, idempotent: true, openWorld: true}, WRITE_HINTS = {readOnly: false, destructive: false, idempotent: false, openWorld: true};
const plain = value => JSON.parse(JSON.stringify(value));
/** Slack's shipped definition without apiSuccessRequire: what a stub provider list would hand the runtime. */
const withoutRule = () => { const {apiSuccessRequire, ...rest} = plain(definitionFor('slack')); void apiSuccessRequire; return validateAuthDefinition(rest); };

// ---- the Slack rig (test/fixtures/actions/slack-rig.mjs) and the test actions -------------------------------------------------------------
const history = (expect = SLACK_OK) => historyAction({expect});
const react = ({add = ALREADY, readback = SLACK_OK} = {}) => slackAction('react', {effect: 'write', row: 'slack.messages.send', hints: WRITE_HINTS,
  inputSchema: closed({channel: words(21), ts: words(17), name: words(100)}), outputSchema: closed({ok: {type: 'boolean'}}),
  perform: [{id: 'add', method: 'POST', path: '/reactions.add', body: {object: {channel: {input: '/channel'}, timestamp: {input: '/ts'}, name: {input: '/name'}}}, expect: add}],
  verify: {requests: [{id: 'check', method: 'GET', path: '/reactions.get', query: {channel: {input: '/channel'}, timestamp: {input: '/ts'}, full: {const: true}}, expect: readback}],
    identity: [{kind: 'membership', step: 'check', listHas: {list: '/message/reactions', where: [{field: '/name', equals: {input: '/name'}}]}}], assert: []},
  output: {ok: {step: 'add', pointer: '/ok'}}});

// ---- the contract ---------------------------------------------------------------------------------------------------------------------
const ajv = new Ajv2020({strict: true, allErrors: true});
addFormats(ajv);
const schema = ajv.compile(JSON.parse(readFileSync(new URL('../contracts/auth-definition.schema.json', import.meta.url), 'utf8')));

test('the contract takes apiSuccessRequire on version 2 only, 1 to 4 {pointer, equals} entries; Slack\'s definition carries exactly /ok true, no other does', () => {
  const slack = plain(definitionFor('slack'));
  assert.deepEqual(slack.apiSuccessRequire, [{pointer: '/ok', equals: true}]);
  for (const providerId of ['google', 'github', 'notion']) assert.equal(Object.hasOwn(plain(definitionFor(providerId)), 'apiSuccessRequire'), false, providerId);
  assert.ok(schema(slack), JSON.stringify(schema.errors));
  const four = [{pointer: '/ok', equals: true}, {pointer: '/a', equals: 'x'}, {pointer: '/b', equals: 1}, {pointer: '/c/d', equals: false}];
  assert.deepEqual(plain(validateAuthDefinition({...slack, apiSuccessRequire: four})).apiSuccessRequire, four);
  const {apiSuccessRequire: _rule, ...without} = slack;
  assert.ok(validateAuthDefinition(without), 'the field is optional');
  for (const [label, value] of [['an empty list', []], ['five entries', [...four, {pointer: '/e', equals: true}]], ['a bad pointer', [{pointer: 'ok', equals: true}]],
    ['a prototype pointer', [{pointer: '/__proto__', equals: true}]], ['a present entry', [{pointer: '/ok', present: true}]], ['an object value', [{pointer: '/ok', equals: {}}]],
    ['a control character', [{pointer: '/ok', equals: 'a\u0000'}]], ['an extra key', [{pointer: '/ok', equals: true, note: 'x'}]], ['a duplicate', [{pointer: '/ok', equals: true}, {pointer: '/ok', equals: true}]],
    ['not a list', {pointer: '/ok', equals: true}]]) {
    assert.throws(() => validateAuthDefinition({...slack, apiSuccessRequire: value}), /apiSuccessRequire/, label);
    if (!['a duplicate', 'a prototype pointer', 'a control character'].includes(label)) assert.equal(schema({...slack, apiSuccessRequire: value}), false, `${label}: the schema agrees`);
  }
  const v1 = JSON.parse(readFileSync(new URL('./fixtures/auth-v1/slack.json', import.meta.url), 'utf8'));
  assert.ok(validateAuthDefinition(v1));
  assert.throws(() => validateAuthDefinition({...v1, apiSuccessRequire: [{pointer: '/ok', equals: true}]}), /apiSuccessRequire is not allowed/, 'a version 1 definition never carries it');
  assert.equal(schema({...v1, apiSuccessRequire: [{pointer: '/ok', equals: true}]}), false);
});

test('apiRuleOf reads the reviewed definition by app: Slack has the rule, a stub definition cannot drop it, another app has none unless its own definition sets one', () => {
  const rule = apiRuleOf('slack');
  assert.deepEqual(plain(rule.require), [{pointer: '/ok', equals: true}]);
  assert.ok(rule.scopes.includes('reactions:write') && rule.scopes.includes('channels:write') && !rule.scopes.includes('admin'), 'the scopes of Slack\'s full level, never a never-request one');
  assert.deepEqual(plain(apiRuleOf('slack', withoutRule())), plain(rule), 'a stub without the rule does not drop it');
  for (const appId of ['gmail', 'google-calendar', 'github', 'notion', 'fixture', 'nothing']) assert.equal(apiRuleOf(appId), null, appId);
  const own = validateAuthDefinition({...plain(fixtureSignIn('fixture-rpc')), apiSuccessRequire: [{pointer: '/ok', equals: true}]});
  assert.deepEqual(plain(apiRuleOf('fixture-rpc', own)), {require: [{pointer: '/ok', equals: true}], scopes: ['fixture:all']});
  assert.equal(apiRuleOf('fixture-rpc', fixtureSignIn('fixture-rpc')), null);
});

test('apiVerdict: ok true is ok; ok false is refused with Slack\'s error; a missing ok or a text body is unknown; needed and provided keep only the app\'s scopes', () => {
  const rule = apiRuleOf('slack');
  assert.deepEqual(apiVerdict(rule, {ok: true, channel: 'C1'}), {state: 'ok', error: null, needed: [], provided: null});
  assert.deepEqual(apiVerdict(rule, {ok: false, error: 'channel_not_found'}), {state: 'refused', error: 'channel_not_found', needed: [], provided: null});
  assert.deepEqual(apiVerdict(rule, {ok: 'true'}).state, 'refused', 'present with another value');
  for (const body of [{}, {error: 'x'}, {messages: []}, 'ok', null, undefined, [], 7]) assert.deepEqual(apiVerdict(rule, body), {state: 'unknown', error: 'unknown', needed: [], provided: null}, JSON.stringify(body));
  for (const error of ['has space', 'a'.repeat(65), 'UPPER', 'a-b', '', 7, null, {x: 1}]) assert.equal(apiVerdict(rule, {ok: false, error}).error, 'unknown', JSON.stringify(error));
  assert.equal(apiVerdict(rule, {ok: false, error: 'a'.repeat(64)}).error, 'a'.repeat(64));
  const scope = apiVerdict(rule, {ok: false, error: 'missing_scope', needed: 'reactions:write,admin.users:write', provided: 'chat:write, users:read,admin,bogus:scope,<b>'});
  assert.deepEqual(scope, {state: 'refused', error: 'missing_scope', needed: ['reactions:write'], provided: ['chat:write', 'users:read']});
  assert.deepEqual(apiVerdict(rule, {ok: false, error: 'missing_scope', needed: 'reactions:write'}).provided, null, 'provided absent stays absent');
  assert.deepEqual(apiVerdict(rule, {ok: false, error: 'missing_scope', needed: 7, provided: ['x']}), {state: 'refused', error: 'missing_scope', needed: [], provided: null});
});

// ---- the proxy ------------------------------------------------------------------------------------------------------------------------
test('proxy on the Slack simulator: ok false fails a read and a write alike (api_error, body kept); ok true on a write stays uncertain; a read without ok fails', async t => {
  const rig = slackRig(t);
  const read = await rig.proxy({method: 'GET', path: '/conversations.history', query: {channel: 'C0NOWHERE1'}});
  assert.deepEqual([read.status, read.errorCode, read.reason, read.details], ['failed', 'provider_failed', 'api_error', {providerError: 'channel_not_found'}]);
  assert.match(read.error, /refused this request \(channel_not_found\)/);
  assert.deepEqual(rig.runtime.proxyResponse(read).body, {ok: false, error: 'channel_not_found'}, 'the body is kept');
  const ok = await rig.proxy({method: 'GET', path: '/conversations.history', query: {channel: IDS.fabricTest}});
  assert.deepEqual([ok.status, ok.reason], ['succeeded', null]);
  const write = await rig.proxy({method: 'POST', path: '/chat.postMessage', body: {channel: IDS.others, text: 'x'}});
  assert.deepEqual([write.status, write.errorCode, write.reason, write.details], ['failed', 'provider_failed', 'api_error', {providerError: 'not_in_channel'}], 'Slack did nothing');
  assert.equal(write.result.verification.status, 'rejected');
  const posted = await rig.proxy({method: 'POST', path: '/chat.postMessage', body: {channel: IDS.fabricTest, text: 'x'}});
  assert.deepEqual([posted.status, posted.errorCode, posted.reason], ['uncertain', 'outcome_uncertain', 'not_verified'], 'a 2xx change is sent, not verified, as before');
  rig.simulator.fail('conversations.history', {status: 200, data: {messages: []}});
  const bare = await rig.proxy({method: 'GET', path: '/conversations.history', query: {channel: IDS.fabricTest}});
  assert.deepEqual([bare.status, bare.reason, bare.details], ['failed', 'api_error', {providerError: 'unknown'}]);
  rig.simulator.fail('chat.postMessage', {status: 200, data: {channel: IDS.fabricTest}});
  const unknownWrite = await rig.proxy({method: 'POST', path: '/chat.postMessage', body: {channel: IDS.fabricTest, text: 'y'}});
  assert.deepEqual([unknownWrite.status, unknownWrite.reason], ['uncertain', 'not_verified'], 'a write whose answer says nothing stays uncertain');
});

test('proxy: another app\'s 2xx without ok is unchanged, and a stub provider list cannot drop Slack\'s rule', async t => {
  const rig = slackRig(t);
  rig.store.put('connections', {id: 'github-account', appId: 'github', driver: 'http', authMethod: 'token', authRevision: 'g1', status: 'ready', label: 'GitHub', identity: {id: '101'},
    allowedOrigins: ['https://api.github.com'], createdAt: new Date().toISOString()});
  const github = new Runtime({store: rig.store, permissions: rig.permissions, proxyPolicy: rig.proxyPolicy, ownerPrincipal: OWNER, clock: () => Date.parse('2026-10-26T15:00:00.000Z'),
    connections: {credentials: async id => ({headers: {Authorization: `Bearer ${TOKEN}`}, allowedOrigins: [id === 'github-account' ? 'https://api.github.com' : ORIGIN]}),
      providers: {providerFor: appId => appId === 'slack' ? 'slack' : null, resolve: () => ({definition: withoutRule()})}},
    request: async request => request.url.startsWith(ORIGIN) ? rig.simulator.request(request) : {status: 200, headers: {'content-type': 'application/json'}, data: Buffer.from('{"items":[]}')}});
  const job = await github.createProxyJob({connectionId: 'github-account', request: {method: 'GET', path: '/user/repos'}}, OWNER);
  assert.deepEqual([job.status, job.reason], ['succeeded', null]);
  const slack = await github.createProxyJob({connectionId: 'slack-account', request: {method: 'GET', path: '/conversations.history', query: {channel: 'C0NOWHERE1'}}}, OWNER);
  assert.deepEqual([slack.status, slack.reason], ['failed', 'api_error'], 'the stub definition has no rule, the reviewed one wins');
});

// ---- the action runtime ---------------------------------------------------------------------------------------------------------------
const RPC_OK = {status: [200], require: [RULE]};
const rpcExtra = (key, fields) => ({id: `fixture-rpc.action.${key}.v1.${'0'.repeat(24)}`, key, version: 1, name: key, description: `The ${key} action of the apiSuccessRequire tests.`, guards: [],
  prepare: [], definitive: [], certified: {evidence: 'docs/live-evidence/fixture-rpc/actions.json', definitionHash: '0'.repeat(64)}, ...fields});
const rpcRuleFile = () => ({schemaVersion: 1, appId: 'fixture-rpc', specVersion: 'fabric/0.2', reviewStatus: 'reviewed', pinnedParameters: {}, actions: [
  rpcExtra('read-canvas', {effect: 'read', row: 'fixture-rpc.messages.read', hints: READ_HINTS, inputSchema: closed({canvasId: words(64)}), outputSchema: closed({title: {type: 'string', maxLength: 200}}),
    perform: [{id: 'canvas', method: 'POST', path: '/canvases.read', body: {object: {canvas_id: {input: '/canvasId'}}}, expect: RPC_OK}], output: {title: {step: 'canvas', pointer: '/title'}},
    preview: [{label: 'Canvas', expr: {input: '/canvasId'}}]}),
  rpcExtra('start-and-post', {effect: 'write', row: 'fixture-rpc.messages.send', hints: WRITE_HINTS, inputSchema: closed({text: words()}),
    outputSchema: closed({ts: {type: 'string', maxLength: 64}}),
    perform: [{id: 'start', method: 'POST', path: '/conversations.start', body: {object: {users: {const: 'U1'}}}, expect: ALREADY},
      {id: 'post', method: 'POST', path: '/messages.post', body: {object: {channel: {const: 'C1'}, text: {input: '/text'}}}, expect: RPC_OK}],
    verify: {requests: [{id: 'check', method: 'GET', path: '/messages.list', query: {channel: {const: 'C1'}}, expect: RPC_OK}],
      identity: [{kind: 'membership', step: 'check', listHas: {list: '/messages', where: [{field: '/ts', equals: {step: 'post', pointer: '/ts'}}]}}], assert: []},
    output: {ts: {step: 'post', pointer: '/ts'}}, preview: [{label: 'Message', expr: {input: '/text'}}]})]});
const ruleSignIn = () => validateAuthDefinition({...plain(fixtureSignIn('fixture-rpc')), apiSuccessRequire: [{pointer: '/ok', equals: true}]});
function rpcRig(t) {
  const h = actionHarness(t, {files: [rpcRuleFile()], rpcSignIn: ruleSignIn()});
  const id = key => h.idOf(`${key} v1`);
  const settle = async job => job.status === 'awaiting_approval' ? settle(await h.runtime.approve(job.id, job.approvalDigest, h.owner)) : job;
  return {h, run: async (key, args) => settle(await h.runtime.createJob({connectionId: h.rpcAccount, capabilityId: id(key), args}, h.owner))};
}

test('actions on the fake RPC app with a rule: ok false fails with no earlier write and is uncertain after one; an already_reacted branch passes', async t => {
  const {h, run} = rpcRig(t);
  const found = await run('read-canvas', {canvasId: 'F1'});
  assert.deepEqual([found.status, found.result.data], ['succeeded', {title: 'Roadmap'}]);
  const missing = await run('read-canvas', {canvasId: 'F9'});
  assert.deepEqual([missing.status, missing.errorCode, missing.reason, missing.details, missing.error], ['failed', 'provider_failed', 'api_error', {providerError: 'canvas_not_found'}, RUN_WORDS.api_error]);
  h.simulator.fail('POST /messages.post', {status: 200, data: {ok: false, error: 'is_archived'}});
  const after = await run('start-and-post', {text: 'hello'});
  assert.deepEqual([after.status, after.errorCode, after.reason, after.details, after.error], ['uncertain', 'outcome_uncertain', 'api_error', {providerError: 'is_archived'}, RUN_WORDS.uncertain]);
  h.simulator.fail('POST /conversations.start', {status: 200, data: {ok: false, error: 'already_reacted'}});
  const alternative = await run('start-and-post', {text: 'again'});
  assert.deepEqual([alternative.status, alternative.reason], ['succeeded', null], 'a reviewed alternative of the step\'s own require passes');
  h.simulator.fail('POST /conversations.start', {status: 200, data: {ok: false, error: 'not_in_channel'}});
  const first = await run('start-and-post', {text: 'third'});
  assert.deepEqual([first.status, first.reason, first.details], ['failed', 'api_error', {providerError: 'not_in_channel'}], 'the first write refused: nothing changed');
});

test('actions: the runtime holds Slack\'s rule even where the validator never saw it: an empty require fails, a non-error branch is no alternative, a refused readback is unverified', async t => {
  const warned = {status: [200], require: [{anyOf: [RULE, {equals: {pointer: '/warning', value: {const: 'w'}}}]}]};
  const rig = slackRig(t, {identity: withoutRule(), actions: [history({status: [200], require: []}), react({add: warned, readback: {status: [200], require: []}})]});
  const bare = await rig.run('history', {channel: 'C0NOWHERE1'});
  assert.deepEqual([bare.status, bare.reason, bare.details], ['failed', 'api_error', {providerError: 'channel_not_found'}]);
  assert.equal((await rig.run('history', {channel: IDS.fabricTest})).status, 'succeeded');
  rig.simulator.fail('reactions.add', {status: 200, data: {ok: false, error: 'x', warning: 'w'}});
  const branch = await rig.run('react', {channel: IDS.fabricTest, ts: rig.simulator.synthetic.two, name: 'eyes'});
  assert.deepEqual([branch.status, branch.reason, branch.details], ['failed', 'api_error', {providerError: 'x'}], 'only a branch on /error is a reviewed alternative');
  rig.simulator.fail('reactions.get', {status: 200, data: {ok: false, error: 'internal_error', message: {reactions: [{name: 'eyes', users: [IDS.owner], count: 1}]}}});
  const readback = await rig.run('react', {channel: IDS.fabricTest, ts: rig.simulator.synthetic.two, name: 'eyes'});
  assert.deepEqual([readback.status, readback.reason, readback.result?.verification?.status], ['uncertain', 'not_verified', 'unverified'], 'a refused readback never verifies');
});

// ---- the validator --------------------------------------------------------------------------------------------------------------------
test('the validator holds every Slack step to the rule: at the top of expect.require, or the first branch of an anyOf of /error alternatives', () => {
  const validate = actions => validateActionFile(withIds(slackFile(actions), {maps: new Map()}), {maps: new Map()});
  assert.equal(validate([history(), react()]).actions.length, 2, 'the two allowed forms');
  assert.equal(validate([history({status: [200], require: [{present: {pointer: '/messages'}}, RULE]})]).actions.length, 1, 'beside other assertions');
  assert.equal(validate([react({add: {status: [200], require: [{anyOf: [RULE, {equals: {pointer: '/error', value: {const: 'already_reacted'}}}, {equals: {pointer: '/error', value: {const: 'no_reaction'}}}]}]}})]).actions.length, 1);
  for (const [label, actions] of [['no require', [history({status: [200], require: []})]], ['another require only', [history({status: [200], require: [{present: {pointer: '/messages'}}]})]],
    ['ok false', [history({status: [200], require: [{equals: {pointer: '/ok', value: {const: false}}}]})]],
    ['a readback without it', [react({readback: {status: [200], require: []}})]],
    ['a non-error branch', [react({add: {status: [200], require: [{anyOf: [RULE, {equals: {pointer: '/warning', value: {const: 'w'}}}]}]}})]],
    ['an error branch from an input', [react({add: {status: [200], require: [{anyOf: [RULE, {equals: {pointer: '/error', value: {input: '/name'}}}]}]}})]],
    ['the rule second in an anyOf', [react({add: {status: [200], require: [{anyOf: [{equals: {pointer: '/error', value: {const: 'already_reacted'}}}, RULE]}]}})]]]) {
    assert.throws(() => validate(actions), /requires \/ok to be true/, label);
  }
});

test('Calendar\'s shipped file and the fixture app\'s file validate with their ids unchanged: the rule binds only an app whose definition sets it', t => {
  const calendar = JSON.parse(readFileSync(new URL('../catalog/actions/google-calendar.json', import.meta.url), 'utf8'));
  assert.equal(validateActionFile(calendar, {maps: new Map([['google-calendar', googleMap('google-calendar')]])}).actions.length, 13);
  const h = actionHarness(t), stored = new Set(fixtureActions().actions.map(action => action.id));
  assert.ok(h.catalog.entries.size > 0 && [...h.catalog.refused].length === 0, 'the fixture app\'s file loads');
  assert.ok([...h.catalog.entries.keys()].every(id => stored.has(id)), 'with the ids it stores');
});

// ---- missing_scope: "Needs more access" ------------------------------------------------------------------------------------------------
const reactArgs = rig => ({channel: IDS.fabricTest, timestamp: rig.simulator.synthetic.two, name: 'white_check_mark'});
const narrowed = rig => current(rig.store, rig.record()).filter(notice => notice.kind === 'grant_narrowed');

test('missing_scope through the proxy: the job fails with needed named, the account loses reactions:write, one notice, and the row needs more access', async t => {
  const rig = slackRig(t);
  rig.simulator.revokeScope('reactions:write');
  const job = await rig.proxy({method: 'POST', path: '/reactions.add', body: reactArgs(rig)});
  assert.deepEqual([job.status, job.errorCode, job.reason, job.details], ['failed', 'provider_failed', 'api_error', {providerError: 'missing_scope', needed: ['reactions:write']}]);
  assert.equal(rig.record().scopes.includes('reactions:write'), false);
  assert.deepEqual(rig.record().scopes, SCOPES.filter(scope => scope !== 'reactions:write'), 'nothing else moved');
  assert.equal(narrowed(rig).length, 1);
  assert.ok(rig.store.list('activity').some(event => event.type === 'connection.narrowed' && event.reason === 'missing_scope' && event.connectionId === 'slack-account'));
  const decision = rig.proxyPolicy.decide('slack-account', {method: 'POST', path: '/reactions.add', body: reactArgs(rig)});
  assert.equal(decision.providerAccess, 'missing', '"Send, edit and react to messages" reads "Needs more access"');
  await assert.rejects(rig.proxy({method: 'POST', path: '/reactions.add', body: reactArgs(rig)}), error => error.code === 'provider_access_missing', 'nothing more is sent');
  assert.equal(narrowNoticeCount(rig), 1);
});
const narrowNoticeCount = rig => narrowed(rig).reduce((sum, notice) => sum + notice.count, 0);

test('missing_scope through an action: the job is written first, then the account narrows once; a second failure raises no new notice', async t => {
  const rig = slackRig(t, {actions: [history(), react()]});
  rig.simulator.revokeScope('reactions:write');
  const writes = [], put = rig.store.put.bind(rig.store);
  rig.store.put = (collection, document) => { writes.push(`${collection}:${collection === 'jobs' ? document.status : document.id}`); return put(collection, document); };
  const job = await rig.run('react', {channel: IDS.fabricTest, ts: rig.simulator.synthetic.two, name: 'white_check_mark'});
  assert.deepEqual([job.status, job.reason, job.details, job.error], ['failed', 'api_error', {providerError: 'missing_scope', needed: ['reactions:write']}, RUN_WORDS.missing_scope]);
  assert.ok(writes.lastIndexOf('jobs:failed') >= 0 && writes.lastIndexOf('jobs:failed') < writes.indexOf('connections:slack-account'), `the job is written before the account changes: ${writes.join(' ')}`);
  assert.equal(rig.record().scopes.includes('reactions:write'), false);
  assert.equal(narrowNoticeCount(rig), 1);
  // The account record no longer holds the scope, so the same answer narrows nothing and raises nothing.
  assert.deepEqual(narrowOnMissingScope(rig.runtime, 'slack-account', apiVerdict(apiRuleOf('slack'), {ok: false, error: 'missing_scope', needed: 'reactions:write', provided: 'chat:write'})), []);
  assert.equal(narrowNoticeCount(rig), 1);
});

test('narrowing: only scopes Slack names in needed and leaves out of provided, that the record holds; never with provided absent; never wider', t => {
  const rig = slackRig(t, {accountScopes: ['chat:write', 'reactions:read', 'reactions:write']});
  const rule = apiRuleOf('slack'), verdict = body => apiVerdict(rule, {ok: false, error: 'missing_scope', ...body});
  assert.deepEqual(narrowOnMissingScope(rig.runtime, 'slack-account', verdict({needed: 'reactions:write'})), [], 'provided absent: nothing narrows');
  assert.deepEqual(narrowOnMissingScope(rig.runtime, 'slack-account', verdict({needed: 'reactions:write', provided: 'chat:write,reactions:write'})), [], 'Slack still lists it');
  assert.deepEqual(narrowOnMissingScope(rig.runtime, 'slack-account', verdict({needed: 'search:read', provided: 'chat:write'})), [], 'a scope the record lacks');
  assert.deepEqual(narrowOnMissingScope(rig.runtime, 'slack-account', verdict({needed: 'reactions:write', provided: 'chat:write,search:read,users:read,reactions:read'})), ['reactions:write']);
  assert.deepEqual(rig.record().scopes, ['chat:write', 'reactions:read'], 'provided wider than the record never widens it');
  assert.equal(narrowNoticeCount(rig), 1);
  assert.deepEqual(narrowOnMissingScope(rig.runtime, 'slack-account', apiVerdict(rule, {ok: false, error: 'channel_not_found'})), [], 'another error narrows nothing');
  assert.deepEqual(narrowOnMissingScope(rig.runtime, 'nobody', verdict({needed: 'chat:write', provided: ''})), [], 'no account');
});

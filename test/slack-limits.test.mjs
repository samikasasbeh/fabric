import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync, mkdtempSync, readdirSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {DISTRIBUTIONS, PACED, distributionOf} from '../lib/slack-limits.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {Store} from '../lib/store.mjs';
import {AppDetailService} from '../lib/app-detail.mjs';
import {catalog} from '../lib/connections.mjs';
import {createApp} from '../server.mjs';
import {createDeveloperApp} from '../developer-server.mjs';
import {testEnvironment} from '../scripts/test.mjs';
import {IDS} from './fixtures/provider-simulators/slack.mjs';
import {slackRig, slackAction, historyAction, SLACK_OK} from './fixtures/actions/slack-rig.mjs';

// F10.21 part 1 d (docs/F10.21-BUILD-MAP.md part 1 d; spec lines 1213-1218): the operator flag FABRIC_SLACK_DISTRIBUTION says how Fabric's
// Slack app is installed: internal (the default: its own workspace only), distributed, or marketplace. Slack limits a distributed app outside
// the Marketplace to one conversations.history and one conversations.replies a minute in each workspace, 15 messages each, so under
// `distributed` Fabric applies that limit itself, before sending, and says so on Slack's app page. The other two values change nothing.
const LINE = 'Slack limits this app to one history or thread read a minute in each workspace, 15 messages each, because it is distributed outside the Slack Marketplace.';
const WORDS = 'FABRIC_SLACK_DISTRIBUTION must be internal, distributed or marketplace.';
const history = (channel, query = {limit: '15'}) => ({method: 'GET', path: '/conversations.history', query: {channel, ...query}});
const replies = rig => ({method: 'GET', path: '/conversations.replies', query: {channel: IDS.fabricTest, ts: rig.simulator.synthetic.one, limit: '15'}});
const sent = (rig, name) => rig.simulator.calls.filter(call => call.name === name).length;

test('the flag: internal by default, one of three values, anything else refused in fixed words', () => {
  assert.deepEqual([...DISTRIBUTIONS], ['internal', 'distributed', 'marketplace']);
  assert.deepEqual([...PACED], ['conversations.history', 'conversations.replies']);
  assert.equal(distributionOf({}), 'internal');
  for (const value of DISTRIBUTIONS) assert.equal(distributionOf({FABRIC_SLACK_DISTRIBUTION: value}), value);
  for (const value of ['public', '', 'Internal', 'distributed ', 'none']) assert.throws(() => distributionOf({FABRIC_SLACK_DISTRIBUTION: value}), {message: WORDS}, JSON.stringify(value));
  for (const value of ['public', 'Distributed', 7]) assert.throws(() => new Runtime({store: {authorityEnabled: false}, slackDistribution: value}), {message: WORDS}, String(value));
  assert.deepEqual(testEnvironment({PATH: '/bin', FABRIC_SLACK_DISTRIBUTION: 'distributed'}), {PATH: '/bin'}, 'the test runner drops the operator setting');
});

test('a bad FABRIC_SLACK_DISTRIBUTION stops both servers before any state opens', async t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'fabric-slack-limits-'));
  t.after(() => { delete process.env.FABRIC_SLACK_DISTRIBUTION; rmSync(directory, {recursive: true, force: true}); });
  process.env.FABRIC_SLACK_DISTRIBUTION = 'public';
  // A server that starts by mistake is closed at once, so the refusal is all a broken check can leave behind.
  const closing = app => app.close().then(() => app);
  await assert.rejects(createApp({dataDir: path.join(directory, 'data'), port: 0}).then(closing), {message: WORDS});
  assert.equal(existsSync(path.join(directory, 'data', 'fabric.sqlite')), false);
  await assert.rejects(createDeveloperApp({dataRoot: path.join(directory, 'tenants'), port: 0}).then(closing), {message: WORDS});
  assert.equal(existsSync(path.join(directory, 'tenants')) && readdirSync(path.join(directory, 'tenants')).length > 0, false, 'nothing opened under the tenant root');
  process.env.FABRIC_SLACK_DISTRIBUTION = 'distributed';
  const app = await createApp({dataDir: path.join(directory, 'data'), port: 0});
  assert.equal(app.runtime.slackDistribution, 'distributed', 'read once at start and passed to the runtime');
  await app.close();
});

test('internal and marketplace pace nothing: two history reads in a minute are both sent, with any limit', async t => {
  for (const slackDistribution of ['internal', 'marketplace', undefined]) {
    const rig = slackRig(t, {slackDistribution});
    for (const query of [{limit: '15'}, {limit: '100'}, {}]) assert.equal((await rig.proxy(history(IDS.fabricTest, query))).status, 'succeeded', `${slackDistribution} ${JSON.stringify(query)}`);
    assert.equal(sent(rig, 'conversations.history'), 3);
  }
});

test('distributed: a second history read in a workspace within 60 seconds is refused rate_limited with retryAfterSeconds, nothing sent; replies and another workspace apart', async t => {
  const rig = slackRig(t, {slackDistribution: 'distributed', accounts: [{id: 'other-team', team: 'T0OTHER01'}]});
  assert.equal((await rig.proxy(history(IDS.fabricTest))).status, 'succeeded');
  rig.advance(20_000);
  const paced = await rig.proxy(history(IDS.general));
  assert.deepEqual([paced.status, paced.errorCode, paced.reason, paced.retryAfterSeconds], ['failed', 'rate_limited', 'slack_pace', 40]);
  assert.match(paced.error, /one history or thread read a minute in each workspace/);
  assert.equal(sent(rig, 'conversations.history'), 1, 'nothing was sent');
  assert.equal((await rig.proxy(replies(rig))).status, 'succeeded', 'replies are paced apart from history');
  assert.equal((await rig.proxy(history(IDS.fabricTest), 'other-team')).status, 'succeeded', 'another workspace is not paced');
  rig.advance(40_000);
  assert.equal((await rig.proxy(history(IDS.fabricTest))).status, 'succeeded', 'a minute later');
  assert.equal(sent(rig, 'conversations.history'), 3);
});

test('distributed: a proxied history or replies read with a limit above 15, or none, is refused slack_page_limit before anything is sent', async t => {
  const rig = slackRig(t, {slackDistribution: 'distributed'});
  for (const query of [{limit: '16'}, {}, {limit: '100'}, {limit: 'many'}, {limit: '0'}]) {
    const job = await rig.proxy(history(IDS.fabricTest, query));
    assert.deepEqual([job.status, job.errorCode, job.reason], ['failed', 'rate_limited', 'slack_page_limit'], JSON.stringify(query));
    assert.match(job.error, /at most 15 messages/);
  }
  assert.equal(sent(rig, 'conversations.history'), 0);
  const {query, ...rest} = replies(rig);
  assert.equal((await rig.proxy({...rest, query: {...query, limit: '16'}})).reason, 'slack_page_limit');
  assert.equal((await rig.proxy(history(IDS.fabricTest, {limit: '15'}))).status, 'succeeded', 'a page of 15 is sent, and the refused ones never used the minute');
});

test('distributed, actions: Read recent messages twice in a minute: the second is refused with nothing sent; a paced readback leaves its write unverified, never failed', async t => {
  const post = slackAction('post', {effect: 'write', row: 'slack.messages.send', hints: {readOnly: false, destructive: false, idempotent: false, openWorld: true},
    inputSchema: {type: 'object', properties: {channel: {type: 'string', minLength: 1, maxLength: 21}, text: {type: 'string', minLength: 1, maxLength: 100}}, required: ['channel', 'text'], additionalProperties: false},
    outputSchema: {type: 'object', properties: {ts: {type: 'string', maxLength: 32}}, required: ['ts'], additionalProperties: false},
    perform: [{id: 'post', method: 'POST', path: '/chat.postMessage', body: {object: {channel: {input: '/channel'}, text: {input: '/text'}}}, expect: SLACK_OK}],
    verify: {requests: [{id: 'back', method: 'GET', path: '/conversations.replies', query: {channel: {input: '/channel'}, ts: {step: 'post', pointer: '/ts'}, limit: {const: 1}}, expect: SLACK_OK}],
      identity: [{kind: 'readback', step: 'back', pointer: '/messages/0/ts', equals: {step: 'post', pointer: '/ts'}}], assert: []},
    output: {ts: {step: 'post', pointer: '/ts'}}});
  const rig = slackRig(t, {slackDistribution: 'distributed', actions: [historyAction(), post]});
  assert.equal((await rig.run('history', {channel: IDS.fabricTest})).status, 'succeeded');
  rig.advance(1000);
  const second = await rig.run('history', {channel: IDS.fabricTest});
  assert.deepEqual([second.status, second.errorCode, second.reason, second.retryAfterSeconds], ['failed', 'rate_limited', 'slack_pace', 59]);
  assert.equal(sent(rig, 'conversations.history'), 1);
  const wide = slackRig(t, {slackDistribution: 'distributed', actions: [historyAction({limit: 16})]});
  const refused = await wide.run('history', {channel: IDS.fabricTest});
  assert.deepEqual([refused.status, refused.reason, sent(wide, 'conversations.history')], ['failed', 'slack_page_limit', 0]);
  // The readback is paced: a replies read just before it took the minute.
  assert.equal((await rig.proxy(replies(rig))).status, 'succeeded');
  const written = await rig.run('post', {channel: IDS.fabricTest, text: 'hello'});
  assert.deepEqual([written.status, written.errorCode, written.reason, written.result?.verification?.status], ['uncertain', 'outcome_uncertain', 'not_verified', 'unverified']);
  assert.equal(sent(rig, 'chat.postMessage'), 1);
  const internal = slackRig(t, {actions: [historyAction(), post]});
  await internal.proxy(replies(internal));
  assert.equal((await internal.run('post', {channel: IDS.fabricTest, text: 'hello'})).status, 'succeeded', 'internal: the same readback verifies');
});

test('the app page adds the fixed line to Slack\'s limitations only under distributed', t => {
  const view = slackDistribution => {
    const directory = mkdtempSync(path.join(tmpdir(), 'fabric-slack-page-'));
    t.after(() => rmSync(directory, {recursive: true, force: true}));
    const store = new Store({dataDir: directory}), runtime = new Runtime({store, ...(slackDistribution ? {slackDistribution} : {})});
    t.after(() => store.close());
    const service = new AppDetailService({store, runtime, catalog: () => catalog, accessLevels: () => [], accessLevelOf: () => 'custom', oauthProviderFor: () => null});
    return id => service.view(id).app.limitations;
  };
  const shipped = catalog.find(app => app.id === 'slack').limitations;
  assert.deepEqual(view('distributed')('slack'), [...shipped, LINE]);
  for (const value of ['internal', 'marketplace', undefined]) assert.deepEqual(view(value)('slack'), shipped, String(value));
  assert.equal(view('distributed')('github').includes(LINE), false, 'only Slack\'s page');
});

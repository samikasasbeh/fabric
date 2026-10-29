import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync, mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {canonicalHash} from '../lib/compiler.mjs';
import {RETENTION, retentionOf, bodyTtl} from '../lib/retention.mjs';
import {RESPONSE_TTL} from '../lib/proxy-runtime.mjs';
import {Runtime, sweepRetention} from '../lib/runtime.mjs';
import {Store} from '../lib/store.mjs';
import {EnvironmentRuntimes} from '../lib/tenant/runtime-bundle.mjs';
import {createApp} from '../server.mjs';
import {IDS} from './fixtures/provider-simulators/slack.mjs';
import {slackRig, historyAction, OWNER, SLACK_TOKEN} from './fixtures/actions/slack-rig.mjs';
import {calendarHarness} from './fixtures/actions/calendar-harness.mjs';

// F10.21 part 1 c (docs/F10.21-BUILD-MAP.md part 1 c; spec line 1220, owner decision 11): until Sami reviews Slack's API Terms, Fabric keeps
// what Slack returned for 24 hours: a proxied Slack response body, and a Slack action's result data. After that only the status, the codes,
// the hashes and the audit rows remain. Other apps keep the proxy's 7 days and their action results. A sweep deletes what expired: at
// start, whenever a job is accepted, and every minute while a Fabric runs.
const HOUR = 3_600_000, DAY = 24 * HOUR;
/** A runtime on the rig's store that also reaches a GitHub account, answered by a stub (another app keeps the proxy's 7 days). */
function withGithub(rig) {
  rig.store.put('connections', {id: 'github-account', appId: 'github', driver: 'http', authMethod: 'token', authRevision: 'g1', status: 'ready', label: 'GitHub', identity: {id: '101'},
    allowedOrigins: ['https://api.github.com'], createdAt: new Date(rig.now).toISOString()});
  return new Runtime({store: rig.store, permissions: rig.permissions, proxyPolicy: rig.proxyPolicy, ownerPrincipal: OWNER, clock: () => rig.now,
    connections: {credentials: async () => ({headers: {Authorization: `Bearer ${SLACK_TOKEN}`}, allowedOrigins: ['https://api.github.com']})},
    request: async () => ({status: 200, headers: {'content-type': 'application/json'}, data: Buffer.from('{"items":[1,2]}')})});
}
const indexOf = (rig, job) => rig.store.get('proxyResponses', `holder:${rig.store.get('proxyResponses', job.id)?.holder ?? 'owner'}`)?.entries.map(entry => entry.id) ?? [];

test('the rule: Slack keeps 24 hours (decision 11); every other app keeps the proxy\'s 7 days', () => {
  assert.equal(RETENTION.slack, DAY);
  assert.deepEqual(Object.keys(RETENTION), ['slack']);
  assert.equal(bodyTtl('slack'), DAY);
  for (const appId of ['github', 'gmail', 'google-calendar', 'notion', 'fixture', undefined]) {
    assert.equal(bodyTtl(appId), RESPONSE_TTL, String(appId));
    assert.equal(retentionOf(appId), null, String(appId));
  }
});

test('a Slack proxy body is readable for 24 hours, hidden once it expires and deleted by the sweep with its index entry; a GitHub body is still kept at 6 days', async t => {
  const rig = slackRig(t), github = withGithub(rig);
  const slack = await rig.proxy({method: 'GET', path: '/conversations.history', query: {channel: IDS.fabricTest}});
  const other = await github.createProxyJob({connectionId: 'github-account', request: {method: 'GET', path: '/user/repos'}}, OWNER);
  assert.deepEqual([slack.status, slack.result.response.payload, other.status, other.result.response.payload], ['succeeded', 'stored', 'succeeded', 'stored']);
  assert.equal(rig.store.get('proxyResponses', slack.id).expiresAt, new Date(rig.now + DAY).toISOString());
  assert.equal(rig.store.get('proxyResponses', other.id).expiresAt, new Date(rig.now + RESPONSE_TTL).toISOString());
  rig.advance(DAY - 60_000);
  assert.equal(rig.runtime.proxyResponse(slack).body.ok, true, 'readable at 23 hours 59 minutes');
  rig.advance(60_001);
  assert.equal(rig.runtime.proxyResponse(slack), null, 'hidden the moment it expires');
  assert.ok(indexOf(rig, slack).includes(slack.id));
  rig.runtime.sweepRetention();
  assert.equal(rig.store.get('proxyResponses', slack.id), null, 'deleted');
  assert.equal(indexOf(rig, slack).includes(slack.id), false, 'and gone from its holder\'s index, so the quota stays right');
  assert.deepEqual([rig.store.get('jobs', slack.id).status, rig.store.get('jobs', slack.id).result.response.payload, typeof rig.store.get('jobs', slack.id).result.response.status],
    ['succeeded', 'stored', 'number'], 'the job keeps its status and response facts');
  rig.advance(5 * DAY);
  rig.runtime.sweepRetention();
  assert.deepEqual(rig.runtime.proxyResponse(other).body, {items: [1, 2]}, 'GitHub keeps the proxy\'s 7 days');
  assert.ok(indexOf(rig, other).includes(other.id));
});

test('a Slack action\'s result keeps its data for 24 hours, then only {verification, dataHash, kept: false}; status, reason and code stay', async t => {
  const rig = slackRig(t, {actions: [historyAction()]});
  const job = await rig.run('history', {channel: IDS.fabricTest});
  const {result} = rig.store.get('jobs', job.id);
  assert.deepEqual([job.status, result.data, result.keepUntil], ['succeeded', {ok: true}, new Date(rig.now + DAY).toISOString()]);
  rig.advance(DAY - 1);
  rig.runtime.sweepRetention();
  assert.deepEqual(rig.store.get('jobs', job.id).result.data, {ok: true}, 'kept until then');
  rig.advance(1);
  rig.runtime.sweepRetention();
  const swept = rig.store.get('jobs', job.id);
  assert.deepEqual(swept.result, {verification: result.verification, dataHash: canonicalHash({ok: true}), kept: false});
  assert.deepEqual([swept.status, swept.reason ?? null, swept.errorCode ?? null, swept.capabilityHash], ['succeeded', null, null, job.capabilityHash]);
  rig.runtime.sweepRetention();
  assert.deepEqual(rig.store.get('jobs', job.id).result, swept.result, 'a second sweep changes nothing');
});

test('a Calendar action\'s result is untouched by the sweep, however old', async t => {
  const h = calendarHarness(t);
  const job = await h.run('list-calendars v1', {});
  assert.equal(job.status, 'succeeded');
  const before = structuredClone(h.store.get('jobs', job.id));
  assert.equal(before.result.keepUntil, undefined);
  sweepRetention(h.store, Date.now() + 30 * DAY);
  assert.deepEqual(h.store.get('jobs', job.id), before);
});

test('the sweep runs at start (recover()), whenever an action or a proxy job is accepted, and in a developer environment\'s sweeper', async t => {
  const rig = slackRig(t, {actions: [historyAction()]});
  const first = await rig.run('history', {channel: IDS.fabricTest});
  rig.advance(DAY + 1);
  rig.runtime.recover();
  assert.equal(rig.store.get('jobs', first.id).result.kept, false, 'at start');
  const second = await rig.run('history', {channel: IDS.fabricTest});
  rig.advance(DAY + 1);
  await rig.runtime.prepareJob({connectionId: rig.account, capabilityId: rig.idOf('history'), args: {channel: IDS.general}}, OWNER);
  assert.equal(rig.store.get('jobs', second.id).result.kept, false, 'when an action job is accepted');
  const body = await rig.proxy({method: 'GET', path: '/conversations.history', query: {channel: IDS.fabricTest}});
  rig.advance(DAY + 1);
  rig.runtime.prepareProxy({connectionId: rig.account, request: {method: 'GET', path: '/conversations.history', query: {channel: IDS.general}}}, OWNER);
  assert.equal(rig.store.get('proxyResponses', body.id), null, 'when a proxy job is accepted');
  // A developer environment: every open environment is swept, through its runtime when it has one.
  const later = await rig.proxy({method: 'GET', path: '/conversations.history', query: {channel: IDS.fabricTest}});
  rig.advance(DAY + 1);
  const runtimes = new EnvironmentRuntimes({stores: {openHandles: () => [{scope: null, repository: rig.store}]}, registry: {now: () => new Date(rig.now).toISOString()}, providerApps: null, origin: 'http://127.0.0.1:1'});
  runtimes.sweepOpen();
  assert.equal(rig.store.get('proxyResponses', later.id), null, 'the developer server\'s sweeper');
});

test('the server sweeps every minute on an unref\'d timer, cleared when the app closes', async t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'fabric-retention-server-'));
  t.after(() => rmSync(directory, {recursive: true, force: true}));
  t.mock.timers.enable({apis: ['setInterval']});
  const app = await createApp({dataDir: path.join(directory, 'data'), port: 0});
  let sweeps = 0;
  app.runtime.sweepRetention = () => { sweeps++; };
  t.mock.timers.tick(59_999);
  assert.equal(sweeps, 0);
  t.mock.timers.tick(1);
  assert.equal(sweeps, 1);
  await app.close();
  t.mock.timers.tick(5 * 60_000);
  assert.equal(sweeps, 1, 'no sweep after close');
  assert.ok(existsSync(path.join(directory, 'data')));
});

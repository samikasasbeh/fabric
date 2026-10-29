import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createApp} from '../server.mjs';
import {activityPage, operationLabel} from '../lib/ui-contracts.mjs';
import {taskTitle} from '../lib/runtime.mjs';
import {owner, fixture} from './fixtures/continuation-fixture.mjs';
import {freePort} from './fixtures/signin-fixture.mjs';
import {describeItem, describeApproval, dayLabel} from '../public/hosted-activity.js';

// UI-4: activity timeline, approvals queue and agent task titles.
const NOW = Date.parse('2026-10-12T12:00:00.000Z');
const job = (id, status, extra = {}) => ({id, status, effect: 'write', connectionId: 'acct-a', capabilityId: 'cap', source: {kind: 'client', clientId: 'c1'},
  preview: {application: 'github', operation: 'createIssue', request: {method: 'POST', url: 'https://api.github.com/repos/o/r/issues', body: '{"title":"x"}'}},
  createdAt: '2026-10-12T10:00:00.000Z', updatedAt: '2026-10-12T10:00:00.000Z', ...extra});
const names = {appName: id => ({github: 'GitHub'})[id] || id, accountName: () => 'octo', clientName: () => 'Muse', now: NOW};

test('task titles are one line of plain text, at most 120 characters, or nothing', () => {
  assert.equal(taskTitle(undefined), null); assert.equal(taskTitle(null), null);
  assert.equal(taskTitle({title: '  Triage\nbilling   emails '}), 'Triage billing emails');
  for (const bad of [{title: ''}, {title: '   '}, {title: 'x'.repeat(121)}, {title: 1}, {title: 'a', extra: 1}, 'title', []]) assert.throws(() => taskTitle(bad), error => error.code === 'invalid_request', JSON.stringify(bad));
});

test('the timeline groups by day, newest first, and Fabric writes every line from recorded state', () => {
  const page = activityPage({...names, jobs: [
    job('j1', 'succeeded', {effect: 'read', preview: {application: 'github', operation: 'listRepos'}, updatedAt: '2026-10-12T11:00:00.000Z', task: {title: 'Find stale repos'}}),
    job('j2', 'uncertain', {updatedAt: '2026-10-12T09:00:00.000Z'}),
    job('j3', 'failed', {updatedAt: '2026-10-11T09:00:00.000Z'}),
  ]});
  assert.deepEqual(page.days.map(day => [day.date, day.items.map(item => item.callRef)]), [['2026-10-12', ['j1', 'j2']], ['2026-10-11', ['j3']]]);
  const [read, uncertain] = page.days[0].items;
  assert.equal(read.taskTitle, 'Find stale repos'); assert.equal(read.title, 'List repos'); assert.equal(read.summary, 'Read from GitHub');
  assert.equal(uncertain.summary, 'Sent to GitHub; the result could not be confirmed', 'an uncertain write is never shown as done');
  assert.equal(page.days[1].items[0].summary, 'Did not complete');
  assert.equal(read.agent, 'Muse'); assert.equal(read.account, 'octo');
});

test('approvals come first, only while they can still be approved, with the exact request', () => {
  const page = activityPage({...names, jobs: [
    job('a1', 'awaiting_approval', {approvalExpiresAt: '2026-10-12T12:05:00.000Z', approvalDigest: 'd1', task: {title: 'File the bug'}}),
    job('a2', 'awaiting_approval', {approvalExpiresAt: '2026-10-12T11:59:59.000Z', approvalDigest: 'd2'}),
  ]});
  assert.deepEqual(page.approvals.map(item => item.callRef), ['a1'], 'an expired approval is not offered');
  const [approval] = page.approvals;
  assert.deepEqual(approval.approve, {path: '/api/jobs/a1/approve', body: {approvalDigest: 'd1'}});
  assert.deepEqual(approval.cancel, {path: '/api/jobs/a1/cancel', body: {}});
  assert.deepEqual(approval.exact, {complete: true, blocks: [{label: 'Request', text: 'POST https://api.github.com/repos/o/r/issues'}, {label: 'Body', text: '{"title":"x"}'}]});
  assert.equal(approval.taskTitle, 'File the bug'); assert.equal(approval.operation, 'Create issue');
});

test('account requests appear on their own while open, and once as their action after they resume', () => {
  const open = {id: '11111111-1111-4111-8111-111111111111', status: 'awaiting_owner', clientId: 'c1', grantEntry: {appId: 'github', capabilityId: 'cap'}, updatedAt: '2026-10-12T11:30:00.000Z', taskTitle: 'Connect GitHub'};
  const resumed = {id: '22222222-2222-4222-8222-222222222222', status: 'resumed', clientId: 'c1', grantEntry: {appId: 'github', capabilityId: 'cap'}, binding: {jobId: 'j9'}, updatedAt: '2026-10-12T11:40:00.000Z'};
  const page = activityPage({...names, capabilityName: () => 'createIssue', continuations: [open, resumed], jobs: [job('j9', 'succeeded', {updatedAt: '2026-10-12T11:45:00.000Z'})]});
  const items = page.days[0].items;
  assert.deepEqual(items.map(item => [item.kind, item.callRef]), [['action', 'j9'], ['account_request', open.id]]);
  assert.equal(items[0].viaRequest, true);
  assert.equal(items[1].openUrl, `/continue/${open.id}`); assert.equal(items[1].summary, 'Waiting for you to choose an account'); assert.equal(items[1].title, 'Create issue needs a GitHub account');
  const closed = activityPage({...names, continuations: [{...open, status: 'declined'}]}).days[0].items[0];
  assert.equal(closed.openUrl, undefined); assert.equal(closed.summary, 'You declined the account request');
});

test('the timeline pages with an opaque cursor', () => {
  const jobs = Array.from({length: 5}, (_, i) => job(`p${i}`, 'succeeded', {updatedAt: `2026-10-12T0${i}:00:00.000Z`}));
  const first = activityPage({...names, jobs, limit: 2});
  assert.deepEqual(first.days.flatMap(day => day.items.map(item => item.callRef)), ['p4', 'p3']);
  const second = activityPage({...names, jobs, limit: 2, cursor: first.nextCursor});
  assert.deepEqual(second.days.flatMap(day => day.items.map(item => item.callRef)), ['p2', 'p1']);
  assert.throws(() => activityPage({...names, jobs, cursor: 'bogus'}), error => error.code === 'invalid_request');
});

test('operation names read as words in the timeline', () => {
  assert.equal(operationLabel('createIssue'), 'Create issue');
  assert.equal(operationLabel('users.drafts: list'), 'Users.drafts list');
  assert.equal(operationLabel('gmail.users.messages.send'), 'Gmail users messages send');
  assert.equal(operationLabel(undefined), 'An operation');
});

test('agents can title their calls and requests; the title follows a request to its derived action', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant({bindings: []});
  const created = await f.invoke(token, 'calls.create', {...f.ask(client), task: {title: 'Find stale repos'}}, 'titled');
  const record = f.store.get('continuations', created.result.id);
  assert.equal(record.taskTitle, 'Find stale repos');
  await f.select(record.id, 'acct-a'); await f.service.settled(record.id);
  assert.deepEqual(f.jobs()[0].task, {title: 'Find stale repos'}, 'the derived action carries it');
  for (const task of [{title: 'x'.repeat(121)}, {title: 'a', extra: 1}, 'just text']) {
    const refused = await f.invoke(token, 'calls.create', {...f.ask(client), task}, `bad-${JSON.stringify(task).length}`);
    assert.equal(refused.error.code, 'invalid_request');
  }
  assert.equal(f.store.list('protocolRequests').length, 1, 'a refused title leaves no reservation');
  const bound = f.protocol.createClient({name: 'Bound', bindings: [{connectionId: 'acct-a', capabilityId: f.read.id}]}, owner);
  const direct = await f.invoke(bound.token, 'calls.create', {connectionId: 'acct-a', capabilityId: f.read.id, definitionHash: bound.client.bindings[0].definitionHash, args: {}, task: {title: 'List repos now'}}, 'direct');
  assert.equal(f.store.get('jobs', direct.result.id).task.title, 'List repos now');
});

test('the page shows the agent title first and makes invisible characters visible in approvals', () => {
  assert.deepEqual(describeItem({title: 'Create issue', taskTitle: 'File the bug', summary: 'Done in GitHub', status: 'succeeded', agent: 'Muse'}),
    {heading: 'File the bug', detail: 'Create issue · Done in GitHub', mark: '✓', attention: false, open: null, by: 'by Muse'});
  assert.equal(describeItem({title: 'Create issue', summary: 'Sent', status: 'uncertain'}).attention, true);
  assert.equal(describeItem({title: 'x', summary: 'y', status: 'awaiting_owner', openUrl: 'https://evil.example/'}).open, null, 'only Fabric\'s own handoff route');
  const shown = describeApproval({operation: 'Send email', appName: 'Gmail', taskTitle: 'Just a note', exact: {complete: true, blocks: [{label: 'Body', text: 'to: boss\u202egnp.exe'}]}, approve: {}, cancel: {}});
  assert.ok(shown.blocks[0].text.includes('⟦U+202E⟧') && !shown.blocks[0].text.includes('\u202e'));
  assert.equal(shown.heading, 'Send email in Gmail'); assert.equal(shown.agentSays, 'Agent says: “Just a note”');
  assert.equal(dayLabel('2026-10-12', new Date('2026-10-12T15:00:00')), 'Today'); assert.equal(dayLabel('2026-10-11', new Date('2026-10-12T15:00:00')), 'Yesterday');
});

test('the activity route and page are owner-only and same-origin', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-activity-')), port = await freePort();
  const app = await createApp({dataDir: dir, port, request: async () => ({status: 200, data: {}})});
  await app.start();
  t.after(async () => { await app.close(); await rm(dir, {recursive: true, force: true}); });
  const ok = await fetch(`${app.origin}/api/ui/activity`);
  assert.equal(ok.status, 200); assert.deepEqual(await ok.json(), {approvals: [], days: []}, 'an empty Fabric shows nothing, not sample data');
  assert.equal((await fetch(`${app.origin}/api/ui/activity`, {headers: {'sec-fetch-site': 'cross-site'}})).status, 400);
  const page = await fetch(`${app.origin}/activity`);
  assert.equal(page.status, 200); assert.match(await page.text(), /src="\/hosted-activity\.js"/);
  assert.match((await fetch(`${app.origin}/hosted-text.js`)).headers.get('content-type'), /javascript/);
});

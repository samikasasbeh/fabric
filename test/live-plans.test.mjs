import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadActionCatalog, triggerEvidencePasses} from '../lib/action-catalog.mjs';
import {assertEvidenceSafe, checkTriggerPlan, PLAN_LIMITS} from '../lib/live-certify.mjs';
import {RULES} from '../lib/live-guard.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {PINS} from '../lib/transform-pins.mjs';
import {GOOGLE_APPS, PATHS_FILE, SCOPES_FILE, methodMap} from '../scripts/google-method-paths.mjs';
import {OWNER_EMAIL as CALENDAR_OWNER, TOKEN as CALENDAR_TOKEN, ZONE} from './fixtures/actions/calendar-harness.mjs';
import {OWNER_EMAIL as GMAIL_OWNER} from './fixtures/actions/gmail-harness.mjs';
import {BASE as CALENDAR_BASE, ORIGIN as CALENDAR_ORIGIN} from './fixtures/provider-simulators/google-calendar.mjs';
import {IDS} from './fixtures/provider-simulators/slack.mjs';
import {livePass, shippedPlan} from './fixtures/actions/live-pass.mjs';

// Iteration 9 part 9b (docs/I07-BUILD-MAP.md step 9): the five shipped trigger plans, each played whole on its app's simulator, behind the real guard, with --leave. A plan that runs here can still fail on a provider, and
// that is what part 9c is for: every switch of a simulator reads from the provider's pages until a probe moves it. What this proves is that each plan is one the guard, the rows, the actions and the checks all accept.

const APPS = Object.freeze(['slack', 'notion', 'github', 'gmail', 'google-calendar']);

test('plans 1: no plan asks the owner to delete anything, holds no cleanup test, opens a row, or names a test account\'s address', () => {
  for (const appId of APPS) {
    const plan = shippedPlan(appId), steps = plan.tests.flatMap(item => [...item.steps, ...(item.undo?.steps ?? [])]);
    assert.equal(plan.triggers, true, appId);
    assert.deepEqual(plan.tests.filter(item => item.cleanup), [], `${appId}: --leave has nothing to skip`);
    assert.deepEqual(steps.filter(step => step.oneTimeAsk), [], `${appId}: a one-time Ask opens a Never row, and a run deletes nothing`);
    for (const step of steps) if (step.owner) assert.doesNotMatch(step.owner.words, /\b(delete|discard|remove|clean)/i, `${appId}: ${step.owner.words}`);
    assert.doesNotMatch(JSON.stringify(plan).replace(/fabric-(?:guest|share)@example\.com/g, ''), /@[a-z0-9-]+\.[a-z]/i, `${appId}: a real address is recorded for a run and never written in its plan, and these two are the guard's own`);
  }
});

test('plans 2: each plan passes checkTriggerPlan() against the shipped catalog, rows, proxy settings and guard, and watches every trigger of its app', () => {
  const read = file => JSON.parse(readFileSync(new URL(`../${file}`, import.meta.url), 'utf8'));
  const maps = new Map(GOOGLE_APPS.map(id => [id, methodMap(read(PATHS_FILE), read(SCOPES_FILE), id)]).filter(([, map]) => map)), catalog = loadActionCatalog({maps});
  for (const appId of APPS) {
    const items = kind => [...catalog[kind].values()].filter(item => item.appId === appId).map(item => item.entry), triggers = items('triggers');
    const deps = {entries: items('entries'), triggers, superseded: [...catalog.superseded.keys()], groups: PERMISSION_GROUPS.get(appId), config: PROXY_CONFIGS.get(appId), rules: RULES};
    const checked = checkTriggerPlan(shippedPlan(appId), deps);
    assert.deepEqual([...checked.triggers.keys()].sort(), triggers.map(entry => `${entry.key}@${entry.version}`).sort(), appId);
    assert.ok(triggers.length >= 6, `${appId}: the catalog holds its triggers`);
    assert.ok(checked.plan.tests.length <= PLAN_LIMITS.tests, appId);
    // The check is not a formality: a plan short of one watch is refused, whichever watch that is.
    const plan = shippedPlan(appId), test = plan.tests.find(item => item.steps.some(step => step.watch)), last = test.steps.findLast(step => step.watch), name = Object.keys(last.watch.save)[0];
    plan.tests = plan.tests.map(item => ({...item, steps: item.steps.filter(step => step !== last && (step.poll ?? step.age ?? step.unwatch)?.subscription?.$saved !== name)})).filter(item => item.steps.length);
    assert.throws(() => checkTriggerPlan(plan, deps), /is watched by no step, so it would get no evidence|\$saved|is watched and never polled/, appId);
  }
});

test('plans 3: what a plan reads, it compares: an event or a gap by a value in it, and a read or a hand step\'s wait by a value, a count, or a named value it saves, so none passes on an empty answer', () => {
  const compares = (check, pointer = '') => (Object.hasOwn(check, 'equals') || Object.hasOwn(check, 'oneOf') || Object.hasOwn(check, 'count')) && check.pointer?.startsWith(pointer);
  const saves = ({save}) => Object.keys(save ?? {}).length > 0 && Object.values(save).every(pointer => pointer !== '');
  for (const appId of APPS) {
    for (const item of shippedPlan(appId).tests) for (const step of [...item.steps, ...(item.undo?.steps ?? [])]) {
      const where = `${appId} ${item.id}: ${JSON.stringify(step).slice(0, 200)}`;
      if (step.poll?.events > 0) assert.ok(step.poll.checks?.some(check => compares(check, '/events')), where);
      if (step.poll?.gaps > 0) assert.ok(step.poll.checks?.some(check => compares(check, '/gaps')), where);
      if (step.read) assert.ok(step.read.checks?.some(check => compares(check)) || saves(step.read), where);
      if (step.owner?.until) assert.ok(step.owner.until.checks.some(check => compares(check)), where);
    }
  }
});

test('plans 4: probes section 12 owes run inside the plans that can reach them: Calendar P1, GitHub 7\'s order, GitHub\'s X-Poll-Interval and Gmail U6, and each only saves or reads, so a no stops no pass', () => {
  const steps = appId => shippedPlan(appId).tests.flatMap(item => item.steps.map(step => ({test: item.id, ...step})));
  const reads = steps('google-calendar').filter(step => step.read?.query?.syncToken);
  assert.equal(reads.length, 3, 'one old token twice, and the token after it');
  assert.equal(new Set(reads.map(step => step.test)).size, 1);
  assert.deepEqual(reads.slice(0, 2).map(step => step.read.query.syncToken), [{$saved: 'replayToken'}, {$saved: 'replayToken'}]);
  const github = steps('github');
  assert.ok(github.some(step => step.read?.path.endsWith('/actions/runs') && step.read.save?.newestRun));
  assert.ok(github.some(step => step.read?.path.endsWith('/releases') && step.read.save?.newestRelease));
  assert.ok(github.some(step => step.poll?.floor > 0 && step.poll.subscription.$saved === 'threads'));
  assert.ok(steps('gmail').some(step => step.call?.action === 'move-to-trash@1'));
});

/** Every test passed, nothing was left standing, and each trigger of the file holds evidence the start would accept. */
function proved(pass) {
  const {run, evidence, triggers} = pass;
  assert.equal(run.stopped, null, JSON.stringify(run.stopped));
  for (const id of run.order) assert.equal(run.results[id].passed, true, `${id}: ${run.results[id].words}`);
  assert.deepEqual(run.left, [], 'a pass leaves nothing for the owner to tidy');
  assert.deepEqual(pass.port.grants(), [], 'every grant of the run revoked');
  for (const entry of triggers) {
    const record = evidence.records[entry.id];
    assert.equal(record?.passed, true, `${entry.key}: ${JSON.stringify(record?.tests.map(item => [item.test, item.passed, item.proof]))}`);
    assert.equal(triggerEvidencePasses(entry, record, PINS.transforms), true, `${entry.key}: ${JSON.stringify(record.tests.map(item => item.proof))}`);
  }
  assertEvidenceSafe(JSON.stringify(evidence), {emails: ['owner@fabric-owner.test']});
}

const SLACK = {
  recorded: h => ({fabricTest: IDS.fabricTest, selfDm: IDS.selfDm, ownerUser: IDS.owner, synthetic1: h.simulator.synthetic.one, synthetic2: h.simulator.synthetic.two, privateChannel: 'fabric-synthetic-tr7-1102'}),
  hands: [['fabric-synthetic\\.txt', ({h}) => { h.advance(1000); h.simulator.post(IDS.fabricTest, {subtype: 'file_share', user: IDS.owner, files: [{id: 'F0SYNTHET1', name: 'fabric-synthetic.txt', mimetype: 'text/plain'}]}); }],
    ['privateChannel', ({h}) => { h.simulator.addChannel({id: 'G0TR700001', name: 'fabric-synthetic-tr7-1102', private: true}); }]],
};

test('pass slack: the shipped plan runs whole behind the real guard, with its hand steps last', async t => {
  const pass = await livePass(t, 'slack', SLACK);
  proved(pass);
  assert.deepEqual(pass.run.order, ['TW', 'TR1', 'TR2', 'TR3', 'TR4', 'TR5', 'TR6', 'TR7']);
  assert.equal(pass.used.length, 2);
  assert.equal(pass.guard.trace('TR3').some(item => item.method === 'POST' && item.path.endsWith('/chat.postMessage')), true);
  assert.deepEqual(pass.h.store.list('jobs').filter(job => job.status !== 'succeeded').map(job => [job.kind, job.status, job.result?.response?.status]), [['proxy', 'uncertain', 200]], 'an ask reads nothing back, so its one job ends uncertain with its answer');
});

/** Notion's test area, as its action plan records it: pages A and B, and a database under A whose rows were made long before any watch. */
const NOTION = {
  setup(h) {
    const {simulator} = h, a = simulator.seedPage({title: '[SYNTHETIC] Page A', markdown: 'A', shared: true}), b = simulator.seedPage({title: '[SYNTHETIC] Page B', markdown: 'B', shared: true});
    const {database, sources: [source]} = simulator.seedDatabase({title: '[SYNTHETIC] Database', parent: {page_id: a.id}, sources: [{name: 'Rows', properties: {Name: {type: 'title'}, Stage: {type: 'select', options: ['Open', 'Done']}, Count: {type: 'number'}}}]});
    const row = simulator.seedRow({dataSource: source.id, properties: {Name: {title: [{text: {content: '[SYNTHETIC] Row 1'}}]}, Count: {number: 1}}});
    h.advance(3_600_000);
    Object.assign(h, {area: {pageA: a.id, pageB: b.id, database: database.id, dataSource: source.id, row1: row.id}});
  },
  recorded: h => h.area,
  hands: [['one small image', ({h}) => { h.simulator.uploadFile(h.area.pageB, 'image.png'); }], ['Access comments to Never', ({h}) => { h.setRow('notion.comments.read', 'deny'); }]],
};

test('pass notion: the shipped plan runs whole behind the real guard, and the schema ends as it started', async t => {
  const pass = await livePass(t, 'notion', NOTION);
  proved(pass);
  assert.deepEqual(pass.run.order, ['TS', 'TW', 'T1', 'TW2', 'T2', 'T3', 'T4', 'T5', 'T6', 'T7', 'T8']);
  assert.equal(pass.used.length, 2);
  assert.equal(pass.guard.trace('T8').length, 0, 'no call to Notion once the row reads Never');
  assert.deepEqual(pass.run.results.T8.checks.map(check => check.name), ['step 2: paused permission_changed, no request and no answer', 'step 3: paused permission_changed, no request and no answer']);
  assert.deepEqual(Object.keys(Object.values(pass.h.simulator.state().sources)[0].properties).sort(), ['Count', 'Name', 'Stage']);
});

const SANDBOX = 'samikasasbeh/fabric-sandbox-test';
/** GitHub's simulator under the sandbox's real name, which is what the guard reads. A run ends some time after it starts, with its notification, as the hand of GitHub's own runner. */
const GITHUB = {
  world: {login: 'samikasasbeh'},
  setup(h) { h.simulator.rename('samikasasbeh/fabric-sandbox', SANDBOX); },
  hands: [['Settings, Notifications', () => {}]],
  onWait({h, state}, ms) {
    const run = state.data.saved.workflowRun;
    if (!run || ms !== 10_000 || h.ended) return;
    h.ended = true;
    h.simulator.finishRun(run);
    h.simulator.notify(SANDBOX, {reason: 'ci_activity', type: 'CheckSuite', title: '[SYNTHETIC] Fabric run'});
  },
};

test('pass github: the shipped plan runs whole behind the real guard, and its last re-poll of issues is a 304', async t => {
  const pass = await livePass(t, 'github', GITHUB);
  proved(pass);
  assert.deepEqual(pass.run.order, ['TS', 'TW', 'TH2', 'TH3', 'TH5', 'TH4', 'TH6', 'TH8', 'TH9']);
  assert.equal(pass.guard.trace('TH2').at(-1).status, 304);
});

const SECOND_ACCOUNT = 'second-test@example.net', encode = text => Buffer.from(text, 'utf8').toString('base64url');
const rawMail = (subject, {from = GMAIL_OWNER, to = GMAIL_OWNER, more = [], body = 'Hello.'} = {}) => encode(`${[`From: ${from}`, `To: ${to}`, `Subject: ${subject}`, ...more].join('\r\n')}\r\n\r\n${body}\r\n`);
const REFERENCE = '<tg4@example.net>';
/** Above the mailbox's current id, which is one of the two answers probe U7 can give. */
const GMAIL = {
  email: GMAIL_OWNER,
  recorded: () => ({staleHistoryId: '9007199254740993'}),
  hands: [['subject \\[SYNTHETIC\\] Fabric TG4 to your second', ({h}) => {
    h.simulator.ownerSends(rawMail('[SYNTHETIC] Fabric TG4', {to: SECOND_ACCOUNT, more: [`Message-ID: ${REFERENCE}`]}));
    h.simulator.deliver(rawMail('Re: [SYNTHETIC] Fabric TG4', {from: SECOND_ACCOUNT, more: [`In-Reply-To: ${REFERENCE}`, `References: ${REFERENCE}`]}));
  }],
  ['subject \\[SYNTHETIC\\] Fabric TG4b', ({h}) => { h.simulator.deliver(rawMail('[SYNTHETIC] Fabric TG4b', {from: SECOND_ACCOUNT})); }],
  ['Fabric TG6', ({h}) => {
    h.simulator.ownerSends(rawMail('[SYNTHETIC] Fabric TG6', {more: ['Content-Type: multipart/mixed; boundary="fabric"'],
      body: '--fabric\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nHello.\r\n--fabric\r\nContent-Type: text/plain; name="fabric-synthetic.txt"\r\nContent-Disposition: attachment; filename="fabric-synthetic.txt"\r\n\r\nData.\r\n--fabric--'}));
  }],
  ['Access emails to Never', ({h}) => { h.setRow('gmail.messages.read', 'deny'); }],
  ['back to Allow', ({h}) => { h.setRow('gmail.messages.read', 'allow'); }]],
};

test('pass gmail: the shipped plan runs whole behind the real guard, and a stale id gives each of five watches one gap and no repeat', async t => {
  const pass = await livePass(t, 'gmail', GMAIL);
  proved(pass);
  assert.deepEqual(pass.run.order, ['TS', 'TW', 'TG1', 'TG2', 'TG3', 'TG4', 'TG5', 'TGO', 'TG6', 'TG7', 'TG8']);
  assert.equal(pass.used.length, 5);
  assert.equal(pass.guard.trace('TG8').length, 0);
  const history = pass.triggers.filter(entry => entry.trigger.poll.cursors.some(cursor => cursor.kind === 'history-id@1'));
  assert.equal(history.length, 5);
  for (const entry of history) assert.deepEqual(pass.evidence.records[entry.id].tests.find(item => item.test === 'TG7').proof.resync, {status: 404, gapEvents: 1, duplicates: 0}, entry.key);
});

const SECOND_GUEST = 'second-test@example.net', SHARED = 'fabric-share@example.com';
/** Google copies an event onto a guest calendar, and takes the copy away with it. The simulator does neither (section 12, step 8), so here that is one hand, once each. */
const GOOGLE = {
  async onWait({h, state}) {
    const {invited, calendarB} = state.data.saved, original = invited ? h.simulator.state().events[invited] : null;
    const at = minutes => ({dateTime: new Date(h.now + 9 * 86_400_000 + minutes * 60_000).toISOString(), timeZone: 'UTC'});
    if (original && !h.copy) h.copy = h.simulator.invite({calendarId: calendarB, summary: original.summary, start: at(0), end: at(30)});
    if (h.copy && !h.copyGone && original?.status === 'cancelled') {
      h.copyGone = true;
      const url = `${CALENDAR_BASE}/calendars/${encodeURIComponent(calendarB)}/events/${h.copy.id}?sendUpdates=none`;
      await h.simulator.request({url, method: 'DELETE', headers: {Authorization: `Bearer ${CALENDAR_TOKEN}`}, allowedOrigins: [CALENDAR_ORIGIN]});
    }
  },
};
const answer = status => ({h, state}) => { const {calendarA, guestEvent} = state.data.saved; h.simulator.guestResponds(calendarA, guestEvent, SECOND_GUEST, status); };
const CALENDAR = {
  email: CALENDAR_OWNER, timeZone: ZONE, onWait: GOOGLE.onWait,
  recorded: () => ({secondGuest: SECOND_GUEST}),
  hands: [['answer Yes to the event whose title ends in guest', answer('accepted')], ['answer Maybe', answer('tentative')], ['answer Yes to that event again', answer('accepted')],
    ['share it with fabric-share', ({h, state}) => { h.simulator.share(state.data.saved.calendarA, SHARED, 'reader'); }],
    ['hide the calendar', ({h, state}) => { h.simulator.hideCalendar(state.data.saved.calendarB); }], ['Show that calendar', ({h, state}) => { h.simulator.hideCalendar(state.data.saved.calendarB, false); }],
    ['Access events to Never', ({h}) => { h.setRow('google-calendar.events.read', 'deny'); }]],
};

test('pass google-calendar: the shipped plan runs whole behind the real guard, a series gives one event, and an event an hour from now is reached only in its own test', async t => {
  const pass = await livePass(t, 'google-calendar', CALENDAR);
  proved(pass);
  assert.equal(pass.used.length, 7);
  assert.equal(pass.guard.trace('TC-never').length, 2, 'only the two watches that do not read that row asked Google anything');
  assert.deepEqual(pass.guard.trace('TC-soon').filter(item => item.method === 'POST').map(item => item.status), [200], 'the one write of the test');
});

test('resume: a stop at a hand step resumes whole on each app, since a resume watches again and no test reads what an earlier test left for a watch it replaced', async t => {
  const SLACK_STOP = {...SLACK, stopAt: 'fabric-synthetic\\.txt'}, CASES = [['slack', SLACK_STOP, 'TR6'], ['notion', {...NOTION, stopAt: 'Access comments to Never'}, 'T8'], ['gmail', {...GMAIL, stopAt: 'Fabric TG6'}, 'TG6'],
    ['google-calendar', {...CALENDAR, stopAt: 'share it with fabric-share'}, 'TC-share'], ['google-calendar', {...CALENDAR, stopAt: 'hide the calendar'}, 'TC-hide']];
  for (const [appId, options, id] of CASES) {
    await t.test(`${appId} at ${id}`, async inner => {
      const pass = await livePass(inner, appId, options);
      assert.equal(pass.stopped?.test, id, JSON.stringify(pass.stopped));
      proved(pass);
    });
  }
});

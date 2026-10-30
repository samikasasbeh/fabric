import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, randomBytes, randomUUID} from 'node:crypto';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {parseTemplate} from '../lib/permission-groups.mjs';
import {normalizeProxyRequest, LIMITS} from '../lib/proxy-request.mjs';
import {LOCK_WORDS} from '../lib/row-locks.mjs';
import {LOCAL_DEPLOYMENT, tenantDeployment} from '../lib/tenant/deployment.mjs';
import {ABSENT, ACTION_REFUSED, REFUSAL_WORDS, actionRefused, createJob, newFrame, evaluate, passes, stepRuns, forEachItems, buildRequest, checkConcrete, checkGuard,
  stepData, nextPage, buildOutput, buildPreview, credentialContext, scrubAnswer, holdsCredential, assertNoCredential, MAX_ITEMS, PREPARED, RECORDS, RUN_WORDS, holds, identityHolds} from '../lib/actions-runtime.mjs';
import {REFUSALS, resolvedSchemaHash} from '../lib/actions.mjs';
import {loadActionCatalog, STATUS_WORDS} from '../lib/action-catalog.mjs';
import {PermissionManager, ACTION_WORDS, capabilityPermissionHash} from '../lib/permissions.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {approvalItem} from '../lib/ui-contracts.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';
import {END_USER_COLLECTIONS} from '../lib/tenant/users.mjs';
import {ERROR_DEFINITIONS} from '../contracts/execution.mts';
import {actionHarness, certifiedFile, slackHarness, EVIDENCE, TOKEN, SLACK_TOKEN} from './fixtures/actions/runtime-fixture.mjs';
import {fixtureMap} from './fixtures/actions/fixture-app.mjs';
import {TRANSFORMS, PINS} from './fixtures/actions/registry.mjs';
import {shippedFolder, ownerApp, accounts} from './fixtures/actions/owner-fixture.mjs';
import {developerHarness} from './fixtures/actions/developer-fixture.mjs';
import {notionHarness} from './fixtures/actions/notion-harness.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';

// F10.11 part b (docs/F10.11-BUILD-MAP.md section 3): the evaluator, the request builder, preparing and sending an action. Part b wrote
// every test of section 3 first, each a todo until the part that builds it. Part g (the evaluator and the request builder, pure, no network)
// turned its own into tests; parts h and i (preparing an action, then sending and checking it) turn theirs into tests on the simulator below.

// ---- helpers ---------------------------------------------------------------------------------------------------------------------------
/** The harness, an entry by its key, a step of an entry, and the app context checkConcrete() reads. */
function setup(t, options) {
  const h = actionHarness(t, options), items = [...h.catalog.entries.values()];
  const item = key => items.find(entry => `${entry.entry.key} v${entry.entry.version}` === key);
  const context = {definition: h.groups.get('fixture'), config: h.configs.get('fixture'), map: fixtureMap()};
  return {h, item, entry: key => item(key).entry, context, pinned: key => item(key).capability.action.pinnedParameters};
}
const stepOf = (entry, id) => [...(entry.action.resolvedInputs ?? []).flatMap(input => input.schema.steps), ...entry.action.prepare, ...entry.action.perform, ...(entry.action.verify?.requests ?? [])]
  .find(step => step.id === id);
/** A job of one action on the fixture account, its clock counting reads. */
function jobOf(entry, {jobId = 'job-1', identity = {id: 'acct-1'}, appId = 'fixture', clock = () => Date.parse('2026-10-23T09:00:00.000Z'), transforms = TRANSFORMS, ...rest} = {}) {
  let reads = 0;
  const job = createJob({jobId, entry, appId, identity, clock: () => { reads++; return clock(); }, transforms, ...rest});
  return {job, reads: () => reads};
}
const answer = (data, headers = {}, status = 200) => ({status, headers, data});
/** Asserts an action refusal: code action_refused, the reason in details, and the reason's fixed words. */
const refused = (fn, reason, words = REFUSAL_WORDS[reason]) => assert.throws(fn, error => {
  assert.equal(error.code, ACTION_REFUSED, error.message);
  assert.equal(error.details?.reason, reason, error.message);
  assert.equal(error.message, words);
  return true;
});

// ---- part g ----------------------------------------------------------------------------------------------------------------------------
test('part g: run-time placement: a literal sibling, a body routed to another row, a locked template and a stricter typed operation each refuse before sending', t => {
  // A literal sibling of GET /items/{item_id} in another row, and a locked template that fits every PATCH.
  const rows = file => ({...file, groups: file.groups.map(group => group.id === 'fixture.keys.read' ? {...group, requests: [...group.requests, 'GET /items/archived']}
    : group.id === 'fixture.access.grant' ? {...group, requests: [...group.requests, 'PATCH /{+rest}']} : group)});
  const {entry, context} = setup(t, {rows}), update = entry('update-item v1');
  const {job} = jobOf(update), frame = newFrame(job, {itemId: 'abc', change: 'rename', name: 'New name'});
  // The read lands on its own member: it is checked and kept.
  const read = buildRequest(update, stepOf(update, 'item'), frame, {config: context.config});
  assert.equal(read.request.url, 'https://api.fixture.test/items/abc');
  assert.equal(checkConcrete(update, 'item', read, context), read);
  // A literal sibling: /items/archived is another row's member, so the item read refuses before anything is sent.
  const sibling = buildRequest(update, stepOf(update, 'item'), newFrame(job, {itemId: 'archived', change: 'rename'}), {config: context.config});
  refused(() => checkConcrete(update, 'item', sibling, context), 'not_on_member');
  // A body that one of the member's routes sends to the delete row.
  const routedBody = {labels: ['Label_1', 'TRASH']}, routed = {request: normalizeProxyRequest({method: 'PATCH', path: '/items/abc', body: routedBody}, context.config),
    parts: {params: {item_id: 'abc'}, query: {}, headers: {}, body: routedBody}};
  refused(() => checkConcrete(update, 'label', routed, context), 'not_on_member');
  // A locked template that fits the concrete request, though the request lands on the step's own member.
  const rename = buildRequest(update, stepOf(update, 'rename'), frame, {config: context.config});
  refused(() => checkConcrete(update, 'rename', rename, context), 'locked', LOCK_WORDS);
  // A typed operation that fits only the concrete request (a literal), set stricter than the step was decided.
  const plain = setup(t), edit = plain.entry('update-item v1'), built = buildRequest(edit, stepOf(edit, 'rename'), newFrame(jobOf(edit).job, {itemId: 'abc', change: 'rename', name: 'x'}), {config: plain.context.config});
  const typed = [{capability: {id: 'fixture.literal'}, template: parseTemplate('PATCH /items/abc')}, {capability: {id: 'fixture.other'}, template: parseTemplate('PATCH /items/other')}];
  assert.equal(checkConcrete(edit, 'rename', built, {...plain.context, typed, typedMode: () => 'ask', stepMode: 'ask'}), built, 'no stricter than the step');
  refused(() => checkConcrete(edit, 'rename', built, {...plain.context, typed, typedMode: capability => capability.id === 'fixture.literal' ? 'deny' : 'allow', stepMode: 'ask'}), 'stricter_typed');
  assert.equal(checkConcrete(edit, 'rename', built, {...plain.context, typed: typed.slice(1), typedMode: () => 'deny', stepMode: 'allow'}), built, 'a typed operation that does not fit adds nothing');
});

test('part g: step data: a whole provider object at a raw position, an output over 1 MiB or off-schema, a non-scalar preview, an object in a concat, an each over its max, 1,001 items or one page too many each refuse; forEach data is the answers in order; paged data is joined', t => {
  const {entry, context} = setup(t), draft = entry('send-draft v1'), list = entry('list-items v1'), remove = entry('remove-labels v1');
  const {job} = jobOf(draft);
  // A raw step-data value at a body position: a string passes; a whole object refuses at checkRequest().
  const steps = new Map([['draft', answer({raw: 'cmF3', subject: 'Hello', id: 'd1'})]]);
  const good = buildRequest(draft, stepOf(draft, 'send'), newFrame(job, {draftId: 'd1'}, steps), {config: context.config});
  assert.deepEqual(JSON.parse(good.request.body), {raw: 'cmF3', sender: 'acct-1'});
  assert.equal(checkConcrete(draft, 'send', good, context), good);
  const whole = buildRequest(draft, stepOf(draft, 'send'), newFrame(job, {draftId: 'd1'}, new Map([['draft', answer({raw: {nested: 'object'}})]])), {config: context.config});
  refused(() => checkConcrete(draft, 'send', whole, context), 'raw_value');
  // The output: held to its closed outputSchema within 1 MiB.
  const sent = new Map([...steps, ['send', answer({id: 'm1'})]]);
  assert.deepEqual(buildOutput(draft, newFrame(job, {draftId: 'd1'}, sent)), {id: 'm1'});
  refused(() => buildOutput(draft, newFrame(job, {draftId: 'd1'}, new Map([['send', answer({id: 42})]]))), 'output_invalid');
  refused(() => buildOutput(draft, newFrame(job, {draftId: 'd1'}, new Map([['send', answer({id: 'x'.repeat(1024 * 1024)})]]))), 'output_invalid');
  // The preview: each line a string or a number; a subject that is an object refuses, and truncate cuts a long one.
  assert.deepEqual(buildPreview(draft, newFrame(job, {draftId: 'd1'}, steps)), ['d1', 'Hello']);
  assert.deepEqual(buildPreview(draft, newFrame(job, {draftId: 'd1'}, new Map([['draft', answer({subject: 'y'.repeat(200)})]])))[1], 'y'.repeat(120));
  refused(() => buildPreview(draft, newFrame(job, {draftId: 'd1'}, new Map([['draft', answer({subject: {text: 'no'}})]]))), 'preview_invalid');
  // concat: strings and safe integers only, within its max.
  const frame = newFrame(job, {word: 'ab', count: 7, object: {a: 1}, names: ['a', 'b', 'c']});
  assert.equal(evaluate({concat: [{input: '/word'}, {const: '-'}, {input: '/count'}], max: 10}, frame), 'ab-7');
  refused(() => evaluate({concat: [{input: '/object'}], max: 10}, frame), 'concat_part');
  refused(() => evaluate({concat: [{const: 1.5}], max: 10}, frame), 'concat_part');
  refused(() => evaluate({concat: [{input: '/word'}, {input: '/word'}], max: 3}, frame), 'concat_too_long');
  // each: a list longer than its max refuses; it never cuts the list short.
  assert.deepEqual(evaluate({each: {input: '/names'}, as: 'name', do: {var: 'name'}, max: 3}, frame), ['a', 'b', 'c']);
  refused(() => evaluate({each: {input: '/names'}, as: 'name', do: {var: 'name'}, max: 2}, frame), 'each_too_long');
  refused(() => evaluate({each: {input: '/word'}, as: 'name', do: {var: 'name'}, max: 2}, frame), 'each_list');
  // forEach: the items it walks within its max, and its data is the answers in order.
  const unlabel = stepOf(remove, 'unlabel');
  assert.deepEqual(forEachItems(unlabel, newFrame(job, {itemId: 'i1', names: ['a', 'b']})), ['a', 'b']);
  refused(() => forEachItems(unlabel, newFrame(job, {itemId: 'i1', names: Array.from({length: 11}, (_, index) => `n${index}`)})), 'each_too_long');
  assert.deepEqual(stepData(unlabel, [answer({n: 1}), answer({n: 2})]), [{n: 1}, {n: 2}]);
  const one = buildRequest(remove, unlabel, {...newFrame(job, {itemId: 'i1', names: ['a b', 'c']}), item: 'a b'}, {config: context.config});
  assert.equal(one.request.url, 'https://api.fixture.test/items/i1/labels/a%20b');
  // Paging: the pages' lists joined; more than 1,000 items, or a next page after page.max pages, refuses.
  const page = stepOf(list, 'list');
  assert.deepEqual(stepData(page, [answer({items: [{id: 1}, {id: 2}]}), answer({items: [{id: 3}]})]), [{id: 1}, {id: 2}, {id: 3}]);
  assert.equal(MAX_ITEMS, 1000);
  refused(() => stepData(page, [answer({items: Array.from({length: 600}, (_, id) => ({id}))}), answer({items: Array.from({length: 401}, (_, id) => ({id}))})]), 'too_many_items');
  assert.deepEqual(stepData(page, [answer({}), answer({items: [{id: 4}]})]), [{id: 4}], 'a page that leaves its list out holds none (Gmail leaves an empty list out)');
  refused(() => stepData(page, [answer({items: 'not a list'})]), 'page_items');
  refused(() => stepData(page, Array.from({length: 4}, () => answer({items: []}))), 'too_many_pages');
  assert.deepEqual(nextPage(page, answer({hasMore: true, nextPageToken: 'p2'}), {pages: 1, job}), {cursor: 'p2'});
  assert.equal(nextPage(page, answer({hasMore: false, nextPageToken: 'p2'}), {pages: 1, job}), null, 'while ends it');
  assert.equal(nextPage(page, answer({hasMore: true}), {pages: 1, job}), null, 'no cursor ends it');
  refused(() => nextPage(page, answer({hasMore: true, nextPageToken: 'p4'}), {pages: 3, job}), 'too_many_pages');
  refused(() => nextPage(page, answer({hasMore: true, nextPageToken: {object: true}}), {pages: 1, job}), 'page_cursor');
  // The cursor goes where page.into says, and only there; an ordinary call binds no poll cursor, so updatedAfter is dropped.
  const first = buildRequest(list, page, newFrame(job, {kind: 'all'}), {config: context.config});
  assert.equal(first.request.url, 'https://api.fixture.test/items?kind=all');
  const second = buildRequest(list, page, newFrame(job, {kind: 'all', labelId: 'L1'}), {config: context.config, cursor: 'p2'});
  assert.equal(second.request.url, 'https://api.fixture.test/items?kind=all&labelIds=L1&pageToken=p2');
});

test('part g: secrets: a credential in an answer is scrubbed before it reaches perform bytes; a credential inside a base64 body refuses before sending; a credential under 8 characters refuses', t => {
  const {entry, context} = setup(t), draft = entry('send-draft v1'), put = entry('put-file v1');
  const credentials = credentialContext({Authorization: `Bearer ${TOKEN}`});
  // A credential an answer echoes is scrubbed, every spelling, before any expression reads it.
  const echoed = scrubAnswer(answer({raw: `x${TOKEN}y`, subject: encodeURIComponent(TOKEN), [`k${TOKEN}`]: 1}, {etag: `"${TOKEN}"`}), credentials);
  assert.ok(!JSON.stringify(echoed).includes(TOKEN));
  const {job} = jobOf(draft);
  job.useCredentials(credentials);
  const built = buildRequest(draft, stepOf(draft, 'send'), newFrame(job, {draftId: 'd1'}, new Map([['draft', echoed]])), {config: context.config});
  assert.ok(!built.request.body.includes(TOKEN) && built.request.body.includes('[redacted]'));
  // An answer that was not scrubbed never reaches the wire: the built bytes are checked too.
  refused(() => buildRequest(draft, stepOf(draft, 'send'), newFrame(job, {draftId: 'd1'}, new Map([['draft', answer({raw: `x${TOKEN}y`})]])), {config: context.config}), 'credential_in_request');
  // A transform output that holds the credential refuses, though it never reaches the request: here a preview line.
  const remove = entry('remove-labels v1'), removeJob = jobOf(remove).job;
  removeJob.useCredentials(credentials);
  refused(() => buildPreview(remove, newFrame(removeJob, {itemId: 'i1', names: [TOKEN]})), 'credential_in_request');
  // Inside base64, which redaction never spells: the transform output refuses once the job holds the credential context...
  const putJob = jobOf(put).job, input = {path: 'docs/a.md', content: `secret: ${TOKEN}`, message: 'Add', kind: 'file'};
  putJob.useCredentials(credentials);
  refused(() => buildRequest(put, stepOf(put, 'put'), newFrame(putJob, input), {config: context.config}), 'credential_in_request');
  // ...and the built bytes refuse when the transform ran before the context was there, at any alignment, line breaks included.
  const early = jobOf(put).job, bytes = buildRequest(put, stepOf(put, 'put'), newFrame(early, input), {config: context.config});
  refused(() => early.useCredentials(credentials), 'credential_in_request');
  refused(() => assertNoCredential(bytes.request.body, credentials), 'credential_in_request');
  for (const prefix of ['', 'a', 'ab']) {
    const wrapped = Buffer.from(`${prefix}${TOKEN}`).toString('base64').replace(/(.{8})/g, '$1\r\n');
    assert.equal(holdsCredential(JSON.stringify({raw: wrapped}), credentials), true, `prefix ${prefix.length}`);
    assert.equal(holdsCredential(Buffer.from(`${prefix}${TOKEN}`).toString('base64url'), credentials), true, `base64url, prefix ${prefix.length}`);
  }
  assert.equal(holdsCredential(`ab${Buffer.from(`zz${TOKEN}`).toString('base64')}`, credentials), true, 'a run that starts before its encoding');
  assert.equal(holdsCredential({deep: [{value: TOKEN}]}, credentials), true);
  assert.equal(holdsCredential({deep: [{value: 'nothing secret here'}], [`${TOKEN}`]: 1}, credentials), true, 'keys are read too');
  assert.equal(holdsCredential({text: 'hello world', encoded: Buffer.from('hello world').toString('base64')}, credentials), false);
  // A credential too short to look for safely refuses the job.
  refused(() => credentialContext({Authorization: 'Bearer short'}), 'credential_short');
  refused(() => credentialContext({}), 'credential_short');
});

test('part g: secrets: a credential two base64 layers deep, as a MIME body inside Gmail\'s base64url raw (F10.15 difference 14), refuses; a third layer is past the bound; a 1 MiB body stays cheap', () => {
  const credentials = credentialContext({Authorization: `Bearer ${TOKEN}`});
  const lines = text => Buffer.from(text).toString('base64').replace(/(.{76})/g, '$1\r\n');
  const message = (head, text) => `${head}Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${lines(text)}\r\n`;
  // Each layer at each alignment: headers of any length before the body, text of any length before the credential.
  for (const head of ['', 'S: a\r\n', 'Subject: ab\r\n', 'Subject: abc\r\n']) {
    for (const prefix of ['', 'a', 'ab', 'abc']) {
      const raw = Buffer.from(message(head, `${prefix}${TOKEN} end`)).toString('base64url');
      assert.equal(holdsCredential(raw, credentials), true, `raw, head ${head.length}, prefix ${prefix.length}`);
      assert.equal(holdsCredential(JSON.stringify({raw}), credentials), true, `request body, head ${head.length}, prefix ${prefix.length}`);
      assert.equal(holdsCredential({raw: Buffer.from(message(head, `${prefix}${TOKEN}`)).toString('base64')}, credentials), true, `base64, head ${head.length}, prefix ${prefix.length}`);
    }
  }
  refused(() => assertNoCredential(JSON.stringify({raw: Buffer.from(message('', TOKEN)).toString('base64url')}), credentials), 'credential_in_request');
  assert.equal(holdsCredential({raw: Buffer.from(message('Subject: Plan\r\n', 'See you at ten.')).toString('base64url')}, credentials), false, 'a clean message');
  // The second layer is the last: the check reads two base64 layers and no deeper, so its work stays a fixed number of passes over the text.
  const third = Buffer.from(message('', Buffer.from(`x ${TOKEN}`).toString('base64'))).toString('base64url');
  assert.equal(holdsCredential(third, credentials), false, 'three layers deep is past the bound');
  // A 1 MiB body whose every layer is long base64 text, and one of random bytes, are each read within 2 seconds.
  const nested = Buffer.from(Buffer.from(Buffer.from('a'.repeat(600_000)).toString('base64')).toString('base64')).toString('base64url').slice(0, 1024 * 1024);
  const random = randomBytes(768 * 1024).toString('base64');
  for (const [what, body] of [['nested', nested], ['random', random], ['request body', JSON.stringify({raw: nested})]]) {
    const started = performance.now();
    assert.equal(holdsCredential(body, credentials), false, what);
    assert.ok(performance.now() - started < 2000, `${what} took ${Math.round(performance.now() - started)} ms`);
  }
});

test('part g: a map transform refusal and a guard each give action_refused with their own code in details.reason', t => {
  const {entry, context} = setup(t), update = entry('update-item v1'), {job} = jobOf(update);
  // The guard reads the item: a closed one refuses with the action's own code, the transform's code kept beside it.
  const [guard] = update.action.guards, open = new Map([['item', answer({id: 'i1', status: 'open'})]]);
  assert.equal(checkGuard(guard, newFrame(job, {itemId: 'i1', change: 'label'}, open)), undefined);
  assert.throws(() => checkGuard(guard, newFrame(job, {itemId: 'i1', change: 'label'}, new Map([['item', answer({id: 'i1', status: 'closed'})]]))), error => {
    assert.deepEqual([error.code, error.message, error.details], [ACTION_REFUSED, REFUSAL_WORDS.wrong_state, {reason: 'wrong_state', transform: 'collections.oneOf@1', transformReason: 'not_one_of'}]);
    return true;
  });
  // A map transform's own refusal while the perform bytes are built: an unknown label refuses with label_unknown.
  const labels = new Map([...open, ['labels', answer({labels: [{id: 'L1', name: 'Receipts'}]})]]);
  const built = buildRequest(update, stepOf(update, 'label'), newFrame(job, {itemId: 'i1', change: 'label', labels: ['receipts']}, labels), {config: context.config});
  assert.deepEqual(JSON.parse(built.request.body), {labels: ['L1']});
  assert.throws(() => buildRequest(update, stepOf(update, 'label'), newFrame(job, {itemId: 'i1', change: 'label', labels: ['Missing']}, labels), {config: context.config}), error => {
    assert.deepEqual([error.code, error.message, error.details], [ACTION_REFUSED, REFUSAL_WORDS.transform, {reason: 'label_unknown', transform: 'collections.labelIds@1'}]);
    return true;
  });
  // A transform's own code keeps the transform words even where it spells a run-time reason (collections.labelIds@1's too_many_items).
  const many = new Map([['labels', answer({labels: Array.from({length: 1001}, (_, index) => ({id: `L${index}`, name: `N${index}`}))})]]);
  assert.throws(() => buildRequest(update, stepOf(update, 'label'), newFrame(job, {itemId: 'i1', change: 'label', labels: ['N1']}, many), {config: context.config}), error => {
    assert.deepEqual([error.message, error.details], [REFUSAL_WORDS.transform, {reason: 'too_many_items', transform: 'collections.labelIds@1'}]);
    return true;
  });
});

test('part g: determinism: jobKey is stable within a job and differs across jobs; now is read once and shared by body and preview; a transform runs once per job per argument set', t => {
  const {entry, context} = setup(t), move = entry('reschedule-event v1');
  let now = Date.parse('2026-10-23T09:00:00.000Z');
  const counted = new Map([...TRANSFORMS].map(([id, transform]) => [id, {...transform, run: input => { runs.push(id); return transform.run(input); }}])), runs = [];
  const {job, reads} = jobOf(move, {clock: () => now, transforms: counted});
  const frame = newFrame(job, {eventId: 'e1', start: '2026-10-24T09:00:00Z', end: '2026-10-24T10:00:00Z'}, new Map([['event', answer({id: 'e1'}, {etag: '"v7"'})]]));
  // The guard reads {now}; the clock moves; the body is built twice and the clock was read once, so body and card agree on one now.
  checkGuard(move.action.guards[0], frame);
  now += 60_000;
  const first = buildRequest(move, stepOf(move, 'move'), frame, {config: context.config}), again = buildRequest(move, stepOf(move, 'move'), frame, {config: context.config});
  assert.equal(reads(), 1);
  assert.equal(job.snapshot().now, Date.parse('2026-10-23T09:00:00.000Z'));
  assert.equal(evaluate({transform: 'time.window@1', args: {instant: {const: '2026-10-23T09:00:30Z'}, now: {now: {}}}}, frame).constructor, Object, 'the instant is not before the job\'s one now');
  // The job key: the same within the job, new for another job.
  assert.equal(first.request.body, again.request.body);
  const requestId = JSON.parse(first.request.body).requestId;
  assert.match(requestId, /^[a-f0-9]{32}$/);
  assert.deepEqual(job.snapshot().jobKeys, {move: requestId});
  const other = buildRequest(move, stepOf(move, 'move'), newFrame(jobOf(move, {jobId: 'job-2'}).job, frame.input, frame.steps), {config: context.config});
  assert.notEqual(JSON.parse(other.request.body).requestId, requestId);
  // The If-Match header is the prepared etag; Fabric's added headers are computed once, by the proxy's own function.
  assert.deepEqual(first.request.headers, {'If-Match': '"v7"'});
  assert.deepEqual(first.added, [{name: 'Authorization', value: '(added by Fabric, hidden)'}, {name: 'Accept', value: 'application/json'}, {name: 'Content-Type', value: 'application/json; charset=utf-8'}]);
  assert.deepEqual(buildRequest(move, stepOf(move, 'move'), frame, {config: context.config, provider: {'X-Fixture-Version': '2026-10'}}).added.map(header => header.name),
    ['Authorization', 'X-Fixture-Version', 'Accept', 'Content-Type']);
  // Each transform ran once for its arguments: the guard once, however often the bytes were built.
  assert.deepEqual(runs, ['time.window@1', 'time.window@1'], 'two argument sets: the guard\'s and the one above');
  checkGuard(move.action.guards[0], frame);
  assert.equal(runs.length, 2);
});

test('part g: identity: the Slack user id words; an email outside 3 to 254 characters refuses', t => {
  const {entry} = setup(t), draft = entry('send-draft v1');
  const slack = jobOf(draft, {appId: 'slack', identity: {id: 'T1:U1'}}).job;
  refused(() => evaluate({account: 'userId'}, newFrame(slack, {})), 'account_user_id', 'Sign in to Slack again so Fabric can read your user id.');
  assert.equal(evaluate({account: 'userId'}, newFrame(jobOf(draft, {appId: 'slack', identity: {id: 'T1:U1', userId: 'U1'}}).job, {})), 'U1');
  refused(() => evaluate({account: 'workspaceId'}, newFrame(slack, {})), 'account_value');
  for (const email of ['ab', `${'a'.repeat(250)}@b.co`]) refused(() => evaluate({account: 'email'}, newFrame(jobOf(draft, {identity: {id: 'a', email}}).job, {})), 'account_value');
  assert.equal(evaluate({account: 'email'}, newFrame(jobOf(draft, {identity: {id: 'a', email: 'a@b'}}).job, {})), 'a@b');
  assert.equal(evaluate({account: 'id'}, newFrame(jobOf(draft).job, {})), 'acct-1');
});

test('part g: the evaluator\'s other nodes: a value left out is dropped, either falls back, when and the tests, cursors bind only when given, a resolved schema is read whole', t => {
  const {entry} = setup(t), list = entry('list-items v1'), {job} = jobOf(list);
  const steps = new Map([['profile', answer({name: 'Ada', tags: [], plan: null}, {etag: '"e1"'}, 200)]]), frame = newFrame(job, {kind: 'all', items: ['a']}, steps);
  assert.deepEqual(evaluate({object: {name: {step: 'profile', pointer: '/name'}, gone: {input: '/missing'}, plan: {step: 'profile', pointer: '/plan'}}}, frame), {name: 'Ada', plan: null});
  assert.deepEqual(evaluate({array: [{input: '/kind'}, {input: '/missing'}, {when: {absent: {input: '/missing'}}, then: {const: 'x'}}]}, frame), ['all', 'x']);
  assert.deepEqual(evaluate({array: [{when: {present: {input: '/missing'}}, then: {const: 'no'}}]}, frame), []);
  assert.equal(evaluate({either: [{step: 'skipped', pointer: '/a'}, {const: 'fallback'}]}, frame), 'fallback');
  assert.equal(evaluate({either: [{step: 'profile', pointer: '/name'}, {const: 'fallback'}]}, frame), 'Ada');
  assert.equal(evaluate({step: 'profile', header: 'etag'}, frame), '"e1"');
  assert.equal(evaluate({pick: {step: 'profile', pointer: ''}, pointer: '/name'}, frame), 'Ada');
  assert.equal(evaluate({input: '/missing'}, frame), ABSENT);
  assert.equal(evaluate({cursor: 'since'}, frame), ABSENT, 'an ordinary call binds no cursor');
  assert.equal(evaluate({cursor: 'since'}, newFrame(jobOf(list, {cursors: new Map([['since', '2026-10-01T00:00:00Z']])}).job, {})), '2026-10-01T00:00:00Z');
  assert.deepEqual([passes({present: {step: 'profile', pointer: '/plan'}}, frame), passes({present: {input: '/missing'}}, frame), passes({nonEmpty: {step: 'profile', pointer: '/tags'}}, frame),
    passes({equals: [{input: '/kind'}, {const: 'all'}]}, frame), passes({status: {step: 'profile', in: [200, 201]}}, frame), passes({status: {step: 'skipped', in: [200]}}, frame),
    passes({anyOf: [{absent: {input: '/kind'}}, {nonEmpty: {input: '/items'}}]}, frame)], [true, false, false, true, true, false, true], 'present holds for null, as body routes read it');
  const resolved = {schema: {type: 'object', properties: {Name: {type: 'string'}}, additionalProperties: false}, bindings: [{name: 'Name', id: 'title', type: 'title'}]};
  assert.deepEqual(evaluate({resolved: 'values'}, newFrame(jobOf(list, {resolved: new Map([['values', resolved]])}).job, {})), resolved);
  refused(() => evaluate({resolved: 'values'}, frame), 'resolved_missing');
  // A step with a when that does not hold does not run; a path value left out refuses; a value of a registration step never reads here.
  const update = entry('update-item v1');
  assert.deepEqual([stepRuns(stepOf(update, 'rename'), newFrame(job, {change: 'rename'})), stepRuns(stepOf(update, 'label'), newFrame(job, {change: 'rename'}))], [true, false]);
  refused(() => buildRequest(update, stepOf(update, 'item'), newFrame(job, {change: 'rename'}), {config: setup(t).context.config}), 'path_value');
  refused(() => evaluate({receiver: 'fixture'}, frame), 'value_missing');
  // A query value that is an object, and a header value that is not text, refuse before the normalizer reads them.
  const listing = stepOf(list, 'list'), app = setup(t).context.config;
  refused(() => buildRequest(list, listing, newFrame(job, {kind: {not: 'text'}}), {config: app}), 'query_value');
  refused(() => buildRequest(list, {...stepOf(list, 'profile'), headers: {'If-None-Match': {step: 'profile', pointer: '/tags'}}}, newFrame(job, {}, steps), {pinned: {account: 'me'}, config: app}), 'header_value');
  // A paged POST takes the next cursor in its body, at page.into.body and nowhere else.
  const search = {id: 'find', method: 'POST', path: '/items/search', body: {object: {kind: {input: '/kind'}}}, page: {next: {pointer: '/next_cursor'}, into: {body: '/start_cursor'}, items: '/results', max: 3}, expect: {status: [200], require: []}};
  assert.deepEqual(JSON.parse(buildRequest(list, search, newFrame(job, {kind: 'open'}), {config: app, cursor: 'c2'}).request.body), {kind: 'open', start_cursor: 'c2'});
  assert.deepEqual(JSON.parse(buildRequest(list, search, newFrame(job, {kind: 'open'}), {config: app}).request.body), {kind: 'open'});
  refused(() => forEachItems(stepOf(entry('remove-labels v1'), 'unlabel'), newFrame(job, {names: 'not a list'})), 'each_list');
  // A body over the network's 1 MiB cap refuses; the proxy's own limit is unchanged.
  const put = entry('put-file v1'), big = {path: 'a.md', content: 'x', message: 'm'.repeat(1_100_000), kind: 'file'}, config = setup(t).context.config;
  refused(() => buildRequest(put, stepOf(put, 'put'), newFrame(jobOf(put).job, big), {config}), 'request_invalid');
  assert.ok(buildRequest(put, stepOf(put, 'put'), newFrame(jobOf(put).job, {...big, message: 'm'.repeat(200_000)}), {config}).request.bodyBytes > LIMITS.body);
  assert.throws(() => normalizeProxyRequest({method: 'PUT', path: '/files/a.md', body: {content: 'x'.repeat(LIMITS.body)}}, setup(t).context.config), /larger than 65536 bytes/);
});

test('part g: one helper raises every action refusal with its code and words in both deployments', () => {
  for (const deployment of [LOCAL_DEPLOYMENT, tenantDeployment({kind: 'tenant', environmentId: 'env_1'})]) {
    void deployment;
    const error = actionRefused('time_window');
    assert.deepEqual([error.code, error.message, error.details], [ACTION_REFUSED, REFUSAL_WORDS.time_window, {reason: 'time_window'}]);
  }
  assert.equal(actionRefused('label_unknown', {transform: 'collections.labelIds@1'}).message, REFUSAL_WORDS.transform);
  assert.equal(REFUSAL_WORDS.wrong_kind, 'This action works only on one kind of item, and this item is another kind.');
  for (const [reason, words] of Object.entries(REFUSAL_WORDS)) assert.ok(typeof words === 'string' && words.endsWith('.') && !/\u2014/.test(words), reason);
});

test('part g: the action catalog carries the evaluator, the request builder and the concrete check, the only way server code reaches them', t => {
  const {h} = setup(t);
  assert.deepEqual([h.catalog.evaluate === evaluate, h.catalog.buildRequest === buildRequest, h.catalog.checkConcrete === checkConcrete], [true, true, true]);
});

// ---- parts h and i: preparing, sending and checking an action, on the fake app's simulator ------------------------------------------------
// A job of an action runs through the runtime as any job does: accepted with no network call, its reads run in phase 1, its exact perform
// bytes stored in actionPrepared and bound by the digest, then sent unchanged, checked and read back. The extra actions below sit beside
// the fixture file's seven.
const OK = {status: [200], require: []};
const WRITE_HINTS = {readOnly: false, destructive: false, idempotent: false, openWorld: true}, READ_HINTS = {readOnly: true, destructive: false, idempotent: true, openWorld: true};
const closed = properties => ({type: 'object', properties, required: Object.keys(properties), additionalProperties: false});
const words = (max = 200) => ({type: 'string', minLength: 1, maxLength: max});
const extra = (key, fields) => ({id: `fixture.action.${key}.v1.${'0'.repeat(24)}`, key, version: 1, name: key, description: `The ${key} action of these tests.`, guards: [], prepare: [],
  definitive: [400], certified: {evidence: EVIDENCE, definitionHash: '0'.repeat(64)}, ...fields});
const LABEL = {id: 'label', method: 'POST', path: '/labels', body: {object: {name: {input: '/name'}}}, expect: OK};
const LABEL_VERIFY = {requests: [{id: 'check', method: 'GET', path: '/labels/{label_id}', params: {label_id: {step: 'label', pointer: '/id'}}, expect: OK}],
  identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {step: 'label', pointer: '/id'}}], assert: []};
/** Add a label: one write in fixture.labels.write, a row that stays in the account and defaults to Allow. */
const createLabel = () => extra('create-label', {effect: 'write', row: 'fixture.labels.write', hints: WRITE_HINTS, inputSchema: closed({name: words()}),
  outputSchema: closed({id: {type: 'string', maxLength: 64}}), perform: [LABEL], verify: LABEL_VERIFY, output: {id: {step: 'label', pointer: '/id'}},
  preview: [{label: 'Label', expr: {input: '/name'}}], definitive: [400, 409]});
/** A label from two halves that only Fabric joins, so no input holds a credential whole: joined into the name the bytes carry, or joined and
 *  cut only for the step's when, a transform output the bytes never carry. */
const HALVES = closed({head: words(), tail: words()}), JOINED = {concat: [{input: '/head'}, {input: '/tail'}], max: 400};
const joinedLabel = () => ({...createLabel(), id: `fixture.action.joined-label.v1.${'0'.repeat(24)}`, key: 'joined-label', inputSchema: HALVES,
  perform: [{...LABEL, body: {object: {name: JOINED}}}], preview: [{label: 'Label', expr: {input: '/head'}}]});
const joinedWhen = () => ({...createLabel(), id: `fixture.action.joined-when.v1.${'0'.repeat(24)}`, key: 'joined-when', inputSchema: HALVES,
  perform: [{...LABEL, when: {nonEmpty: {pick: {transform: 'text.truncate@1', args: {text: JOINED, max: {const: 100}}}, pointer: '/text'}}, body: {object: {name: {input: '/head'}}}}],
  preview: [{label: 'Label', expr: {input: '/head'}}]});
/** Note and label: POST /messages, then POST /labels: two writes, so the second can fail after the first was sent (critique test 9). */
const noteAndLabel = () => ({...createLabel(), id: `fixture.action.note-and-label.v1.${'0'.repeat(24)}`, key: 'note-and-label', inputSchema: closed({text: words(), name: words()}),
  perform: [{id: 'note', method: 'POST', path: '/messages', body: {object: {text: {input: '/text'}}}, expect: OK}, LABEL],
  preview: [{label: 'Note', expr: {input: '/text'}}, {label: 'Label', expr: {input: '/name'}}], definitive: [400, 404, 409, 429]});
/** Reply to an item's owner (critique test 4): the recipient comes from a prepare read, so the card shows it only after phase 1 ran. */
const reply = () => extra('reply', {effect: 'write', row: 'fixture.messages.send', hints: WRITE_HINTS, inputSchema: closed({itemId: words(64), text: words()}),
  outputSchema: closed({id: {type: 'string', maxLength: 64}}),
  prepare: [{id: 'parent', method: 'GET', path: '/items/{item_id}', params: {item_id: {input: '/itemId'}}, expect: OK}],
  perform: [{id: 'send', method: 'POST', path: '/messages', body: {object: {to: {step: 'parent', pointer: '/owner'}, text: {input: '/text'}, item: {input: '/itemId'}}}, expect: OK}],
  verify: {requests: [{id: 'check', method: 'GET', path: '/items/{item_id}', params: {item_id: {input: '/itemId'}}, expect: OK}],
    identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {input: '/itemId'}}], assert: []},
  output: {id: {step: 'send', pointer: '/id'}}, preview: [{label: 'To', expr: {step: 'parent', pointer: '/owner'}}, {label: 'Message', expr: {input: '/text'}}]});
/** Search items: a read action whose one step is the reviewed-read POST /items/search (F10.10's end-to-end case). */
const searchItems = () => extra('search-items', {effect: 'read', row: 'fixture.items.read', hints: READ_HINTS, inputSchema: closed({query: words()}),
  outputSchema: closed({first: {type: 'string', maxLength: 64}}),
  perform: [{id: 'find', method: 'POST', path: '/items/search', body: {object: {query: {input: '/query'}}}, expect: OK}],
  output: {first: {step: 'find', pointer: '/results/0/id'}}, preview: [{label: 'Search', expr: {input: '/query'}}]});
/** Export items: POST /items/export is not a reviewed read, so it stays a write, read back by the record it made. */
const exportItems = () => extra('export-items', {effect: 'write', row: 'fixture.items.read', hints: WRITE_HINTS, inputSchema: closed({kind: words(16)}),
  outputSchema: closed({exportId: {type: 'string', maxLength: 64}}),
  perform: [{id: 'export', method: 'POST', path: '/items/export', body: {object: {kind: {input: '/kind'}}}, expect: OK}],
  verify: {requests: [{id: 'check', method: 'GET', path: '/items/{item_id}', params: {item_id: {step: 'export', pointer: '/exportId'}}, expect: OK}],
    identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {step: 'export', pointer: '/exportId'}}], assert: []},
  output: {exportId: {step: 'export', pointer: '/exportId'}}, preview: [{label: 'Kind', expr: {input: '/kind'}}]});
/** Note and move (F10.13 part 1): POST /messages, then the etag-bound PATCH of an event, so the bound write can be refused after a write. */
const noteAndMove = () => extra('note-and-move', {effect: 'write', row: 'fixture.messages.send', hints: WRITE_HINTS, inputSchema: closed({eventId: words(64), text: words()}),
  outputSchema: closed({etag: {type: 'string', maxLength: 200}}),
  prepare: [{id: 'event', method: 'GET', path: '/events/{event_id}', params: {event_id: {input: '/eventId'}}, expect: OK}],
  perform: [{id: 'note', method: 'POST', path: '/messages', body: {object: {text: {input: '/text'}}}, expect: OK},
    {id: 'move', method: 'PATCH', path: '/events/{event_id}', params: {event_id: {input: '/eventId'}}, headers: {'If-Match': {step: 'event', header: 'etag'}},
      body: {object: {summary: {input: '/text'}}}, bindContent: 'etag', expect: OK}],
  verify: {requests: [{id: 'check', method: 'GET', path: '/events/{event_id}', params: {event_id: {input: '/eventId'}}, expect: OK}],
    identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {step: 'move', pointer: '/id'}}], assert: []},
  output: {etag: {step: 'move', header: 'etag'}}, preview: [{label: 'Event', expr: {input: '/eventId'}}, {label: 'Note', expr: {input: '/text'}}], definitive: [400, 404, 412]});
/** The fixture file, reviewed and certified, with these extra actions added. */
const withActions = (...more) => certifiedFile(file => { file.actions.push(...more.map(make => make())); });
/** The RPC twin's action file: a reviewed-read canvas read, a history read that is not a reviewed read, and two posts (Slack style, {ok}). */
const RPC_OK = {status: [200], require: [{equals: {pointer: '/ok', value: {const: true}}}]};
const ALREADY = {status: [200], require: [{anyOf: [{equals: {pointer: '/ok', value: {const: true}}}, {equals: {pointer: '/error', value: {const: 'already_reacted'}}}]}]};
const RPC_EVIDENCE = {evidence: 'docs/live-evidence/fixture-rpc/actions.json', definitionHash: '0'.repeat(64)};
const rpcFile = () => ({schemaVersion: 1, appId: 'fixture-rpc', specVersion: 'fabric/0.2', reviewStatus: 'reviewed', pinnedParameters: {}, actions: [
  extra('read-canvas', {id: `fixture-rpc.action.read-canvas.v1.${'0'.repeat(24)}`, certified: RPC_EVIDENCE, effect: 'read', row: 'fixture-rpc.messages.read', hints: READ_HINTS, inputSchema: closed({canvasId: words(64)}),
    outputSchema: closed({title: {type: 'string', maxLength: 200}}), perform: [{id: 'canvas', method: 'POST', path: '/canvases.read', body: {object: {canvas_id: {input: '/canvasId'}}}, expect: RPC_OK}],
    output: {title: {step: 'canvas', pointer: '/title'}}, preview: [{label: 'Canvas', expr: {input: '/canvasId'}}]}),
  extra('post-twice', {id: `fixture-rpc.action.post-twice.v1.${'0'.repeat(24)}`, certified: RPC_EVIDENCE, effect: 'write', row: 'fixture-rpc.messages.send', hints: WRITE_HINTS, inputSchema: closed({text: words()}),
    outputSchema: closed({ts: {type: 'string', maxLength: 64}}),
    perform: [{id: 'first', method: 'POST', path: '/messages.post', body: {object: {channel: {const: 'C1'}, text: {input: '/text'}}}, expect: ALREADY},
      {id: 'second', method: 'POST', path: '/messages.post', body: {object: {channel: {const: 'C1'}, text: {concat: [{input: '/text'}, {const: ' (again)'}], max: 300}}}, expect: RPC_OK}],
    verify: {requests: [{id: 'check', method: 'GET', path: '/messages.list', query: {channel: {const: 'C1'}}, expect: RPC_OK}],
      identity: [{kind: 'membership', step: 'check', listHas: {list: '/messages', where: [{field: '/ts', equals: {step: 'second', pointer: '/ts'}}]}}], assert: []},
    output: {ts: {step: 'second', pointer: '/ts'}}, preview: [{label: 'Message', expr: {input: '/text'}}]}),
  extra('history', {id: `fixture-rpc.action.history.v1.${'0'.repeat(24)}`, certified: RPC_EVIDENCE, effect: 'write', row: 'fixture-rpc.messages.read', hints: WRITE_HINTS, inputSchema: closed({channel: words(64)}),
    outputSchema: closed({ok: {type: 'boolean'}}),
    perform: [{id: 'history', method: 'POST', path: '/messages.history', body: {object: {channel: {input: '/channel'}}}, expect: RPC_OK}],
    verify: {requests: [{id: 'check', method: 'GET', path: '/messages.list', query: {channel: {input: '/channel'}}, expect: RPC_OK}],
      identity: [{kind: 'readback', step: 'check', pointer: '/ok', equals: {step: 'history', pointer: '/ok'}}], assert: []},
    output: {ok: {step: 'history', pointer: '/ok'}}, preview: [{label: 'Channel', expr: {input: '/channel'}}]})]});

/** Accepts one action job (no request is sent), runs one, approves one with its shown digest. */
const accept = (h, key, input, options) => h.runtime.prepareJob({connectionId: h.account, capabilityId: h.idOf(key), args: input}, h.owner, options);
const runJob = (h, key, input) => h.runtime.createJob({connectionId: h.account, capabilityId: h.idOf(key), args: input}, h.owner);
const approveJob = (h, job, digest = job.approvalDigest) => h.runtime.approve(job.id, digest, h.owner);
const setOwn = (h, key, mode = 'allow') => h.permissions.set({connectionId: h.account, capabilityId: h.idOf(key), mode});
const setRow = (h, groupId, mode) => h.proxyPolicy.set({connectionId: h.account, row: `group:${groupId}`, mode, confirmAllow: true});
const preparedOf = (h, job) => h.store.get(PREPARED, job.id);
const stored = (h, job) => h.store.get('jobs', job.id);
/** The fixture items carry a status the update guard reads, and the item I1 an owner to reply to. */
function seedItems(h) { for (const item of h.simulator.data.items) { item.status = 'open'; item.owner = `owner-of-${item.id}@fixture.test`; } }
const routes = h => h.simulator.calls.map(call => `${call.method} ${call.path}`);
const RESCHEDULE = {eventId: 'E1', start: '2026-10-29T10:00:00Z', end: '2026-10-29T10:30:00Z'};
/** Waits until a held route is reached, failing at once (never hanging) when the run ends before it sends that request. */
const reached = (gate, running) => Promise.race([gate.reached, running.then(job => assert.fail(`The run ended before the held request was sent: ${job.status} ${job.error}`))]);
/** Asserts a job ended as the outcome table says. */
function ended(job, status, errorCode, extra = {}) {
  assert.deepEqual([job.status, job.errorCode ?? null], [status, errorCode], `${job.error}`);
  for (const [key, value] of Object.entries(extra)) assert.deepEqual(job[key], value, key);
}

test('part h: effectOf() is the validated entry\'s effect, never a method, and refuses an action with no catalog, an unplaced one or one that is not its entry\'s definition', t => {
  const h = actionHarness(t, {file: withActions(searchItems)});
  assert.deepEqual(['list-items v1', 'update-item v1', 'remove-labels v1', 'search-items v1'].map(key => h.runtime.effectOf(h.capability(key))), ['read', 'write', 'delete', 'read'],
    'a reviewed-read POST is a read: the entry\'s effect, never the method');
  const changed = error => error.code === 'capability_changed' && error.message === ACTION_WORDS.changed;
  assert.throws(() => h.runtime.effectOf({...h.capability('list-items v1'), effect: 'write'}), changed, 'a record whose effect is not its entry\'s is not that entry\'s definition');
  assert.throws(() => Runtime.prototype.effectOf.call({actions: null}, h.capability('list-items v1')), error => error.code === 'capability_changed' && error.message === ACTION_WORDS.unsupported);
  const bare = actionHarness(t, {map: null}), unplaced = {...bare.capability('list-items v1'), status: 'active'};
  assert.throws(() => bare.runtime.effectOf(unplaced), error => error.code === 'capability_changed' && error.message === ACTION_WORDS.unplaced);
});

test('part h: preparing makes no network call; the job holds hashes only, queued in phase prepare under Allow prepare rows and waiting in phase reads under an Ask one', async t => {
  const h = actionHarness(t, {file: withActions(createLabel)});
  setOwn(h, 'reschedule-event v1');
  const job = await accept(h, 'reschedule-event v1', RESCHEDULE);
  assert.equal(h.simulator.calls.length, 0, 'no request at acceptance');
  assert.deepEqual([job.kind, job.status, job.effect, job.action.phase, job.action.twoPhase, job.action.readsDone], ['action', 'queued', 'write', 'prepare', false, false]);
  assert.deepEqual(job.action.modes, {prepare: 'allow', resolve: null, perform: 'allow'});
  assert.deepEqual([job.action.writeRows, job.action.plan.run, job.action.plan.skipped], [['group:fixture.messages.send'], ['event', 'move', 'check'], []]);
  assert.deepEqual((await accept(h, 'list-items v1', {kind: 'all'})).action.writeRows, [], 'a read action has no write rows for c7');
  assert.equal(h.store.get(PREPARED, job.id), null, 'nothing is prepared before phase 1 runs');
  assert.ok(!Object.hasOwn(job.preview, 'request') && !JSON.stringify(job.action).includes('"body"'), 'the job never holds a body');
  // An Ask prepare row: the job waits in phase reads with a digest over the reads it will send, built from its inputs.
  setRow(h, 'fixture.items.read', 'ask');
  const asked = await accept(h, 'reschedule-event v1', RESCHEDULE);
  assert.deepEqual([asked.status, asked.action.phase, asked.action.modes.prepare, h.simulator.calls.length], ['awaiting_approval', 'reads', 'ask', 0]);
  assert.deepEqual(asked.action.reads.map(read => [read.stepId, read.method, read.url, read.bodySha256]), [['event', 'GET', 'https://api.fixture.test/events/E1', null]]);
  assert.equal(asked.approvalDigest, h.runtime.digest(asked));
  assert.ok(asked.preview.warnings.includes('prepares_first'));
  assert.equal(preparedOf(h, asked).content.phase, 'reads', 'the reads the card shows are kept beside the job');
  // c7 and askUnless are decided here and stored: an uncertain write to the row asks, and editing an item Fabric did not make asks.
  h.store.put('jobs', {id: 'earlier', kind: 'action', connectionId: h.account, capabilityId: h.idOf('create-label v1'), effect: 'write', status: 'uncertain', updatedAt: new Date(h.now).toISOString(),
    action: {writeRows: ['group:fixture.labels.write']}});
  const again = await accept(h, 'create-label v1', {name: 'Receipts'});
  assert.deepEqual([again.action.duplicateOfUncertain, again.action.modes.perform, again.status], [true, 'ask', 'queued']);
  assert.ok(again.preview.warnings.includes('duplicate_of_uncertain'));
  seedItems(h);
  setRow(h, 'fixture.items.read', 'allow');
  setOwn(h, 'update-item v1');
  const edit = await accept(h, 'update-item v1', {itemId: 'I1', change: 'rename', name: 'Plan C'});
  assert.deepEqual([edit.action.askUnless, edit.action.modes.perform], [true, 'ask'], 'Fabric did not make I1');
  assert.ok(edit.preview.warnings.includes('not_made_by_fabric'));
  assert.deepEqual(edit.action.plan.run.includes('labels'), true, 'the plan lists the step; its when decides at run time');
});

test('part h: digest: any perform byte (method, URL, header, added header, one body byte) changes it; a body edited in actionPrepared makes dispatch refuse with zero requests', async t => {
  const h = actionHarness(t);
  const job = await runJob(h, 'reschedule-event v1', RESCHEDULE);
  assert.deepEqual([job.status, job.action.phase, h.simulator.writes().length], ['awaiting_approval', 'final', 0]);
  const [perform] = job.action.perform, digest = h.runtime.digest(job);
  assert.equal(job.approvalDigest, digest);
  const body = preparedOf(h, job).content.perform[0].body, flipped = body.replace('10:00', '10:01');
  assert.deepEqual(Object.keys(perform), ['stepId', 'index', 'method', 'url', 'headers', 'added', 'bodySha256', 'bodyBytes'], 'everything sent but the credential and the body');
  assert.deepEqual([perform.bodySha256, perform.bodyBytes, perform.headers], [createHash('sha256').update(body).digest('hex'), Buffer.byteLength(body), {'If-Match': '"1"'}]);
  for (const change of [{method: 'PUT'}, {url: `${perform.url}x`}, {headers: {...perform.headers, 'If-Match': '"2"'}}, {added: [...perform.added, {name: 'X-Fixture-Version', value: '2'}]},
    {bodySha256: createHash('sha256').update(flipped).digest('hex')}]) {
    assert.notEqual(h.runtime.digest({...job, action: {...job.action, perform: [{...perform, ...change}]}}), digest, Object.keys(change)[0]);
  }
  for (const change of [{now: job.action.now + 1}, {jobKeys: {move: 'f'.repeat(32)}}, {preparedHash: '0'.repeat(64)}, {schemaHashes: {values: '0'.repeat(64)}}, {skipped: ['x']}]) {
    assert.notEqual(h.runtime.digest({...job, action: {...job.action, ...change}}), digest, Object.keys(change)[0]);
  }
  // One body byte edited in the stored prepared request: dispatch refuses before sending anything.
  const row = preparedOf(h, job);
  row.content.perform[0].body = flipped;
  h.store.put(PREPARED, row);
  const done = await approveJob(h, job);
  ended(done, 'failed', 'fabric_failed', {reason: 'prepared_changed', error: RUN_WORDS.prepared_changed});
  assert.equal(h.simulator.writes().length, 0);
  assert.equal(h.simulator.data.events.E1.start, '2026-10-28T10:00:00Z', 'the event did not move');
});

test('part h: a Never prepare, schema, lookup, perform or verify row makes zero requests', async t => {
  for (const [key, input, groupId] of [
    ['reschedule-event v1', RESCHEDULE, 'fixture.items.read'],
    ['add-row v1', {tableId: 'T1', values: {}}, 'fixture.items.read'],
    ['list-items v1', {kind: 'all', labelId: 'L2'}, 'fixture.items.read'],
    ['create-label v1', {name: 'Receipts'}, 'fixture.labels.write'],
    ['create-label v1', {name: 'Receipts'}, 'fixture.items.read'],
  ]) {
    const h = actionHarness(t, {file: withActions(createLabel)});
    setRow(h, groupId, 'deny');
    await assert.rejects(runJob(h, key, input), error => error.code === 'permission_denied' || /Never/.test(error.message), `${key} ${groupId}`);
    assert.deepEqual([h.simulator.calls.length, h.store.list('jobs').length], [0, 0], `${key} ${groupId}`);
  }
});

test('part h: an unplaced action is never executable and says why', async t => {
  const h = actionHarness(t, {map: null}), id = h.idOf('list-items v1');
  assert.deepEqual([h.catalog.entries.get(id).status, h.catalog.entries.get(id).reason], ['candidate', STATUS_WORDS.unplaced]);
  h.store.put('capabilities', {...h.store.get('capabilities', id), status: 'active'});
  const decision = h.permissions.decision(h.store.get('connections', h.account), h.capability('list-items v1'));
  assert.deepEqual([decision.status, decision.executable, decision.reason], ['unsupported', false, ACTION_WORDS.unplaced]);
  await assert.rejects(runJob(h, 'list-items v1', {kind: 'all'}), error => error.message === ACTION_WORDS.unplaced && error.code === 'capability_changed');
  assert.equal(h.simulator.calls.length, 0);
});

test('part h: resource-dependent inputs: the schema hash is in the digest; a schema change between approval and dispatch gives input_schema_changed with nothing sent', async t => {
  const h = actionHarness(t);
  h.simulator.data.items.push({id: 'T1', name: 'Costs', kind: 'table', labels: [], in_trash: false, updated: '2026-10-01T09:00:00.000Z',
    properties: {Name: {id: 'title', type: 'title'}, Cost: {id: 'c1', type: 'number'}}});
  // Static inputs are checked before any call: values is an object; its fields are checked only after the schema is read.
  await assert.rejects(runJob(h, 'add-row v1', {tableId: 'T1', values: 'not an object'}));
  assert.equal(h.simulator.calls.length, 0);
  const off = await runJob(h, 'add-row v1', {tableId: 'T1', values: {Nope: 1}});
  ended(off, 'failed', 'invalid_arguments');
  assert.deepEqual([routes(h), h.simulator.writes().length], [['GET /items/T1'], 0], 'refused after the schema read, before any write');
  // The schema hash is the one resolvedSchemaHash() gives, and the digest binds it.
  const job = await runJob(h, 'add-row v1', {tableId: 'T1', values: {Name: 'Taxi', Cost: 12}});
  assert.deepEqual([job.status, job.action.phase], ['awaiting_approval', 'final']);
  // F10.19 listed churn: the shipped notion.schema@1 replaced the fixture stub, so text holds up to 200,000 characters and the bindings come
  // sorted by name.
  const schema = {type: 'object', properties: {Cost: {type: 'number'}, Name: {type: 'string', maxLength: 200_000}}, required: [], additionalProperties: false};
  const hash = resolvedSchemaHash({resource: {tableId: 'T1'}, transform: 'notion.schema@1', codeHash: PINS['notion.schema@1'], schema,
    bindings: [{name: 'Cost', id: 'c1', type: 'number'}, {name: 'Name', id: 'title', type: 'title'}]});
  assert.deepEqual(job.action.schemaHashes, {values: hash});
  assert.notEqual(h.runtime.digest({...job, action: {...job.action, schemaHashes: {values: '0'.repeat(64)}}}), job.approvalDigest);
  // The table's fields change before the owner approves: dispatch reads them again with the same bytes and refuses before any write.
  h.simulator.data.items.at(-1).properties.Cost = {id: 'c1', type: 'checkbox'};
  const done = await approveJob(h, job);
  ended(done, 'failed', 'input_schema_changed', {error: RUN_WORDS.input_schema_changed});
  assert.deepEqual([h.simulator.writes().length, routes(h).filter(route => route === 'GET /items/T1').length], [0, 3], 'one read for the refused values, one in phase 1 and one again at dispatch');
});

test('part h: after a map transform refusal or a guard, nothing is sent after the prepare reads', async t => {
  const h = actionHarness(t);
  seedItems(h);
  setOwn(h, 'update-item v1');
  const unknown = await runJob(h, 'update-item v1', {itemId: 'I1', change: 'label', labels: ['Missing']});
  ended(unknown, 'failed', ACTION_REFUSED, {details: {reason: 'label_unknown', transform: 'collections.labelIds@1'}, error: REFUSAL_WORDS.transform});
  assert.deepEqual(routes(h), ['GET /items/I1', 'GET /labels'], 'the prepare reads, and nothing after them');
  h.simulator.calls.length = 0;
  h.simulator.data.items.find(item => item.id === 'I2').status = 'closed';
  const closedItem = await runJob(h, 'update-item v1', {itemId: 'I2', change: 'rename', name: 'X'});
  ended(closedItem, 'failed', ACTION_REFUSED, {details: {reason: 'wrong_state', transform: 'collections.oneOf@1', transformReason: 'not_one_of'}, error: REFUSALS.wrong_state});
  assert.deepEqual(routes(h), ['GET /items/I2'], 'the guard runs after its step, and nothing is sent after it');
});

test('part h: an action refusal keeps its code and words in both deployments, and the error table defines the two new codes', async t => {
  assert.deepEqual([ERROR_DEFINITIONS.action_refused, ERROR_DEFINITIONS.input_schema_changed], [{source: 'caller', retryable: false}, {source: 'caller', retryable: false}]);
  assert.ok(END_USER_COLLECTIONS.includes(PREPARED) && END_USER_COLLECTIONS.includes(RECORDS));
  const outcomes = [];
  for (const tenant of [false, true]) {
    const h = actionHarness(t), owner = tenant ? {kind: 'product_user', subjectId: 'user-1', userRecordId: `usr_${'a'.repeat(26)}`} : null;
    seedItems(h);
    let runtime = h.runtime;
    if (tenant) {
      const permissions = new PermissionManager({store: h.store, groups: h.groups, configs: h.configs}), proxyPolicy = new ProxyPolicy({store: h.store, permissions, groups: h.groups, configs: h.configs, rowFloor: true});
      runtime = new Runtime({store: h.store, permissions, proxyPolicy, connections: h.connections, request: h.simulator.request, clock: () => h.now, actions: h.catalog,
        deployment: tenantDeployment({kind: 'tenant', environmentId: 'env_1'})});
      h.store.put('connections', stampOwner(h.store.get('connections', h.account), owner));
    }
    runtime.permissions.set({connectionId: h.account, capabilityId: h.idOf('update-item v1'), mode: 'allow'});
    h.simulator.data.items.find(item => item.id === 'I2').status = 'closed';
    const job = await runtime.createJob({connectionId: h.account, capabilityId: h.idOf('update-item v1'), args: {itemId: 'I2', change: 'rename', name: 'X'}}, owner);
    outcomes.push([job.status, job.errorCode, job.error, job.details]);
  }
  assert.deepEqual(outcomes[0], outcomes[1]);
  assert.deepEqual(outcomes[0], ['failed', ACTION_REFUSED, REFUSALS.wrong_state, {reason: 'wrong_state', transform: 'collections.oneOf@1', transformReason: 'not_one_of'}]);
});
test('parts m and p: the same refusal reaches /api and /v1 with the same code and words, once both servers load the action catalog', async t => {
  // A direct message to an address holding a NUL character, with its read row at Ask: the read's exact bytes are built when the call is
  // accepted, and the proxy's normalizer refuses them there, in the owner's Fabric and in a developer environment alike.
  const where = shippedFolder(t), dir = mkdtempSync(path.join(tmpdir(), 'fabric-action-refusal-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  const args = {email: 'grace\u0000@example.com', text: 'Lunch?'};
  const owner = await ownerApp(t, where, {dir});
  accounts(owner.app);
  owner.app.runtime.proxyPolicy.set({connectionId: 'slack-account', row: 'group:slack.workspace.read', mode: 'ask'});
  const local = await owner.call('POST', '/api/jobs', {connectionId: 'slack-account', capabilityId: where.idOf('send-dm v1'), args});
  const d = await developerHarness(t), dm = d.capability('send-dm v1'), environment = d.app.registry.get('environments', d.scope.environmentId);
  d.app.registry.put('environments', {...environment, apps: {...environment.apps, slack: {...environment.apps?.slack, ceilings: {'slack.workspace.read': 'ask'}}}});
  const remote = await d.call(d.keys.standard, 'POST', '/v1/executions', {externalUserId: 'u1', capabilityId: dm.id, definitionHash: capabilityPermissionHash(dm), args, waitMs: 0}, {'Idempotency-Key': randomUUID()});
  assert.equal(dm.id, where.idOf('send-dm v1'), 'one action, one id, in both deployments');
  assert.deepEqual([local.status, local.body.code, local.body.error], [400, ACTION_REFUSED, REFUSAL_WORDS.request_invalid]);
  assert.deepEqual([remote.status, remote.body.error.code, remote.body.error.message, remote.body.error.details], [400, ACTION_REFUSED, REFUSAL_WORDS.request_invalid, {reason: 'request_invalid'}]);
  assert.deepEqual([owner.slack.calls.length, d.slack.calls.length, owner.app.store.list('jobs').length], [0, 0, 0], 'nothing was sent and no job was kept');
});

test('parts h and i: secrets: no credential in the job, actionPrepared, audit rows, card or output', async t => {
  const h = actionHarness(t, {file: withActions(reply)});
  seedItems(h);
  // An answer that echoes the account's token: it is scrubbed before anything reads it or keeps it.
  h.simulator.data.items.find(item => item.id === 'I1').owner = `x${TOKEN}y@fixture.test`;
  const job = await runJob(h, 'reply v1', {itemId: 'I1', text: 'Hello'});
  assert.deepEqual([job.status, job.action.phase], ['awaiting_approval', 'final']);
  const card = approvalItem(job, {prepared: id => h.store.get(PREPARED, id)});
  assert.ok(card.approve, 'the card is complete');
  const done = await approveJob(h, job);
  assert.equal(done.status, 'succeeded');
  for (const [name, value] of [['job', stored(h, done)], ['card', card], ['audit', h.store.list('activity')], ['prepared', h.store.list(PREPARED)], ['output', done.result]]) {
    assert.ok(!JSON.stringify(value).includes(TOKEN), name);
  }
  assert.ok(JSON.stringify(card).includes('[redacted]'), 'the scrubbed recipient is what the owner approved');
  assert.equal(h.simulator.writes()[0].body.to, 'x[redacted]y@fixture.test', 'and what was sent');
});

test('part i: send-time checks: a read with approved bytes, a perform and a resolving write each refuse prepared_changed when their bytes or Fabric\'s added headers change, with that request unsent', async t => {
  // A phase 1 read rebuilt with one byte different from its approved entry (here the entry is changed and approved as shown): not sent.
  const h = actionHarness(t);
  setRow(h, 'fixture.items.read', 'ask');
  const read = await accept(h, 'reschedule-event v1', RESCHEDULE);
  const tampered = {...read, action: {...read.action, reads: [{...read.action.reads[0], url: 'https://api.fixture.test/events/E2'}]}};
  tampered.approvalDigest = h.runtime.digest(tampered);
  h.store.put('jobs', tampered);
  ended(await approveJob(h, tampered), 'failed', 'fabric_failed', {reason: 'prepared_changed', error: RUN_WORDS.prepared_changed});
  assert.equal(h.simulator.calls.length, 0, 'the read whose bytes differ from its approved entry is not sent');
  // A provider header that changed while a job waited, across a restart: the perform is not sent.
  setRow(h, 'fixture.items.read', 'allow');
  const job = await runJob(h, 'reschedule-event v1', RESCHEDULE);
  assert.equal(job.action.phase, 'final');
  const restarted = new Runtime({store: h.store, permissions: h.permissions, proxyPolicy: h.proxyPolicy, request: h.simulator.request, clock: () => h.now, actions: h.catalog,
    connections: {credentials: async () => ({headers: {Authorization: `Bearer ${TOKEN}`, 'X-Fixture-Version': '2026-11'}, allowedOrigins: ['https://api.fixture.test']})}});
  restarted.recover();
  const after = await restarted.approve(job.id, job.approvalDigest, h.owner);
  ended(after, 'failed', 'fabric_failed', {reason: 'prepared_changed'});
  assert.equal(h.simulator.writes().length, 0);
  // The same for a resolving write: a provider header that changed while the job waited before conversations.open.
  const s = slackHarness(t);
  const waiting = await s.runtime.createJob({connectionId: s.account, capabilityId: s.id, args: {email: 'grace@example.com', text: 'Hi'}}, null);
  assert.deepEqual([waiting.status, waiting.action.phase, waiting.action.resolving?.stepId], ['awaiting_approval', 'reads', 'open']);
  const moved = new Runtime({store: s.store, permissions: s.permissions, proxyPolicy: s.proxyPolicy, request: s.script.request, clock: () => s.now, actions: s.catalog,
    connections: {credentials: async () => ({headers: {Authorization: `Bearer ${SLACK_TOKEN}`, 'X-Slack-Version': '2'}, allowedOrigins: ['https://slack.com']})}});
  ended(await moved.approve(waiting.id, waiting.approvalDigest, null), 'failed', 'fabric_failed', {reason: 'prepared_changed'});
  assert.deepEqual(s.script.writes(), [], 'conversations.open was not sent');
});

test('part i: critique test 4: a reply whose recipient comes from a prepare read shows the final recipient before anything is sent', async t => {
  const h = actionHarness(t, {file: withActions(reply)});
  seedItems(h);
  const job = await runJob(h, 'reply v1', {itemId: 'I1', text: 'See you'});
  assert.deepEqual([job.status, job.action.phase, h.simulator.writes().length], ['awaiting_approval', 'final', 0]);
  const {exact} = approvalItem(job, {prepared: id => h.store.get(PREPARED, id)});
  assert.equal(exact.blocks[0].label, 'Fields');
  assert.match(exact.blocks[0].text, /^To: owner-of-I1@fixture\.test\nMessage: See you$/);
  const body = exact.blocks.find(block => block.label === 'send: Body');
  assert.deepEqual(JSON.parse(body.text), {to: 'owner-of-I1@fixture.test', text: 'See you', item: 'I1'});
});

test('part i: critique test 9 and the outcome table: a write then a 404, a listed code, an unlisted code, a redirect and a 304; nothing is retried', async t => {
  const fresh = () => { const h = actionHarness(t, {file: withActions(noteAndLabel)}); setOwn(h, 'note-and-label v1'); setOwn(h, 'reschedule-event v1'); return h; };
  const input = {text: 'Hi', name: 'Receipts'};
  // Step 1 writes and step 2 answers 404: uncertain, not failed, though 404 is a listed code.
  let h = fresh();
  h.simulator.fail('POST /labels', {status: 404, data: {error: 'not_found'}});
  ended(await runJob(h, 'note-and-label v1', input), 'uncertain', 'outcome_uncertain', {providerStatus: 404});
  assert.deepEqual(routes(h), ['POST /messages', 'POST /labels'], 'the first failure stops the job, and nothing is retried');
  // A listed code on the first write: failed, nothing changed.
  h = fresh();
  h.simulator.fail('PATCH /events/{event_id}', {status: 404, data: {error: 'not_found'}});
  ended(await runJob(h, 'reschedule-event v1', RESCHEDULE), 'failed', 'provider_failed', {providerStatus: 404});
  // An unlisted code on a write: uncertain.
  h = fresh();
  h.simulator.fail('PATCH /events/{event_id}', {status: 500, data: {error: 'boom'}});
  ended(await runJob(h, 'reschedule-event v1', RESCHEDULE), 'uncertain', 'outcome_uncertain', {providerStatus: 500});
  assert.equal(h.simulator.writes().length, 1);
  // A redirect or a 304 on a write: uncertain.
  for (const answer of [{status: 302, headers: {location: '/events/E9'}, data: null}, {status: 304, data: null}]) {
    h = fresh();
    h.simulator.fail('PATCH /events/{event_id}', answer);
    ended(await runJob(h, 'reschedule-event v1', RESCHEDULE), 'uncertain', 'outcome_uncertain');
  }
});

test('part i: a 429 on the first write fails with its Retry-After and one request; after a write it is uncertain; it is never retried and never rate_limited', async t => {
  let h = actionHarness(t);
  setOwn(h, 'reschedule-event v1');
  h.simulator.fail('PATCH /events/{event_id}', {status: 429, headers: {'retry-after': '30'}, data: {error: 'slow_down'}});
  ended(await runJob(h, 'reschedule-event v1', RESCHEDULE), 'failed', 'provider_failed', {providerStatus: 429, retryAfterSeconds: 30, error: RUN_WORDS.limited});
  assert.equal(h.simulator.writes().length, 1, 'one request, not retried');
  h = actionHarness(t, {file: withActions(noteAndLabel)});
  setOwn(h, 'note-and-label v1');
  h.simulator.fail('POST /labels', {status: 429, headers: {'retry-after': '5'}, data: {}});
  ended(await runJob(h, 'note-and-label v1', {text: 'Hi', name: 'Receipts'}), 'uncertain', 'outcome_uncertain', {providerStatus: 429, retryAfterSeconds: 5});
  assert.equal(h.simulator.writes().length, 2);
});

test('part i: a network error before sending is failed, after sending uncertain', async t => {
  let h = actionHarness(t);
  setOwn(h, 'reschedule-event v1');
  const send = h.simulator.request;
  h.runtime.request = async options => { if (options.method === 'PATCH') throw Object.assign(new Error('Provider DNS lookup failed or timed out.'), {sent: false}); return send(options); };
  ended(await runJob(h, 'reschedule-event v1', RESCHEDULE), 'failed', 'fabric_failed');
  h = actionHarness(t);
  setOwn(h, 'reschedule-event v1');
  h.simulator.drop('PATCH /events/{event_id}');
  ended(await runJob(h, 'reschedule-event v1', RESCHEDULE), 'uncertain', 'outcome_uncertain');
  assert.equal(h.simulator.data.events.E1.start, RESCHEDULE.start, 'the change was applied, and the job says it could not be confirmed');
});

test('part i: readback: verified on a match, uncertain on a mismatch; statusIn 404 or 410, two verify requests, listLacks and anyOf', async t => {
  let h = actionHarness(t);
  setOwn(h, 'reschedule-event v1');
  const done = await runJob(h, 'reschedule-event v1', RESCHEDULE);
  ended(done, 'succeeded', null);
  assert.deepEqual([done.result.verification.status, done.result.verification.kind, done.result.data.etag], ['verified', 'action-readback', '"2"']);
  // The provider answers as if applied but changes nothing: the readback mismatches, so the write is uncertain, its checked output kept.
  h = actionHarness(t);
  setOwn(h, 'reschedule-event v1');
  h.simulator.swallow('PATCH /events/{event_id}');
  const swallowed = await runJob(h, 'reschedule-event v1', RESCHEDULE);
  ended(swallowed, 'uncertain', 'outcome_uncertain');
  assert.deepEqual([swallowed.result.verification.status, swallowed.result.data], ['unverified', {etag: '"2"'}], 'the provider\'s answer, checked, beside unverified');
  // Send a draft: two verify requests, and the draft read back gone, as 404 or as 410 (anyOf).
  for (const status of [404, 410]) {
    h = actionHarness(t, {file: certifiedFile(file => { file.actions.find(action => action.key === 'send-draft').verify.requests[1].expect.status = [404, 410]; })});
    setOwn(h, 'send-draft v1');
    const send = h.simulator.request;
    let drafts = 0;
    h.runtime.request = async options => options.method === 'GET' && /\/drafts\/D1$/.test(options.url) && ++drafts === 2 && status === 410 ? {status: 410, headers: {}, data: {error: 'gone'}} : send(options);
    const sent = await runJob(h, 'send-draft v1', {draftId: 'D1'});
    ended(sent, 'succeeded', null);
    assert.deepEqual(routes(h), ['GET /drafts/D1', 'POST /drafts/D1/send', 'GET /items/S1', ...(status === 404 ? ['GET /drafts/D1'] : [])], `two verify requests, the draft gone as ${status}`);
  }
  // Remove labels: a forEach of deletes, read back by a membership identity per item (listLacks).
  h = actionHarness(t);
  setOwn(h, 'remove-labels v1');
  const removed = await runJob(h, 'remove-labels v1', {itemId: 'I1', names: ['Work']});
  ended(removed, 'succeeded', null);
  assert.deepEqual(removed.result.data, {removed: 1});
  // The assertions themselves, each kind, over one answer.
  const job = createJob({jobId: 'j', entry: h.catalog.entries.get(h.idOf('list-items v1')).entry, appId: 'fixture', clock: () => 0});
  const frame = newFrame(job, {name: 'Work', id: 'L2'}, new Map([['check', {status: 200, headers: {}, data: {labels: [{id: 'L2', name: 'Work'}], name: 'Plan A', tags: ['a', 'b']}}]]));
  const check = node => holds(node, frame);
  assert.deepEqual([check({step: 'check', equals: {pointer: '/name', value: {const: 'Plan A'}}}), check({step: 'check', contains: {pointer: '/tags', value: {const: ['b']}}}),
    check({step: 'check', present: {pointer: '/name'}}), check({step: 'check', absent: {pointer: '/gone'}}), check({step: 'check', statusIn: [200]}),
    check({step: 'check', listHas: {list: '/labels', where: [{field: '/id', equals: {input: '/id'}}, {field: '/name', equals: {input: '/name'}}]}}),
    check({step: 'check', listLacks: {list: '/labels', where: [{field: '/id', equals: {const: 'L9'}}]}}), check({step: 'check', listLacks: {list: '/missing', where: [{field: '/id', equals: {const: 'L2'}}]}}),
    check({step: 'check', test: {equals: [{step: 'check', pointer: '/name'}, {const: 'Plan A'}]}}),
    check({anyOf: [{step: 'check', statusIn: [404]}, {step: 'check', present: {pointer: '/name'}}]})], [true, true, true, true, true, true, true, true, true, true]);
  assert.deepEqual([check({step: 'check', equals: {pointer: '/name', value: {const: 'Plan B'}}}), check({step: 'check', contains: {pointer: '/tags', value: {const: ['a', 'c']}}}),
    check({step: 'check', listHas: {list: '/labels', where: [{field: '/id', equals: {const: 'L9'}}]}}), check({step: 'check', listLacks: {list: '/labels', where: [{field: '/id', equals: {input: '/id'}}]}}),
    check({step: 'check', equals: {pointer: '/name', value: {input: '/missing'}}}), check({step: 'gone', statusIn: [200]}),
    check({step: 'check', test: {equals: [{step: 'check', pointer: '/name'}, {const: 'Plan B'}]}}), check({step: 'gone', test: {equals: [{step: 'check', pointer: '/name'}, {const: 'Plan A'}]}})], [false, false, false, false, false, false, false, false]);
});

test('part i: expect.require: ok false on the first write fails, after a write is uncertain; a reviewed alternative (already_reacted) succeeds', async t => {
  const rpc = () => { const h = actionHarness(t, {files: [rpcFile()]}); h.allow('post-twice v1'); return h; };
  let r = rpc();
  r.simulator.fail('POST /messages.post', {status: 200, data: {ok: false, error: 'channel_not_found'}}, {times: 1});
  ended(await r.run('post-twice v1', {text: 'Hi'}), 'failed', 'provider_failed', {providerStatus: 200});
  assert.equal(r.simulator.writes().length, 1);
  r = rpc();
  const second = r.simulator.request;
  let posts = 0;
  r.runtime.request = async options => (options.method === 'POST' && ++posts === 2 ? {status: 200, headers: {}, data: {ok: false, error: 'rate_limited'}} : second(options));
  ended(await r.run('post-twice v1', {text: 'Hi'}), 'uncertain', 'outcome_uncertain');
  r = rpc();
  r.simulator.fail('POST /messages.post', {status: 200, data: {ok: false, error: 'already_reacted'}}, {times: 1});
  ended(await r.run('post-twice v1', {text: 'Hi'}), 'succeeded', null);
});

test('part i: locks: a read action takes none; a write holds the account across perform and verify, and a typed or proxied write on it is refused meanwhile; a twoPhase action releases it while it waits', async t => {
  const h = actionHarness(t, {designated: true});
  setOwn(h, 'reschedule-event v1');
  // A read: no lock while it runs.
  const gate = h.simulator.hold('GET /items');
  const listing = runJob(h, 'list-items v1', {kind: 'all'});
  await reached(gate, listing);
  assert.deepEqual([...h.runtime.writeLocks], []);
  gate.release();
  ended(await listing, 'succeeded', null);
  // A write: the account is held from the perform through the readback.
  const verify = h.simulator.hold('PATCH /events/{event_id}');
  const moving = runJob(h, 'reschedule-event v1', RESCHEDULE);
  await reached(verify, moving);
  assert.deepEqual([...h.runtime.writeLocks], [`account:${h.account}`]);
  setRow(h, 'fixture.labels.write', 'allow');
  const proxied = h.runtime.prepareProxy({connectionId: h.account, request: {method: 'POST', path: '/labels', body: {name: 'x'}}}, h.owner);
  const sent = await h.runtime.execute(proxied.id);
  assert.deepEqual([sent.status, sent.errorCode], ['failed', 'write_in_progress']);
  assert.equal(h.simulator.writes().filter(call => call.path.startsWith('/labels')).length, 0, 'it was not sent');
  // A typed http write takes the same key (lib/runtime.mjs execute()), so it is refused the same way; a typed capability cannot run on the
  // fixture's .test host, so the key is checked here.
  assert.ok(h.runtime.writeLocks.has(`account:${h.account}`));
  verify.release();
  ended(await moving, 'succeeded', null);
  assert.deepEqual([...h.runtime.writeLocks], []);
  // A twoPhase action: no lock while it waits for its final approval, and the account held again while the final bytes are sent.
  const s = slackHarness(t), waiting = await s.runtime.createJob({connectionId: s.account, capabilityId: s.id, args: {email: 'grace@example.com', text: 'Hi'}}, null);
  const opened = await s.runtime.approve(waiting.id, waiting.approvalDigest, null);
  assert.deepEqual([opened.action.phase, opened.action.writesSent, [...s.runtime.writeLocks]], ['final', ['open'], []]);
  let held = null;
  const post = s.script.request;
  s.runtime.request = async options => { if (/chat\.postMessage/.test(options.url)) held = [...s.runtime.writeLocks]; return post(options); };
  ended(await s.runtime.approve(opened.id, opened.approvalDigest, null), 'succeeded', null);
  assert.deepEqual([held, [...s.runtime.writeLocks]], [[`account:${s.account}`], []]);
});

test('part i: bindContent: If-Match carries the prepared etag; a 412 on the first write fails with nothing changed', async t => {
  const h = actionHarness(t);
  const job = await runJob(h, 'reschedule-event v1', RESCHEDULE);
  assert.equal(preparedOf(h, job).content.perform[0].headers['If-Match'], '"1"');
  h.simulator.data.events.E1.version = 2;
  const done = await approveJob(h, job);
  ended(done, 'failed', 'provider_failed', {providerStatus: 412, reason: 'content_changed'});
  assert.equal(h.simulator.data.events.E1.start, '2026-10-28T10:00:00Z');
  assert.equal(h.simulator.writes()[0].headers['if-match'], '"1"');
});

// F10.13 part 1 (docs/F10.13-BUILD-MAP.md part 1): a content-bound write the provider refuses because the content changed since Fabric read
// it (an etag-bound 412, a sha-bound 409) carries reason content_changed. Before any write it fails with its own words; after one it stays
// uncertain. The code is unchanged, so every surface sees one error shape.
test('F10.13 part 1: content_changed: a stale etag or sha fails with its own words and nothing changed; an unbound 412 keeps http_status; after an earlier write it is uncertain', async t => {
  assert.equal(RUN_WORDS.content_changed, 'It changed after Fabric read it, so nothing was changed. Read it again and ask again.');
  // A stale etag: the event changed between the read and the approval.
  let h = actionHarness(t);
  const moving = await runJob(h, 'reschedule-event v1', RESCHEDULE);
  h.simulator.data.events.E1.version = 2;
  ended(await approveJob(h, moving), 'failed', 'provider_failed', {providerStatus: 412, reason: 'content_changed', error: RUN_WORDS.content_changed});
  assert.deepEqual([h.simulator.data.events.E1.start, h.simulator.writes().length], ['2026-10-28T10:00:00Z', 1], 'nothing changed, and one request');
  // A stale sha: the file changed between the read and the approval, so the PUT names an old sha and Google-style providers answer 409.
  h = actionHarness(t);
  const putting = await runJob(h, 'put-file v1', {path: 'docs/a.md', content: 'new', message: 'm', kind: 'file'});
  assert.equal(putting.status, 'awaiting_approval');
  h.simulator.data.files['docs/a.md'] = {path: 'docs/a.md', content: Buffer.from('theirs').toString('base64'), sha: 'f'.repeat(40)};
  ended(await approveJob(h, putting), 'failed', 'provider_failed', {providerStatus: 409, reason: 'content_changed', error: RUN_WORDS.content_changed});
  assert.equal(Buffer.from(h.simulator.data.files['docs/a.md'].content, 'base64').toString(), 'theirs', 'nothing changed');
  // The status must be the binding's own: a 409 on an etag-bound write, or a 412 on a sha-bound one, is not content_changed.
  h = actionHarness(t);
  setOwn(h, 'reschedule-event v1');
  h.simulator.fail('PATCH /events/{event_id}', {status: 409, data: {error: 'conflict'}});
  ended(await runJob(h, 'reschedule-event v1', RESCHEDULE), 'uncertain', 'outcome_uncertain', {providerStatus: 409, reason: 'http_status'});
  h = actionHarness(t);
  h.simulator.fail('PUT /files/{+path}', {status: 412, data: {error: 'precondition'}});
  const stale = await runJob(h, 'put-file v1', {path: 'docs/a.md', content: 'x', message: 'm', kind: 'file'});
  ended(await approveJob(h, stale), 'uncertain', 'outcome_uncertain', {providerStatus: 412, reason: 'http_status'});
  // A 412 on a step with no content binding, listed as definitive: failed with the generic words and reason http_status.
  h = actionHarness(t, {file: withActions(() => ({...createLabel(), definitive: [400, 409, 412]}))});
  h.simulator.fail('POST /labels', {status: 412, data: {error: 'precondition'}});
  ended(await runJob(h, 'create-label v1', {name: 'Receipts'}), 'failed', 'provider_failed', {providerStatus: 412, reason: 'http_status', error: RUN_WORDS.failed});
  // A bound 412 after an earlier write was sent: the note went out, so the job is uncertain, with the uncertain words.
  h = actionHarness(t, {file: withActions(noteAndMove)});
  const both = await runJob(h, 'note-and-move v1', {eventId: 'E1', text: 'Moved'});
  h.simulator.data.events.E1.version = 2;
  ended(await approveJob(h, both), 'uncertain', 'outcome_uncertain', {providerStatus: 412, reason: 'content_changed', error: RUN_WORDS.uncertain});
  assert.deepEqual(routes(h).filter(route => !route.startsWith('GET')), ['POST /messages', 'PATCH /events/E1'], 'the note was sent before the refused PATCH');
  assert.equal(h.simulator.data.events.E1.summary, 'Review');
});

test('part i: askUnless: editing a record Fabric did not make asks under Allow; one recorded after a verified write runs at Allow; an unverified write records nothing', async t => {
  const h = actionHarness(t);
  seedItems(h);
  h.simulator.data.items.push({id: 'T1', name: 'Costs', kind: 'table', labels: [], in_trash: false, updated: '2026-10-01T09:00:00.000Z', properties: {Name: {id: 'title', type: 'title'}}});
  setOwn(h, 'update-item v1');
  setOwn(h, 'add-row v1');
  const notMine = await runJob(h, 'update-item v1', {itemId: 'I1', change: 'label', labels: ['Work']});
  assert.deepEqual([notMine.status, notMine.action.phase, h.simulator.writes().length], ['awaiting_approval', 'final', 0]);
  // A row Fabric adds, verified: recorded for this account, so editing it runs at Allow.
  const made = await runJob(h, 'add-row v1', {tableId: 'T1', values: {Name: 'Taxi'}});
  ended(made, 'succeeded', null);
  const id = made.result.data.id;
  h.simulator.data.items.find(item => item.id === id).status = 'open';
  assert.equal(h.store.list(RECORDS).length, 1);
  const mine = await runJob(h, 'update-item v1', {itemId: id, change: 'label', labels: ['Work']});
  ended(mine, 'succeeded', null);
  assert.equal(mine.action.askUnless, false);
  // An unverified write records nothing, though its readback names the row it made.
  const send = h.simulator.request;
  let reads = 0;
  h.runtime.request = async options => { const answer = await send(options); return options.method === 'GET' && /\/items\/I\d+$/.test(options.url) && ++reads === 1 ? {...answer, status: 500} : answer; };
  ended(await runJob(h, 'add-row v1', {tableId: 'T1', values: {Name: 'Bus'}}), 'uncertain', 'outcome_uncertain');
  assert.equal(h.store.list(RECORDS).length, 1);
});

test('part i: restart: before any write the job fails, after a write it is uncertain; stale actionPrepared rows are swept', async t => {
  const h = actionHarness(t, {file: withActions(noteAndLabel)});
  setOwn(h, 'note-and-label v1');
  const at = new Date(h.now).toISOString();
  h.store.put('jobs', {id: 'a', kind: 'action', status: 'running', effect: 'write', connectionId: h.account, updatedAt: at, action: {writesSent: []}});
  h.store.put('jobs', {id: 'b', kind: 'action', status: 'running', effect: 'write', connectionId: h.account, updatedAt: at, action: {writesSent: ['note']}});
  h.store.put('jobs', {id: 'c', kind: 'action', status: 'queued', effect: 'write', connectionId: h.account, updatedAt: at, action: {writesSent: []}});
  const waiting = await runJob(h, 'reschedule-event v1', RESCHEDULE);
  for (const id of ['a', 'b', 'c', 'gone']) h.store.put(PREPARED, {id, connectionId: h.account, expiresAt: at, content: {}});
  h.runtime.recover();
  ended(stored(h, {id: 'a'}), 'failed', 'fabric_failed', {reason: 'restarted', error: RUN_WORDS.restarted});
  ended(stored(h, {id: 'b'}), 'uncertain', 'outcome_uncertain', {reason: 'restarted'});
  ended(stored(h, {id: 'c'}), 'failed', 'fabric_failed', {reason: 'restarted'});
  assert.deepEqual(h.store.list(PREPARED).map(row => row.id), [waiting.id], 'only the waiting job keeps its prepared bytes');
});

test('part i: step 10\'s end-to-end case: reviewed-read POST /items/search and POST /canvases.read succeed under Allow and take no write lock; /items/export and /messages.history stay writes', async t => {
  const h = actionHarness(t, {file: withActions(searchItems, exportItems), files: [rpcFile()]});
  const found = await h.run('search-items v1', {query: 'plan'});
  ended(found, 'succeeded', null);
  assert.deepEqual([found.effect, found.result.data, found.result.verification.status, found.approvedBy, h.runtime.writeLocks.size], ['read', {first: 'I4'}, 'observed', 'standing-policy', 0]);
  const canvas = await h.run('read-canvas v1', {canvasId: 'F1'});
  ended(canvas, 'succeeded', null);
  assert.deepEqual([canvas.effect, canvas.result.data], ['read', {title: 'Roadmap'}]);
  // The writes take the account's lock: held while they run.
  for (const [route, key, input] of [['POST /items/export', 'export-items v1', {kind: 'note'}], ['POST /messages.history', 'history v1', {channel: 'C1'}]]) {
    h.allow(key);
    const gate = h.simulator.hold(route), running = h.run(key, input);
    await reached(gate, running);
    assert.equal(h.runtime.writeLocks.size, 1, route);
    gate.release();
    const done = await running;
    assert.equal(done.effect, 'write', route);
  }
});

test('part i: determinism: dispatch sends the stored bytes and re-runs no transform, recomputing only Fabric\'s added headers to compare them', async t => {
  const runs = [], counted = new Map([...TRANSFORMS].map(([id, transform]) => [id, {...transform, run: input => { runs.push(id); return transform.run(input); }}]));
  const h = actionHarness(t);
  const catalog = loadActionCatalog({directory: h.directory, evidenceRoot: h.root, maps: h.maps, deps: {...h.deps, transforms: counted}, codeHashes: h.codeHashes});
  const runtime = new Runtime({store: h.store, permissions: h.permissions, proxyPolicy: h.proxyPolicy, connections: h.connections, request: h.simulator.request, clock: () => h.now, actions: catalog});
  seedItems(h);
  runtime.permissions.set({connectionId: h.account, capabilityId: h.idOf('update-item v1'), mode: 'allow'});
  const job = await runtime.createJob({connectionId: h.account, capabilityId: h.idOf('update-item v1'), args: {itemId: 'I1', change: 'label', labels: ['Later']}}, null);
  assert.deepEqual([job.action.phase, job.action.askUnless], ['final', true], 'Fabric did not make I1, so it asks');
  assert.ok(runs.includes('collections.labelIds@1'));
  const before = runs.length, row = preparedOf(h, job);
  h.advance(60_000);
  const done = await runtime.approve(job.id, job.approvalDigest, null);
  ended(done, 'succeeded', null);
  assert.equal(runs.length, before, 'no transform ran again at dispatch');
  const [sent] = h.simulator.writes();
  assert.deepEqual(sent.body, JSON.parse(row.content.perform[0].body), 'the stored bytes, unchanged, though the clock moved');
});

// ---- parts h and i: each guard of the runner on its own ----------------------------------------------------------------------------------
test('part h: a job refuses an action on another route, one whose transform code no longer matches its pin, a time outside its guard, and runs nothing without a catalog', async t => {
  const h = actionHarness(t);
  h.store.put('connections', {id: 'fixture-browser', appId: 'fixture', driver: 'browser', transport: 'helper', status: 'session_ready', label: 'Fixture in a browser', identity: {id: 'acct-1'}, createdAt: new Date(h.now).toISOString()});
  await assert.rejects(h.runtime.createJob({connectionId: 'fixture-browser', capabilityId: h.idOf('list-items v1'), args: {kind: 'all'}}, null), /^Error: Capability does not belong to this application and connection route\.$/);
  // A guard without after runs before any read.
  setOwn(h, 'reschedule-event v1');
  ended(await runJob(h, 'reschedule-event v1', {...RESCHEDULE, start: RESCHEDULE.end, end: RESCHEDULE.start}), 'failed', ACTION_REFUSED, {details: {reason: 'time_window', transform: 'time.window@1', transformReason: 'window_order'}});
  assert.equal(h.simulator.calls.length, 0);
  // The code of a transform it runs changed since it was pinned: not run, nothing sent.
  const repinned = actionHarness(t, {codeHashes: ids => Object.fromEntries(ids.map(id => [id, id === 'encoding.base64Encode@1' ? '0'.repeat(64) : PINS[id]]))});
  repinned.store.put('capabilities', {...repinned.capability('put-file v1'), status: 'active'});
  await assert.rejects(runJob(repinned, 'put-file v1', {path: 'docs/a.md', content: 'x', message: 'm', kind: 'file'}));
  assert.equal(repinned.simulator.calls.length, 0);
  // A stored action job and no catalog: it fails as unsupported, nothing is sent.
  const job = await accept(h, 'list-items v1', {kind: 'all'});
  const bare = new Runtime({store: h.store, permissions: new PermissionManager({store: h.store, groups: h.groups, configs: h.configs}), connections: h.connections, request: h.simulator.request, clock: () => h.now});
  ended(await bare.execute(job.id), 'failed', 'capability_changed', {error: ACTION_WORDS.unsupported});
  assert.equal(h.simulator.calls.length, 0);
});

test('part h: a step whose when does not hold is not read or shown, and is in the final digest as skipped; a recorded Never refuses at dispatch', async t => {
  const h = actionHarness(t);
  seedItems(h);
  setRow(h, 'fixture.items.read', 'ask');
  const asked = await accept(h, 'update-item v1', {itemId: 'I1', change: 'label', labels: ['Work']});
  assert.deepEqual(asked.action.reads.map(read => read.stepId), ['item', 'labels']);
  const renamed = await accept(h, 'update-item v1', {itemId: 'I1', change: 'rename', name: 'X'});
  assert.deepEqual(renamed.action.reads.map(read => read.stepId), ['item'], 'the labels read does not run for a rename');
  setRow(h, 'fixture.items.read', 'allow');
  const job = await runJob(h, 'update-item v1', {itemId: 'I1', change: 'label', labels: ['Work']});
  assert.deepEqual([job.action.phase, job.action.skipped], ['final', ['rename']]);
  // The mode recorded at acceptance is never loosened by the current one: a recorded Never refuses with nothing sent.
  h.store.put('jobs', {...job, action: {...job.action, modes: {...job.action.modes, perform: 'deny'}}});
  ended(await approveJob(h, stored(h, job)), 'failed', 'policy_denied');
  assert.equal(h.simulator.writes().length, 0);
});

test('part i: a scope a step requires on an OAuth account refuses before any write when the account lacks it', async t => {
  const h = actionHarness(t);
  h.store.put('connections', {...h.store.get('connections', h.account), authMethod: 'oauth', scopes: ['fixture:all']});
  setOwn(h, 'put-file v1');
  ended(await runJob(h, 'put-file v1', {path: 'docs/a.md', content: 'x', message: 'm', kind: 'workflow'}), 'failed', ACTION_REFUSED, {details: {reason: 'scope_missing'}, error: REFUSAL_WORDS.scope_missing});
  assert.equal(h.simulator.writes().length, 0);
  const plain = await runJob(h, 'put-file v1', {path: 'docs/a.md', content: 'x', message: 'm', kind: 'file'});
  assert.deepEqual([plain.status, plain.action.phase], ['awaiting_approval', 'final'], 'a file that is not a workflow needs no such scope (Fabric did not make it, so it asks)');
});

test('part i: credentials at dispatch: a credential in the inputs, in a transform output or in bytes built before any fetch refuses before sending', async t => {
  const h = actionHarness(t, {file: withActions(createLabel, joinedLabel, joinedWhen)});
  setOwn(h, 'put-file v1');
  ended(await runJob(h, 'put-file v1', {path: 'docs/a.md', content: `secret: ${TOKEN}`, message: 'm', kind: 'file'}), 'failed', ACTION_REFUSED, {details: {reason: 'credential_in_request'}});
  ended(await runJob(h, 'create-label v1', {name: `x${TOKEN}`}), 'failed', ACTION_REFUSED, {details: {reason: 'credential_in_request'}});
  // Split across two inputs, neither holds it: the bytes check finds it in the joined name, the output check in the when's cut text.
  const split = {head: TOKEN.slice(0, 13), tail: `${TOKEN.slice(13)} fin`};
  assert.equal(holdsCredential(split, credentialContext({Authorization: `Bearer ${TOKEN}`})), false, 'neither input holds it');
  ended(await runJob(h, 'joined-label v1', split), 'failed', ACTION_REFUSED, {details: {reason: 'credential_in_request'}});
  ended(await runJob(h, 'joined-when v1', split), 'failed', ACTION_REFUSED, {details: {reason: 'credential_in_request'}});
  assert.equal(h.simulator.writes().length, 0, 'none left the machine');
});

test('part i: identity, authority and the API address are checked again after every credential fetch, before the request is sent', async t => {
  // The account's identity changes while its credentials are fetched.
  let h = actionHarness(t);
  setOwn(h, 'reschedule-event v1');
  const fetch = h.connections.credentials;
  h.runtime.connections = {credentials: async id => { h.store.put('connections', {...h.store.get('connections', h.account), identity: {id: 'acct-2'}}); return fetch(id); }};
  ended(await runJob(h, 'reschedule-event v1', RESCHEDULE), 'failed', 'authority_changed');
  assert.equal(h.simulator.calls.length, 0);
  // The owner sets the action to Never between its read and its write: the write is not sent.
  h = actionHarness(t);
  setOwn(h, 'reschedule-event v1');
  let fetches = 0;
  h.runtime.connections = {credentials: async id => { if (++fetches === 2) setOwn(h, 'reschedule-event v1', 'deny'); return h.connections.credentials(id); }};
  ended(await runJob(h, 'reschedule-event v1', RESCHEDULE), 'failed', 'authority_changed', {error: 'Execution is denied by your setting for this account and operation.'});
  assert.deepEqual(routes(h), ['GET /events/E1']);
  // An account whose grant does not hold the app's reviewed API address.
  h = actionHarness(t);
  setOwn(h, 'reschedule-event v1');
  h.runtime.connections = {credentials: async () => ({headers: {Authorization: `Bearer ${TOKEN}`}, allowedOrigins: ['https://elsewhere.fixture.test']})};
  ended(await runJob(h, 'reschedule-event v1', RESCHEDULE), 'failed', 'fabric_failed', {reason: 'proxy_unavailable'});
  assert.equal(h.simulator.calls.length, 0);
});

test('part i: a write that never left the machine is removed from writesSent', async t => {
  const h = actionHarness(t);
  setOwn(h, 'reschedule-event v1');
  const send = h.simulator.request;
  h.runtime.request = async options => { if (options.method === 'PATCH') throw Object.assign(new Error('Provider DNS lookup failed or timed out.'), {sent: false}); return send(options); };
  const job = await runJob(h, 'reschedule-event v1', RESCHEDULE);
  assert.deepEqual([job.status, job.action.writesSent], ['failed', []]);
});

test('part i: an action is refused while a proxied write holds the account, and holds it from its resolving write to the end of phase 1', async t => {
  const h = actionHarness(t, {designated: true});
  setOwn(h, 'reschedule-event v1');
  setRow(h, 'fixture.labels.write', 'allow');
  const gate = h.simulator.hold('POST /labels');
  const proxied = h.runtime.prepareProxy({connectionId: h.account, request: {method: 'POST', path: '/labels', body: {name: 'x'}}}, h.owner);
  const writing = h.runtime.execute(proxied.id);
  await reached(gate, writing);
  ended(await runJob(h, 'reschedule-event v1', RESCHEDULE), 'failed', 'write_in_progress', {error: RUN_WORDS.write_in_progress});
  assert.equal(h.simulator.writes().filter(call => call.path.startsWith('/events')).length, 0);
  gate.release();
  assert.equal((await writing).status, 'uncertain');
  const s = slackHarness(t), waiting = await s.runtime.createJob({connectionId: s.account, capabilityId: s.id, args: {email: 'grace@example.com', text: 'Hi'}}, null);
  let held = null;
  const open = s.script.request;
  s.runtime.request = async options => { if (/conversations\.open/.test(options.url)) held = [...s.runtime.writeLocks]; return open(options); };
  await s.runtime.approve(waiting.id, waiting.approvalDigest, null);
  assert.deepEqual([held, [...s.runtime.writeLocks]], [[`account:${s.account}`], []]);
});

test('part i: a verify answer outside its expect is unverified even when its fields match; a lost readback keeps the output, unverified; a membership readback that misses is uncertain', async t => {
  let h = actionHarness(t);
  setOwn(h, 'reschedule-event v1');
  const send = h.simulator.request;
  let reads = 0;
  h.runtime.request = async options => (options.method === 'GET' && ++reads === 2 ? {status: 500, headers: {}, data: {id: 'E1', start: RESCHEDULE.start}} : send(options));
  const odd = await runJob(h, 'reschedule-event v1', RESCHEDULE);
  assert.deepEqual([odd.status, odd.result.verification.status], ['uncertain', 'unverified']);
  h = actionHarness(t);
  setOwn(h, 'reschedule-event v1');
  const drop = h.simulator.request;
  let gets = 0;
  h.runtime.request = async options => { if (options.method === 'GET' && ++gets === 2) throw Object.assign(new Error('Provider connection failed.'), {sent: true}); return drop(options); };
  const lost = await runJob(h, 'reschedule-event v1', RESCHEDULE);
  assert.deepEqual([lost.status, lost.errorCode, lost.result?.verification.status, lost.result?.data], ['uncertain', 'outcome_uncertain', 'unverified', {etag: '"2"'}]);
  h = actionHarness(t, {files: [rpcFile()]});
  h.allow('post-twice v1');
  h.simulator.swallow('POST /messages.post', {times: 2});
  ended(await h.run('post-twice v1', {text: 'Hi'}), 'uncertain', 'outcome_uncertain');
  // Each identity kind over a frame.
  const entry = h.catalog.entries.get(h.idOf('remove-labels v1')).entry, frameOf = (answers, input = {itemId: 'I1', names: ['Work', 'Later']}) => newFrame(createJob({jobId: 'j', entry, appId: 'fixture', clock: () => 0}), input, new Map(answers));
  const membership = {kind: 'membership', step: 'check', listLacks: {list: '/labels', where: [{field: '/name', equals: {item: ''}}]}, forEach: 'unlabel'};
  assert.equal(identityHolds(entry, membership, frameOf([['check', {status: 200, headers: {}, data: {labels: [{name: 'Other'}]}}]])), true);
  assert.equal(identityHolds(entry, membership, frameOf([['check', {status: 200, headers: {}, data: {labels: [{name: 'Later'}]}}]])), false, 'each forEach item is checked');
  assert.deepEqual([404, 410, 200].map(status => identityHolds(entry, {kind: 'address', step: 'check', of: 'unlabel'}, frameOf([['check', {status, headers: {}, data: null}]]))), [true, true, false]);
  const readback = {kind: 'readback', step: 'check', pointer: '/id', equals: {input: '/itemId'}};
  assert.deepEqual([identityHolds(entry, readback, frameOf([['check', {status: 200, headers: {}, data: {id: 'I1'}}]])), identityHolds(entry, readback, frameOf([['check', {status: 200, headers: {}, data: {id: 'I2'}}]])),
    identityHolds(entry, readback, frameOf([]))], [true, false, false]);
});

test('part i: an output is withheld when authority changed by the last answer, and the write is uncertain', async t => {
  const h = actionHarness(t);
  setOwn(h, 'reschedule-event v1');
  const send = h.simulator.request;
  let gets = 0;
  h.runtime.request = async options => { const answer = await send(options); if (options.method === 'GET' && ++gets === 2) setOwn(h, 'reschedule-event v1', 'ask'); return answer; };
  const done = await runJob(h, 'reschedule-event v1', RESCHEDULE);
  ended(done, 'uncertain', 'authority_changed', {reason: 'authority_changed', error: RUN_WORDS.authority_changed, result: null});
  assert.equal(h.simulator.data.events.E1.start, RESCHEDULE.start, 'the change was made; its output is not returned');
});

test('part j: a developer environment\'s relay decides one stop at a time; a rejection cancels the job, keeps the decision and removes the prepared bytes', async t => {
  const h = actionHarness(t), owner = {kind: 'product_user', subjectId: 'user-1', userRecordId: `usr_${'a'.repeat(26)}`};
  const permissions = new PermissionManager({store: h.store, groups: h.groups, configs: h.configs}), proxyPolicy = new ProxyPolicy({store: h.store, permissions, groups: h.groups, configs: h.configs, rowFloor: true});
  const runtime = new Runtime({store: h.store, permissions, proxyPolicy, connections: h.connections, request: h.simulator.request, clock: () => h.now, actions: h.catalog,
    deployment: tenantDeployment({kind: 'tenant', environmentId: 'env_1'})});
  h.store.put('connections', stampOwner(h.store.get('connections', h.account), owner));
  const job = await runtime.createJob({connectionId: h.account, capabilityId: h.idOf('reschedule-event v1'), args: RESCHEDULE}, owner);
  assert.deepEqual([job.status, job.action.phase, Boolean(h.store.get(PREPARED, job.id))], ['awaiting_approval', 'final', true]);
  const rejected = runtime.decideWaiting(job.id, job.approvalDigest, owner, {decision: 'rejected', decidedIn: 'relay', keyId: 'key_1'});
  assert.deepEqual([rejected.status, rejected.action.decisions.map(item => [item.phase, item.decision]), h.store.get(PREPARED, job.id), h.simulator.writes().length],
    ['cancelled', [['final', 'rejected']], null, 0]);
  // A stop nobody decided in time: the late decision is refused and the prepared bytes go.
  const late = await runtime.createJob({connectionId: h.account, capabilityId: h.idOf('reschedule-event v1'), args: RESCHEDULE}, owner);
  h.advance(10 * 60_000 + 1000);
  assert.throws(() => runtime.decideWaiting(late.id, late.approvalDigest, owner, {decision: 'approved', decidedIn: 'relay', keyId: 'key_1'}), error => error.code === 'approval_expired');
  assert.equal(h.store.get(PREPARED, late.id), null);
});

test('part h: in a developer environment the prepared row of a stop made at acceptance carries its end user, as every later one does', async t => {
  const h = actionHarness(t), owner = {kind: 'product_user', subjectId: 'user-1', userRecordId: `usr_${'a'.repeat(26)}`};
  const permissions = new PermissionManager({store: h.store, groups: h.groups, configs: h.configs}), proxyPolicy = new ProxyPolicy({store: h.store, permissions, groups: h.groups, configs: h.configs, rowFloor: true});
  const runtime = new Runtime({store: h.store, permissions, proxyPolicy, connections: h.connections, request: h.simulator.request, clock: () => h.now, actions: h.catalog,
    deployment: tenantDeployment({kind: 'tenant', environmentId: 'env_1'})});
  h.store.put('connections', stampOwner(h.store.get('connections', h.account), owner));
  proxyPolicy.set({connectionId: h.account, row: 'group:fixture.items.read', mode: 'ask', confirmAllow: true});
  const job = await runtime.createJob({connectionId: h.account, capabilityId: h.idOf('reschedule-event v1'), args: RESCHEDULE}, owner);
  assert.deepEqual([job.status, job.action.phase, h.simulator.calls.length], ['awaiting_approval', 'reads', 0]);
  const row = h.store.get(PREPARED, job.id);
  assert.deepEqual([row.ownership, row.userRecordId], [{owner: {kind: 'product_user', id: 'user-1'}}, owner.userRecordId]);
  // The relay's approval only queues the job; accepting another action job before it is dispatched leaves its prepared bytes in place.
  const queued = runtime.decideWaiting(job.id, job.approvalDigest, owner, {decision: 'approved', decidedIn: 'relay', keyId: 'key_1'});
  assert.equal(queued.status, 'queued');
  await runtime.prepareJob({connectionId: h.account, capabilityId: h.idOf('reschedule-event v1'), args: RESCHEDULE}, owner);
  assert.ok(h.store.get(PREPARED, job.id), 'a queued job keeps the bytes it was approved on');
  const final = await runtime.execute(job.id);
  assert.deepEqual([final.status, final.action.phase, routes(h)], ['awaiting_approval', 'final', ['GET /events/E1']], final.error);
});

// ---- F10.19 part 1 (docs/F10.19-BUILD-MAP.md part 1 item 4): three runtime fixes, on Notion's shipped rows and proxy settings ----------------
// Small inline Notion actions run on notionHarness(): a real ConnectionManager adds Notion-Version from the shipped sign-in, and the Notion
// simulator refuses any other version, so every request here also shows 2026-03-11 going out.
const NOTION_OK = {status: [200], require: []};
const PAGE_ID = {pick: {transform: 'ids.notionId@1', args: {value: {input: '/page'}}}, pointer: '/id'};
const PAGE_INPUT = {type: 'string', minLength: 1, maxLength: 2048};
const TITLE_LINE = {label: 'Page', expr: {pick: {transform: 'notion.title@1', args: {object: {step: 'page', pointer: ''}}}, pointer: '/title'}};
const notionAction = (key, fields) => ({id: `notion.action.${key}.v1.${'0'.repeat(24)}`, key, version: 1, name: key, description: `The ${key} action of these tests.`, guards: [], prepare: [],
  definitive: [400, 403, 404, 409], ...fields});
const notionActions = (...actions) => ({schemaVersion: 1, appId: 'notion', specVersion: 'fabric/0.2', reviewStatus: 'reviewed', pinnedParameters: {}, actions: actions.map(make => make())});
const PAGE_READ = {id: 'page', method: 'GET', path: '/v1/pages/{page_id}', params: {page_id: PAGE_ID}, expect: NOTION_OK};
const readPage = () => notionAction('read-page', {effect: 'read', row: 'notion.content.read', hints: READ_HINTS, inputSchema: closed({page: PAGE_INPUT}),
  outputSchema: closed({id: words(64), inTrash: {type: 'boolean'}}), perform: [PAGE_READ], output: {id: {step: 'page', pointer: '/id'}, inTrash: {step: 'page', pointer: '/in_trash'}},
  preview: [], definitive: [400, 403, 404]});
/** Restore, as section 2 plans it: the prepare read, then the one constant {in_trash: false}, which routes the PATCH into the trash row. */
const restorePage = () => notionAction('restore-page', {effect: 'delete', row: 'notion.content.trash', hints: {readOnly: false, destructive: true, idempotent: false, openWorld: true},
  inputSchema: closed({page: PAGE_INPUT}), outputSchema: closed({id: words(64), inTrash: {type: 'boolean'}}), prepare: [PAGE_READ],
  perform: [{id: 'restore', method: 'PATCH', path: '/v1/pages/{page_id}', params: {page_id: {step: 'page', pointer: '/id'}}, body: {const: {in_trash: false}}, expect: NOTION_OK}],
  verify: {requests: [{id: 'check', method: 'GET', path: '/v1/pages/{page_id}', params: {page_id: {step: 'page', pointer: '/id'}}, expect: NOTION_OK}],
    identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {step: 'page', pointer: '/id'}}], assert: [{step: 'check', equals: {pointer: '/in_trash', value: {const: false}}}]},
  output: {id: {step: 'check', pointer: '/id'}, inTrash: {step: 'check', pointer: '/in_trash'}}, preview: [TITLE_LINE]});
/** Two writes on one page: a rename, then a line added to its markdown, so the second refusal comes after a write was sent. */
const renameAndAdd = () => notionAction('rename-and-add', {effect: 'write', row: 'notion.content.edit', hints: WRITE_HINTS, inputSchema: closed({page: PAGE_INPUT, title: words(), text: words()}),
  outputSchema: closed({id: words(64)}), prepare: [PAGE_READ],
  perform: [{id: 'rename', method: 'PATCH', path: '/v1/pages/{page_id}', params: {page_id: {step: 'page', pointer: '/id'}}, body: {object: {properties: {object: {title: {object: {title: {each:
      {pick: {transform: 'text.chunk@1', args: {text: {input: '/title'}}}, pointer: '/chunks'}, as: 'chunk', max: 100, do: {object: {text: {object: {content: {var: 'chunk'}}}}}}}}}}}}, expect: NOTION_OK},
    {id: 'add', method: 'PATCH', path: '/v1/pages/{page_id}/markdown', params: {page_id: {step: 'page', pointer: '/id'}},
      body: {object: {type: {const: 'insert_content'}, insert_content: {object: {content: {input: '/text'}}}}}, expect: NOTION_OK}],
  verify: {requests: [{id: 'check', method: 'GET', path: '/v1/pages/{page_id}', params: {page_id: {step: 'page', pointer: '/id'}}, expect: NOTION_OK}],
    identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {step: 'page', pointer: '/id'}}], assert: []},
  output: {id: {step: 'check', pointer: '/id'}}, preview: [TITLE_LINE]});
/**
 * Update a title, with section 2's two schema steps: the page read, and its data source read only when the page is a row. Section 2 derives
 * the schema from {either: [source, page]}, but step 9's grammar takes step data only as a {step, pointer} or a pick of one, never an
 * {either} (F10.8 open point Minor 14, pinned by test/actions-validator.test.mjs), so the derive here reads the page alone: its title. The
 * data source read is still a schema step whose when the fresh answers decide, which is what the dispatch recheck must handle.
 */
const updatePage = () => notionAction('update-page', {effect: 'write', row: 'notion.content.edit', hints: WRITE_HINTS,
  inputSchema: {type: 'object', properties: {page: PAGE_INPUT, values: {type: 'object', properties: {}, additionalProperties: false}}, required: ['page', 'values'], additionalProperties: false},
  outputSchema: closed({id: words(64)}),
  resolvedInputs: [{input: 'values', dependsOn: ['page'], schema: {steps: [{id: 'current', method: 'GET', path: '/v1/pages/{page_id}', params: {page_id: PAGE_ID}, expect: NOTION_OK},
    {id: 'source', method: 'GET', path: '/v1/data_sources/{data_source_id}', params: {data_source_id: {step: 'current', pointer: '/parent/data_source_id'}},
      when: {present: {step: 'current', pointer: '/parent/data_source_id'}}, expect: NOTION_OK}],
    derive: {transform: 'notion.schema@1', args: {dataSource: {step: 'current', pointer: ''}}}}, maxProperties: 100}],
  perform: [{id: 'update', method: 'PATCH', path: '/v1/pages/{page_id}', params: {page_id: {step: 'current', pointer: '/id'}},
    body: {object: {properties: {transform: 'notion.propertyValues@1', args: {schema: {resolved: 'values'}, values: {input: '/values'}}}}}, expect: NOTION_OK}],
  verify: {requests: [{id: 'check', method: 'GET', path: '/v1/pages/{page_id}', params: {page_id: {step: 'current', pointer: '/id'}}, expect: NOTION_OK}],
    identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {step: 'update', pointer: '/id'}}], assert: []},
  output: {id: {step: 'update', pointer: '/id'}}, preview: []});
/** A shared page A, a child page under it, and under A a database whose one data source has a title and a number. */
function notionWorld(h) {
  const a = h.simulator.seedPage({title: '[SYNTHETIC] A', markdown: 'Hello', shared: true}), child = h.simulator.seedPage({title: 'Child', parent: {page_id: a.id}});
  const {database, sources: [source]} = h.simulator.seedDatabase({title: 'Tasks', parent: {page_id: a.id}, sources: [{name: 'Tasks', properties: {Name: {type: 'title'}, Cost: {type: 'number'}}}]});
  const row = h.simulator.seedRow({dataSource: source.id, properties: {Name: {title: [{text: {content: 'Row 1'}}]}, Cost: {number: 3}}});
  const unshared = h.simulator.seedPage({title: 'Private'});
  return {a, child, database, source, row, unshared};
}
const notionRoutes = h => h.simulator.calls.map(call => call.route);

test('F10.19 part 1: on Notion\'s shipped settings a step body {in_trash: false} is built and sent; in_trash true, a nested archived and another app\'s in_trash are refused request_invalid before sending', async t => {
  const h = notionHarness(t, {file: notionActions(restorePage)}), {child} = notionWorld(h);
  await h.simulator.request({url: `https://api.notion.com/v1/blocks/${child.id}`, method: 'DELETE', headers: {Authorization: `Bearer ${h.simulator.token}`, 'Notion-Version': '2026-03-11'}, allowedOrigins: ['https://api.notion.com']});
  h.simulator.calls.length = 0;
  const job = await h.run('restore-page v1', {page: child.url});
  assert.deepEqual([job.status, job.action.phase, h.card(job).effect], ['awaiting_approval', 'final', 'delete'], job.error);
  const done = await h.approve(job);
  ended(done, 'succeeded', null);
  const sent = h.simulator.writes();
  assert.deepEqual(sent.map(call => [call.method, call.route, JSON.stringify(call.body)]), [['PATCH', 'PATCH /pages/{page_id}', '{"in_trash":false}']], 'exactly the constant, nothing else');
  assert.ok(h.simulator.calls.every(call => call.headers['notion-version'] === '2026-03-11'), 'every request carries the version from the shipped sign-in');
  assert.deepEqual([h.simulator.state().pages[child.id].in_trash, done.result.data, done.result.verification.status], [false, {id: child.id, inTrash: false}, 'verified']);
  // The runtime check itself, on bodies the validator never lets a file write: only the constant false, only for Notion.
  const entry = h.entry('restore-page v1').entry, step = entry.action.perform[0], config = PROXY_CONFIGS.get('notion');
  const frame = newFrame(createJob({jobId: 'job-n', entry, appId: 'notion', clock: () => h.now}), {page: child.id}, new Map([['page', answer({id: child.id, object: 'page'})]]));
  assert.equal(buildRequest(entry, step, frame, {config}).request.body, '{"in_trash":false}');
  for (const [label, body] of [['in_trash true', {in_trash: true}], ['in_trash as text', {in_trash: 'false'}], ['a nested in_trash true', {properties: {x: {in_trash: true}}}],
    ['a nested archived', {in_trash: false, properties: {x: {archived: true}}}], ['erase_content', {in_trash: false, erase_content: true}], ['display_name', {display_name: 'x'}]]) {
    assert.throws(() => buildRequest(entry, {...step, body: {const: body}}, frame, {config}), error => error.code === ACTION_REFUSED && error.details?.reason === 'request_invalid', label);
  }
  refused(() => buildRequest(entry, step, frame, {config: {...config, appId: 'notion-twin'}}), 'request_invalid', REFUSAL_WORDS.request_invalid);
});

test('F10.19 part 1: the proxy\'s own requests are unchanged: a raw PATCH naming in_trash is still refused', () => {
  assert.throws(() => normalizeProxyRequest({method: 'PATCH', path: '/v1/pages/p1', body: {in_trash: false}}, PROXY_CONFIGS.get('notion'), {}), error => error.code === 'parameter_not_allowed');
});

test('F10.19 part 1: Notion\'s 404 object_not_found reads not_shared and 403 restricted_resource capability_off, each with its words; other codes keep http_status; a 429 keeps its Retry-After', async t => {
  assert.equal(RUN_WORDS.not_shared, 'This page may not be shared with Fabric. Nothing was changed. Share it in Notion, or use Share more pages.');
  assert.equal(RUN_WORDS.capability_off, 'Notion has turned this capability off for Fabric\'s integration. Nothing was changed. Turn it back on in Notion\'s integration settings.');
  let h = notionHarness(t, {file: notionActions(readPage, renameAndAdd)});
  let world = notionWorld(h);
  ended(await h.run('read-page v1', {page: world.unshared.id}), 'failed', 'provider_failed', {providerStatus: 404, reason: 'not_shared', error: RUN_WORDS.not_shared});
  h.simulator.fail('GET /pages/{page_id}', {status: 404, data: {object: 'error', status: 404, code: 'directory_not_found', message: 'x'}});
  ended(await h.run('read-page v1', {page: world.a.id}), 'failed', 'provider_failed', {providerStatus: 404, reason: 'http_status', error: RUN_WORDS.failed});
  h.simulator.fail('GET /pages/{page_id}', {status: 403, data: {object: 'error', status: 403, code: 'status_change_not_allowed', message: 'x'}});
  ended(await h.run('read-page v1', {page: world.a.id}), 'failed', 'provider_failed', {providerStatus: 403, reason: 'http_status', error: RUN_WORDS.failed});
  h.simulator.limit('GET /pages/{page_id}', 30);
  ended(await h.run('read-page v1', {page: world.a.id}), 'failed', 'provider_failed', {providerStatus: 429, reason: 'http_status', retryAfterSeconds: 30, error: RUN_WORDS.limited});
  assert.equal(h.simulator.calls.length, 4, 'never retried');
  h = notionHarness(t, {file: notionActions(readPage), capabilities: ['update_content', 'insert_content', 'read_comments', 'insert_comments', 'user_email']});
  world = notionWorld(h);
  ended(await h.run('read-page v1', {page: world.a.id}), 'failed', 'provider_failed', {providerStatus: 403, reason: 'capability_off', error: RUN_WORDS.capability_off});
});

test('F10.19 part 1: after an earlier write was sent, not_shared and capability_off stay uncertain, with the uncertain words', async t => {
  for (const [status, code, reason] of [[404, 'object_not_found', 'not_shared'], [403, 'restricted_resource', 'capability_off']]) {
    const h = notionHarness(t, {file: notionActions(renameAndAdd)}), {a} = notionWorld(h);
    const job = await h.run('rename-and-add v1', {page: a.id, title: '[SYNTHETIC] Renamed', text: 'Added'});
    assert.equal(job.status, 'awaiting_approval', job.error);
    h.simulator.fail('PATCH /pages/{page_id}/markdown', {status, data: {object: 'error', status, code, message: 'x'}});
    ended(await h.approve(job), 'uncertain', 'outcome_uncertain', {providerStatus: status, reason, error: RUN_WORDS.uncertain});
    assert.deepEqual(h.simulator.writes().map(call => call.route), ['PATCH /pages/{page_id}', 'PATCH /pages/{page_id}/markdown'], 'the rename went out first');
    assert.equal(h.simulator.state().pages[a.id].properties.title.title[0].plain_text, '[SYNTHETIC] Renamed');
  }
});

test('F10.19 part 1: a schema step skipped at prepare is skipped again at dispatch; a skipped step that would now run, or a run step that would now skip, ends input_schema_changed with nothing sent', async t => {
  // A plain page: its data source read is skipped, and the schema binds its title alone.
  let h = notionHarness(t, {file: notionActions(updatePage)}), world = notionWorld(h);
  let job = await h.run('update-page v1', {page: world.child.id, values: {title: '[SYNTHETIC] Renamed'}});
  assert.deepEqual([job.status, job.action.skipped], ['awaiting_approval', ['source']], job.error);
  let done = await h.approve(job);
  ended(done, 'succeeded', null);
  assert.deepEqual(h.simulator.writes().map(call => [call.route, call.body]), [['PATCH /pages/{page_id}', {properties: {title: {title: [{text: {content: '[SYNTHETIC] Renamed'}}]}}}]]);
  assert.deepEqual(notionRoutes(h).filter(route => route.includes('data_sources')), [], 'the data source was never read');
  // A row: its data source read runs; the page binds its title property.
  job = await h.run('update-page v1', {page: world.row.id, values: {Name: '[SYNTHETIC] Row'}});
  assert.deepEqual([job.status, job.action.skipped], ['awaiting_approval', []], job.error);
  ended(await h.approve(job), 'succeeded', null);
  assert.equal(h.simulator.state().pages[world.row.id].properties.Name.title[0].plain_text, '[SYNTHETIC] Row');
  assert.equal(notionRoutes(h).filter(route => route === 'GET /data_sources/{data_source_id}').length, 2, 'read at prepare and again at dispatch');
  // Between approval and dispatch the plain page becomes a row: the skipped read would now run.
  h = notionHarness(t, {file: notionActions(updatePage)});
  world = notionWorld(h);
  job = await h.run('update-page v1', {page: world.child.id, values: {title: '[SYNTHETIC] Renamed'}});
  h.simulator.data.pages[world.child.id].parent = {type: 'data_source_id', data_source_id: world.source.id, database_id: world.database.id};
  ended(await h.approve(job), 'failed', 'input_schema_changed', {error: RUN_WORDS.input_schema_changed});
  assert.equal(h.simulator.writes().length, 0, 'nothing sent');
  // And a row becomes a plain page: the read that ran would now skip.
  h = notionHarness(t, {file: notionActions(updatePage)});
  world = notionWorld(h);
  job = await h.run('update-page v1', {page: world.row.id, values: {Name: '[SYNTHETIC] Row'}});
  assert.equal(job.status, 'awaiting_approval', job.error);
  h.simulator.data.pages[world.row.id].parent = {type: 'page_id', page_id: world.a.id};
  ended(await h.approve(job), 'failed', 'input_schema_changed', {error: RUN_WORDS.input_schema_changed});
  assert.equal(h.simulator.writes().length, 0, 'nothing sent');
});


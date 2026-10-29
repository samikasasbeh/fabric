import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {PERMISSION_GROUPS, validatePermissionGroups} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {templatesFor, matchRequest, routeMatch} from '../lib/proxy-match.mjs';
import {checkExpression} from '../lib/action-expressions.mjs';
import {placeStep, placeRegistration, placeRequest, stepEffect, actionEffect, accessOf, RESOLVING_WRITES, PHASES} from '../lib/action-placement.mjs';
import {validateActionFile} from '../lib/actions.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {fixtureGroups, fixtureConfigs, fixtureMap, fixtureRows, fixtureActions, withIds, actionSchema} from './fixtures/actions/fixture-app.mjs';
import {TRANSFORMS} from './fixtures/actions/registry.mjs';
import {googleMap} from './fixtures/access/google-maps.mjs';

// F10.9 part e (docs/F10.9-BUILD-MAP.md part e and section 4): where an action step lands, on the five shipped apps and the fixture app.
// placeStep() places a step on a reviewed member of a reviewed row through the proxy's own matcher, applies the row's body routes to the
// body's constant skeleton, and gives the step's effect; placeRequest() is the run-time hook F10.11 calls on every concrete request. The
// first test pins the matcher facts the map measured (section 1, "Measured placements"), the ground part e stands on.
function placed(appId, method, path, body) {
  const definition = PERMISSION_GROUPS.get(appId), config = PROXY_CONFIGS.get(appId), templates = templatesFor(definition, config, null);
  assert.ok(templates, `${appId} places without a map`);
  const segments = path === '/' ? [] : path.slice(1).split('/');
  const match = matchRequest(templates, {method, segments}, {style: config.style, inheritFamilies: config.inheritFamilies});
  return body === undefined ? match : routeMatch(definition, match, {body: JSON.stringify(body)}, {style: config.style});
}
const row = match => match.kind === 'group' ? match.groupId : match.kind;

test('the measured placements part e builds on (section 1)', () => {
  const contents = placed('github', 'PUT', '/repos/o/r/contents/docs/a.md');
  assert.deepEqual([row(contents), contents.member], ['github.code.write', 'PUT /repos/{owner}/{repo}/contents/{path}'], 'a {+path} template takes a multi-segment path');
  const ref = placed('github', 'GET', '/repos/o/r/git/ref/heads/feature/x');
  assert.deepEqual([row(ref), ref.member], ['github.repos.read', 'GET /repos/{owner}/{repo}/git/ref/{ref}']);
  const events = placed('github', 'GET', '/repos/o/r/issues/events');
  assert.equal(events.template, 'GET /repos/{owner}/{repo}/issues/events', 'a literal beats a parameter, so placement must run again on every concrete request');
  const unlabel = placed('github', 'DELETE', '/repos/o/r/issues/1/labels/bug');
  assert.deepEqual([row(unlabel), unlabel.effect], ['github.issues.write', 'delete']);
  assert.equal(row(placed('github', 'POST', '/repos/o/r/hooks')), 'github.access.grant', 'hook creation sits in the locked row');
  for (const path of ['/repos/o/r/hooks', '/repos/o/r/hooks/1/deliveries']) assert.equal(row(placed('github', 'GET', path)), 'other-reads', path);
  for (const method of ['GET', 'POST']) assert.equal(row(placed('slack', method, '/auth.test')), 'other-changes', `${method} /auth.test`);
  assert.equal(row(placed('slack', 'POST', '/apps.connections.open')), 'slack.admin');
  const history = placed('slack', 'POST', '/conversations.history');
  assert.deepEqual([history.member, history.effect], ['GET /conversations.history', 'read'], 'an RPC match ignores the method, so part e compares it');
  const canvas = placed('slack', 'POST', '/canvases.getContent');
  assert.deepEqual([row(canvas), canvas.effect], ['slack.files.read', 'read'], 'the proxy reads a reviewed-read RPC POST as a read; an action step counts it a read only when what it sends is built from reads (F10.10)');
  assert.equal(row(placed('slack', 'POST', '/conversations.open')), 'slack.conversations.mark', 'the one resolving write sits in a write row');
  const restore = placed('notion', 'PATCH', '/v1/pages/p1', {in_trash: false});
  assert.deepEqual([row(restore), restore.effect, restore.routedFrom?.groupId], ['notion.content.trash', 'delete', 'notion.content.edit'], 'present routes on any value, false included');
  assert.equal(row(placed('notion', 'PATCH', '/v1/pages/p1/markdown', {type: 'replace_content'})), 'notion.content.trash');
  assert.equal(row(placed('notion', 'PATCH', '/v1/pages/p1/markdown', {type: 'insert_content'})), 'notion.content.edit');
  const search = placed('notion', 'POST', '/v1/search');
  assert.deepEqual([row(search), search.effect], ['notion.search.read', 'read']);
  const query = placed('notion', 'POST', '/v1/views/v1/queries');
  assert.deepEqual([row(query), query.effect], ['notion.content.read', 'write'], 'a POST in a read row that is not a reviewed read is a write');
  // Gmail and Calendar are reviewed by operation id: without a map nothing places, so part e's actions are unplaced, not a crash.
  for (const appId of ['gmail', 'google-calendar']) assert.equal(templatesFor(PERMISSION_GROUPS.get(appId), PROXY_CONFIGS.get(appId), null), null, appId);
});

// ---- part e: the helpers --------------------------------------------------------------------------------------------------------------
const json = file => JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8'));
// The application maps the store keeps for Gmail and Calendar, as F10.7 built them for its churn test: every reviewed operation, at a path
// that is the id after the app prefix (GET for ids ending .list or .get, POST otherwise). They are not Google's paths (F10.11 part a
// recorded those in test/fixtures/access/google-method-paths.json, and the last test places on them), so they show how a step on an app
// reviewed by operation id places, never where a real request goes.
const SYNTHETIC = json('./fixtures/access/f10-7-bindings.before.json').maps;
// The same maps carrying Discovery's scope facts per method, as the store's map carries them (lib/permissions.mjs scopeSetsOf()).
const SCOPES = json('./fixtures/access/google-method-scopes.json').apps;
const withScopes = appId => ({...SYNTHETIC[appId], operations: SYNTHETIC[appId].operations.map(operation => ({...operation, scopeSets: (SCOPES[appId].methods[operation.id] ?? []).map(scope => [scope])}))});
const shipped = (appId, map = null) => ({definition: PERMISSION_GROUPS.get(appId), config: PROXY_CONFIGS.get(appId), map});
const GROUPS = fixtureGroups(), CONFIGS = fixtureConfigs(GROUPS);
const fixture = (appId = 'fixture', map = fixtureMap()) => ({definition: GROUPS.get(appId), config: CONFIGS.get(appId), map});

// A body is checked as part f checks it, at slot body, and placeStep() reads its fact.
const INPUTS = {type: 'object', properties: {
  name: {type: 'string', minLength: 1, maxLength: 200},
  names: {type: 'array', maxItems: 10, items: {type: 'string', minLength: 1, maxLength: 100}},
  kind: {type: 'string', maxLength: 100},
  link: {type: 'string', maxLength: 2048},
  owner: {type: 'object', properties: {address: {type: 'string', minLength: 3, maxLength: 254}}, required: ['address'], additionalProperties: false},
  pairs: {type: 'array', maxItems: 100, items: {type: 'object', properties: {name: {type: 'string', minLength: 1, maxLength: 100}, value: {type: 'string', maxLength: 1000}}, required: ['name', 'value'], additionalProperties: false}},
  values: {type: 'object', properties: {}, additionalProperties: false},
}, required: ['name'], additionalProperties: false};
const STEPS = new Map([['labels', {source: 'prepare'}], ['item', {source: 'prepare'}]]);
const fact = (node, transforms = TRANSFORMS) => checkExpression(node, {where: '$body', slot: 'body', transforms, inputSchema: INPUTS, resolvedInputs: ['values'], steps: STEPS});
/** One step placed. `request` is "METHOD /path"; `step` adds step fields (query, optional, fallbackFor, resolves); `transforms` is the
 *  registry the body is checked with; the rest are deps. */
function place(deps, request, {body, step = {}, transforms, ...more} = {}) {
  const space = request.indexOf(' ');
  return placeStep({id: 'step', method: request.slice(0, space), path: request.slice(space + 1), ...(body === undefined ? {} : {body}), ...step},
    {...deps, ...(body === undefined ? {} : {body: fact(body, transforms)}), where: 'perform[0]', ...more});
}
const refused = (deps, request, pattern, more, message = request) => assert.throws(() => place(deps, request, more), pattern, message);
const labelIds = names => ({transform: 'collections.labelIds@1', args: {list: {step: 'labels', pointer: ''}, names}});
const ids = names => ({pick: labelIds(names), pointer: '/ids'});
const propertyValues = {transform: 'notion.propertyValues@1', args: {schema: {resolved: 'values'}, values: {input: '/values'}}};
const stringValues = {transform: 'collections.stringValues@1', args: {values: {input: '/pairs'}}};
const when = then => ({when: {present: {input: '/kind'}}, then});
const LOCKED = /lands in Give access to other people or services, a row Fabric locks: no action step ever runs there \(T4\)/;
const ROUTED_LOCKED = /the body routes this step to Give access to other people or services, a row Fabric locks: no action step ever runs there \(T4\)/;

// ---- part e: rows -----------------------------------------------------------------------------------------------------------------
test('part e: a step lands on a reviewed member of a reviewed row, never in Other, GraphQL, a locked row, a documented route no row reviews or an unavailable member', () => {
  const issues = place(shipped('github'), 'GET /repos/{owner}/{repo}/issues');
  assert.deepEqual(issues, {stepId: 'step', phase: 'perform', method: 'GET', template: 'GET /repos/{owner}/{repo}/issues', member: 'GET /repos/{owner}/{repo}/issues',
    groupId: 'github.issues.read', rowEffect: 'read', effect: 'read', fromReads: false, reviewedRead: false, routedFrom: null, unplaced: false});
  assert.ok(Object.isFrozen(issues));
  // F10.10: fromReads says what the request reads, true only when the caller proves it; effect says what the step does.
  assert.equal(place(shipped('github'), 'GET /repos/{owner}/{repo}/issues', {fromReads: true}).fromReads, true);
  assert.equal(place(shipped('github'), 'GET /repos/{owner}/{repo}/issues', {fromReads: 'yes'}).fromReads, false, 'only true counts');
  const hook = placeRegistration({id: 'hook', method: 'POST', path: '/hooks'}, {...fixture(), phase: 'register', members: ['POST /hooks']});
  assert.deepEqual([hook.groupId, hook.fromReads, hook.reviewedRead, hook.effect], ['fixture.access.grant', false, false, 'write'], 'a registration step never reads as built from reads');
  for (const method of ['GET', 'POST']) refused(shipped('slack'), `${method} /auth.test`, /perform\[0\]: .* \/auth\.test lands in Other changes: an action step runs only on a reviewed member of a reviewed row/);
  refused(shipped('github'), 'GET /repos/{owner}/{repo}/hooks', /lands on GET \/repos\/\{owner\}\/\{repo\}\/hooks, a documented route no row reviews, so it would run in Other reads/);
  refused(shipped('github'), 'DELETE /repos/{owner}/{repo}/nothing-here', /lands in Other deletes/);
  refused(shipped('github'), 'POST /graphql', /lands in GraphQL/);
  refused(shipped('github'), 'POST /repos/{owner}/{repo}/hooks', LOCKED);
  refused(fixture(), 'POST /hooks', LOCKED);
  refused(fixture(), 'DELETE /hooks/{hook_id}', LOCKED);
  // Gmail's watch sits in its locked row (the synthetic map stands in for the method facts).
  refused(shipped('gmail', SYNTHETIC.gmail), 'POST /gmail/v1/users/{userId}/watch', LOCKED);
  refused(fixture(), 'GET /items/{item_id}/history', /lands on GET \/items\/\{item_id\}\/history, which is unavailable: Fabric never asks for the permission this needs/);
});

test('part e: Gmail and Calendar place only through a map that holds every reviewed operation; without one a step is unplaced, never a crash', () => {
  const unplaced = place(shipped('gmail'), 'GET /gmail/v1/users/{userId}/messages/{id}');
  assert.deepEqual(unplaced, {stepId: 'step', phase: 'perform', method: 'GET', template: null, member: null, groupId: null, rowEffect: null, effect: null, fromReads: false, reviewedRead: false, routedFrom: null, unplaced: true});
  assert.equal(place(shipped('gmail'), 'GET /gmail/v1/users/{userId}/messages/{id}', {fromReads: true}).fromReads, false, 'an unplaced step is never read as built from reads');
  assert.equal(place(shipped('google-calendar'), 'GET /calendars/{calendarId}/events').unplaced, true);
  // The step's own shape is still checked.
  refused(shipped('gmail'), 'GET /upload/gmail/v1/users/{userId}/messages', /a step path starts with \/gmail\/v1\//);
  refused(shipped('gmail'), 'GET https://gmail.googleapis.com/gmail/v1/users/me/profile', /a step path is relative to the app's reviewed API base, never a URL/);
  // A map missing one reviewed operation leaves every step unplaced (lib/proxy-match.mjs:37-38); a whole map places them.
  for (const [appId, request, member, groupId] of [['gmail', 'GET /gmail/v1/users/{userId}/messages/list', 'gmail.users.messages.list', 'gmail.messages.search'],
    ['google-calendar', 'GET /settings/get', 'calendar.settings.get', 'google-calendar.settings.read']]) {
    const other = SYNTHETIC[appId].operations.find(operation => operation.id !== member).id, short = {...SYNTHETIC[appId], operations: SYNTHETIC[appId].operations.filter(operation => operation.id !== other)};
    assert.equal(place(shipped(appId, short), request).unplaced, true, `${appId} with a map missing ${other}`);
    const whole = place(shipped(appId, SYNTHETIC[appId]), request);
    assert.deepEqual([whole.unplaced, whole.member, whole.groupId, whole.template], [false, member, groupId, request], appId);
  }
  const list = place(fixture(), 'GET /items');
  assert.deepEqual([list.member, list.groupId], ['fixture.items.list', 'fixture.items.read'], 'the fixture\'s typed operation places through its map');
  assert.equal(place(fixture('fixture', null), 'GET /items').unplaced, true);
  assert.equal(place(fixture('fixture', {operations: []}), 'GET /labels').unplaced, true, 'without its typed operation no step of the app places');
});

test('part e: strictness: the member\'s own method, literals in exact case, {+x} only on a rest segment, and no ambiguous tie', () => {
  refused(shipped('slack'), 'POST /conversations.history', /POST \/conversations\.history lands on GET \/conversations\.history: an RPC app is matched by path alone, so a step uses its member's own method, GET/);
  refused(fixture('fixture-rpc', null), 'GET /canvases.read', /lands on POST \/canvases\.read: an RPC app is matched by path alone, so a step uses its member's own method, POST/);
  refused(fixture(), 'GET /Items/{item_id}', /the literal Items is written items in the reviewed template GET \/items\/\{item_id\}/);
  refused(shipped('slack'), 'POST /Chat.postMessage', /the literal Chat\.postMessage is written chat\.postMessage in the reviewed template/);
  refused(fixture(), 'GET /items/{+item_id}', /\{\+item_id\} spans segments, but the reviewed template GET \/items\/\{item_id\} takes one segment there/);
  assert.equal(place(fixture(), 'GET /files/{+path}').member, 'GET /files/{path}');
  assert.equal(place(fixture(), 'GET /files/docs/a.md').member, 'GET /files/{path}', 'literals where the template spans segments');
  assert.equal(place(fixture(), 'GET /accounts/me/profile').member, 'GET /accounts/{account}/profile', 'a literal in a parameter position');
  assert.equal(place(shipped('github'), 'PUT /repos/{owner}/{repo}/contents/{+path}').groupId, 'github.code.write');
  assert.equal(place(shipped('github'), 'GET /repos/{owner}/{repo}/issues/{issue_number}').member, 'GET /repos/{owner}/{repo}/issues/{issue_number}', 'a parameter never lands on a literal sibling');
  // Two typed operations of two rows at one path tie; the validator cannot see map paths, so placement refuses the tie.
  const rows = fixtureRows(), tie = {definition: validatePermissionGroups({...rows, groups: rows.groups.map(group => group.id === 'fixture.items.edit' ? {...group, operations: ['fixture.items.copy']} : group)}),
    config: CONFIGS.get('fixture'), map: {...fixtureMap(), operations: [...fixtureMap().operations, {id: 'fixture.items.copy', method: 'GET', path: '/items'}]}};
  refused(tie, 'GET /items', /GET \/items matches templates of two rows equally well, so the row it lands in is ambiguous/);
  // The path itself: relative, plain segments, inside the app's prefixes; the methods the proxy takes; RPC shape.
  for (const request of ['GET https://api.fixture.test/items', 'GET //api.fixture.test/items', 'GET items']) refused(fixture(), request, /a step path is relative to the app's reviewed API base, never a URL/);
  for (const request of ['GET /items/..', 'GET /items/a%2Fb', 'GET /items/a b', 'GET /items/x?y=1', 'GET /items/{item_id}/{a}b']) refused(fixture(), request, /is not a path template of plain segments|never a URL/);
  for (const request of ['HEAD /items/{item_id}', 'get /items/{item_id}', 'OPTIONS /items']) refused(fixture(), request, /an action step uses GET, POST, PUT, PATCH or DELETE/);
  refused(shipped('slack'), 'PUT /chat.postMessage', /an RPC app takes GET or POST only/);
  refused(shipped('slack'), 'GET /chat/postMessage', /a method of an RPC app is one path segment/);
  refused(shipped('slack'), 'POST /chat.postMessage', /a POST to an RPC app sends its arguments in the body, never the query/, {step: {query: {channel: {const: 'C1'}}}});
  refused(fixture(), 'GET /items/{item_id}', /a GET step has no body/, {body: {object: {}}});
  assert.deepEqual(PHASES, ['prepare', 'perform', 'verify', 'schema', 'lookup', 'poll', 'seed', 'enrich']);
  refused(fixture(), 'GET /items/{item_id}', /a step's phase is one of prepare, perform, verify, schema, lookup, poll, seed and enrich/, {phase: 'register'});
});

test('part e: placeRequest() places every concrete request again and refuses a change of row, member or method (open question 19)', () => {
  const github = shipped('github'), issue = place(github, 'GET /repos/{owner}/{repo}/issues/{issue_number}');
  assert.equal(placeRequest(issue, {method: 'GET', segments: ['repos', 'o', 'r', 'issues', '7'], body: null}, github).member, issue.member);
  assert.throws(() => placeRequest(issue, {method: 'GET', segments: ['repos', 'o', 'r', 'issues', 'events'], body: null}, github),
    /the request lands on GET \/repos\/\{owner\}\/\{repo\}\/issues\/events in github\.issues\.read, not on the step's reviewed member GET \/repos\/\{owner\}\/\{repo\}\/issues\/\{issue_number\} in github\.issues\.read: nothing is sent/);
  assert.throws(() => placeRequest(issue, {method: 'GET', segments: ['repos', 'o', 'r', 'hooks'], body: null}, github), /the request lands in Other reads, not on the step's reviewed member/);
  const slack = shipped('slack'), post = place(slack, 'POST /chat.postMessage', {body: {object: {text: {input: '/name'}}}});
  assert.throws(() => placeRequest(post, {method: 'GET', segments: ['chat.postMessage'], body: null}, slack), /the request uses GET, but the step's reviewed member is sent with POST: nothing is sent/);
  // A body that would route the request elsewhere at run time is refused too.
  const notion = shipped('notion'), edit = place(notion, 'PATCH /v1/pages/{page_id}', {body: {object: {icon: {const: null}}}});
  assert.equal(edit.groupId, 'notion.content.edit');
  assert.equal(placeRequest(edit, {method: 'PATCH', segments: ['v1', 'pages', 'p1'], body: JSON.stringify({icon: null})}, notion).groupId, 'notion.content.edit');
  assert.throws(() => placeRequest(edit, {method: 'PATCH', segments: ['v1', 'pages', 'p1'], body: JSON.stringify({in_trash: true})}, notion), /the request lands on PATCH \/v1\/pages\/\{page_id\} in notion\.content\.trash, not on the step's reviewed member/);
  const gmail = shipped('gmail'), unplaced = place(gmail, 'GET /gmail/v1/users/{userId}/profile');
  assert.throws(() => placeRequest(unplaced, {method: 'GET', segments: ['gmail', 'v1', 'users', 'me', 'profile'], body: null}, gmail), /this step is unplaced: its app is reviewed by operation id and has no stored map holding every reviewed operation/);
});

// ---- part e: effects (F10.10 rewrote this test: a reviewed-read POST is a read only when everything it sends is built from reads) ----
test('part e and F10.10: stepEffect() is the method\'s, the row\'s and any routed row\'s, never the match\'s; a reviewed-read POST is a read only when what it sends is built from reads (I5)', () => {
  // Notion Search: listed in its read row's reviewedReads, read with fromReads, a write with fromReads false or left out.
  const notion = shipped('notion'), words = {body: {object: {query: {input: '/name'}}}}, search = place(notion, 'POST /v1/search', {...words, fromReads: true});
  assert.deepEqual([search.groupId, search.reviewedRead, search.fromReads, search.effect, stepEffect(search, notion.config)], ['notion.search.read', true, true, 'read', 'read']);
  for (const more of [{fromReads: false}, {}]) {
    const written = place(notion, 'POST /v1/search', {...words, ...more});
    assert.deepEqual([written.reviewedRead, written.fromReads, written.effect], [true, false, 'write'], JSON.stringify(more));
  }
  // A POST in a read row that is not listed stays a write, whatever it reads.
  const query = place(notion, 'POST /v1/views/{view_id}/queries', {body: {object: {}}, fromReads: true});
  assert.deepEqual([query.groupId, query.reviewedRead, query.effect], ['notion.content.read', false, 'write']);
  const github = shipped('github'), unlabel = place(github, 'DELETE /repos/{owner}/{repo}/issues/{issue_number}/labels/{name}', {fromReads: true});
  assert.deepEqual([unlabel.groupId, unlabel.rowEffect, unlabel.effect], ['github.issues.write', 'write', 'delete'], 'a DELETE in a write row deletes');
  // RPC: Slack canvases.getContent and the twin's canvases.read are reads only with fromReads; a POST in a read row that is not listed is a write.
  const slack = shipped('slack'), canvas = body => place(slack, 'POST /canvases.getContent', {body: {object: {canvas_id: {input: '/name'}}}, ...body});
  assert.deepEqual([canvas({fromReads: true}).groupId, canvas({fromReads: true}).reviewedRead, canvas({fromReads: true}).effect, canvas({}).effect], ['slack.files.read', true, 'read', 'write']);
  assert.equal(place(slack, 'GET /conversations.history').effect, 'read');
  const twin = fixture('fixture-rpc', null);
  assert.deepEqual(['POST /messages.history', 'POST /canvases.read', 'GET /messages.list', 'POST /messages.post'].map(request => place(twin, request, {fromReads: true}).effect), ['write', 'read', 'read', 'write'],
    'an RPC POST in a read row is a read only when listed in reviewedReads and built from reads');
  assert.equal(place(twin, 'POST /canvases.read').effect, 'write', 'without fromReads');
  assert.deepEqual(['POST /items/search', 'POST /items/export'].map(request => place(fixture(), request, {fromReads: true})).map(step => [step.reviewedRead, step.effect]), [[true, 'read'], [false, 'write']]);
  assert.equal(place(fixture(), 'POST /items/search').effect, 'write', 'a caller that forgets fromReads gets a write');
  // Calendar Find free time is reviewed by operation id: through the synthetic map it is calendar.freebusy.query, read with fromReads; with no
  // map it is unplaced (open point Minor 9).
  const free = place(shipped('google-calendar', SYNTHETIC['google-calendar']), 'POST /freebusy/query', {body: {object: {}}, fromReads: true});
  assert.deepEqual([free.member, free.groupId, free.reviewedRead, free.effect], ['calendar.freebusy.query', 'google-calendar.availability.read', true, 'read']);
  assert.equal(place(shipped('google-calendar', SYNTHETIC['google-calendar']), 'POST /freebusy/query', {body: {object: {}}}).effect, 'write');
  assert.equal(place(shipped('google-calendar'), 'POST /freebusy/query', {body: {object: {}}, fromReads: true}).unplaced, true);
  // The rule itself: a POST, listed and built from reads, in both styles. Drop either flag and it is a write; a listed PATCH is a write; a
  // routed placement is never weaker than the row it came from.
  const READ = {method: 'POST', rowEffect: 'read', reviewedRead: true, fromReads: true, routedFrom: null};
  for (const style of ['rest', 'rpc']) {
    assert.equal(stepEffect(READ, {style}), 'read', style);
    for (const flag of ['reviewedRead', 'fromReads']) for (const value of [false, undefined, 'true']) assert.equal(stepEffect({...READ, [flag]: value}, {style}), 'write', `${style} ${flag} ${value}`);
  }
  assert.equal(stepEffect({...READ, method: 'PATCH'}, {style: 'rest'}), 'write', 'a listed PATCH is a write');
  assert.equal(stepEffect({...READ, routedFrom: {groupId: 'a', member: 'b', rowEffect: 'write'}}, {style: 'rest'}), 'write', 'a routed placement is never a read');
  assert.equal(stepEffect({...READ, rowEffect: 'write'}, {style: 'rest'}), 'write', 'never weaker than its row');
  // Never the match's effect, whatever the placement says: a write-fed reviewed-read POST stays a write.
  const fed = place(notion, 'POST /v1/search', {...words, fromReads: false});
  assert.equal(stepEffect({...fed, effect: 'read'}, notion.config), 'write');
  assert.equal(stepEffect({method: 'POST', rowEffect: 'read', routedFrom: null}, {style: 'rpc'}), 'write');
  assert.equal(stepEffect({method: 'GET', rowEffect: 'write', routedFrom: null}, {style: 'rpc'}), 'write');
  assert.equal(stepEffect({method: 'GET', rowEffect: 'read', routedFrom: null}, {style: 'rpc'}), 'read');
  assert.equal(stepEffect({method: 'PATCH', rowEffect: 'delete', routedFrom: {groupId: 'a', member: 'b', rowEffect: 'write'}}, {style: 'rest'}), 'delete');
  assert.equal(stepEffect({method: 'GET', rowEffect: 'read', routedFrom: {groupId: 'a', member: 'b', rowEffect: 'write'}}, {style: 'rest'}), 'write', 'never weaker than the row it came from');
  // The action's effect is the strongest over its prepare and perform steps; verify steps never count; an unplaced step leaves it unknown.
  const read = place(github, 'GET /repos/{owner}/{repo}/issues/{issue_number}', {phase: 'prepare'}), check = place(github, 'GET /repos/{owner}/{repo}/issues/{issue_number}', {phase: 'verify'});
  assert.equal(actionEffect([read, unlabel, check]), 'delete');
  assert.equal(actionEffect([read, place(github, 'POST /repos/{owner}/{repo}/issues/{issue_number}/labels', {body: {object: {labels: {input: '/names'}}}}), check]), 'write');
  assert.equal(actionEffect([read, place(github, 'GET /repos/{owner}/{repo}/issues')]), 'read');
  assert.equal(actionEffect([read, search]), 'read', 'a reviewed read built from reads keeps a read action a read');
  assert.equal(actionEffect([{...unlabel, phase: 'verify'}, read]), 'read', 'only prepare and perform steps count');
  assert.equal(actionEffect([place(shipped('gmail'), 'GET /gmail/v1/users/{userId}/profile')]), null);
});

test('F10.10 check: a reviewed-read POST that a constant body route moves, even into another read row, is no reviewed read, so it stays a write built from reads or not (I5, T8)', () => {
  const rows = fixtureRows();
  rows.groups.find(group => group.id === 'fixture.items.read').bodyRoutes = [{member: 'POST /items/search', pointer: '/scope', equals: 'all', to: 'fixture.keys.read'}];
  const deps = {...fixture(), definition: validatePermissionGroups(rows)};
  const moved = place(deps, 'POST /items/search', {body: {object: {scope: {const: 'all'}}}, fromReads: true});
  assert.deepEqual([moved.groupId, moved.rowEffect, moved.routedFrom, moved.reviewedRead, moved.fromReads, moved.effect],
    ['fixture.keys.read', 'read', {groupId: 'fixture.items.read', member: 'POST /items/search', rowEffect: 'read'}, false, true, 'write']);
  const kept = place(deps, 'POST /items/search', {body: {object: {scope: {const: 'mine'}}}, fromReads: true});
  assert.deepEqual([kept.groupId, kept.routedFrom, kept.reviewedRead, kept.effect], ['fixture.items.read', null, true, 'read'], 'a constant that misses the route');
});

test('part e: resolves: true places only on a member of RESOLVING_WRITES (R2)', () => {
  assert.deepEqual(RESOLVING_WRITES, {slack: ['POST /conversations.open']});
  assert.ok(Object.isFrozen(RESOLVING_WRITES) && Object.isFrozen(RESOLVING_WRITES.slack));
  const open = place(shipped('slack'), 'POST /conversations.open', {body: {object: {users: {input: '/name'}}}, step: {resolves: true}});
  assert.deepEqual([open.groupId, open.effect], ['slack.conversations.mark', 'write']);
  const words = /resolves: true is allowed only on a reviewed resolving write \(RESOLVING_WRITES\), and .* is not one/;
  refused(shipped('slack'), 'POST /chat.postMessage', words, {body: {object: {text: {input: '/name'}}}, step: {resolves: true}});
  refused(fixture('fixture-rpc', null), 'POST /conversations.start', words, {step: {resolves: true}});
  refused(fixture(), 'POST /items', words, {body: {object: {}}, step: {resolves: true}});
  refused(shipped('slack'), 'POST /conversations.open', /resolves is true or absent/, {step: {resolves: false}});
});

// ---- part e: body routes -------------------------------------------------------------------------------------------------------------
test('part e: body routes: a constant hit moves the step to the target row, a hit into a locked row is refused, and a value that might hit is refused (spec line 738)', () => {
  const notion = shipped('notion'), restore = place(notion, 'PATCH /v1/pages/{page_id}', {body: {object: {in_trash: {const: false}}}});
  assert.deepEqual([restore.groupId, restore.rowEffect, restore.effect, restore.reviewedRead, restore.routedFrom],
    ['notion.content.trash', 'delete', 'delete', false, {groupId: 'notion.content.edit', member: 'PATCH /v1/pages/{page_id}', rowEffect: 'write'}], 'Restore lands in the trash row');
  const markdown = type => place(notion, 'PATCH /v1/pages/{page_id}/markdown', {body: {object: {type, insert_content: {object: {content: {input: '/name'}}}}}});
  assert.equal(markdown({const: 'insert_content'}).groupId, 'notion.content.edit');
  assert.equal(markdown({const: 'Replace_Content'}).groupId, 'notion.content.trash', 'strings fold A to Z, as the proxy folds them');
  assert.throws(() => markdown({input: '/kind'}), /perform\[0\]: the body's \/type could equal "replace_content", which routes this step from notion\.content\.edit to notion\.content\.trash, and nothing shows it never does/);
  // Into a locked row: Gmail's forward (the synthetic map stands in for the method facts) and GitHub's visibility.
  const gmail = shipped('gmail', SYNTHETIC.gmail), filter = action => ({body: {object: {criteria: {object: {from: {input: '/name'}}}, action}}});
  refused(gmail, 'POST /gmail/v1/users/{userId}/settings/filters/create', ROUTED_LOCKED,
    filter({object: {forward: {const: 'someone@example.com'}}}));
  assert.equal(place(gmail, 'POST /gmail/v1/users/{userId}/settings/filters/create', filter({object: {addLabelIds: ids({input: '/names'})}})).groupId, 'gmail.settings.write');
  const github = shipped('github');
  refused(github, 'PATCH /repos/{owner}/{repo}', ROUTED_LOCKED, {body: {object: {visibility: {const: 'public'}}}});
  refused(github, 'PATCH /repos/{owner}/{repo}', /the body's \/visibility could be present, which routes this step from github\.code\.write to github\.access\.grant/, {body: {object: {visibility: {input: '/kind'}}}});
  assert.equal(place(github, 'PATCH /repos/{owner}/{repo}', {body: {object: {description: {input: '/name'}}}}).groupId, 'github.code.write');
  refused(fixture(), 'PATCH /items/{item_id}', ROUTED_LOCKED, {body: {object: {share: {object: {to: {const: 'someone@example.com'}}}}}});
});

test('part e: body routes: a {when} at or above a routed pointer, or a run-time-typed result at or above one, is refused; a closed type that cannot hold the pointer passes', () => {
  const deps = fixture(), item = 'PATCH /items/{item_id}';
  refused(deps, item, /a \{when\} sits at or above \/in_trash, which fixture\.items\.edit routes to fixture\.items\.delete/, {body: {object: {in_trash: when({const: false})}}});
  refused(deps, item, /a \{when\} sits at or above \/share\/to, which fixture\.items\.edit routes to fixture\.access\.grant/, {body: {object: {share: when({object: {to: {const: 'x'}}})}}});
  // A run-time-typed result has no closed schema below it, so no route may sit at or under it (part d places it whole).
  refused(deps, item, /the body's \/in_trash sits at or under an outputFrom result, which has no closed schema: no body route may read there/, {body: propertyValues});
  refused(deps, item, /the body's \/share\/to sits at or under an outputMap result/, {body: {object: {share: stringValues}}});
  assert.equal(place(deps, 'POST /items', {body: {object: {properties: propertyValues}}}).groupId, 'fixture.items.edit', 'a member with no routes takes it whole');
  // Above the pointer, a transform result (or a pick of one) whose closed output schema has no field on its path never hits; an input or
  // step data there is refused, whatever its type (F10.8 map part m).
  const truncated = {transform: 'text.truncate@1', args: {text: {input: '/name'}, max: {const: 100}}};
  assert.equal(place(deps, item, {body: {object: {share: truncated}}}).groupId, 'fixture.items.edit');
  assert.equal(place(deps, item, {body: {object: {share: {pick: truncated, pointer: '/text'}}}}).groupId, 'fixture.items.edit');
  assert.equal(place(deps, item, {body: {object: {share: {pick: {transform: 'ids.slackLink@1', args: {link: {input: '/link'}}}, pointer: '/parent'}}}}).groupId, 'fixture.items.edit', 'a string has no field');
  const reply = {transform: 'rfc5322.replyHeaders@1', args: {parent: {step: 'item', pointer: ''}, owner: {input: '/owner'}, replyAll: {const: false}}};
  refused(deps, item, /the body's \/share\/to could be present/, {body: {object: {share: reply}}}, 'a closed output schema with a to field may hold it');
  for (const share of [{step: 'item', pointer: '/share'}, {input: '/owner'}, {concat: [{input: '/name'}], max: 100}]) refused(deps, item, /the body's \/share\/to could be present/, {body: {object: {share}}});
  refused(deps, item, /the body's \/in_trash could be present/, {body: {object: {in_trash: {input: '/kind'}}}});
});

test('part e: projections and excludes (R1): only a value whose surviving exclusions hold the route\'s value may sit at a contains or equals pointer', () => {
  const deps = fixture(), item = 'PATCH /items/{item_id}', labels = node => ({body: {object: {labels: node}}});
  assert.equal(place(deps, item, labels(ids({input: '/names'}))).groupId, 'fixture.items.edit', 'labelIds picked at /ids keeps its exclusion of TRASH');
  for (const node of [
    {array: [{const: 'INBOX'}, {pick: labelIds({input: '/names'}), pointer: '/ids/0'}]},
    {each: ids({input: '/names'}), as: 'id', max: 100, do: {var: 'id'}},
    {array: [when({const: 'INBOX'})]},
  ]) assert.equal(place(deps, item, labels(node)).groupId, 'fixture.items.edit', JSON.stringify(node));
  const contains = /the body's \/labels could contain "TRASH", which routes this step from fixture\.items\.edit to fixture\.items\.delete, and nothing shows it never does/;
  for (const node of [
    {pick: labelIds({input: '/names'}), pointer: '/labels'},
    {pick: {transform: 'collections.diff@1', args: {before: {input: '/names'}, after: {array: []}}}, pointer: '/add'},
    {input: '/names'},
    {array: [{concat: [{pick: labelIds({input: '/names'}), pointer: '/ids/0'}], max: 100}]},
    {pick: {transform: 'collections.diff@1', args: {before: ids({input: '/names'}), after: {array: []}}}, pointer: '/add'},
    {array: [when({const: 'TRASH'})]},
    {each: {input: '/names'}, as: 'id', max: 10, do: {const: 'TRASH'}},
  ]) refused(deps, item, contains, labels(node));
  // An exclusion holds a route's value only as the route folds it: one that compares exactly says nothing about "trash" in lower case.
  const exact = new Map(TRANSFORMS);
  exact.set('collections.labelIds@1', {...TRANSFORMS.get('collections.labelIds@1'), excludes: [{pointer: '/ids', items: true, values: ['SENT', 'DRAFT', 'TRASH', 'SPAM'], fold: 'none'}]});
  refused(deps, item, contains, {...labels(ids({input: '/names'})), transforms: exact});
  const trash = place(deps, item, labels({array: [{const: 'inbox'}, {const: 'trash'}]}));
  assert.deepEqual([trash.groupId, trash.effect, trash.routedFrom.groupId], ['fixture.items.delete', 'delete', 'fixture.items.edit'], 'a constant hit, folded');
  // Gmail's Organize email: both lists picked at /ids (the synthetic map stands in for the method facts).
  const gmail = shipped('gmail', SYNTHETIC.gmail), modify = 'POST /gmail/v1/users/{userId}/messages/modify';
  const organize = place(gmail, modify, {body: {object: {addLabelIds: ids({input: '/names'}), removeLabelIds: ids({array: []})}}});
  assert.deepEqual([organize.member, organize.groupId, organize.effect], ['gmail.users.messages.modify', 'gmail.messages.mark', 'write']);
  refused(gmail, modify, /the body's \/addLabelIds could contain "TRASH"/, {body: {object: {addLabelIds: {input: '/names'}}}});
  refused(gmail, modify, /the body's \/removeLabelIds could contain "TRASH"/, {body: {object: {removeLabelIds: {pick: labelIds({input: '/names'}), pointer: '/labels'}}}});
  // Slack has no body routes (RPC): ids.slackLink picked into channel and ts places as it is.
  const link = pointer => ({pick: {transform: 'ids.slackLink@1', args: {link: {input: '/link'}}}, pointer});
  assert.equal(place(shipped('slack'), 'POST /chat.update', {body: {object: {channel: link('/channel'), ts: link('/ts'), text: {input: '/name'}}}}).groupId, 'slack.messages.send');
});

// ---- part e: optional steps and fallbacks (R7) ------------------------------------------------------------------------------------
test('part e: an optional step is a read on a member that needs a scope the sign-in holds beyond its required ones; its fallback is a read that needs only the required scopes (R7)', () => {
  const slack = {...shipped('slack'), access: accessOf(definitionFor('slack'), 'slack')};
  assert.ok(slack.access.required.includes('users:read') && slack.access.optional.includes('users:read.email') && !slack.access.required.includes('users:read.email'));
  assert.ok(Object.isFrozen(slack.access));
  assert.deepEqual(accessOf(definitionFor('github'), 'github'), {required: ['public_repo', 'read:user', 'repo', 'repo:invite', 'repo:status', 'repo_deployment', 'security_events'],
    optional: ['gist', 'read:org', 'workflow']}, 'with what a granted parent grants: repo holds public_repo');
  assert.equal(place(slack, 'GET /users.lookupByEmail', {phase: 'prepare', step: {optional: true}}).groupId, 'slack.workspace.read');
  assert.equal(place(slack, 'GET /users.list', {phase: 'prepare', step: {fallbackFor: 'lookup'}}).groupId, 'slack.channels.read');
  refused(slack, 'GET /users.list', /an optional step reads a member that needs a scope the sign-in holds beyond its required ones, and GET \/users\.list needs none/, {step: {optional: true}});
  refused(slack, 'POST /chat.postMessage', /a write is never optional \(R7\)/, {body: {object: {text: {input: '/name'}}}, step: {optional: true}});
  refused(slack, 'POST /chat.postMessage', /a fallback is a read \(R7\)/, {body: {object: {text: {input: '/name'}}}, step: {fallbackFor: 'lookup'}});
  refused(slack, 'GET /users.lookupByEmail', /a fallback runs when an optional scope is missing, so it needs only the sign-in's required scopes, and GET \/users\.lookupByEmail needs more/, {step: {fallbackFor: 'lookup'}});
  refused(slack, 'GET /users.lookupByEmail', /a fallback is never optional itself/, {step: {optional: true, fallbackFor: 'lookup'}});
  refused(slack, 'GET /users.lookupByEmail', /optional is true or absent/, {step: {optional: false}});
  refused(slack, 'GET /users.list', /fallbackFor names the optional step it stands in for/, {step: {fallbackFor: ''}});
  refused(shipped('slack'), 'GET /users.lookupByEmail', /an optional step or a fallback needs the app's reviewed sign-in, which says which scopes are optional/, {step: {optional: true}});
  refused({...fixture(), access: {required: ['fixture:all'], optional: ['fixture:more']}}, 'GET /labels', /GET \/labels says nothing about the scopes it needs/, {step: {optional: true}});
  // Calendar's time zone: settings.get needs calendar.settings.readonly, an optional scope; calendarList.get works on the required ones. The
  // synthetic map carries Discovery's scope facts, as the store's map does.
  const calendar = {...shipped('google-calendar', withScopes('google-calendar')), access: accessOf(definitionFor('google'), 'google-calendar')};
  assert.equal(place(calendar, 'GET /settings/get', {phase: 'prepare', step: {optional: true}}).member, 'calendar.settings.get');
  assert.equal(place(calendar, 'GET /calendarList/get', {phase: 'prepare', step: {fallbackFor: 'zone'}}).member, 'calendar.calendarList.get');
  refused(calendar, 'GET /calendarList/get', /calendar\.calendarList\.get needs none/, {step: {optional: true}});
  assert.throws(() => accessOf(definitionFor('google'), 'nothing'), /The google sign-in has no app nothing/);
});

// ---- part e: the fixture action file ------------------------------------------------------------------------------------------------
test('part e: every step of the fixture action file places on a reviewed member of an unlocked row; each action\'s last perform step lands in its declared row with its declared effect', () => {
  const deps = fixture();
  for (const action of fixtureActions().actions) {
    const steps = new Map(), placements = [], resolvedInputs = (action.resolvedInputs ?? []).map(entry => entry.input);
    const placeAll = (list, phase, source) => {
      for (const step of list) {
        const body = step.body === undefined ? undefined : checkExpression(step.body, {where: `${action.key}.${step.id}.body`, slot: 'body', transforms: TRANSFORMS, inputSchema: action.inputSchema, resolvedInputs, steps});
        placements.push(placeStep(step, {...deps, phase, ...(body ? {body} : {}), where: `${action.key}.${step.id}`}));
        steps.set(step.id, {source, skippable: step.when !== undefined});
      }
    };
    for (const resolved of action.resolvedInputs ?? []) placeAll(resolved.schema.steps, 'schema', 'schema');
    placeAll(action.prepare ?? [], 'prepare', 'prepare');
    placeAll(action.perform, 'perform', action.effect === 'read' ? 'perform-read' : 'perform-write');
    placeAll(action.verify?.requests ?? [], 'verify', 'verify');
    for (const placement of placements) {
      assert.equal(placement.unplaced, false, `${action.key}.${placement.stepId}`);
      assert.notEqual(deps.definition.groups.find(group => group.id === placement.groupId).locked, 'fabric', `${action.key}.${placement.stepId}`);
    }
    assert.equal(placements.filter(placement => placement.phase === 'perform').at(-1).groupId, action.row, `${action.key}: its last perform step lands in its row`);
    assert.equal(actionEffect(placements), action.effect, `${action.key}: its computed effect`);
  }
});

// ---- part e check: rules the first tests left unpinned ----------------------------------------------------------------------------
// The fixture app's edit row with more routes on PATCH /items/{item_id}: pointers through list items and through a transform's list, and a
// member with a custom verb. No shipped route passes through a list, so these rows stand in for one that will.
const LISTS = (() => {
  const rows = fixtureRows(), routes = [
    {member: 'PATCH /items/{item_id}', pointer: '/batch/0/in_trash', present: true, to: 'fixture.items.delete'},
    {member: 'PATCH /items/{item_id}', pointer: '/batch/2/share/to', present: true, to: 'fixture.access.grant'},
    {member: 'PATCH /items/{item_id}', pointer: '/marks/0', equals: 'TRASH', to: 'fixture.items.delete'},
    {member: 'PATCH /items/{item_id}', pointer: '/reply/to/0/address', present: true, to: 'fixture.access.grant'},
  ];
  const groups = rows.groups.map(group => group.id === 'fixture.items.edit' ? {...group, requests: [...group.requests, 'POST /items/{item_id}:archive'], bodyRoutes: [...group.bodyRoutes, ...routes]} : group);
  return {definition: validatePermissionGroups({...rows, groups}), config: CONFIGS.get('fixture'), map: fixtureMap()};
})();

test('part e check: a route pointer through list items: a {when} among them moves the positions, an {each} element might hit, and a transform\'s list is read item by item', () => {
  const item = 'PATCH /items/{item_id}', title = {object: {title: {input: '/name'}}}, share = {object: {share: {object: {to: {const: 'someone@example.com'}}}}};
  assert.equal(place(LISTS, item, {body: {object: {batch: {array: [title, title, title]}, marks: {array: [{const: 'INBOX'}]}}}}).groupId, 'fixture.items.edit');
  assert.equal(place(LISTS, item, {body: {object: {batch: {array: [{object: {in_trash: {const: false}}}]}}}}).groupId, 'fixture.items.delete', 'a constant hit through a list index');
  assert.equal(place(LISTS, item, {body: {object: {marks: {array: [{const: 'trash'}]}}}}).groupId, 'fixture.items.delete');
  refused(LISTS, item, /the body's \/batch\/0\/in_trash could be present, which routes this step from fixture\.items\.edit to fixture\.items\.delete/, {body: {object: {batch: {array: [{input: '/owner'}]}}}});
  // Left out, the {when} at index 1 would move the share object from index 3 to index 2, which routes to the locked row.
  refused(LISTS, item, /a \{when\} sits at or above \/batch\/0\/in_trash, which fixture\.items\.edit routes to fixture\.items\.delete: a list item left out moves the positions after it/,
    {body: {object: {batch: {array: [title, when({object: {}}), title, share]}}}});
  // An {each} element is there only when the list is long enough, so a possible hit at one is refused; past max nothing is there.
  for (const value of [{const: false}, {array: []}]) {
    refused(LISTS, item, /the body's \/batch\/0\/in_trash could be present/, {body: {object: {batch: {each: {input: '/names'}, as: 'n', max: 10, do: {object: {in_trash: value}}}}}});
  }
  assert.equal(place(LISTS, item, {body: {object: {batch: {each: {input: '/names'}, as: 'n', max: 10, do: {object: {title: {var: 'n'}}}}}}}).groupId, 'fixture.items.edit');
  assert.equal(place(LISTS, item, {body: {object: {batch: {each: {input: '/names'}, as: 'n', max: 2, do: {object: {title: {var: 'n'}, share: {object: {to: {const: 'x'}}}}}}}}}).groupId,
    'fixture.items.edit', 'an {each} of at most 2 has no element at index 2');
  assert.equal(place(LISTS, item, {body: {object: {marks: {each: ids({input: '/names'}), as: 'id', max: 100, do: {var: 'id'}}}}}).groupId, 'fixture.items.edit');
  refused(LISTS, item, /the body's \/marks\/0 could equal "TRASH"/, {body: {object: {marks: {each: {input: '/names'}, as: 'n', max: 10, do: {var: 'n'}}}}});
  // A transform's closed output schema is read through its lists too: rfc5322.replyHeaders@1's /to is a list of objects with an address.
  const reply = {transform: 'rfc5322.replyHeaders@1', args: {parent: {step: 'item', pointer: ''}, owner: {input: '/owner'}, replyAll: {const: false}}};
  refused(LISTS, item, /the body's \/reply\/to\/0\/address could be present/, {body: {object: {reply}}});
  assert.equal(place(LISTS, item, {body: {object: {reply: {pick: reply, pointer: '/subject'}}}}).groupId, 'fixture.items.edit');
});

test('part e check: an exclusion holds a route\'s value only on exactly its field, only as listed and folded, and never for a present route', () => {
  const deps = fixture(), item = 'PATCH /items/{item_id}';
  // ascii folding covers the listed values only: an exclusion of SENT and DRAFT says nothing about TRASH.
  const partial = new Map(TRANSFORMS);
  partial.set('collections.labelIds@1', {...TRANSFORMS.get('collections.labelIds@1'), excludes: [{pointer: '/ids', items: true, values: ['SENT', 'DRAFT'], fold: 'ascii'}]});
  refused(deps, item, /the body's \/labels could contain "TRASH"/, {body: {object: {labels: ids({input: '/names'})}}, transforms: partial});
  // The whole labelIds result at the body's root: its /ids exclusion says nothing about its /labels field, which /labels reads.
  refused(deps, item, /the body's \/labels could contain "TRASH"/, {body: labelIds({input: '/names'})});
  // A present route asks whether anything is there; an exclusion of some values says nothing about that.
  refused(deps, item, /the body's \/in_trash could be present/, {body: {object: {in_trash: ids({input: '/names'})}}});
});

test('part e check: an optional step\'s member needs a scope the sign-in asks for; a custom verb is written exactly; an action with an unplaced step has no effect yet', () => {
  const slack = {...shipped('slack'), access: accessOf(definitionFor('slack'), 'slack')};
  refused({...slack, access: {required: slack.access.required, optional: []}}, 'GET /users.lookupByEmail',
    /an optional step reads a member the sign-in can hold once its optional scopes are granted, and GET \/users\.lookupByEmail needs a scope the sign-in never asks for \(R7\)/, {step: {optional: true}});
  assert.equal(place(LISTS, 'POST /items/{item_id}:archive').member, 'POST /items/{item_id}:archive');
  assert.equal(place(LISTS, 'POST /items/abc:archive').member, 'POST /items/{item_id}:archive');
  refused(LISTS, 'POST /items/{item_id}:Archive', /the custom verb :archive is written exactly as the reviewed template POST \/items\/\{item_id\}:archive writes it/);
  const github = shipped('github'), unlabel = place(github, 'DELETE /repos/{owner}/{repo}/issues/{issue_number}/labels/{name}');
  const profile = place(shipped('gmail'), 'GET /gmail/v1/users/{userId}/profile', {phase: 'prepare'});
  for (const placements of [[profile, unlabel], [unlabel, profile]]) assert.equal(actionEffect(placements), null, 'unknown while any counted step is unplaced, whatever the others');
});

test('part e check: placeRequest() reads only the canonical JSON text of a body, so a body it cannot read is never sent unrouted', () => {
  const notion = shipped('notion'), edit = place(notion, 'PATCH /v1/pages/{page_id}', {body: {object: {icon: {const: null}}}}), segments = ['v1', 'pages', 'p1'];
  for (const body of [{in_trash: true}, '{"in_trash": true', ['in_trash'], 7]) {
    assert.throws(() => placeRequest(edit, {method: 'PATCH', segments, body}, notion), /a request body is the JSON text the proxy normalizer gives, so its body routes can be read: nothing is sent/, JSON.stringify(body));
  }
  assert.equal(placeRequest(edit, {method: 'PATCH', segments, body: null}, notion).groupId, 'notion.content.edit');
  assert.equal(placeRequest(edit, {method: 'PATCH', segments}, notion).groupId, 'notion.content.edit', 'no body at all');
});

// ---- part f: the resolving write (R2), through the file validator ------------------------------------------------------------------
const OK = {status: [200], require: [{equals: {pointer: '/ok', value: {const: true}}}]};
/** Slack Send a direct message (spec line 1480): find the person, open the direct message (a resolving write), post to it. */
function directMessage({users = {step: 'person', pointer: '/user/id'}, resolves = true, prepare = true, change = action => action} = {}) {
  return {schemaVersion: 1, appId: 'slack', specVersion: 'fabric/0.2', reviewStatus: 'candidate', pinnedParameters: {}, actions: [change({
    id: `slack.action.send-dm.v1.${'0'.repeat(24)}`, key: 'send-dm', version: 1, name: 'Send a direct message', description: 'Sends one direct message to a person found by email.',
    effect: 'write', row: 'slack.messages.send', hints: {readOnly: false, destructive: false, idempotent: false, openWorld: true},
    inputSchema: {type: 'object', properties: {...(prepare ? {email: {type: 'string', minLength: 3, maxLength: 254}} : {}), text: {type: 'string', minLength: 1, maxLength: 4000}},
      required: [...(prepare ? ['email'] : []), 'text'], additionalProperties: false},
    outputSchema: {type: 'object', properties: {channel: {type: 'string', maxLength: 64}, ts: {type: 'string', maxLength: 64}}, required: ['channel', 'ts'], additionalProperties: false},
    guards: [],
    prepare: prepare ? [{id: 'person', method: 'GET', path: '/users.lookupByEmail', query: {email: {input: '/email'}}, expect: OK}] : [],
    perform: [
      {id: 'open', method: 'POST', path: '/conversations.open', body: {object: {users}}, ...(resolves ? {resolves: true} : {}),
        expect: {status: [200], require: [{equals: {pointer: '/ok', value: {const: true}}}, {present: {pointer: '/channel/id'}}]}},
      {id: 'post', method: 'POST', path: '/chat.postMessage', body: {object: {channel: {step: 'open', pointer: '/channel/id'},
        text: {pick: {transform: 'text.slackEscape@1', args: {text: {input: '/text'}}}, pointer: '/text'}}}, expect: OK}],
    verify: {requests: [{id: 'link', method: 'GET', path: '/chat.getPermalink', query: {channel: {step: 'post', pointer: '/channel'}, message_ts: {step: 'post', pointer: '/ts'}}, expect: OK}],
      identity: [{kind: 'readback', step: 'link', pointer: '/channel', equals: {step: 'post', pointer: '/channel'}}], assert: []},
    output: {channel: {step: 'post', pointer: '/channel'}, ts: {step: 'post', pointer: '/ts'}},
    preview: [{label: 'To', expr: prepare ? {step: 'person', pointer: '/user/real_name'} : {const: 'You'}}, {label: 'Message', expr: {input: '/text'}}], definitive: [400]})]};
}

test('part f: the resolving write (R2): Send a direct message reads conversations.open\'s answer, is two-phase, and S5 opens the channel with the bare user id', () => {
  const deps = {groups: PERMISSION_GROUPS, configs: PROXY_CONFIGS, maps: new Map(), transforms: TRANSFORMS, choices: new Map(), identities: new Map([['slack', definitionFor('slack')]])};
  // Part g: the accepted files carry their computed ids (withIds()); a refusal comes before any id.
  const [entry] = validateActionFile(withIds(directMessage(), deps), deps).actions;
  assert.deepEqual([entry.effect, entry.row, entry.twoPhase, entry.placements.map(placement => [placement.stepId, placement.groupId])], ['write', 'slack.messages.send', true,
    [['person', 'slack.workspace.read'], ['open', 'slack.conversations.mark'], ['post', 'slack.messages.send'], ['link', 'slack.messages.read']]]);
  // Without resolves the open is an ordinary write, and a later perform step never reads a write's answer (T5).
  assert.throws(() => validateActionFile(directMessage({resolves: false}), deps), /perform\[1\] \(post\): body reads a write step's answer, which a perform step's bytes never read/);
  // At most one resolving step; it carries no forEach or page, and its expect requires the resolved value.
  assert.throws(() => validateActionFile(directMessage({change: action => ({...action, perform: [action.perform[0], {...action.perform[0], id: 'again'}, action.perform[1]]})}), deps), /an action holds at most one resolving step \(R2\)/);
  assert.throws(() => validateActionFile(directMessage({change: action => ({...action, perform: [{...action.perform[0], expect: {status: [200], require: []}}, action.perform[1]]})}), deps),
    /perform\[0\] \(open\): a resolving step's expect requires the resolved value, so its answer is checked before a later step reads it \(R2\)/);
  assert.throws(() => validateActionFile(directMessage({change: action => ({...action, perform: [{...action.perform[0], forEach: {over: {const: ['U1']}, max: 1}}, action.perform[1]]})}), deps),
    /perform\[0\] \(open\): a resolving step carries no forEach or page \(R2\)/);
  assert.throws(() => validateActionFile(directMessage({change: action => ({...action, prepare: [{...action.prepare[0], resolves: true}]})}), deps), /prepare\[0\] \(person\): resolves marks only a perform step \(R2\)/);
  // S5: a direct message to yourself opens the channel with {account: 'userId'}, the bare U... id, never the T...:U... account id.
  const [self] = validateActionFile(withIds(directMessage({users: {account: 'userId'}, prepare: false}), deps), deps).actions;
  assert.equal(self.twoPhase, true);
  assert.deepEqual(definitionFor('slack').identity.attributes.userId, '/user_id');
  assert.throws(() => validateActionFile(directMessage({users: {account: 'userId'}, prepare: false}), {...deps, identities: new Map([['slack', definitionFor('github')]])}),
    /\{account: 'userId'\} needs the app's reviewed identity to yield userId/);
});

// Part l: the two accepted Send a direct message files, the one shape here no other suite writes (a resolving step, R2), pass the action
// schema, and a resolves that is not true fails it.
test('part l: the accepted Send a direct message files pass schemas/action.schema.json under ajv', () => {
  const check = actionSchema(), deps = {groups: PERMISSION_GROUPS, configs: PROXY_CONFIGS, maps: new Map(), transforms: TRANSFORMS, choices: new Map(), identities: new Map([['slack', definitionFor('slack')]])};
  for (const file of [directMessage(), directMessage({users: {account: 'userId'}, prepare: false})]) {
    const written = withIds(file, deps);
    assert.doesNotThrow(() => validateActionFile(written, deps));
    assert.ok(check(written), JSON.stringify(check.errors?.slice(0, 3)));
  }
  assert.equal(check(directMessage({change: action => ({...action, perform: [{...action.perform[0], resolves: 'yes'}, action.perform[1]]})})), false);
});

// F10.11 part a: the former todo, on Google's own method paths (test/fixtures/access/google-method-paths.json, recorded from the public
// Discovery documents) through the map googleMap() builds from them and the scope facts, as DiscoveryEngine would store it.
test('F10.11 part a: on Google\'s own paths every first-action step of spec section 5 places, the watch and ACL insert are locked, ACL delete is a delete in a write row, and the time zone places', () => {
  const gmail = shipped('gmail', googleMap('gmail')), calendar = shipped('google-calendar', googleMap('google-calendar'));
  const G = '/gmail/v1/users/{userId}', E = '/calendars/{calendarId}/events';
  // [app deps, step, member, row, effect], one line per provider call of the 13 Gmail and 13 Calendar first actions (spec sections 5.1 and 5.2).
  for (const [deps, request, member, groupId, effect] of [
    [gmail, `GET ${G}/messages`, 'gmail.users.messages.list', 'gmail.messages.search', 'read'],
    [gmail, `GET ${G}/messages/{id}`, 'gmail.users.messages.get', 'gmail.messages.read', 'read'],
    [gmail, `GET ${G}/threads/{id}`, 'gmail.users.threads.get', 'gmail.messages.read', 'read'],
    [gmail, `GET ${G}/profile`, 'gmail.users.getProfile', 'gmail.messages.read', 'read'],
    [gmail, `POST ${G}/messages/send`, 'gmail.users.messages.send', 'gmail.messages.send', 'write'],
    [gmail, `POST ${G}/drafts`, 'gmail.users.drafts.create', 'gmail.drafts.write', 'write'],
    [gmail, `GET ${G}/drafts/{id}`, 'gmail.users.drafts.get', 'gmail.drafts.read', 'read'],
    [gmail, `PUT ${G}/drafts/{id}`, 'gmail.users.drafts.update', 'gmail.drafts.write', 'write'],
    [gmail, `POST ${G}/drafts/send`, 'gmail.users.drafts.send', 'gmail.messages.send', 'write'],
    [gmail, `GET ${G}/labels`, 'gmail.users.labels.list', 'gmail.labels.read', 'read'],
    [gmail, `POST ${G}/messages/{id}/modify`, 'gmail.users.messages.modify', 'gmail.messages.mark', 'write'],
    [gmail, `POST ${G}/threads/{id}/modify`, 'gmail.users.threads.modify', 'gmail.messages.mark', 'write'],
    [gmail, `POST ${G}/messages/batchModify`, 'gmail.users.messages.batchModify', 'gmail.messages.mark', 'write'],
    [gmail, `POST ${G}/labels`, 'gmail.users.labels.create', 'gmail.labels.manage', 'write'],
    [gmail, `POST ${G}/messages/{id}/trash`, 'gmail.users.messages.trash', 'gmail.messages.trash', 'delete'],
    [gmail, `POST ${G}/messages/{id}/untrash`, 'gmail.users.messages.untrash', 'gmail.messages.trash', 'delete'],
    [gmail, `POST ${G}/threads/{id}/trash`, 'gmail.users.threads.trash', 'gmail.messages.trash', 'delete'],
    [gmail, `POST ${G}/threads/{id}/untrash`, 'gmail.users.threads.untrash', 'gmail.messages.trash', 'delete'],
    [gmail, `GET ${G}/settings/vacation`, 'gmail.users.settings.getVacation', 'gmail.labels.read', 'read'],
    [gmail, `PUT ${G}/settings/vacation`, 'gmail.users.settings.updateVacation', 'gmail.settings.write', 'write'],
    [gmail, `POST ${G}/settings/filters`, 'gmail.users.settings.filters.create', 'gmail.settings.write', 'write'],
    [calendar, `GET ${E}`, 'calendar.events.list', 'google-calendar.events.read', 'read'],
    [calendar, `GET ${E}/{eventId}`, 'calendar.events.get', 'google-calendar.events.read', 'read'],
    [calendar, 'GET /users/me/calendarList', 'calendar.calendarList.list', 'google-calendar.calendars.read', 'read'],
    [calendar, `POST ${E}`, 'calendar.events.insert', 'google-calendar.events.write', 'write'],
    [calendar, `POST ${E}/quickAdd`, 'calendar.events.quickAdd', 'google-calendar.events.write', 'write'],
    [calendar, `PATCH ${E}/{eventId}`, 'calendar.events.patch', 'google-calendar.events.write', 'write'],
    [calendar, `DELETE ${E}/{eventId}`, 'calendar.events.delete', 'google-calendar.events.delete', 'delete'],
    [calendar, `POST ${E}/{eventId}/move`, 'calendar.events.move', 'google-calendar.events.write', 'write'],
    [calendar, 'POST /calendars', 'calendar.calendars.insert', 'google-calendar.calendars.write', 'write'],
    [calendar, 'DELETE /calendars/{calendarId}/acl/{ruleId}', 'calendar.acl.delete', 'google-calendar.sharing.write', 'delete'],
  ]) {
    const placed = place(deps, request);
    assert.deepEqual([placed.unplaced, placed.member, placed.groupId, placed.effect, placed.template], [false, member, groupId, effect, request], request);
  }
  // Find free time is Google's own POST /freeBusy, a reviewed read: a read when what it sends is built from reads (F10.10), else a write.
  const freeBusy = place(calendar, 'POST /freeBusy', {fromReads: true});
  assert.deepEqual([freeBusy.member, freeBusy.groupId, freeBusy.reviewedRead, freeBusy.effect], ['calendar.freebusy.query', 'google-calendar.availability.read', true, 'read']);
  assert.equal(place(calendar, 'POST /freeBusy').effect, 'write');
  // Gmail users.watch and Calendar acl.insert land in their locked rows on Google's own paths, so no action step runs there (T4).
  refused(gmail, `POST ${G}/watch`, LOCKED);
  refused(calendar, 'POST /calendars/{calendarId}/acl', LOCKED);
  refused(calendar, `POST ${E}/watch`, LOCKED);
  // Calendar acl.delete is a delete in a write row: the step's effect is its method's, the row's effect stays write.
  const unshare = place(calendar, 'DELETE /calendars/{calendarId}/acl/{ruleId}');
  assert.deepEqual([unshare.rowEffect, unshare.effect], ['write', 'delete']);
  // The time zone: settings.get needs calendar.settings.readonly, an optional scope; calendarList.get, its fallback, works on the required ones.
  const zone = {...calendar, access: accessOf(definitionFor('google'), 'google-calendar')};
  const optional = place(zone, 'GET /users/me/settings/{setting}', {phase: 'prepare', step: {optional: true}});
  assert.deepEqual([optional.member, optional.groupId], ['calendar.settings.get', 'google-calendar.settings.read']);
  const fallback = place(zone, 'GET /users/me/calendarList/{calendarId}', {phase: 'prepare', step: {fallbackFor: 'zone'}});
  assert.deepEqual([fallback.member, fallback.groupId], ['calendar.calendarList.get', 'google-calendar.calendars.read']);
  refused(zone, 'GET /users/me/calendarList/{calendarId}', /calendar\.calendarList\.get needs none/, {step: {optional: true}});
  // The synthetic paths F10.7's map stood in with are not Google's: on the recorded map they land nowhere a row reviews.
  assert.throws(() => place(calendar, 'GET /settings/get'), /an action step runs only on a reviewed member of a reviewed row|a documented route no row reviews|lands in Other/);
});

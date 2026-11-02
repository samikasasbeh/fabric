import test from 'node:test';
import assert from 'node:assert/strict';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {TRANSFORMS, runTransform} from '../lib/transforms/index.mjs';
import {TransformError} from '../lib/transforms/_shared/error.v1.mjs';
import {foldAscii} from '../lib/transforms/_shared/ascii.v1.mjs';
import {vectorTests} from './fixtures/transform-vectors.mjs';

// F10.8 (docs/F10.8-BUILD-MAP.md part j): the six collections transforms and the vectors of test/fixtures/transforms/collections.json.
// Every provider list is capped at 1,000 items and every list of names or addresses at 100; each transform makes one pass.
const FIND = 'collections.findBy@1', MERGE = 'collections.mergeEmails@1', LABELS = 'collections.labelIds@1', DIFF = 'collections.diff@1', ONE_OF = 'collections.oneOf@1', MISSING = 'collections.missing@1';
const IDS = [FIND, MERGE, LABELS, DIFF, ONE_OF, MISSING];
const refused = code => error => {
  assert.ok(error instanceof TransformError, `expected a TransformError, got ${error}`);
  assert.equal(error.code, code);
  return true;
};
const run = (id, args) => runTransform(id, args);
const sorted = list => [...list].sort();
const LIST = {labels: [{id: 'INBOX', name: 'INBOX', type: 'system'}, {id: 'SENT', name: 'SENT', type: 'system'}, {id: 'DRAFT', name: 'DRAFT', type: 'system'},
  {id: 'TRASH', name: 'TRASH', type: 'system'}, {id: 'SPAM', name: 'SPAM', type: 'system'}, {id: 'Label_1', name: 'Receipts', type: 'user'}, {id: 'Label_2', name: 'Work', type: 'user'}]};
const EVENT = {id: 'e1', organizer: {email: 'org@example.com', displayName: 'Org'}, attendees: [
  {email: 'org@example.com', organizer: true, responseStatus: 'accepted', displayName: 'Org'},
  {email: 'Guest@Example.com', responseStatus: 'tentative', optional: true, comment: 'maybe', additionalGuests: 1},
  {email: 'owner@example.com', self: true, responseStatus: 'needsAction'},
  {email: 'room@resource.calendar.google.com', resource: true, responseStatus: 'accepted', id: 'r1'}]};
const merge = args => run(MERGE, {event: EVENT, add: [], remove: [], owner: 'owner@example.com', ...args});

vectorTests('collections');

test('part j registers six transforms with their step data, pointer arguments, kinds and codes; none reads a runtime fact', () => {
  for (const id of IDS) assert.ok(TRANSFORMS.has(id), id);
  const entry = id => TRANSFORMS.get(id);
  const refuses = {[FIND]: ['match_many', 'match_none', 'too_many_items'], [MERGE]: ['attendee_protected', 'too_many_items'], [LABELS]: ['label_system', 'label_unknown', 'match_many', 'too_many_items'],
    [DIFF]: [], [ONE_OF]: ['not_one_of'], [MISSING]: ['too_many_items']};
  const stepData = {[FIND]: ['list'], [MERGE]: ['event'], [LABELS]: ['list'], [DIFF]: [], [ONE_OF]: [], [MISSING]: ['list']};
  for (const id of IDS) {
    assert.deepEqual(sorted(entry(id).refuses), refuses[id], id);
    assert.deepEqual(Object.keys(entry(id).stepData), stepData[id], id);
    assert.deepEqual(entry(id).runtimeFacts, [], `${id} folds ASCII only`);
    assert.equal(entry(id).kind, id === ONE_OF ? 'guard' : 'map', id);
  }
  // Open point Minor 14: the attendees mergeEmails keeps whole come from the prepared event, a step-data argument, never a closed one, so
  // an action cannot fill them from an input. F10.9 checks that a step-data argument is fed from step data only.
  assert.ok(!Object.hasOwn(entry(MERGE).input.properties, 'event') && !Object.hasOwn(entry(MERGE).input.properties, 'current'));
});

test('findBy: one pass over a provider list at declared pointers, never guessing, at most 1,000 items and 100 matches', () => {
  const people = Array.from({length: 1000}, (_, index) => ({id: `U${index}`, profile: {email: `u${index}@example.com`, name: `User ${index}`}}));
  const find = args => run(FIND, {list: {members: people}, items: '/members', field: '/profile/email', id: '/id', label: '/profile/name', fold: 'ascii', require: 'one', ...args});
  assert.deepEqual(find({value: 'U999@EXAMPLE.com'}), {matches: [{id: 'U999', label: 'User 999'}]});
  assert.throws(() => run(FIND, {list: {members: [...people, people[0]]}, items: '/members', field: '/id', id: '/id', value: 'x', fold: 'none', require: 'any'}), refused('too_many_items'));
  const same = Array.from({length: 101}, (_, index) => ({id: `S${index}`, team: 'a'}));
  assert.equal(run(FIND, {list: same.slice(1), items: '', field: '/team', id: '/id', value: 'a', fold: 'none', require: 'any'}).matches.length, 100);
  assert.throws(() => run(FIND, {list: same, items: '', field: '/team', id: '/id', value: 'a', fold: 'none', require: 'any'}), refused('too_many_items'), 'a 101st match refuses, never truncating');
  assert.throws(() => run(FIND, {list: same.slice(0, 2), items: '', field: '/team', id: '/id', value: 'a', fold: 'none', require: 'one'}), refused('match_many'));
  // A value that is no string never matches; a label that is no string is left out; a matched item with no string id refuses.
  const odd = [{id: 'A', email: 7}, {id: 'B', email: 'b@example.com', name: 5}, {email: 'c@example.com'}];
  assert.deepEqual(run(FIND, {list: odd, items: '', field: '/email', id: '/id', label: '/name', value: 'b@example.com', fold: 'none', require: 'one'}), {matches: [{id: 'B'}]});
  assert.throws(() => run(FIND, {list: odd, items: '', field: '/email', id: '/id', value: 'c@example.com', fold: 'none', require: 'one'}), refused('input_invalid'));
  assert.throws(() => run(FIND, {list: {members: 'x'}, items: '/members', field: '/id', id: '/id', value: 'x', fold: 'none', require: 'any'}), refused('input_invalid'), 'a value at items that is no list');
  assert.deepEqual(run(FIND, {list: {}, items: '/members', field: '/id', id: '/id', value: 'x', fold: 'none', require: 'any'}), {matches: []}, 'an absent list is empty, as Calendar omits attendees');
  // Only the declared pointers are read, and each is a well-formed pointer: a step-9 constant (R11).
  assert.throws(() => run(FIND, {list: [], items: 'members', field: '/id', id: '/id', value: 'x', fold: 'none', require: 'any'}), refused('input_invalid'));
  assert.deepEqual(sorted(TRANSFORMS.get(FIND).pointerArgs), ['field', 'id', 'items', 'label']);
  assert.deepEqual(sorted(TRANSFORMS.get(MISSING).pointerArgs), ['field', 'items']);
});

test('mergeEmails keeps each guest whole, adds and removes in any ASCII case, lists the change, and never drops the organizer or the owner', () => {
  const added = merge({add: ['new@example.com', 'GUEST@example.com']});
  assert.deepEqual(added.attendees, [...EVENT.attendees, {email: 'new@example.com'}], 'responseStatus, organizer, self, optional, comment and the rest are kept whole');
  assert.deepEqual([added.added, added.removed], [['new@example.com'], []], 'a guest already there in another case is not added again');
  const removed = merge({remove: ['guest@EXAMPLE.COM', 'nobody@example.com']});
  assert.deepEqual(removed.attendees, [EVENT.attendees[0], EVENT.attendees[2], EVENT.attendees[3]]);
  assert.deepEqual([removed.added, removed.removed], [[], ['Guest@Example.com']], 'a guest who is not there is not listed as removed');
  for (const address of ['org@example.com', 'ORG@example.com', 'owner@example.com', 'Owner@Example.COM']) assert.throws(() => merge({remove: [address]}), refused('attendee_protected'), address);
  const noFlag = {...EVENT, attendees: EVENT.attendees.map(({organizer, self, ...attendee}) => attendee)};
  assert.throws(() => run(MERGE, {event: noFlag, add: [], remove: ['org@example.com'], owner: 'owner@example.com'}), refused('attendee_protected'), 'the organizer by the event\'s /organizer/email');
  assert.throws(() => run(MERGE, {event: {attendees: [{email: 'x@example.com', organizer: true}]}, add: [], remove: ['x@example.com'], owner: 'o@example.com'}), refused('attendee_protected'), 'the organizer by its organizer flag');
  assert.throws(() => run(MERGE, {event: noFlag, add: [], remove: ['OWNER@example.com'], owner: 'owner@example.com'}), refused('attendee_protected'), 'the owner by the account\'s address');
  assert.throws(() => run(MERGE, {event: {...EVENT, organizer: {email: 'x@example.com'}}, add: [], remove: ['owner@example.com'], owner: 'me@example.com'}), refused('attendee_protected'), 'the owner by self');
  assert.throws(() => run(MERGE, {event: {attendees: []}, add: [], remove: ['me@example.com'], owner: 'me@example.com'}), refused('attendee_protected'), 'asking to remove the owner refuses even when the owner is no guest');
  assert.throws(() => merge({add: ['a@example.com'], remove: ['A@example.com']}), refused('input_invalid'), 'one address both added and removed is no merge');
  for (const address of ['a', 'a@', '@b', 'a@b@c', 'a b@c', 'a@b c', '<a@b>', 'a@b,c@d', 'ü@b', 'a\n@b', '"a"@b']) assert.throws(() => merge({add: [address]}), refused('input_invalid'), address);
  for (const extra of [{colorId: '1'}, {email: 7}, {optional: 'yes'}]) {
    assert.throws(() => run(MERGE, {event: {attendees: [{email: 'a@example.com', ...extra}]}, add: [], remove: [], owner: 'o@example.com'}), refused('output_invalid'), JSON.stringify(extra));
  }
  assert.throws(() => run(MERGE, {event: {attendees: 'x'}, add: [], remove: [], owner: 'o@example.com'}), refused('input_invalid'));
  const full = {attendees: Array.from({length: 1000}, (_, index) => ({email: `g${index}@example.com`}))};
  assert.equal(run(MERGE, {event: full, add: ['g1@example.com'], remove: [], owner: 'o@example.com'}).attendees.length, 1000);
  assert.throws(() => run(MERGE, {event: full, add: ['new@example.com'], remove: [], owner: 'o@example.com'}), refused('too_many_items'));
  assert.throws(() => run(MERGE, {event: {attendees: [...full.attendees, {email: 'x@example.com'}]}, add: [], remove: [], owner: 'o@example.com'}), refused('too_many_items'));
  const fields = Object.keys(TRANSFORMS.get(MERGE).output.properties.attendees.items.properties).sort();
  assert.deepEqual(fields, ['additionalGuests', 'comment', 'displayName', 'email', 'id', 'optional', 'organizer', 'resource', 'responseStatus', 'self'], 'every attendee field of Calendar\'s Discovery document');
  // A removed guest is the attendee's address as Calendar wrote it, which folds to one of `remove`, so it has the same length bounds.
  const schema = TRANSFORMS.get(MERGE);
  for (const field of ['added', 'removed']) {
    assert.deepEqual(schema.output.properties[field].items, schema.input.properties.add.items, `/${field} holds addresses as add and remove take them, so text.joinList@1 takes it for the card`);
  }
});

test('labelIds: names and ids resolve case-insensitively, system labels and unknown names refuse, and /ids holds exactly the ids of /labels', () => {
  const result = run(LABELS, {list: LIST, names: ['work', 'INBOX', 'label_1', 'Work']});
  assert.deepEqual(result, {labels: [{id: 'Label_2', name: 'Work'}, {id: 'INBOX', name: 'INBOX'}, {id: 'Label_1', name: 'Receipts'}], ids: ['Label_2', 'INBOX', 'Label_1']});
  assert.deepEqual(result.ids, result.labels.map(label => label.id));
  for (const name of ['SENT', 'sent', 'Draft', 'TRASH', 'trash', 'Spam', 'sPaM']) assert.throws(() => run(LABELS, {list: LIST, names: ['Work', name]}), refused('label_system'), name);
  // A label whose own id or name is a system label refuses however it is named.
  const sneaky = {labels: [{id: 'Label_7', name: 'Trash'}, {id: 'spam', name: 'Junk'}]};
  for (const name of ['Label_7', 'Junk']) assert.throws(() => run(LABELS, {list: sneaky, names: [name]}), refused('label_system'), name);
  for (const name of ['Travel', 'Wor', 'Work ', 'Receipt']) assert.throws(() => run(LABELS, {list: LIST, names: [name]}), refused('label_unknown'), name);
  assert.throws(() => run(LABELS, {list: LIST, names: ['Wörk']}), refused('label_unknown'), 'the fold is A to Z only');
  assert.throws(() => run(LABELS, {list: {labels: [{id: 'Label_1', name: 'Work'}, {id: 'Label_2', name: 'WORK'}]}, names: ['work']}), refused('match_many'));
  assert.throws(() => run(LABELS, {list: {labels: [{id: 'Label_1'}]}, names: ['x']}), refused('input_invalid'), 'a label with no name is not the documented shape');
  assert.throws(() => run(LABELS, {list: {labels: Array.from({length: 1001}, (_, index) => ({id: `L${index}`, name: `N${index}`}))}, names: []}), refused('too_many_items'));
  assert.throws(() => run(LABELS, {list: LIST, names: Array.from({length: 101}, () => 'Work')}), refused('input_invalid'), 'at most 100 names, the schema bound');
  assert.deepEqual(run(LABELS, {list: {}, names: []}), {labels: [], ids: []});
});

test('labelIds\' exclusion on /ids covers every contains value of the Gmail body routes', () => {
  const routes = PERMISSION_GROUPS.get('gmail').groups.flatMap(group => group.bodyRoutes ?? []).filter(route => Object.hasOwn(route, 'contains'));
  assert.ok(routes.length > 0, 'catalog/permissions/gmail.json has contains routes');
  const [exclusion] = TRANSFORMS.get(LABELS).excludes.filter(rule => rule.pointer === '/ids');
  for (const route of routes) assert.ok(exclusion.values.some(value => foldAscii(value) === foldAscii(route.contains)), `${route.member} ${route.pointer} contains ${route.contains}`);
  assert.deepEqual(TRANSFORMS.get(LABELS).excludes, [{pointer: '/ids', items: true, values: ['SENT', 'DRAFT', 'TRASH', 'SPAM'], fold: 'ascii'}]);
});

test('diff: stable additions and removals, each value once, exact comparison', () => {
  assert.deepEqual(run(DIFF, {before: ['c', 'a', 'B'], after: ['b', 'd', 'c', 'e', 'd']}), {add: ['b', 'd', 'e'], remove: ['a', 'B']});
  assert.deepEqual(run(DIFF, {before: [], after: []}), {add: [], remove: []});
  const big = Array.from({length: 1000}, (_, index) => `v${index}`);
  assert.deepEqual(run(DIFF, {before: big, after: [...big].reverse()}), {add: [], remove: []});
  assert.throws(() => run(DIFF, {before: [...big, 'x'], after: []}), refused('input_invalid'), 'at most 1,000 values, the schema bound');
});

test('oneOf: a guard that passes {value} or refuses with not_one_of; fold none keeps case and fold ascii folds A to Z only', () => {
  assert.deepEqual(run(ONE_OF, {value: 'default', set: ['default'], fold: 'none'}), {value: 'default'});
  for (const value of ['focusTime', 'outOfOffice', 'workingLocation', 'birthday', 'fromGmail', 'Default', ' default', '']) {
    assert.throws(() => run(ONE_OF, {value, set: ['default'], fold: 'none'}), refused('not_one_of'), value);
  }
  assert.deepEqual(run(ONE_OF, {value: 'PAGE_ID', set: ['page_id', 'workspace'], fold: 'ascii'}), {value: 'PAGE_ID'});
  assert.throws(() => run(ONE_OF, {value: 'ſ', set: ['s'], fold: 'ascii'}), refused('not_one_of'), 'the long s is no ASCII s');
  assert.throws(() => run(ONE_OF, {value: 'a', set: [], fold: 'none'}), refused('input_invalid'));
});

test('missing: zero or one name for find-or-create, folded as asked, so Create label never makes a second label in another case', () => {
  const list = {labels: [{id: 'Label_2', name: 'Work'}, {id: 'Label_3', name: 7}]};
  const missing = (name, fold = 'ascii') => run(MISSING, {list, items: '/labels', field: '/name', name, fold}).missing;
  assert.deepEqual(missing('WORK'), []);
  assert.deepEqual(missing('work', 'none'), ['work']);
  assert.deepEqual(missing('Wörk'), ['Wörk']);
  assert.deepEqual(missing('7'), ['7'], 'a field that is no string never matches');
  assert.deepEqual(run(MISSING, {list: {}, items: '/labels', field: '/name', name: 'New', fold: 'ascii'}).missing, ['New'], 'an absent list is empty');
  assert.throws(() => run(MISSING, {list: {labels: {}}, items: '/labels', field: '/name', name: 'New', fold: 'ascii'}), refused('input_invalid'));
  assert.equal(TRANSFORMS.get(MISSING).output.properties.missing.maxItems, 1, 'the POST that creates it runs at most once');
});

// F10.17 part 1 (docs/F10.17-BUILD-MAP.md part 1, F10.8 map part k): collections.stringValues@1, Run a workflow's inputs as one object of
// strings keyed by checked names (an outputMap, F10.8 part b). Its codes name_invalid and name_repeated come in _shared/error.v2.mjs.
const VALUES = 'collections.stringValues@1';

test('stringValues: {name, value} pairs become one object of strings in the order given; no pairs give {}', () => {
  const entry = TRANSFORMS.get(VALUES);
  assert.ok(entry, `${VALUES} is registered`);
  assert.deepEqual([entry.kind, entry.refuses, entry.runtimeFacts], ['map', ['name_invalid', 'name_repeated'], []]);
  assert.deepEqual(entry.outputMap, {key: 'identifier', maxKeys: 100, maxKeyLength: 100, value: {type: 'string', maxLength: 65_535}});
  assert.deepEqual(run(VALUES, {values: [{name: 'a', value: '1'}]}), {a: '1'});
  const out = run(VALUES, {values: [{name: 'env', value: 'prod'}, {name: '_dry-run', value: ''}, {name: 'B2', value: 'x'.repeat(65_535)}]});
  assert.deepEqual([Object.keys(out), out.env, out['_dry-run'], out.B2.length], [['env', '_dry-run', 'B2'], 'prod', '', 65_535]);
  assert.deepEqual(run(VALUES, {values: []}), {});
  assert.throws(() => run(VALUES, {values: [{name: 'a', value: 1}]}), refused('input_invalid'), 'every value is a string');
  assert.throws(() => run(VALUES, {values: [{name: 'a', value: 'x'.repeat(65_536)}]}), refused('input_invalid'));
  assert.throws(() => run(VALUES, {values: Array.from({length: 101}, (_, index) => ({name: `n${index}`, value: ''}))}), refused('input_invalid'), 'at most 100');
});

test('stringValues: a repeated name, in any ASCII case, refuses name_repeated; a name that is no workflow input name or names the prototype chain refuses name_invalid', () => {
  for (const values of [[{name: 'a', value: '1'}, {name: 'a', value: '2'}], [{name: 'Env', value: '1'}, {name: 'env', value: '2'}]]) {
    assert.throws(() => run(VALUES, {values}), refused('name_repeated'), JSON.stringify(values));
  }
  for (const name of ['1abc', 'a b', '-a', 'a.b', 'é', 'a/b', '__proto__', 'constructor', 'prototype']) assert.throws(() => run(VALUES, {values: [{name, value: '1'}]}), refused('name_invalid'), name);
  assert.deepEqual(run(VALUES, {values: [{name: '_', value: '1'}, {name: 'a-b_c9', value: '2'}]}), {_: '1', 'a-b_c9': '2'});
});

// Iteration 9 step 4 (docs/I07-BUILD-MAP.md section 2.7): what a reaction watch reads. Slack caps `users` below `count` in a history answer, so count is the provider's own number, never a length.
test('collections.slackReactions@1 reads step data, names its one code, and takes each count from Slack, since users is cut short of it', () => {
  const REACTIONS = 'collections.slackReactions@1', entry = TRANSFORMS.get(REACTIONS);
  assert.ok(entry, REACTIONS);
  assert.deepEqual([Object.keys(entry.stepData), entry.stepData.list.maxBytes, entry.refuses, entry.pointerArgs, entry.usesClock, entry.runtimeFacts], [['list'], 2_097_152, ['too_many_items'], [], false, []]);
  const message = {ts: '1761490000.000100', user: 'U0ADA0001', reactions: [{name: 'tada', users: ['U0ADA0001', 'U0GRACE01', 'U0OWNER01'], count: 7}]};
  assert.deepEqual(run(REACTIONS, {list: [message]}).items, [{name: 'tada', count: 7, parent: {ts: message.ts, user: 'U0ADA0001'}}]);
  assert.throws(() => run(REACTIONS, {list: 'messages'}), refused('input_invalid'));
  assert.throws(() => run(REACTIONS, {}), refused('input_invalid'), 'the harness holds step data to being there');
});

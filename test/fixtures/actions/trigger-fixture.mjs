// Iteration 9 step 2 (docs/I07-BUILD-MAP.md step 2): the fake app's triggers, and the harness the poll engine's tests run on. Test data only: nothing
// in lib/ imports it. feedTriggers() gives one trigger per cursor kind on GET /feed of test/fixtures/provider-simulators/fixture.mjs, in the shape of
// the 35 drafts, plus two more no-input triggers on the history-id poll, so two lenses share a feed: one enriches through GET /items/{item_id}
// under fixture.items.read, and one through GET /keys under fixture.keys.read, whose default is Ask, so a test saves it at Allow.
//   feed-synced          sync-token@1, resyncs on 410
//   feed-logged          history-id@1, seeded, resyncs on 404, read through collections.feedHistory@1 as Gmail's are through collections.gmailHistory@1
//   feed-logged-detail   the same poll, with an enrich step on fixture.items.read
//   feed-logged-keys     the same poll, with an enrich step on fixture.keys.read
//   feed-updated         high-water-time@1 on an asc list, one feed per kind ({each: '/kinds'}), seeded
//   feed-posted          high-water-ts@1 on a desc list, seeded
//   feed-tagged          snapshot@1 with etag@1, as GitHub's activity list is
//   feed-modified        high-water-time@1 with last-modified@1, as GitHub's notifications are
//   feed-listed          snapshot@1 of a whole list
//
// A test that needs another shape edits one of these before the harness loads it. WINDOWS and BUDGETS of lib/trigger-rules.mjs name real apps only.
import {randomUUID} from 'node:crypto';
import {mkdirSync, writeFileSync} from 'node:fs';
import path from 'node:path';
import {canonicalHash} from '../../../lib/compiler.mjs';
import {checkEntry} from '../../../lib/transforms/index.mjs';
import {deepFreeze} from '../../../lib/transforms/run.mjs';
import {triggerIds, validateTriggerFile} from '../../../lib/triggers.mjs';
import {argsHashOf, authorityOf} from '../../../lib/trigger-gate.mjs';
import {fixtureChoices} from './fixture-app.mjs';
import {TRANSFORMS, PINS} from './registry.mjs';
import {actionHarness} from './runtime-fixture.mjs';

const closed = (properties, required = Object.keys(properties)) => ({type: 'object', properties, required, additionalProperties: false});
const text = (max = 200) => ({type: 'string', minLength: 1, maxLength: max});
const ZEROS = '0'.repeat(24), MAX_RECORD_ITEMS = 500;
const OK = {status: [200], require: []}, CACHED = {status: [200, 304], require: []};
const LIST = {next: {pointer: '/nextPageToken'}, into: {query: 'pageToken'}, items: '/items', max: 10};
const feedStep = (query, more = {}) => ({id: 'feed', method: 'GET', path: '/feed', query: {limit: {const: 50}, ...query}, page: LIST, maxResponseBytes: 262_144, expect: OK, ...more});
const SINCE = {name: 'since', kind: 'high-water-time@1', next: {max: 'itemTime'}, compare: 'time.rfc3339ToEpochSeconds@1', overlapSeconds: 60}, SEEN = {name: 'seen', kind: 'snapshot@1', compare: 'collections.diff@1'};
const ITEM_TIME = {pointer: '/updated', format: 'rfc3339'};
const ITEM_EVENT = {schema: closed({id: text(64), name: text(200)}), id: {item: '/id'}, occurredAt: {item: '/updated'},
  fields: {id: {item: '/id'}, name: {pick: {transform: 'text.truncate@1', args: {text: {item: '/name'}, max: {const: 200}}}, pointer: '/text'}}, summary: [{label: 'Item', expr: {item: '/name'}, truncate: 120}]};

/** One polling trigger of the fixture app, in the shape of the drafts. */
const trigger = (key, name, poll, more = {}) => ({id: `fixture.trigger.${key}.v1.${ZEROS}`, key, version: 1, name, description: `${name}, on the fixture feed.`, delivery: {method: 'polling', intervalSeconds: {default: 120, min: 60}},
  inputSchema: closed({}), resource: [], poll: {items: {step: 'feed', pointer: ''}, itemId: {item: '/id'}, itemVersion: null, order: 'unordered', resync: {statusIn: []}, minIntervalSeconds: 60, ...poll},
  dedupe: {kind: 'id'}, event: ITEM_EVENT, backfill: {default: 0, max: 25}, retention: {days: 7}, bounds: {pages: 10, items: 500, pollSeconds: 10}, rows: ['fixture.items.read'], ...more});

/** The poll the three history triggers share: only these fields make a feed, so they share one (section 2.1). */
const logged = () => ({seed: {step: {id: 'start', method: 'GET', path: '/feed', query: {limit: {const: 1}}, maxResponseBytes: 4096, expect: OK}, cursor: {name: 'history', pointer: '/historyId'}},
  source: {steps: [feedStep({startHistoryId: {cursor: 'history'}}, {page: {...LIST, items: '/history'}})]}, items: {pick: {transform: 'collections.feedHistory@1', args: {list: {step: 'feed', pointer: ''}}}, pointer: '/items'},
  order: 'asc', cursors: [{name: 'history', kind: 'history-id@1', next: {step: 'feed', pointer: '/historyId'}, compare: 'time.decimalCompare@1', lastPageOnly: true}], resync: {statusIn: [404]}});
const LOGGED_EVENT = {schema: closed({id: text(64)}), id: {item: '/id'}, occurredAt: {item: '/recordId'}, fields: {id: {item: '/id'}}, summary: []};
/** An enrich step, and the event field it fills. */
const enriched = (key, name, step, pointer, rows) => trigger(key, name, {...logged(), enrich: {max: 25, steps: [step]}}, {rows, event: {...LOGGED_EVENT, schema: closed({id: text(64), read: text(200)}),
  fields: {id: {item: '/id'}, read: {step: step.id, pointer}}, summary: [{label: 'Read', expr: {step: step.id, pointer}, truncate: 120}]}});

/** Every trigger of the fixture app, fresh, with stub ids. */
export const feedTriggers = () => [
  trigger('feed-synced', 'An item changed', {source: {steps: [feedStep({syncToken: {cursor: 'sync'}})]}, itemVersion: '/updated', cursors: [{name: 'sync', kind: 'sync-token@1', next: {step: 'feed', pointer: '/nextSyncToken'}, lastPageOnly: true}],
    resync: {statusIn: [410]}}, {dedupe: {kind: 'id+version'}}),
  trigger('feed-logged', 'An item was logged', logged(), {event: LOGGED_EVENT}),
  enriched('feed-logged-detail', 'A logged item, with its detail', {id: 'detail', method: 'GET', path: '/items/{item_id}', params: {item_id: {item: '/id'}}, maxResponseBytes: 65_536, expect: {status: [200, 404], require: []}}, '/name', ['fixture.items.read']),
  enriched('feed-logged-keys', 'A logged item, with a key', {id: 'keys', method: 'GET', path: '/keys', maxResponseBytes: 65_536, expect: OK}, '/keys/0/name', ['fixture.items.read', 'fixture.keys.read']),
  trigger('feed-updated', 'An item of a kind changed', {seed: {step: {id: 'latest', method: 'GET', path: '/feed', query: {kind: {var: 'kind'}, order: {const: 'desc'}, limit: {const: 1}}, maxResponseBytes: 4096, expect: OK}, cursor: {name: 'since', pointer: '/items/0/updated'}},
    source: {steps: [feedStep({kind: {var: 'kind'}, order: {const: 'asc'}, updatedAfter: {cursor: 'since'}})]}, itemVersion: '/updated', itemTime: ITEM_TIME, order: 'asc', cursors: [SINCE]},
  {inputSchema: closed({kinds: {type: 'array', minItems: 1, maxItems: 4, items: {type: 'string', enum: ['note', 'task', 'row']}}}), resource: {each: '/kinds', as: 'kind'}, dedupe: {kind: 'id+version'}}),
  trigger('feed-posted', 'An item was posted', {seed: {step: {id: 'latest', method: 'GET', path: '/feed', query: {order: {const: 'desc'}, limit: {const: 1}}, maxResponseBytes: 4096, expect: OK}, cursor: {name: 'ts', pointer: '/items/0/ts'}},
    source: {steps: [feedStep({order: {const: 'desc'}, oldest: {cursor: 'ts'}})]}, itemTime: {pointer: '/ts', format: 'slack-ts'}, order: 'desc',
    cursors: [{name: 'ts', kind: 'high-water-ts@1', next: {max: 'itemTime'}, compare: 'time.slackTs@1', overlapSeconds: 30}]}),
  trigger('feed-tagged', 'An item appeared', {source: {steps: [feedStep({order: {const: 'desc'}}, {headers: {'If-None-Match': {cursor: 'etag'}}, expect: CACHED})]}, itemTime: ITEM_TIME, order: 'desc',
    cursors: [SEEN, {name: 'etag', kind: 'etag@1', next: {step: 'feed', header: 'etag'}}]}),
  trigger('feed-modified', 'An item was modified', {source: {steps: [feedStep({order: {const: 'asc'}, updatedAfter: {cursor: 'since'}}, {headers: {'If-Modified-Since': {cursor: 'changed'}}, expect: CACHED})]}, itemVersion: '/updated', itemTime: ITEM_TIME, order: 'asc',
    cursors: [SINCE, {name: 'changed', kind: 'last-modified@1', next: {step: 'feed', header: 'last-modified'}}]}, {dedupe: {kind: 'id+version'}}),
  trigger('feed-listed', 'An item joined the list', {source: {steps: [feedStep({order: {const: 'unordered'}})]}, cursors: [SEEN]}),
];

/**
 * collections.feedHistory@1, the fixture app's own transform: Section 2.7's contract of collections.gmailHistory@1 (step 7), over GET /feed's history
 * records, so the engine reads a history-id@1 feed here as it will read Gmail's. Out: {items: [{id, threadId, recordId}], throughRecordId?}, at most
 * 500 items in record order: it stops at a whole record and names it. It lives here, not in the fixture registry, whose stubs a test pins.
 */
const feedHistory = {name: 'collections.feedHistory', version: 1, kind: 'map', input: closed({}), pointerArgs: [], stepData: {list: {maxBytes: 2_097_152}}, resolvedValues: {},
  output: closed({items: {type: 'array', maxItems: MAX_RECORD_ITEMS, items: closed({id: text(64), threadId: text(64), recordId: text(20)})}, throughRecordId: text(20)}, ['items']),
  maxInputBytes: 2_097_152, maxOutputBytes: 262_144, usesClock: false, runtimeFacts: [], refuses: [], excludes: [],
  example: {input: {list: [{id: '12', messagesAdded: [{message: {id: 'F1', threadId: 'F1'}}]}]}, output: {items: [{id: 'F1', threadId: 'F1', recordId: '12'}]}},
  run({list}) {
    const items = [];
    let finished;
    for (const record of list) {
      const added = (record.messagesAdded ?? []).map(({message}) => ({id: message.id, threadId: message.threadId, recordId: record.id}));
      if (items.length + added.length > MAX_RECORD_ITEMS) return {items, ...(finished === undefined ? {} : {throughRecordId: finished})};
      items.push(...added);
      finished = record.id;
    }
    return {items};
  }};
const FEED_HISTORY = 'collections.feedHistory@1';
checkEntry(feedHistory, 'collections/feedHistory.v1.mjs');
/** The fixture registry with the feed's transform, and their pins. */
const REGISTRY = new Map([...TRANSFORMS, [FEED_HISTORY, deepFreeze(feedHistory)]]);
export const REGISTRY_PINS = Object.freeze({...PINS, [FEED_HISTORY]: canonicalHash({kind: 'fabric-fixture-stub', transform: FEED_HISTORY, run: feedHistory.run.toString(), entry: JSON.parse(JSON.stringify(feedHistory))})});

/** Where the fixture app's trigger evidence lives, as a certified trigger names it. */
export const TRIGGER_EVIDENCE = 'docs/live-evidence/fixture/triggers.json';
const PROOF = {afterWrite: 1, repoll: 0, resync: {gapEvents: 1, duplicates: 0}};
/** The shared fixture rows, with GET /feed in the read row. The rows file itself stays as it is, since a golden test pins its bindings. */
const withFeed = rows => { rows.groups.find(group => group.id === 'fixture.items.read').requests.push('GET /feed'); return rows; };

/**
 * The action harness (test/fixtures/actions/runtime-fixture.mjs) with the fixture app's trigger file loaded beside its actions, the simulator's feed in
 * its read row and one active client. Options, beside the action harness's: `triggers` (the list, feedTriggers() by default), `reviewed` (false writes
 * a candidate file) and `evidence(entries)` (the evidence file's content; a passing record for each by default). It adds: triggerFile, entryOf(key),
 * itemOf(key), idOf(key) for a trigger, connection(), grant(id, fields) (a client grant), setRow(groupId, mode), and watch(key, {args, status, ...})
 * (a subscription stored as an approval leaves it: status active by default, its authority read from the current decision; at awaiting_approval, no authority).
 */
export function triggerHarness(t, {triggers = feedTriggers(), reviewed = true, evidence, rows = file => file, ...options} = {}) {
  const h = actionHarness(t, {...options, rows: file => rows(withFeed(file)), transforms: REGISTRY, pins: REGISTRY_PINS});
  const map = h.maps.get('fixture') ?? null, deps = {...h.deps, maps: h.maps, choices: new Map([['fixture', fixtureChoices().sources]]), actions: new Map([['fixture', h.file]])};
  const file = {schemaVersion: 1, appId: 'fixture', specVersion: 'fabric/0.2', reviewStatus: reviewed ? 'reviewed' : 'candidate', pinnedParameters: {},
    triggers: triggers.map(item => reviewed ? {...item, certified: {evidence: TRIGGER_EVIDENCE}} : item)};
  const ids = triggerIds(file, deps), written = {...file, triggers: file.triggers.map(item => ({...item, id: ids.get(`${item.key} v${item.version}`)}))};
  const entries = validateTriggerFile(written, deps).triggers, folder = path.join(h.root, 'catalog', 'triggers');
  mkdirSync(folder, {recursive: true});
  writeFileSync(path.join(folder, 'fixture.json'), JSON.stringify(written));
  const passing = Object.fromEntries(entries.map(entry => [entry.id, {passed: true, transforms: Object.fromEntries(entry.transforms.map(id => [id, REGISTRY_PINS[id]])), tests: [{test: 'fixture', passed: true, proof: PROOF}]}]));
  writeFileSync(path.join(h.root, TRIGGER_EVIDENCE), JSON.stringify(evidence ? evidence(entries) : passing));
  h.catalog.reload('fixture', map);
  const idOf = key => entries.find(entry => entry.key === key).id, itemOf = key => h.catalog.triggerOf(idOf(key));
  const grant = (id = 'client-1', fields = {}) => {
    h.store.put('clientGrants', {id, name: 'Fixture agent', bindings: [], status: 'active', createdAt: new Date(h.now).toISOString(), expiresAt: new Date(h.now + 86_400_000).toISOString(), tokenHash: '0'.repeat(64), ...fields});
    return id;
  };
  grant();
  return Object.assign(h, {triggerFile: written, triggerId: idOf, itemOf, entryOf: key => itemOf(key).entry, connection: () => h.store.get('connections', h.account), grant,
    setRow: (groupId, mode) => h.proxyPolicy.set({connectionId: h.account, row: `group:${groupId}`, mode, confirmAllow: true}),
    watch(key, {args = {}, status = 'active', ...fields} = {}) {
      const at = new Date(h.now).toISOString(), {appId, entry} = itemOf(key), connection = h.store.get('connections', h.account);
      const record = {id: randomUUID(), clientId: 'client-1', appId, triggerId: entry.id, triggerKey: entry.key, connectionId: h.account, args, argsHash: argsHashOf(args), revision: 1, status,
        approvalDigest: '0'.repeat(64), approvalExpiresAt: at, feeds: [], pending: [], createdAt: at, updatedAt: at};
      const approved = status === 'awaiting_approval' ? {} : {approvedAt: at, authority: authorityOf(record, connection, h.permissions.triggerDecision(connection, entry))};
      const subscription = {...record, ...approved, ...fields};
      h.store.put('subscriptions', subscription);
      return subscription;
    }});
}

// F10.8 part i (docs/F10.8-BUILD-MAP.md, open point Minor 10): ids.slackLink@1. In: {link}, a message link as Slack's "Copy link" gives
// it: https://<team>.slack.com/archives/<channel>/p<16 digits> (or <org>.enterprise.slack.com on Enterprise Grid), with an optional
// ?thread_ts=<ts> when the message is a reply in a thread.
// Out: {channel, ts, thread, parent?}:
// - channel: the C, G or D id from the path;
// - ts: the 16 digits as Slack's ts, ten digits, a dot and six (p1355517523000008 is 1355517523.000008);
// - parent: thread_ts, only when the link points at a reply (spec line 1465);
// - thread: always the ts of the thread's parent, thread_ts when present and the ts otherwise, so Read a thread and Reply in a thread
//   take one field for both kinds of link (spec lines 1465, 1469).
// Other query parameters (cid) and a fragment are ignored. Another host or scheme, a user or port, another path, another digit count, a
// thread_ts that is no ts, or two of them refuse with slack_link_invalid. The output holds ids only, never a URL or a host (I4).
import {TransformError} from '../_shared/error.v1.mjs';
import {httpsUrl} from './_url.v1.mjs';

const HOST = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.enterprise)?\.slack\.com$/;
const PATH = /^\/archives\/([CGD][A-Z0-9]{8,20})\/p([0-9]{10})([0-9]{6})$/;
const TS = /^[0-9]{10}\.[0-9]{6}$/;
const TS_SCHEMA = {type: 'string', minLength: 17, maxLength: 17};
const refuse = () => { throw new TransformError('slack_link_invalid'); };

/** The thread_ts of a query, null when it has none; it refuses one that is no ts, and a second one. */
function threadTs(query) {
  let found = null;
  for (const parameter of query === '' ? [] : query.split('&')) {
    if (!parameter.startsWith('thread_ts=')) continue;
    const value = parameter.slice('thread_ts='.length);
    if (found !== null || !TS.test(value)) refuse();
    found = value;
  }
  return found;
}

export const ENTRY = {name: 'ids.slackLink', version: 1, kind: 'map',
  input: {type: 'object', properties: {link: {type: 'string', maxLength: 2048}}, required: ['link'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {channel: {type: 'string', minLength: 9, maxLength: 21}, ts: TS_SCHEMA, thread: TS_SCHEMA, parent: TS_SCHEMA},
    required: ['channel', 'ts', 'thread'], additionalProperties: false},
  maxInputBytes: 4096, maxOutputBytes: 512, usesClock: false, runtimeFacts: [], refuses: ['slack_link_invalid'], excludes: [],
  example: {input: {link: 'https://acme.slack.com/archives/C024BE91L/p1355517523000008?thread_ts=1355517523.000005&cid=C024BE91L'},
    output: {channel: 'C024BE91L', ts: '1355517523.000008', thread: '1355517523.000005', parent: '1355517523.000005'}},
  run(input) {
    const url = httpsUrl(input.link);
    if (url === null || !HOST.test(url.host)) refuse();
    const match = PATH.exec(url.path);
    if (!match) refuse();
    const ts = `${match[2]}.${match[3]}`, parent = threadTs(url.query);
    return parent === null ? {channel: match[1], ts, thread: ts} : {channel: match[1], ts, thread: parent, parent};
  }};

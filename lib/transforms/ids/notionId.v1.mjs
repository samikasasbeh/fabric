// F10.8 part i (docs/F10.8-BUILD-MAP.md): ids.notionId@1. In: {value}: a Notion link a person pasted, or a bare id. Out: {id}, the
// hyphenated lower-case UUID the API takes. It accepts:
// - 32 hex digits, or the hyphenated 8-4-4-4-12 form, in either case;
// - an https link on notion.so, www.notion.so or a workspace's <name>.notion.site, with no user or port, whose last path segment is the
//   32 hex digits alone or after a hyphen (My-Page-<id>). The path id wins: a ?v= view id, a ?p= peeked page and a #fragment are
//   ignored.
// Any other host, scheme or length refuses with notion_id_invalid. The output is an id only, never a URL or a host (I4).
import {TransformError} from '../_shared/error.v1.mjs';
import {foldAscii} from '../_shared/ascii.v1.mjs';
import {httpsUrl} from './_url.v1.mjs';

const HEX = /^[0-9A-Fa-f]{32}$/;
const UUID = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/;
const SEGMENT_ID = /(?:^|-)([0-9A-Fa-f]{32})$/;
const SITE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.notion\.site$/;
const NOTION_HOSTS = new Set(['notion.so', 'www.notion.so']);

/** The 32 hex digits of a Notion link's last path segment, or null when the link is not on Notion's own hosts or holds no id there. */
function linkId(value) {
  const url = httpsUrl(value);
  if (url === null || !(NOTION_HOSTS.has(url.host) || SITE.test(url.host))) return null;
  const segment = url.path.split('/').filter(part => part !== '').pop() ?? '';
  const match = SEGMENT_ID.exec(segment);
  return match ? match[1] : null;
}

export const ENTRY = {name: 'ids.notionId', version: 1, kind: 'map',
  input: {type: 'object', properties: {value: {type: 'string', maxLength: 2048}}, required: ['value'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {id: {type: 'string', minLength: 36, maxLength: 36}}, required: ['id'], additionalProperties: false},
  maxInputBytes: 4096, maxOutputBytes: 256, usesClock: false, runtimeFacts: [], refuses: ['notion_id_invalid'], excludes: [],
  example: {input: {value: 'https://www.notion.so/My-Page-1429989fe8ac4effbc8f57f56486db54'}, output: {id: '1429989f-e8ac-4eff-bc8f-57f56486db54'}},
  run(input) {
    const value = input.value;
    const hex = HEX.test(value) ? value : UUID.test(value) ? value.split('-').join('') : linkId(value);
    if (hex === null) throw new TransformError('notion_id_invalid');
    const id = foldAscii(hex);
    return {id: `${id.slice(0, 8)}-${id.slice(8, 12)}-${id.slice(12, 16)}-${id.slice(16, 20)}-${id.slice(20)}`};
  }};

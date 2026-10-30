// Step 20's live runs (2026-10-30; docs/F10.19-BUILD-MAP.md section 9): notion.markdownShows@1, the read-back of Add to page and Edit page text.
// Step data `before` and `after`: a page's markdown as Notion read it just before the write and after it. Argument `text`: what the action
// wrote. Argument `removed`, for Edit page text: the text it replaced. Out: {shows}, true when both of these hold:
// - The page changed. One read cannot tell a write that landed from text already there, so a write Notion swallowed never shows. A link to an
//   uploaded file is no change: Notion signs it anew on every read, as the run measured on two reads seconds apart.
// - The text stands on the page. Notion never reads markdown back as it was sent: it puts a backslash before \ * ~ ` $ [ ] < > { } | ^ (its
//   enhanced markdown reference), and the run saw it strip blank lines, read a heading 5 as a 4, a * bullet as -, _italic_ as *italic* and
//   ```js as ```javascript, renumber an ordered list and turn a pipe table into <table> tags. So the text stands as given, those backslashes
//   aside, or word for word once those marks are set aside, in any case. Words keep their boundaries: 10.5 is not 105. Only table tags count
//   as tags: a < and a > in text hold words between them. Text of nothing but marks has only the first test.
// An empty text with `removed` wrote nothing to look for, so there the removed text must be gone, by the first test alone: a short removal
// must not count as still there because its letters stand together elsewhere on the page.
// A before or after that is not a string refuses with input_invalid.
import {TransformError} from '../_shared/error.v3.mjs';
import {MAX_TEXT} from './_types.v1.mjs';

const unsigned = value => value.replace(/\?X-Amz-[^\s)]*/g, '');
const read = value => value.replace(/\\([\\*~`$[\]<>{}|^])/g, '$1');
const words = value => read(value.replace(/<\/?(?:table|tr|td|th)\b[^<>]*>/g, ' ')).replace(/^[ \t]*```.*$/gm, '').replace(/^[ \t]*\d+\.\s/gm, '').split(/[\s!-/:-@[-`{-~]+/).filter(word => word !== '').join(' ').toLowerCase();

export const ENTRY = {name: 'notion.markdownShows', version: 1, kind: 'map',
  input: {type: 'object', properties: {text: {type: 'string', maxLength: MAX_TEXT}, removed: {type: 'string', maxLength: MAX_TEXT}}, required: ['text'], additionalProperties: false},
  pointerArgs: [], stepData: {before: {maxBytes: 1_048_576}, after: {maxBytes: 1_048_576}}, resolvedValues: {},
  output: {type: 'object', properties: {shows: {type: 'boolean'}}, required: ['shows'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 256, usesClock: false, runtimeFacts: ['unicode'], refuses: [], excludes: [],
  example: {input: {before: 'Plan', after: 'Plan\n\\[SYNTHETIC\\] Fabric note', text: '[SYNTHETIC] Fabric note'}, output: {shows: true}},
  run({before, after, text, removed}) {
    if (typeof before !== 'string' || typeof after !== 'string') throw new TransformError('input_invalid');
    if (unsigned(before) === unsigned(after)) return {shows: false};
    const page = read(after), wanted = read(text).trim(), said = words(text);
    if (wanted === '' && removed !== undefined) return {shows: !page.includes(read(removed))};
    return {shows: page.includes(wanted) || (said !== '' && ` ${words(after)} `.includes(` ${said} `))};
  }};

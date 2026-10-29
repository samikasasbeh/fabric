// F10.19 part 1 (docs/F10.19-BUILD-MAP.md part 1 item 3, question 5): notion.plainValues@1. A closed output cannot hold Notion's open
// property values, so Read page, Find rows and Update's card read a page's values through this one reviewed reader. Step data `page`. Out:
// {properties: [{name, id, type, text, line}]}, sorted by name, at most 100 (too_many_properties). `text` is the type table's plain form
// (notion/_types.v1.mjs textOf()): a file property gives the files' names, never a link to one (Notion signs those links for about an hour).
// `line` is `text` with each line break (CR LF, CR, LF, vertical tab, form feed, next line, line and paragraph separators) turned into a
// space and cut at 200 code points, for a card's one line. F10.19 part 2: `lines` is one card line per property, "Name: line", in name
// order, joined by LF, each name made one line of at most 200 code points the same way: Update database row's "Values now".
import {MAX_TEXT, propertiesOf, textOf} from './_types.v1.mjs';

const LINE = 200;
/** One "name: line" line per property, at most 100, and the LFs between them. */
const LINES = 100 * (LINE + 2 + LINE) + 99;
const NAME = {type: 'string', minLength: 1, maxLength: 1000};

/** The text on one line of at most 200 code points. */
function lineOf(text) {
  const flat = text.replace(/\r\n|[\n\r\u000b\u000c\u0085\u2028\u2029]/g, ' ');
  return Array.from(flat).slice(0, LINE).join('');
}

export const ENTRY = {name: 'notion.plainValues', version: 1, kind: 'map',
  input: {type: 'object', properties: {}, additionalProperties: false},
  pointerArgs: [], stepData: {page: {maxBytes: 2_097_152}}, resolvedValues: {},
  output: {type: 'object', properties: {properties: {type: 'array', maxItems: 100, items: {type: 'object', properties: {name: NAME, id: {type: 'string', minLength: 1, maxLength: 256},
    type: {type: 'string', minLength: 1, maxLength: 64}, text: {type: 'string', maxLength: MAX_TEXT}, line: {type: 'string', maxLength: LINE}}, required: ['name', 'id', 'type', 'text', 'line'],
    additionalProperties: false}}, lines: {type: 'string', maxLength: LINES}}, required: ['properties', 'lines'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 2_097_152, usesClock: false, runtimeFacts: [], refuses: ['too_many_properties'], excludes: [],
  example: {input: {page: {object: 'page', properties: {Name: {id: 'title', type: 'title', title: [{plain_text: 'Taxi'}]}, Cost: {id: 'c1', type: 'number', number: 12}}}},
    output: {properties: [{name: 'Cost', id: 'c1', type: 'number', text: '12', line: '12'}, {name: 'Name', id: 'title', type: 'title', text: 'Taxi', line: 'Taxi'}], lines: 'Cost: 12\nName: Taxi'}},
  run({page}) {
    const properties = propertiesOf(page).map(entry => {
      const text = textOf(entry);
      return {name: entry.name, id: entry.id, type: entry.type, text, line: lineOf(text)};
    });
    return {properties, lines: properties.map(item => `${lineOf(item.name)}: ${item.line}`).join('\n')};
  }};

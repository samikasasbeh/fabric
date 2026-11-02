// Iteration 9 step 5 (docs/I07-BUILD-MAP.md section 2.7): notion.markdownFingerprint@1. Closed `markdown`, a page's markdown, at most 1,000,000 characters. Out: {text}, the markdown with the
// query string taken off each link to an uploaded file. Notion signs those links anew on every read, as the live run of 2026-10-30 measured on two reads seconds apart, so a raw hash of
// the markdown would fire on every poll. Its file store is Amazon S3, or file.notion.so. Any other link keeps its query, since that is what the page says.
// It is closed, because a step-data argument refuses an item built from two steps, and a page's item is. It reads the text word by word, never by a pattern that could look back,
// so a page of a million characters built to be slow costs what any other does.
const MAX_TEXT = 1_000_000;

/** A host Notion serves signed files from: file.notion.so, or an address of Amazon S3. */
const signsFiles = host => host === 'file.notion.so' || (host.endsWith('.amazonaws.com') && host.split('.').some(label => label === 's3' || label.startsWith('s3-')));
/** One run of text with no break in it, its query gone if it holds a link to a file. */
function unsigned(run) {
  const start = run.indexOf('https://'), query = start < 0 ? -1 : run.indexOf('?', start);
  return query >= 0 && signsFiles(run.slice(start + 8, query).split('/', 1)[0]) ? run.slice(0, query) : run;
}

export const ENTRY = {name: 'notion.markdownFingerprint', version: 1, kind: 'map',
  input: {type: 'object', properties: {markdown: {type: 'string', maxLength: MAX_TEXT}}, required: ['markdown'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {text: {type: 'string', maxLength: MAX_TEXT}}, required: ['text'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 2_097_152, usesClock: false, runtimeFacts: [], refuses: [], excludes: [],
  example: {input: {markdown: 'Plan\n[report](https://example.com/report?year=2026)'}, output: {text: 'Plan\n[report](https://example.com/report?year=2026)'}},
  run({markdown}) {
    return {text: markdown.replace(/[^"'<>() \t\r\n]+/g, unsigned)};
  }};

// Iteration 9 step 6 (docs/I07-BUILD-MAP.md section 2.7): ids.linkPage@1. In: {link, url, param}: an answer's Link header, the URL of the request that drew it, and the
// query parameter that holds a page number. Out: {page?}: the number of the next page, and nothing when no link in the header is rel="next". Only the number leaves this
// transform, so a provider's URL is never followed (I4).
// A next link counts only on the request's own origin, with the request's own path, or with /repositories/<digits> followed by the request's path after /repos/<owner>/<repo>,
// which is how GitHub writes the next link of a repository's list. Its page must be one whole number of 1 to 5 digits, given once. Anything else refuses with link_invalid, and so
// does a header it cannot read: that next link would otherwise read as the end of the list, and what follows it would be lost in silence.
// The header is read by hand, by the rules of RFC 8288: a comma can sit inside a URL or a quoted value, a parameter name takes any case, and rel holds relations split by spaces.
import {foldAscii} from '../_shared/ascii.v1.mjs';
import {TransformError} from '../_shared/error.v5.mjs';
import {httpsUrl} from './_url.v1.mjs';

const OWN_LIST = /^\/repos\/[^/]+\/[^/]+(.*)$/;
const ID_LIST = /^\/repositories\/[0-9]+(.*)$/;
const PAGE = /^[1-9][0-9]{0,4}$/;
const SPACES = /[ \t]+/;
const refuse = () => { throw new TransformError('link_invalid'); };
const blank = character => character === ' ' || character === '\t';
/** Where the text after `at` stops being blank. */
function skipped(text, at) {
  let index = at;
  while (index < text.length && blank(text.charAt(index))) index++;
  return index;
}
/** Where a parameter's name or bare value that starts at `at` ends. */
function tokenEnd(text, at, stops) {
  let index = at;
  while (index < text.length && !blank(text.charAt(index)) && !stops.includes(text.charAt(index))) index++;
  return index;
}
/** One parameter that starts at `at`: {name, value, at}, with `at` where it ends. */
function parameter(link, start) {
  const nameEnd = tokenEnd(link, start, '=;,');
  let at = skipped(link, nameEnd), value = '';
  if (link.charAt(at) === '=') {
    at = skipped(link, at + 1);
    if (link.charAt(at) === '"') {
      const close = link.indexOf('"', at + 1);
      if (close === -1) refuse();
      value = link.slice(at + 1, close);
      at = close + 1;
    } else {
      const end = tokenEnd(link, at, ';,');
      value = link.slice(at, end);
      at = end;
    }
  }
  return {name: foldAscii(link.slice(start, nameEnd)), value, at};
}
/** The links of a Link header in order, each as {target, relations}. */
function linksOf(link) {
  const links = [];
  for (let at = skipped(link, 0); at < link.length; at = skipped(link, at)) {
    if (link.charAt(at) !== '<') refuse();
    const close = link.indexOf('>', at);
    if (close === -1) refuse();
    const target = link.slice(at + 1, close);
    let relations = null;
    at = skipped(link, close + 1);
    while (link.charAt(at) === ';') {
      const read = parameter(link, skipped(link, at + 1));
      // RFC 8288: a second rel on one link is ignored.
      if (read.name === 'rel' && relations === null) relations = foldAscii(read.value).split(SPACES);
      at = skipped(link, read.at);
    }
    if (at < link.length && link.charAt(at) !== ',') refuse();
    at++;
    links.push({target, relations: relations ?? []});
  }
  return links;
}
/** True for the request's own path, or the /repositories/<digits> form of it. */
function samePath(next, request) {
  if (next === request) return true;
  const own = OWN_LIST.exec(request), id = ID_LIST.exec(next);
  return own !== null && id !== null && own[1] === id[1];
}
/** The one value of a query parameter, or null when it is missing or given twice. */
function single(query, name) {
  const found = (query === '' ? [] : query.split('&')).filter(part => part.startsWith(`${name}=`));
  return found.length === 1 ? found[0].slice(name.length + 1) : null;
}

export const ENTRY = {name: 'ids.linkPage', version: 1, kind: 'map',
  input: {type: 'object', properties: {link: {type: 'string', maxLength: 8192}, url: {type: 'string', minLength: 1, maxLength: 2048}, param: {type: 'string', minLength: 1, maxLength: 64}},
    required: ['link', 'url', 'param'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {page: {type: 'integer', minimum: 1, maximum: 100_000}}, required: [], additionalProperties: false},
  maxInputBytes: 16_384, maxOutputBytes: 256, usesClock: false, runtimeFacts: [], refuses: ['link_invalid'], excludes: [],
  example: {input: {link: '<https://api.fixture.test/items?page=2>; rel="next", <https://api.fixture.test/items?page=9>; rel="last"', url: 'https://api.fixture.test/items?page=1', param: 'page'},
    output: {page: 2}},
  run({link, url, param}) {
    const nexts = linksOf(link).filter(item => item.relations.includes('next'));
    if (!nexts.length) return {};
    if (nexts.length > 1) refuse();
    const target = httpsUrl(nexts[0].target), request = httpsUrl(url);
    if (target === null || request === null || target.host !== request.host || !samePath(target.path, request.path)) refuse();
    const value = single(target.query, param);
    if (value === null || !PAGE.test(value)) refuse();
    return {page: Number(value)};
  }};

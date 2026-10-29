// F10.8 part f (docs/F10.8-BUILD-MAP.md): html.toText@1. In: {html}, at most 1,000,000 code points. Out: {text, truncated?}: the text a
// reader sees, cut at 500,000 code points on a code-point boundary with truncated: true. Read email feeds it the decode's /html (R1).
//
// A linear state machine after the HTML Living Standard's tokenizer, with no backtracking regex: every character is read a bounded number
// of times, and an input that ends inside a tag, a comment or a raw text element ends the text, as a parser discards an unfinished tag.
// - script, style, noscript, iframe, noembed, noframes and title are raw text, dropped with their contents up to their own end tag
//   (spec line 691); a script keeps the tokenizer's escaped states, so <!--<script> inside one holds the next </script>. template is
//   dropped with everything inside it, templates nested; comments, CDATA, doctypes and processing instructions are dropped whole. A head
//   goes with its contents by these rules: what a head holds is void or dropped, and text ends a head, as parsers end it.
// - Numeric references, and the named ones of a reviewed list (HTML 4's Latin-1, special and symbol sets, all of them), decode; a named
//   one needs its semicolon. NUL, surrogates and values past U+10FFFF become U+FFFD, and 0x80 to 0x9F read as windows-1252, as HTML reads
//   them.
// - ASCII white space collapses to one space outside pre, listing, xmp, textarea and plaintext (which keeps the rest as text); block
//   elements and br become line breaks, and p and h1 to h6 a blank line, with at most one blank line in a row. Attributes are never
//   read, links included.
// It refuses nothing of its own: the harness codes cover the caps. It reads no runtime fact: case folds and spaces are ASCII only.
import {foldAscii, isAsciiSpace} from '../_shared/ascii.v1.mjs';

const MAX_TEXT = 500_000;
// Raw text elements whose contents are dropped, and the two whose contents are kept (textarea decodes references, xmp does not).
const DROPPED_RAW = new Set(['script', 'style', 'noscript', 'iframe', 'noembed', 'noframes', 'title']);
const KEPT_RAW = new Set(['textarea', 'xmp']);
// Elements whose text keeps its white space.
const VERBATIM = new Set(['pre', 'listing']);
const BLOCKS = new Set(['address', 'article', 'aside', 'blockquote', 'caption', 'center', 'dd', 'details', 'dialog', 'dir', 'div', 'dl', 'dt', 'fieldset', 'figcaption',
  'figure', 'footer', 'form', 'header', 'hgroup', 'hr', 'legend', 'li', 'listing', 'main', 'menu', 'nav', 'ol', 'pre', 'section', 'summary', 'table', 'tbody', 'tfoot', 'thead',
  'tr', 'ul', 'xmp']);
const PARAGRAPHS = new Set(['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']);
const CELLS = new Set(['td', 'th']);

// The reviewed named references: HTML 4's Latin-1 set (U+00A0 to U+00FF, in order); its special set, with apos and the upper-case forms
// HTML keeps for four of them; and its whole symbol set, in code-point order, at the values the HTML Living Standard gives them (it moved
// only lang and rang, to U+27E8 and U+27E9).
const LATIN1 = ('nbsp iexcl cent pound curren yen brvbar sect uml copy ordf laquo not shy reg macr deg plusmn sup2 sup3 acute micro para middot cedil sup1 ordm raquo '
  + 'frac14 frac12 frac34 iquest Agrave Aacute Acirc Atilde Auml Aring AElig Ccedil Egrave Eacute Ecirc Euml Igrave Iacute Icirc Iuml ETH Ntilde Ograve Oacute Ocirc '
  + 'Otilde Ouml times Oslash Ugrave Uacute Ucirc Uuml Yacute THORN szlig agrave aacute acirc atilde auml aring aelig ccedil egrave eacute ecirc euml igrave iacute icirc '
  + 'iuml eth ntilde ograve oacute ocirc otilde ouml divide oslash ugrave uacute ucirc uuml yacute thorn yuml').split(' ');
const SPECIAL = [['quot', 0x22], ['amp', 0x26], ['apos', 0x27], ['lt', 0x3c], ['gt', 0x3e], ['QUOT', 0x22], ['AMP', 0x26], ['LT', 0x3c], ['GT', 0x3e], ['OElig', 0x152],
  ['oelig', 0x153], ['Scaron', 0x160], ['scaron', 0x161], ['Yuml', 0x178], ['circ', 0x2c6], ['tilde', 0x2dc], ['ensp', 0x2002], ['emsp', 0x2003], ['thinsp', 0x2009],
  ['zwnj', 0x200c], ['zwj', 0x200d], ['lrm', 0x200e], ['rlm', 0x200f], ['ndash', 0x2013], ['mdash', 0x2014], ['lsquo', 0x2018], ['rsquo', 0x2019], ['sbquo', 0x201a],
  ['ldquo', 0x201c], ['rdquo', 0x201d], ['bdquo', 0x201e], ['dagger', 0x2020], ['Dagger', 0x2021], ['permil', 0x2030], ['lsaquo', 0x2039], ['rsaquo', 0x203a],
  ['euro', 0x20ac]];
const SYMBOL = [['fnof', 0x192], ['Alpha', 0x391], ['Beta', 0x392], ['Gamma', 0x393], ['Delta', 0x394], ['Epsilon', 0x395], ['Zeta', 0x396], ['Eta', 0x397], ['Theta', 0x398],
  ['Iota', 0x399], ['Kappa', 0x39a], ['Lambda', 0x39b], ['Mu', 0x39c], ['Nu', 0x39d], ['Xi', 0x39e], ['Omicron', 0x39f], ['Pi', 0x3a0], ['Rho', 0x3a1],
  ['Sigma', 0x3a3], ['Tau', 0x3a4], ['Upsilon', 0x3a5], ['Phi', 0x3a6], ['Chi', 0x3a7], ['Psi', 0x3a8], ['Omega', 0x3a9], ['alpha', 0x3b1], ['beta', 0x3b2],
  ['gamma', 0x3b3], ['delta', 0x3b4], ['epsilon', 0x3b5], ['zeta', 0x3b6], ['eta', 0x3b7], ['theta', 0x3b8], ['iota', 0x3b9], ['kappa', 0x3ba], ['lambda', 0x3bb],
  ['mu', 0x3bc], ['nu', 0x3bd], ['xi', 0x3be], ['omicron', 0x3bf], ['pi', 0x3c0], ['rho', 0x3c1], ['sigmaf', 0x3c2], ['sigma', 0x3c3], ['tau', 0x3c4],
  ['upsilon', 0x3c5], ['phi', 0x3c6], ['chi', 0x3c7], ['psi', 0x3c8], ['omega', 0x3c9], ['thetasym', 0x3d1], ['upsih', 0x3d2], ['piv', 0x3d6], ['bull', 0x2022],
  ['hellip', 0x2026], ['prime', 0x2032], ['Prime', 0x2033], ['oline', 0x203e], ['frasl', 0x2044], ['image', 0x2111], ['weierp', 0x2118], ['real', 0x211c],
  ['trade', 0x2122], ['alefsym', 0x2135], ['larr', 0x2190], ['uarr', 0x2191], ['rarr', 0x2192], ['darr', 0x2193], ['harr', 0x2194], ['crarr', 0x21b5],
  ['lArr', 0x21d0], ['uArr', 0x21d1], ['rArr', 0x21d2], ['dArr', 0x21d3], ['hArr', 0x21d4], ['forall', 0x2200], ['part', 0x2202], ['exist', 0x2203], ['empty', 0x2205],
  ['nabla', 0x2207], ['isin', 0x2208], ['notin', 0x2209], ['ni', 0x220b], ['prod', 0x220f], ['sum', 0x2211], ['minus', 0x2212], ['lowast', 0x2217], ['radic', 0x221a],
  ['prop', 0x221d], ['infin', 0x221e], ['ang', 0x2220], ['and', 0x2227], ['or', 0x2228], ['cap', 0x2229], ['cup', 0x222a], ['int', 0x222b], ['there4', 0x2234],
  ['sim', 0x223c], ['cong', 0x2245], ['asymp', 0x2248], ['ne', 0x2260], ['equiv', 0x2261], ['le', 0x2264], ['ge', 0x2265], ['sub', 0x2282], ['sup', 0x2283],
  ['nsub', 0x2284], ['sube', 0x2286], ['supe', 0x2287], ['oplus', 0x2295], ['otimes', 0x2297], ['perp', 0x22a5], ['sdot', 0x22c5], ['lceil', 0x2308],
  ['rceil', 0x2309], ['lfloor', 0x230a], ['rfloor', 0x230b], ['lang', 0x27e8], ['rang', 0x27e9], ['loz', 0x25ca], ['spades', 0x2660], ['clubs', 0x2663],
  ['hearts', 0x2665], ['diams', 0x2666]];
const NAMED = new Map([...LATIN1.map((name, index) => [name, String.fromCharCode(0xa0 + index)]),
  ...[...SPECIAL, ...SYMBOL].map(([name, code]) => [name, String.fromCharCode(code)])]);
// HTML reads numeric references 0x80 to 0x9F as windows-1252; the five it leaves undefined stay as they are.
const WINDOWS_1252 = new Map([[0x80, 0x20ac], [0x82, 0x201a], [0x83, 0x192], [0x84, 0x201e], [0x85, 0x2026], [0x86, 0x2020], [0x87, 0x2021], [0x88, 0x2c6], [0x89, 0x2030],
  [0x8a, 0x160], [0x8b, 0x2039], [0x8c, 0x152], [0x8e, 0x17d], [0x91, 0x2018], [0x92, 0x2019], [0x93, 0x201c], [0x94, 0x201d], [0x95, 0x2022], [0x96, 0x2013], [0x97, 0x2014],
  [0x98, 0x2dc], [0x99, 0x2122], [0x9a, 0x161], [0x9b, 0x203a], [0x9c, 0x153], [0x9e, 0x17e], [0x9f, 0x178]]);

const LT = 0x3c, GT = 0x3e, SLASH = 0x2f, BANG = 0x21, QUESTION = 0x3f, AMP = 0x26, HASH = 0x23, SEMICOLON = 0x3b, EQUALS = 0x3d, DASH = 0x2d, CR = 0x0d, LF = 0x0a;
const isLetter = code => (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a);
const isDigit = code => code >= 0x30 && code <= 0x39;
const hexValue = code => isDigit(code) ? code - 0x30 : code >= 0x41 && code <= 0x46 ? code - 0x37 : code >= 0x61 && code <= 0x66 ? code - 0x57 : -1;

/** The text of a numeric reference to `value`, as HTML maps it. */
function numericText(value) {
  if (value === 0 || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return '�';
  return String.fromCodePoint(WINDOWS_1252.get(value) ?? value);
}
/** The reference starting at the & at `at`: {text, end}, or null when none starts there and the & is text. */
function reference(html, at) {
  let index = at + 1;
  if (html.charCodeAt(index) === HASH) {
    index++;
    const hex = html.charCodeAt(index) === 0x78 || html.charCodeAt(index) === 0x58;
    if (hex) index++;
    const start = index;
    let value = 0;
    for (; index < html.length; index++) {
      const digit = hex ? hexValue(html.charCodeAt(index)) : isDigit(html.charCodeAt(index)) ? html.charCodeAt(index) - 0x30 : -1;
      if (digit < 0) break;
      // Past U+10FFFF the value only has to stay past it, so it stops growing; the digits are still read.
      if (value <= 0x10ffff) value = value * (hex ? 16 : 10) + digit;
    }
    if (index === start) return null;
    return {text: numericText(value), end: html.charCodeAt(index) === SEMICOLON ? index + 1 : index};
  }
  const start = index;
  while (index < html.length && index - start < 32 && (isLetter(html.charCodeAt(index)) || isDigit(html.charCodeAt(index)))) index++;
  if (index === start || html.charCodeAt(index) !== SEMICOLON) return null;
  const text = NAMED.get(html.slice(start, index));
  return text === undefined ? null : {text, end: index + 1};
}

/** The index just past the > that ends a tag whose name ends at `from`, or -1 when the input ends first. A > inside a quoted attribute
 * value does not end the tag; a quote starts a value only after =, as the tokenizer's attribute states read it. */
function tagEnd(html, from) {
  let state = 'before', quote = 0;
  for (let index = from; index < html.length; index++) {
    const code = html.charCodeAt(index);
    if (state === 'quoted') { if (code === quote) state = 'before'; continue; }
    if (code === GT) return index + 1;
    const space = isAsciiSpace(code);
    if (state === 'before') { if (!space && code !== SLASH) state = 'name'; }
    else if (state === 'name') { if (space) state = 'after'; else if (code === SLASH) state = 'before'; else if (code === EQUALS) state = 'value'; }
    else if (state === 'after') { if (code === SLASH) state = 'before'; else if (code === EQUALS) state = 'value'; else if (!space) state = 'name'; }
    else if (state === 'value') { if (code === 0x22 || code === 0x27) { state = 'quoted'; quote = code; } else if (!space) state = 'unquoted'; }
    else if (space) state = 'before';
  }
  return -1;
}
/** The end of a tag name that starts at `from`: the first white space, / or >, or the end. */
function nameEnd(html, from) {
  let index = from;
  while (index < html.length && !isAsciiSpace(html.charCodeAt(index)) && html.charCodeAt(index) !== SLASH && html.charCodeAt(index) !== GT) index++;
  return index;
}
/** The index of the < of the end tag that closes raw text `name`, from `from` on, or -1. The name is followed by white space, / or >. */
function rawEnd(html, from, name) {
  for (let at = html.indexOf('</', from); at !== -1; at = html.indexOf('</', at + 2)) {
    const after = at + 2 + name.length;
    if (after >= html.length) return -1;
    const next = html.charCodeAt(after);
    if ((isAsciiSpace(next) || next === SLASH || next === GT) && foldAscii(html.slice(at + 2, after)) === name) return at;
  }
  return -1;
}
/**
 * The index of the < of the end tag that closes a script, from `from` on, or -1. Script text follows the tokenizer's script data states:
 * <!-- makes it escaped; inside an escape, a <script start (the name followed by white space, / or >) makes it double escaped, where the
 * next </script ends only that; --> leaves either. So a browser's script and this one end at the same tag. One pass, each < read once.
 */
function scriptEnd(html, from) {
  // 0: script data, 1: escaped, 2: double escaped. `dashes` counts the - just read, so --> is seen.
  let state = 0, dashes = 0;
  const script = at => at + 6 < html.length && foldAscii(html.slice(at, at + 6)) === 'script'
    && (isAsciiSpace(html.charCodeAt(at + 6)) || html.charCodeAt(at + 6) === SLASH || html.charCodeAt(at + 6) === GT);
  for (let at = from; at < html.length; at++) {
    const code = html.charCodeAt(at);
    if (code === DASH) { dashes++; continue; }
    const after = dashes;
    dashes = 0;
    if (code === GT) { if (state > 0 && after >= 2) state = 0; continue; }
    if (code !== LT) continue;
    if (html.charCodeAt(at + 1) === SLASH) {
      if (script(at + 2)) { if (state < 2) return at; state = 1; }
    } else if (state === 0) {
      if (html.startsWith('!--', at + 1)) { state = 1; dashes = 2; at += 3; }
    } else if (state === 1 && script(at + 1)) state = 2;
  }
  return -1;
}
/** The end of a comment whose <!-- ends just before `from`: past -->, --!>, or the > of <!--> and <!--->; the input's length when none. */
function commentEnd(html, from) {
  if (html.charCodeAt(from) === GT) return from + 1;
  if (html.startsWith('->', from)) return from + 2;
  for (let at = html.indexOf('--', from); at !== -1; at = html.indexOf('--', at + 1)) {
    if (html.charCodeAt(at + 2) === GT) return at + 3;
    if (html.startsWith('!>', at + 2)) return at + 4;
  }
  return html.length;
}
/** The index just past the next > from `from`, or the input's length: the end of a bogus comment. */
function bogusEnd(html, from) {
  const at = html.indexOf('>', from);
  return at === -1 ? html.length : at + 1;
}

/** The text being written: white space collapses, line breaks are counted, and there is never a break at the start. */
function textOut() {
  const pieces = [];
  let breaks = 0, space = false, empty = true;
  return {
    text(chars) { if (space && breaks === 0 && !empty) pieces.push(' '); pieces.push(chars); space = false; breaks = 0; empty = false; },
    verbatim(chars) { pieces.push(chars); space = false; breaks = chars === '\n' ? breaks + 1 : 0; empty = false; },
    space() { space = true; },
    lines(count) {
      space = false;
      if (empty) return;
      while (breaks < count) { pieces.push('\n'); breaks++; }
    },
    lineBreak() { space = false; if (!empty && breaks < 2) { pieces.push('\n'); breaks++; } },
    result() {
      const text = pieces.join('');
      let start = 0, end = text.length;
      while (start < end && text.charCodeAt(start) === LF) start++;
      while (end > start && isAsciiSpace(text.charCodeAt(end - 1))) end--;
      return text.slice(start, end);
    },
  };
}

/** The text of an HTML document, before the cut. */
function htmlText(html) {
  const out = textOut();
  let index = 0, template = 0, verbatim = 0, skipNewline = false;
  const put = chars => {
    const newline = skipNewline;
    skipNewline = false;
    if (template > 0 || chars === '\0') return;
    const code = chars.charCodeAt(0);
    if (verbatim > 0) {
      if (code === CR || code === LF) { if (!newline) out.verbatim('\n'); return; }
      out.verbatim(chars);
    } else if (chars.length === 1 && isAsciiSpace(code)) out.space();
    else out.text(chars);
  };
  // Characters from `from` to `to`: CRLF and CR read as LF, and references decode when `decode` is set.
  const putRun = (from, to, decode) => {
    for (let at = from; at < to;) {
      const code = html.charCodeAt(at);
      if (code === CR) { put('\n'); at += html.charCodeAt(at + 1) === LF && at + 1 < to ? 2 : 1; continue; }
      if (decode && code === AMP) {
        const found = reference(html, at);
        if (found && found.end <= to) { put(found.text); at = found.end; continue; }
      }
      put(html.charAt(at));
      at++;
    }
  };
  const block = count => { if (template === 0) out.lines(count); };
  const startTag = (name, end) => {
    if (name === 'template') { template++; return end; }
    if (DROPPED_RAW.has(name)) { const close = name === 'script' ? scriptEnd(html, end) : rawEnd(html, end, name); return close === -1 ? html.length : close; }
    if (name === 'plaintext') { block(1); verbatim++; putRun(end, html.length, false); return html.length; }
    if (KEPT_RAW.has(name)) {
      if (name === 'xmp') block(1);
      const close = rawEnd(html, end, name), stop = close === -1 ? html.length : close;
      verbatim++;
      skipNewline = name === 'textarea';
      putRun(end, stop, name === 'textarea');
      verbatim--;
      return stop;
    }
    if (name === 'br') { if (template === 0) out.lineBreak(); }
    else if (PARAGRAPHS.has(name)) block(2);
    else if (BLOCKS.has(name)) block(1);
    else if (CELLS.has(name)) { if (template === 0) out.space(); }
    if (VERBATIM.has(name) && template === 0) { verbatim++; skipNewline = true; }
    return end;
  };
  const endTag = name => {
    if (name === 'template') { if (template > 0) template--; return; }
    if (name === 'br') { if (template === 0) out.lineBreak(); return; }
    if (VERBATIM.has(name) && verbatim > 0 && template === 0) verbatim--;
    if (PARAGRAPHS.has(name)) block(2);
    else if (BLOCKS.has(name)) block(1);
  };
  while (index < html.length) {
    const lt = html.indexOf('<', index), stop = lt === -1 ? html.length : lt;
    putRun(index, stop, true);
    if (lt === -1) break;
    skipNewline = false;
    const next = html.charCodeAt(lt + 1);
    if (next === BANG) {
      if (html.startsWith('<!--', lt)) index = commentEnd(html, lt + 4);
      else if (html.startsWith('<![CDATA[', lt)) { const close = html.indexOf(']]>', lt + 9); index = close === -1 ? html.length : close + 3; }
      else index = bogusEnd(html, lt + 2);
    } else if (next === QUESTION) index = bogusEnd(html, lt + 2);
    else if (next === SLASH) {
      const first = html.charCodeAt(lt + 2);
      if (isLetter(first)) {
        const end = nameEnd(html, lt + 2), close = tagEnd(html, end);
        if (close === -1) break;
        endTag(foldAscii(html.slice(lt + 2, end)));
        index = close;
      } else if (first === GT) index = lt + 3;
      else if (lt + 2 >= html.length) { putRun(lt, html.length, false); break; }
      else index = bogusEnd(html, lt + 2);
    } else if (isLetter(next)) {
      const end = nameEnd(html, lt + 1), close = tagEnd(html, end);
      if (close === -1) break;
      index = startTag(foldAscii(html.slice(lt + 1, end)), close);
    } else { put('<'); index = lt + 1; }
  }
  return out.result();
}

/** The first `max` code points of `text`, or null when it has no more than that. */
function cut(text, max) {
  let points = 0;
  for (let index = 0; index < text.length; index++) {
    if (points === max) return text.slice(0, index);
    const code = text.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff && index + 1 < text.length) {
      const low = text.charCodeAt(index + 1);
      if (low >= 0xdc00 && low <= 0xdfff) index++;
    }
    points++;
  }
  return null;
}

export const ENTRY = {name: 'html.toText', version: 1, kind: 'map',
  input: {type: 'object', properties: {html: {type: 'string', maxLength: 1_000_000}}, required: ['html'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {text: {type: 'string', maxLength: MAX_TEXT}, truncated: {type: 'boolean', enum: [true]}}, required: ['text'], additionalProperties: false},
  maxInputBytes: 2_097_152, maxOutputBytes: 2_097_152, usesClock: false, runtimeFacts: [], refuses: [], excludes: [],
  example: {input: {html: '<p>Hello <b>there</b></p><script>steal()</script><p>Bye &amp; thanks</p>'}, output: {text: 'Hello there\n\nBye & thanks'}},
  run(input) {
    const text = htmlText(input.html), short = cut(text, MAX_TEXT);
    return short === null ? {text} : {text: short, truncated: true};
  }};

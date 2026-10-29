import test from 'node:test';
import assert from 'node:assert/strict';
import {TRANSFORMS, runTransform} from '../lib/transforms/index.mjs';
import {TransformError} from '../lib/transforms/_shared/error.v1.mjs';
import {vectorTests} from './fixtures/transform-vectors.mjs';

// F10.8 (docs/F10.8-BUILD-MAP.md part f): html.toText@1, a linear state machine with no backtracking regex, and the vectors of
// test/fixtures/transforms/html-text.json. Read email feeds it the decode's /html through {pick} (R1).
const ID = 'html.toText@1';
const refused = code => error => {
  assert.ok(error instanceof TransformError, `expected a TransformError, got ${error}`);
  assert.equal(error.code, code);
  return true;
};
const plain = html => {
  const result = runTransform(ID, {html});
  assert.equal(result.truncated, undefined, 'only a cut sets truncated');
  return result.text;
};
const codePoints = text => [...text].length;

vectorTests('html-text');

test('part f registers html.toText@1 with no code of its own, no runtime fact, and an input the decode\'s /html fits', () => {
  const entry = TRANSFORMS.get(ID);
  assert.ok(entry, ID);
  assert.deepEqual([entry.kind, entry.usesClock, entry.runtimeFacts, entry.refuses, entry.stepData], ['map', false, [], [], {}]);
  assert.deepEqual(entry.input.properties.html, {type: 'string', maxLength: 1_000_000});
  assert.deepEqual(entry.output.properties.text, {type: 'string', maxLength: 500_000});
  assert.ok(TRANSFORMS.get('rfc5322.decodeGmailPayload@1').output.properties.html.maxLength <= entry.input.properties.html.maxLength);
});

test('script, style, head, noscript, template, title, comments and CDATA are removed with their contents (spec line 691)', () => {
  assert.equal(plain('a<script>alert("x")</script>b'), 'ab');
  assert.equal(plain('a<SCRIPT type="text/javascript">x()</SCRIPT >b'), 'ab', 'tag names fold in ASCII case, and a space may follow the name');
  assert.equal(plain('a<script>if (a < b) { "</scriptx>"; }</script/>b'), 'ab', '</scriptx> does not end a script');
  assert.equal(plain('a<script>never closed <p>b</p>'), 'a', 'an unclosed script takes the rest');
  assert.equal(plain('a<script>x</script'), 'a', 'an end tag cut off by the end is not one');
  assert.equal(plain('<style>p > b { color: red } <b>x</b></style>Hi'), 'Hi', 'style is raw text: a tag inside is not one');
  for (const tag of ['style', 'title', 'noscript', 'iframe']) assert.equal(plain(`a<${tag}>x</${tag}x>y</${tag}\n>b`), 'ab', `</${tag}x> does not end ${tag}`);
  assert.equal(plain('<textarea>a</textareax>b</textarea>'), 'a</textareax>b', '</textareax> does not end a textarea');
  assert.equal(plain('<noscript><p>Turn on scripts</p></noscript>Hi'), 'Hi');
  assert.equal(plain('<template>a<template>b</template>c</template>d'), 'd', 'templates nest');
  assert.equal(plain('<template><script>x</script></template>e'), 'e');
  assert.equal(plain('<template><pre></template>a\n  b'), 'a b', 'a pre inside a template changes nothing outside it');
  assert.equal(plain('<pre>x<template></pre></template>\n  y</pre>z'), 'x\n  y\nz', 'nor does an end tag inside one');
  for (const tag of ['iframe', 'noembed', 'noframes', 'title']) assert.equal(plain(`a<${tag}>hidden <b>x</b></${tag}>b`), 'ab', tag);
  assert.equal(plain('<html><head><title>T</title><meta charset="utf-8"><style>p{}</style></head><body><p>Hello</p></body></html>'), 'Hello');
  // A head goes with its contents: what it holds is void or dropped, and text ends it, as parsers end it.
  assert.equal(plain('<head><title>T</title><body>Hi'), 'Hi');
  assert.equal(plain('<head><meta name="x"><link rel="y"><base href="z"><div>Hi</div>'), 'Hi');
  assert.equal(plain('<head>  <link rel="x">Hi'), 'Hi');
  assert.equal(plain('<head><noscript><link rel="x"></noscript><template>T</template></head>b'), 'b');
  assert.equal(plain('<head>a</head>b'), 'ab');
  assert.equal(plain('Hi <head>there'), 'Hi there');
  assert.equal(plain('a<!-- hidden <b>x</b> -->b'), 'ab');
  assert.equal(plain('a<!-->b'), 'ab', 'an empty comment');
  assert.equal(plain('a<!--->b'), 'ab');
  assert.equal(plain('a<!-- x --!>b'), 'ab');
  assert.equal(plain('a<!-- x --->b'), 'ab');
  assert.equal(plain('a<!-- never closed'), 'a');
  assert.equal(plain('a<![CDATA[x > y]]>b'), 'ab');
  assert.equal(plain('<!DOCTYPE html><?xml version="1.0"?>a<!bogus>b'), 'ab');
  assert.equal(plain('a</ x>b'), 'ab', 'an end tag open without a letter is a comment');
  // No script or style text reaches the output, whatever surrounds it.
  for (const html of ['<p><script>SECRET</script></p>', '<div><style>SECRET</style>', '<script><!--SECRET</script>', '<head><script>SECRET</script></head>', '<svg><script>SECRET</script></svg>',
    '<script\n>SECRET</script\t>', '<script src="x">SECRET']) {
    assert.ok(!plain(html).includes('SECRET'), html);
  }
});

test('a script follows the tokenizer\'s escaped states: after <!--, a <script> start holds the next </script>, and --> leaves the escape', () => {
  // The HTML Living Standard's script data escaped and double escaped states: a browser runs none of this text and shows none of it.
  assert.equal(plain('a<script><!--<script>x</script>SECRET</script>b'), 'ab', 'the inner </script> ends only the double escape');
  assert.equal(plain('a<script><!--<SCRIPT >x</Script/>SECRET</script>b'), 'ab', 'names fold in ASCII case and end at white space or /');
  assert.equal(plain('a<script><!--<script>x-->SECRET</script>b'), 'ab', '--> leaves the double escape, and the next </script> ends the script');
  assert.equal(plain('a<script><!--<script>x</script>y-->SECRET</script>b'), 'ab');
  assert.equal(plain('a<script><!--<script>x</script>SECRET<!--<script>y</script>SECRET</script>b'), 'ab', 'a second double escape inside the same escape');
  assert.equal(plain('a<script><!--</script>b'), 'ab', 'an escaped script still ends at its own end tag');
  assert.equal(plain('a<script><!-- x --></script>b'), 'ab');
  assert.equal(plain('a<script><!--><script></script>b'), 'ab', '<!--> leaves the escape at once');
  assert.equal(plain('a<script><!--<scripts></script>b'), 'ab', 'only <script followed by white space, / or > double escapes');
  assert.equal(plain('a<script><script></script>b'), 'ab', 'outside an escape a <script> start changes nothing');
  assert.equal(plain('a<script>--><!-<script></script>b'), 'ab', '<!- opens no escape, and --> outside one ends nothing');
  assert.equal(plain('a<script><!--<script>never closed</script>'), 'a', 'a double escape the input never leaves takes the rest');
  assert.equal(plain('a<style><!--<script></style>b'), 'ab', 'style has no escaped states');
  assert.equal(plain('a<template><script><!--<script></script>SECRET</script></template>b'), 'ab', 'inside a template too');
});

test('the named list holds HTML 4\'s whole symbol set, at the values the HTML Living Standard gives them', () => {
  // HTML 4's symbol set (HTMLsymbol.ent): each name and its code point in hex, in code-point order. The Living Standard moved only lang
  // and rang, to U+27E8 and U+27E9.
  const SYMBOLS = (`fnof 192 Alpha 391 Beta 392 Gamma 393 Delta 394 Epsilon 395 Zeta 396 Eta 397 Theta 398 Iota 399 Kappa 39a Lambda 39b Mu 39c Nu 39d Xi 39e Omicron 39f
    Pi 3a0 Rho 3a1 Sigma 3a3 Tau 3a4 Upsilon 3a5 Phi 3a6 Chi 3a7 Psi 3a8 Omega 3a9 alpha 3b1 beta 3b2 gamma 3b3 delta 3b4 epsilon 3b5 zeta 3b6 eta 3b7
    theta 3b8 iota 3b9 kappa 3ba lambda 3bb mu 3bc nu 3bd xi 3be omicron 3bf pi 3c0 rho 3c1 sigmaf 3c2 sigma 3c3 tau 3c4 upsilon 3c5 phi 3c6 chi 3c7
    psi 3c8 omega 3c9 thetasym 3d1 upsih 3d2 piv 3d6 bull 2022 hellip 2026 prime 2032 Prime 2033 oline 203e frasl 2044 image 2111 weierp 2118 real 211c
    trade 2122 alefsym 2135 larr 2190 uarr 2191 rarr 2192 darr 2193 harr 2194 crarr 21b5 lArr 21d0 uArr 21d1 rArr 21d2 dArr 21d3 hArr 21d4 forall 2200
    part 2202 exist 2203 empty 2205 nabla 2207 isin 2208 notin 2209 ni 220b prod 220f sum 2211 minus 2212 lowast 2217 radic 221a prop 221d infin 221e
    ang 2220 and 2227 or 2228 cap 2229 cup 222a int 222b there4 2234 sim 223c cong 2245 asymp 2248 ne 2260 equiv 2261 le 2264 ge 2265 sub 2282 sup 2283
    nsub 2284 sube 2286 supe 2287 oplus 2295 otimes 2297 perp 22a5 sdot 22c5 lceil 2308 rceil 2309 lfloor 230a rfloor 230b lang 27e8 rang 27e9 loz 25ca
    spades 2660 clubs 2663 hearts 2665 diams 2666`).split(/\s+/);
  assert.equal(SYMBOLS.length / 2, 124);
  for (let index = 0; index < SYMBOLS.length; index += 2) {
    assert.equal(plain(`a&${SYMBOLS[index]};b`), `a${String.fromCodePoint(Number.parseInt(SYMBOLS[index + 1], 16))}b`, SYMBOLS[index]);
  }
  assert.equal(plain('&alpha &Omega &rArr'), '&alpha &Omega &rArr', 'a symbol name still needs its semicolon');
  assert.equal(plain('&ALPHA; &Rarr;'), '&ALPHA; &Rarr;', 'names keep their case');
});

test('references: numeric and the reviewed named list decode; unknown names and a missing semicolon on a name stay as written', () => {
  assert.equal(plain('&amp; &lt; &gt; &quot; &apos; &#39; &#x27; &AMP;'), '& < > " \' \' \' &');
  assert.equal(plain('&#x1F600;&#128512;&#X1f600;'), '😀😀😀');
  assert.equal(plain('caf&eacute; &copy; 2026 &hellip; a&mdash;b &euro;5 &trade;'), 'café © 2026 … a\u2014b €5 ™', 'the dash is U+2014');
  assert.equal(plain('x&nbsp;&nbsp;y'), 'x  y', 'no-break spaces never collapse');
  assert.equal(plain('&nbsp;&iexcl;&Agrave;&times;&divide;&frac34;&THORN;&yuml;'), ' ¡À×÷¾Þÿ', 'the Latin-1 names map in order');
  assert.equal(plain('&bogus; &amp &copy &#x; &#; &'), '&bogus; &amp &copy &#x; &#; &');
  assert.equal(plain('&#65&#66;C'), 'ABC', 'a numeric reference may end without a semicolon');
  assert.equal(plain('&#0;&#xD800;&#xDFFF;&#x110000;&#99999999999999999999;'), '�'.repeat(5), 'NUL, surrogates and values past U+10FFFF become U+FFFD');
  assert.equal(plain('&#128;&#x99;&#x81;'), '€™\u0081', '0x80 to 0x9F read as windows-1252, as HTML does');
  assert.equal(plain('a&#32;&#32;b&#10;c'), 'a b c', 'a reference to white space collapses like white space');
  assert.equal(plain('<textarea>&amp;</textarea><xmp>&amp;</xmp>'), '&\n&amp;', 'textarea decodes references; xmp is raw text');
});

test('white space collapses; blocks and br become line breaks, paragraphs and headings a blank line; pre keeps its text', () => {
  assert.equal(plain('  a \n\t b  '), 'a b');
  assert.equal(plain('<div>a</div><div>b</div>'), 'a\nb');
  assert.equal(plain('<div>a</div> <div> b</div>'), 'a\nb');
  assert.equal(plain('a<br>b'), 'a\nb');
  assert.equal(plain('a<br/><br />b'), 'a\n\nb');
  assert.equal(plain('a<br><br><br><br>b'), 'a\n\nb', 'at most one blank line');
  assert.equal(plain('a</br>b'), 'a\nb', '</br> reads as <br>, as parsers read it');
  assert.equal(plain('<p>a</p><p>b</p>'), 'a\n\nb');
  assert.equal(plain('<h1>Title</h1>text'), 'Title\n\ntext');
  assert.equal(plain('<b>bold</b> and <i>it</i>'), 'bold and it');
  assert.equal(plain('<ul><li>one</li><li>two</li></ul>'), 'one\ntwo');
  assert.equal(plain('<table><tr><td>a</td><td>b</td></tr><tr><th>c</th></tr></table>'), 'a b\nc');
  assert.equal(plain('<pre>\n  a\n    b</pre>c'), '  a\n    b\nc', 'the first line break after <pre> goes, as parsers drop it');
  assert.equal(plain('<pre>a\r\nb\rc</pre>'), 'a\nb\nc', 'CRLF and CR read as LF');
  assert.equal(plain('a\r\nb'), 'a b');
  assert.equal(plain('<br><p>a</p><br>'), 'a', 'no line break at either end');
  assert.equal(plain('a\u0000b'), 'ab', 'a NUL in the text is dropped');
  assert.equal(plain(''), '');
});

test('markup that is not a tag stays text; a tag the input cuts off ends the text; quoted attribute values may hold >', () => {
  assert.equal(plain('a < b'), 'a < b');
  assert.equal(plain('1<2 and 3>2'), '1<2 and 3>2');
  assert.equal(plain('<<<'), '<<<');
  assert.equal(plain('a</'), 'a</');
  assert.equal(plain('a</>b'), 'ab');
  assert.equal(plain('<a title="x>y">link</a>'), 'link');
  assert.equal(plain('<a title=\'x>y\' data-x=1>link</a>'), 'link');
  assert.equal(plain('<img alt=">">done'), 'done');
  assert.equal(plain('<a "b>c">d'), 'c">d', 'a quote is a value only after =, so the tag ends at the first >');
  assert.equal(plain('text<div'), 'text');
  assert.equal(plain('ab<a href="x'), 'ab');
  assert.equal(plain('<a href=x>y</a>'), 'y');
});

test('the output is cut at 500,000 code points, never inside a surrogate pair, with truncated: true', () => {
  assert.equal(plain('a'.repeat(500_000)).length, 500_000);
  const cut = runTransform(ID, {html: 'a'.repeat(500_001)});
  assert.deepEqual([cut.text.length, cut.truncated], [500_000, true]);
  const pair = runTransform(ID, {html: `${'a'.repeat(499_999)}😀b`});
  assert.equal(pair.text, `${'a'.repeat(499_999)}😀`);
  assert.equal(pair.truncated, true);
  assert.equal(codePoints(pair.text), 500_000);
  assert.equal(plain(`${'😀'.repeat(500_000)}`).length, 1_000_000, '500,000 code points outside the BMP pass whole');
  assert.throws(() => runTransform(ID, {html: 'a'.repeat(1_000_001)}), refused('input_invalid'));
});

test('the scanner is linear: inputs that would make a backtracking parser crawl finish quickly', () => {
  for (const [what, html] of [['100,000 unfinished references', '&#'.repeat(100_000)], ['100,000 near end tags in a script', `<script>${'</scrip'.repeat(100_000)}`],
    ['100,000 near comment ends', `<!--${'--'.repeat(100_000)}`], ['100,000 nested templates', '<template>'.repeat(100_000)], ['100,000 quotes in attributes', `<a ${'b="x" '.repeat(100_000)}`],
    ['100,000 named references with no semicolon', '&abcdefghijklmnopqrstuvwxyzabcdefghij'.repeat(25_000)],
    ['50,000 double escapes in a script', `<script><!--${'<script></script>'.repeat(50_000)}`], ['100,000 near double escapes in a script', `<script><!--${'<scrip-->'.repeat(100_000)}`]]) {
    const started = performance.now();
    runTransform(ID, {html});
    assert.ok(performance.now() - started < 2000, `${what} took ${Math.round(performance.now() - started)} ms`);
  }
});

test('Read email: the decode\'s /html feeds html.toText@1, and its script and head never reach the text', () => {
  const html = '<html><head><title>Invoice</title><style>p{}</style></head><body><p>Your total is &euro;5.</p><script>steal()</script></body></html>';
  const message = {id: 'm1', threadId: 't1', payload: {partId: '', mimeType: 'multipart/alternative', filename: '', headers: [{name: 'From', value: 'shop@example.com'}], body: {size: 0},
    parts: [{partId: '0', mimeType: 'text/html', filename: '', headers: [{name: 'Content-Type', value: 'text/html; charset=UTF-8'}], body: {size: html.length, data: Buffer.from(html).toString('base64url')}}]}};
  const decoded = runTransform('rfc5322.decodeGmailPayload@1', {message});
  assert.equal(decoded.html, html);
  assert.deepEqual(runTransform(ID, {html: decoded.html}), {text: 'Your total is €5.'});
});

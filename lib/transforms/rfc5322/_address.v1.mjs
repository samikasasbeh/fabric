// F10.8 part e (docs/F10.8-BUILD-MAP.md): the RFC 5322 grammar the rfc5322 family reads and writes by. Address lists (section 3.4, with
// groups, comments and the obsolete forms of section 4.4) are read by a hand-written scanner, linear in its input: comments nest at most
// 32 deep and a value holds at most 1,000 addresses. The builder writes only ASCII dot-atom addresses of at most 254 characters, and message
// ids (section 3.6.4) of at most 900, so a field that holds one never passes 998 characters. Each function returns null or false for a bad
// value and leaves the code to its caller. No Unicode tables: a code point from U+0080 reads as atext (RFC 6532), and nothing folds case.

const MAX_COMMENT_DEPTH = 32;
const MAX_ADDRESSES = 1000;
const MAX_ADDRESS = 254;
const MAX_MESSAGE_ID = 900;
const MAX_REFERENCES = 100;
// atext (section 3.2.3), one piece of a dot-atom. Written without a repeated group, which the source scan refuses.
const ATOM = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+$/;
const DTEXT = /^\[[\x21-\x5a\x5e-\x7e]*\]$/;
const SPECIALS = '<>@,;:.';
const ATEXT = "!#$%&'*+-/=?^_`{|}~";

const dotAtom = text => text.length > 0 && text.split('.').every(part => ATOM.test(part));
const isAtext = code => (code >= 0x30 && code <= 0x39) || (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a) || code >= 0x80 || ATEXT.includes(String.fromCharCode(code));
const isSpace = code => code === 0x20 || code === 0x09 || code === 0x0d || code === 0x0a;

/** True for an address the builder writes: ASCII dot-atom, one @, dot-atom, at most 254 characters. */
export function buildableAddress(text) {
  if (typeof text !== 'string' || text.length > MAX_ADDRESS) return false;
  const at = text.indexOf('@');
  return at > 0 && text.lastIndexOf('@') === at && dotAtom(text.slice(0, at)) && dotAtom(text.slice(at + 1));
}

/** True for one msg-id: '<' dot-atom '@' (dot-atom or [dtext]) '>', at most 900 characters, nothing around it. */
export function validMessageId(text) {
  if (typeof text !== 'string' || text.length > MAX_MESSAGE_ID || !text.startsWith('<') || !text.endsWith('>')) return false;
  const inner = text.slice(1, -1), at = inner.indexOf('@');
  if (at < 1) return false;
  const right = inner.slice(at + 1);
  return dotAtom(inner.slice(0, at)) && (dotAtom(right) || DTEXT.test(right));
}

/** True for a References value the builder writes: 1 to 100 message ids, each followed by one space but the last. */
export function validReferences(text) {
  if (typeof text !== 'string') return false;
  const ids = text.split(' ');
  return ids.length <= MAX_REFERENCES && ids.every(validMessageId);
}

/** Every well-formed message id in a header value, in order: anything between them that is not one is skipped. */
export function messageIdsIn(text) {
  const ids = [];
  let index = 0;
  while (index < text.length) {
    const open = text.indexOf('<', index);
    if (open === -1) break;
    const close = text.indexOf('>', open);
    if (close === -1) break;
    const id = text.slice(open, close + 1);
    if (validMessageId(id)) ids.push(id);
    index = close + 1;
  }
  return ids;
}

/**
 * The tokens of a header value: words (atoms, and quoted strings unquoted), domain literals and the specials, each marked when white space
 * or a comment came before it. Null for anything no address list holds: a control outside a comment, a backslash outside quotes, an
 * unclosed quote, comment or literal, or comments nested over 32 deep.
 */
function tokenize(text) {
  const tokens = [];
  let space = false, index = 0;
  while (index < text.length) {
    const code = text.charCodeAt(index);
    if (isSpace(code)) { space = true; index++; continue; }
    if (code === 0x28) {
      let depth = 0, end = index;
      for (; end < text.length; end++) {
        const inner = text.charCodeAt(end);
        if (inner === 0x5c) { end++; continue; }
        if (inner === 0x28 && ++depth > MAX_COMMENT_DEPTH) return null;
        if (inner === 0x29 && --depth === 0) break;
      }
      if (end >= text.length) return null;
      index = end + 1;
      space = true;
      continue;
    }
    if (code === 0x22) {
      let value = '', end = index + 1, closed = false;
      for (; end < text.length; end++) {
        const inner = text.charCodeAt(end);
        if (inner === 0x5c && end + 1 < text.length) { end++; value += text.charAt(end); continue; }
        if (inner === 0x22) { closed = true; break; }
        // A fold inside a quoted string: the line break goes, its white space stays (section 3.2.2).
        if (inner === 0x0d || inner === 0x0a) continue;
        if (inner < 0x20 && inner !== 0x09) return null;
        value += text.charAt(end);
      }
      if (!closed) return null;
      tokens.push({type: 'word', quoted: true, text: value, space});
      space = false;
      index = end + 1;
      continue;
    }
    if (code === 0x5b) {
      const end = text.indexOf(']', index);
      if (end === -1) return null;
      const literal = `[${text.slice(index + 1, end).replace(/[ \t\r\n]/g, '')}]`;
      if (!DTEXT.test(literal)) return null;
      tokens.push({type: 'literal', text: literal, space});
      space = false;
      index = end + 1;
      continue;
    }
    if (SPECIALS.includes(text.charAt(index))) {
      tokens.push({type: text.charAt(index), space});
      space = false;
      index++;
      continue;
    }
    if (!isAtext(code)) return null;
    let end = index;
    while (end < text.length && isAtext(text.charCodeAt(end))) end++;
    tokens.push({type: 'word', quoted: false, text: text.slice(index, end), space});
    space = false;
    index = end;
  }
  return tokens;
}

const quote = text => `"${text.replace(/["\\]/g, '\\$&')}"`;

/** An address list's addresses: {name?, address, group?}, names as written, unquoted; null when the value is no address list. */
export function parseAddressList(text) {
  if (typeof text !== 'string') return null;
  const tokens = tokenize(text);
  if (tokens === null) return null;
  const type = position => tokens.at(position)?.type;
  const out = [];
  let pos = 0;

  /** The display name of tokens [from, to): words and the dots of an obsolete phrase, '' when there are none, null otherwise. */
  function phrase(from, to) {
    let name = '';
    for (const token of tokens.slice(from, to)) {
      if (token.type !== 'word' && token.type !== '.') return null;
      name += `${token.space && name ? ' ' : ''}${token.type === '.' ? '.' : token.text}`;
    }
    return name;
  }
  /** The addr-spec of tokens [from, to): local-part '@' domain, with the obsolete dots between words; null otherwise. */
  function addrSpec(from, to) {
    const slice = tokens.slice(from, to), at = slice.findIndex(token => token.type === '@');
    if (at < 1) return null;
    const local = slice.slice(0, at), domain = slice.slice(at + 1);
    const words = (list, quoted) => list.length % 2 === 1 && list.every((token, index) => index % 2 === 1 ? token.type === '.' : token.type === 'word' && (quoted || !token.quoted));
    if (!words(local, true)) return null;
    const left = local.map(token => token.type === '.' ? '.' : token.quoted ? quote(token.text) : token.text).join('');
    if (domain.length === 1 && domain.at(0).type === 'literal') return `${left}@${domain.at(0).text}`;
    return words(domain, false) ? `${left}@${domain.map(token => token.type === '.' ? '.' : token.text).join('')}` : null;
  }
  /** One mailbox from pos: a name-addr (with an obsolete route) or an addr-spec, ending before a ',' or ';'. */
  function mailbox() {
    let end = pos;
    while (end < tokens.length && !['<', ',', ';', ':'].includes(type(end))) end++;
    if (type(end) === '<') {
      const name = phrase(pos, end);
      if (name === null) return null;
      pos = end + 1;
      if (type(pos) === '@' || type(pos) === ',') {
        while (pos < tokens.length && type(pos) !== ':' && type(pos) !== '>' && type(pos) !== '<') pos++;
        if (type(pos) !== ':') return null;
        pos++;
      }
      let close = pos;
      while (close < tokens.length && type(close) !== '>' && type(close) !== '<') close++;
      if (type(close) !== '>') return null;
      const address = addrSpec(pos, close);
      pos = close + 1;
      return address === null ? null : name ? {name, address} : {address};
    }
    const address = addrSpec(pos, end);
    pos = end;
    return address === null ? null : {address};
  }
  const add = item => { out.push(item); return out.length <= MAX_ADDRESSES; };

  while (pos < tokens.length) {
    if (type(pos) === ',') { pos++; continue; }
    let end = pos;
    while (end < tokens.length && !['<', ',', ';', ':'].includes(type(end))) end++;
    if (type(end) === ':') {
      const group = phrase(pos, end);
      if (!group) return null;
      pos = end + 1;
      while (pos < tokens.length && type(pos) !== ';') {
        if (type(pos) === ',') { pos++; continue; }
        const box = mailbox();
        if (box === null || !add({...box, group})) return null;
        if (pos < tokens.length && type(pos) !== ',' && type(pos) !== ';') return null;
      }
      if (type(pos) !== ';') return null;
      pos++;
    } else {
      const box = mailbox();
      if (box === null || !add(box)) return null;
    }
    if (pos < tokens.length && type(pos) !== ',') return null;
  }
  return out;
}

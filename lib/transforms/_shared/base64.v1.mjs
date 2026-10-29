// F10.8 part b (docs/F10.8-BUILD-MAP.md part d): strict base64 and base64url. Buffer decodes leniently: it drops characters outside the
// alphabet, accepts both alphabets in either mode and skips whitespace (measured: 'aGVs*bG8' decodes to "hello"). So every text is
// checked before Buffer sees it: one alphabet, padding either correct or absent, canonical trailing bits, and no whitespace but a line
// feed in `lf` mode, for GitHub's wrapped contents. Encoding always writes padding.

const ALPHABETS = Object.freeze({
  base64: /^[A-Za-z0-9+/]*$/,
  base64url: /^[A-Za-z0-9_-]*$/,
});
const SIXTY_FOUR = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const alphabetOf = name => {
  if (name === 'base64') return ALPHABETS.base64;
  if (name === 'base64url') return ALPHABETS.base64url;
  throw new Error('The alphabet is base64 or base64url.');
};
/** The 6-bit value of one alphabet character. */
const sextet = char => char === '+' || char === '-' ? 62 : char === '/' || char === '_' ? 63 : SIXTY_FOUR.indexOf(char);

/** Padded base64 or base64url of the bytes. */
export function encodeBase64(bytes, alphabet) {
  alphabetOf(alphabet);
  if (!(bytes instanceof Uint8Array)) throw new Error('encodeBase64 takes bytes.');
  const text = Buffer.from(bytes).toString('base64');
  return alphabet === 'base64' ? text : text.replace(/\+/g, '-').replace(/\//g, '_');
}

/** The bytes of strict base64 or base64url text, or null when the text is not exactly that. */
export function decodeBase64(text, alphabet, lineBreaks = 'none') {
  const pattern = alphabetOf(alphabet);
  if (lineBreaks !== 'none' && lineBreaks !== 'lf') throw new Error('The line breaks are none or lf.');
  if (typeof text !== 'string') return null;
  const flat = lineBreaks === 'lf' ? text.split('\n').join('') : text;
  let body = flat, pads = 0;
  while (pads < 2 && body.endsWith('=')) { body = body.slice(0, -1); pads++; }
  const rest = body.length % 4;
  if (!pattern.test(body) || rest === 1 || (pads > 0 && pads !== 4 - rest)) return null;
  // The unused low bits of the last character must be zero, so each byte string has exactly one encoding.
  if (rest === 2 && sextet(body.at(-1)) % 16 !== 0) return null;
  if (rest === 3 && sextet(body.at(-1)) % 4 !== 0) return null;
  return new Uint8Array(Buffer.from(body, 'base64'));
}

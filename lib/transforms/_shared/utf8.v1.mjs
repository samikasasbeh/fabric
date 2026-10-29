// F10.8 part b (docs/F10.8-BUILD-MAP.md): strict UTF-8 both ways. Bytes become text only through a fatal decoder that keeps a leading
// byte-order mark (so it can be refused as a hidden character instead of vanishing), as the proxy decodes (lib/proxy-request.mjs:23).
// Copied, not imported, so an edit there never moves a pin. Text with a lone surrogate has no UTF-8 form.

const STRICT = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true});
const ENCODER = new TextEncoder();

/** The text of UTF-8 bytes, or null when they are not valid UTF-8. Nothing is ever replaced with U+FFFD. */
export function decodeUtf8(bytes) {
  try { return STRICT.decode(bytes); } catch { return null; }
}

/** The UTF-8 bytes of well-formed text, or null when the text holds a lone surrogate. */
export function encodeUtf8(text) {
  return typeof text === 'string' && text.isWellFormed() ? ENCODER.encode(text) : null;
}

import {credentialName, nameWords} from './compiler.mjs';

// F09.1 value redaction (docs/F09-COMPILER-COVERAGE.md I6). One scrubber for every place a provider's answer or an
// error can carry a credential back: typed results, readback, proxy responses and errors. Credentials are matched by
// value in every spelling, and fields with credential-shaped names are dropped whatever their value.

/** The credential values a connection sends: each credential header value, with and without its "Bearer" or "Basic" prefix. */
export function credentialValues(headers) {
  return [...new Set(Object.entries(headers || {}).filter(([name]) => /authorization|token|api-key|cookie/i.test(name)).flatMap(([, value]) => [String(value), String(value).replace(/^(?:Bearer|Basic)\s+/i, '')]).filter(Boolean))];
}
/** A scrub context for these values: each value raw, JSON-escaped, URL-encoded and form-encoded, longest first. */
export function secretContext(values) {
  const forms = [...new Set(values.flatMap(value => [value, JSON.stringify(value).slice(1, -1), encodeURIComponent(value), new URLSearchParams({v: value}).toString().slice(2)]))].sort((a, b) => b.length - a.length);
  return {values: [...values], forms, count: 0};
}
/** Percent-decodes every run of valid escapes (any hex case), leaving anything malformed as it is. */
function percentDecoded(text) {return text.replace(/(?:%[0-9a-fA-F]{2})+/g, run => {try {return decodeURIComponent(run);} catch {return run;}});}
/**
 * One string with every credential removed: the raw value and its JSON-escaped and URL-encoded spellings are replaced;
 * if any other spelling is still there once percent escapes ("+" as a space too) are decoded, the whole string goes.
 */
export function scrubString(text, ctx) {
  let out = String(text);
  for (const form of ctx.forms) {const parts = out.split(form); if (parts.length > 1) {ctx.count += parts.length - 1; out = parts.join('[redacted]');}}
  const views = [percentDecoded(out), percentDecoded(out.replace(/\+/g, '%20'))];
  if (ctx.values.some(value => views.some(view => view.includes(value)))) {ctx.count++; return '[redacted]';}
  return out;
}
// Field names whose value is always a credential, whatever its type.
const SECRET_KEY = /^(access_token|refresh_token|id_token|client_secret|api_key|authorization|cookie|set-cookie|password|pem|encoded_jit_config|jit_config)$/i;
// Words before "token" that make it a position marker, not a credential (nextPageToken, syncToken).
const NOT_A_CREDENTIAL = new Set(['page', 'next', 'prev', 'previous', 'sync', 'continuation', 'start', 'resume', 'cursor', 'skip', 'idempotency', 'cache', 'etag', 'nonce']);
// Plural heads name collections or permission levels (GitHub's "organization_personal_access_tokens": "read").
const COLLECTIONS = new Set(['tokens', 'keys', 'credentials']);
/** A field whose value is always a credential. */
export const fixedSecretKey = name => SECRET_KEY.test(name);
/** A field whose string value is a credential: auth, a credential-shaped name, or a token that is not a position marker. */
export function credentialKey(name) {
  const words = nameWords(name), head = words.at(-1);
  if (!head || COLLECTIONS.has(head)) return false;
  return name === 'auth' || credentialName(name) || (head === 'token' && words.length > 1 && !NOT_A_CREDENTIAL.has(words.at(-2)));
}
/** A response field that carries a credential, by name alone. */
export const secretKey = name => fixedSecretKey(name) || credentialKey(name);
/**
 * A parsed value with every string and key scrubbed. Fixed credential fields lose their value whatever its type; other
 * credential-named fields lose strings and lists of strings, keep their nested objects (scrubbed), and keep numbers,
 * booleans and null, which cannot carry a credential.
 */
export function scrubValue(value, ctx) {
  if (typeof value === 'string') return scrubString(value, ctx);
  if (Array.isArray(value)) return value.map(item => scrubValue(item, ctx));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => {
    const name = scrubString(key, ctx);
    // A pem field is a credential only when it holds a private key; certificates and public keys are kept.
    if (/^pem$/i.test(key) ? typeof item !== 'string' || /PRIVATE KEY/.test(item)
      : fixedSecretKey(key) || (credentialKey(key) && (typeof item === 'string' || (Array.isArray(item) && item.length > 0 && item.every(entry => typeof entry === 'string'))))) {ctx.count++; return [name, '[redacted]'];}
    return [name, scrubValue(item, ctx)];
  }));
  return value;
}
/** Free text for logs and reports: bearer values in any case, and Basic credentials (case-sensitive, so the word "basic" survives). */
export function scrubAuthorization(text) {return String(text).replace(/Bearer\s+\S+/gi, '[redacted]').replace(/Basic\s+[A-Za-z0-9+/=]{8,}/g, '[redacted]');}

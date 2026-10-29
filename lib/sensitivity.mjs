import {credentialName, nameWords as words} from './compiler.mjs';
import {fixedSecretKey, credentialKey} from './redaction.mjs';

// F09.1 classifiers (docs/F09-COMPILER-COVERAGE.md I9). Two kinds of operation never get a standing Allow by default,
// and a row-level Allow never covers them:
// - "secrets": its documented response carries a credential field (Twilio's account read returns the auth token,
//   GitHub's manifest conversion returns a client secret and private key), or, with no documented response, its
//   name says it does;
// - "suspected-write": a GET or HEAD whose name says it changes something (deleteThing, Items_Delete).
// Both only make defaults stricter. The HTTP method still decides the effect (I5).

const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const BUDGET = 20_000;
/** Bumped whenever these rules change: maps classified by an older version are classified again when read. */
export const SENSITIVITY_VERSION = 1;
// Descriptions that say a field is never sent back or is public (Gmail SmtpMsa.password, S/MIME and CSE certificates).
const NOT_RETURNED = /never populated in responses|not returned in responses|write[- ]only|not (?:a |the )?private key|output only\.?[^.]{0,80}\bpublic\b/i;
// Google Calendar conference entry points carry meeting join codes (password, passcode, pin, accessCode): meeting
// content the calendar's own users see, not credentials to the account or the API.
const CONTENT_SCHEMAS = new Set(['google-discovery:EntryPoint']);


const READ_VERBS = new Set(['get', 'list', 'search', 'read', 'retrieve', 'fetch', 'describe', 'query', 'find', 'check', 'count', 'export', 'download', 'lookup', 'look', 'show', 'view', 'head', 'poll', 'preview', 'browse', 'watch', 'stream', 'scan', 'inspect', 'compare', 'estimate', 'batch']);
const MUTATING_VERBS = new Set(['delete', 'remove', 'destroy', 'purge', 'erase', 'wipe', 'clear', 'reset', 'revoke', 'cancel', 'abort', 'terminate', 'kill', 'stop', 'start', 'restart', 'run', 'rerun', 'execute', 'exec', 'trigger', 'invoke',
  'send', 'post', 'publish', 'push', 'submit', 'create', 'add', 'insert', 'new', 'make', 'generate', 'regenerate', 'rotate', 'issue', 'mint', 'update', 'set', 'put', 'patch', 'modify', 'edit', 'change', 'rename', 'move', 'copy', 'merge',
  'import', 'upload', 'approve', 'reject', 'accept', 'decline', 'deny', 'grant', 'assign', 'unassign', 'enable', 'disable', 'activate', 'deactivate', 'archive', 'unarchive', 'restore', 'lock', 'unlock', 'block', 'unblock', 'ban', 'unban',
  'mute', 'unmute', 'pin', 'unpin', 'star', 'unstar', 'follow', 'unfollow', 'subscribe', 'unsubscribe', 'join', 'leave', 'invite', 'share', 'unshare', 'transfer', 'pay', 'refund', 'charge', 'capture', 'void', 'book', 'reserve', 'order',
  'buy', 'purchase', 'sell', 'sign', 'mark', 'flag', 'close', 'reopen', 'complete', 'finish', 'confirm', 'sync', 'refresh', 'retry', 'replay', 'dispatch', 'notify', 'like', 'unlike', 'vote', 'react', 'hide', 'unhide', 'logout', 'login',
  'register', 'unregister', 'apply', 'install', 'uninstall', 'deploy', 'release', 'rollback', 'schedule', 'unschedule', 'convert', 'attach', 'detach', 'link', 'unlink', 'connect', 'disconnect', 'upgrade', 'downgrade', 'renew', 'extend',
  'increment', 'decrement', 'toggle', 'save', 'store', 'write', 'empty', 'flush', 'rebuild', 'reindex', 'provision', 'deprovision', 'enroll', 'unenroll', 'redeem', 'claim', 'dismiss', 'resolve', 'escalate', 'forward', 'reply']);

/** The words of an operation's name as the provider wrote it: after the last "/" (GitHub) or "." (Google method ids). */
function operationWords(capability) {
  const id = typeof capability?.provenance?.operationId === 'string' ? capability.provenance.operationId : '';
  const tail = id.includes('/') ? id.slice(id.lastIndexOf('/') + 1) : /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$/.test(id) ? id.slice(id.lastIndexOf('.') + 1) : id;
  return words(tail || capability?.name || '');
}

/** A GET or HEAD whose name says it changes something: its first word is a change, or it does not start with a read and ends with one. */
export function suspectedWrite(capability) {
  if (capability?.driver !== 'http' || !['GET', 'HEAD'].includes(String(capability.request?.method).toUpperCase())) return false;
  const words = operationWords(capability), list = words[0] === 're' && words.length > 1 ? words.slice(1) : words, first = list[0], last = list.at(-1);
  return Boolean(first && (MUTATING_VERBS.has(first) || (!READ_VERBS.has(first) && MUTATING_VERBS.has(last))));
}

/** True when text mentions a credential at any word position (createRegistrationToken, list-repo-secrets). */
export function mentionsCredential(text) {
  const list = words(text);
  return list.includes('secrets') || list.some((_, index) => credentialName(list.slice(0, index + 1).join('_')));
}

/** A response field that carries a credential: its name says so, and its schema neither rules it out nor calls it public. */
function returnsCredential(name, schema) {
  if (record(schema)) {
    if (['integer', 'number', 'boolean'].includes(schema.type) || Array.isArray(schema.enum) || schema.writeOnly === true) return false;
    if (typeof schema.description === 'string' && NOT_RETURNED.test(schema.description)) return false;
  }
  return fixedSecretKey(name) || credentialKey(name);
}

/**
 * The credential fields of a documented response: OpenAPI {responses, components} or Google {root, schemas}.
 * Returns null when there is no documented response, and ['(too large to inspect)'] when the walk runs out of budget.
 */
export function responseSecretFields(responseSchema) {
  if (!record(responseSchema)) return null;
  const google = responseSchema.dialect === 'google-discovery', dialect = google ? 'google-discovery' : 'openapi';
  if (google ? !record(responseSchema.root) : !record(responseSchema.responses) || !Object.keys(responseSchema.responses).length) return null;
  const found = new Set(), seen = new Set();
  let nodes = 0;
  const lookup = ref => {
    if (typeof ref !== 'string') return undefined;
    if (google) return record(responseSchema.schemas) && Object.hasOwn(responseSchema.schemas, ref) ? {name: ref, schema: responseSchema.schemas[ref]} : undefined;
    const match = /^#\/components\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/.exec(ref);
    const section = match && record(responseSchema.components) ? responseSchema.components[match[1]] : undefined;
    return match && record(section) && Object.hasOwn(section, match[2]) ? {name: match[2], schema: section[match[2]]} : undefined;
  };
  const resolved = value => record(value) && typeof value.$ref === 'string' ? lookup(value.$ref)?.schema ?? value : value;
  // `owner` is the named schema whose properties are being read, so content schemas can be told apart.
  const walk = (value, names = false, owner = null) => {
    if (++nodes > BUDGET) throw new Error('budget');
    if (Array.isArray(value)) { value.forEach(item => walk(item, false, owner)); return; }
    if (!record(value)) return;
    if (!names && typeof value.$ref === 'string' && !seen.has(value.$ref)) {
      seen.add(value.$ref);
      const target = lookup(value.$ref);
      if (target) walk(target.schema, false, target.name);
    }
    for (const [key, item] of Object.entries(value)) {
      if (names && !CONTENT_SCHEMAS.has(`${dialect}:${owner}`) && returnsCredential(key, resolved(item))) found.add(key);
      walk(item, !names && key === 'properties', owner);
    }
  };
  try { walk(google ? responseSchema.root : responseSchema.responses); } catch { return ['(too large to inspect)']; }
  return [...found].sort();
}

/**
 * Why an operation is sensitive, or null. A documented response decides by its fields (a response too large to inspect
 * counts as secrets); with none, a credential mention in the operation name does. Direct imports are read from their
 * stored description by the permission manager.
 */
export function sensitivity(capability, operation) {
  const fields = responseSecretFields(operation?.responseSchema);
  if (fields ? fields.length > 0 : mentionsCredential(capability?.provenance?.operationId || capability?.name || '')) return 'secrets';
  if (suspectedWrite(capability)) return 'suspected-write';
  return null;
}

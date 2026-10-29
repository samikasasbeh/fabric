// F10.8 part i (docs/F10.8-BUILD-MAP.md): the one URL reader ids.notionId@1 and ids.slackLink@1 share. It reads a link a person pasted
// and returns its parts; no ids transform ever outputs a URL or a host (I4). Written by hand, with no URL parser: an https URL of
// printable ASCII with no space, a host of letters, digits, dots and hyphens (no user, password or port), folded to lower case, then an
// optional path, query and fragment. Each caller checks the host against its own list.
import {foldAscii} from '../_shared/ascii.v1.mjs';

const PRINTABLE = /^[\x21-\x7e]+$/;
const HOST = /^[A-Za-z0-9.-]+$/;
const MAX_LENGTH = 2048;

/** {host, path, query} of an https URL (host folded to lower case, path starting with / or empty, query without its ?), or null. */
export function httpsUrl(text) {
  if (typeof text !== 'string' || text.length > MAX_LENGTH || !PRINTABLE.test(text) || foldAscii(text.slice(0, 8)) !== 'https://') return null;
  const rest = text.slice(8), hash = rest.indexOf('#'), beforeHash = hash === -1 ? rest : rest.slice(0, hash);
  const question = beforeHash.indexOf('?'), beforeQuery = question === -1 ? beforeHash : beforeHash.slice(0, question);
  const slash = beforeQuery.indexOf('/'), host = slash === -1 ? beforeQuery : beforeQuery.slice(0, slash);
  if (!HOST.test(host)) return null;
  return {host: foldAscii(host), path: slash === -1 ? '' : beforeQuery.slice(slash), query: question === -1 ? '' : beforeHash.slice(question + 1)};
}

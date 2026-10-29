// F10.8 part b (docs/F10.8-BUILD-MAP.md part i): the GitHub owner and repository rule that ids.ownerRepo@1 and text.githubQuery@1
// share. An owner is 1 to 39 letters, digits or single inner hyphens; a repository is 1 to 100 letters, digits, '-', '_' or '.', never
// '.' or '..'. Written as loops, since the obvious regex for the owner repeats a group that holds a quantifier.

const isAlnum = code => (code >= 0x30 && code <= 0x39) || (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a);

/** True for a GitHub owner name. */
export function validOwner(text) {
  if (typeof text !== 'string' || text.length < 1 || text.length > 39) return false;
  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index);
    if (isAlnum(code)) continue;
    if (code !== 0x2d || index === 0 || index === text.length - 1 || text.charCodeAt(index - 1) === 0x2d) return false;
  }
  return true;
}

/** True for a GitHub repository name. */
export function validRepo(text) {
  if (typeof text !== 'string' || text.length < 1 || text.length > 100 || text === '.' || text === '..') return false;
  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index);
    if (!isAlnum(code) && code !== 0x2d && code !== 0x5f && code !== 0x2e) return false;
  }
  return true;
}

/** {owner, repo} of 'owner/repo', or null unless it is exactly one valid owner and one valid repository. */
export function splitOwnerRepo(text) {
  if (typeof text !== 'string') return null;
  const parts = text.split('/');
  return parts.length === 2 && validOwner(parts[0]) && validRepo(parts[1]) ? {owner: parts[0], repo: parts[1]} : null;
}

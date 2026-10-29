// F10.8 part h (docs/F10.8-BUILD-MAP.md, open point Important 5): text.githubQuery@1 (unicode). In: `type` ('issue' or 'pull-request',
// required), `repo` ({owner, name}, optional), `scope` (author, assignee, mentions, involves or review-requested), `state` (open or
// closed) and `text`, the user's words. Out: {q}, written in this fixed order:
//   is:<type> repo:<owner>/<name> <scope>:@me is:<state> "word" "word" ...
// - is:issue or is:pull-request is always there (spec line 1342).
// - The repository is checked by _shared/ownerRepo.v1.mjs, the rule ids.ownerRepo@1 uses: repo_invalid. Without one, an @me scope is
//   required, so "my open pull requests" works across the owner's repositories: neither refuses with query_scope_missing.
// - User text is split at spaces and each word is quoted, so a user's is:, type:, repo: or org: stays a quoted word, never a qualifier.
//   Text that could leave its quotes (a double quote, a backslash, a control, a hidden or direction character, a lone surrogate) refuses
//   with query_value_invalid: foo" repo:x/y "bar would otherwise close the quote and search another repository.
// - GitHub's own limits on the text: more than 256 characters (code points) refuses with query_too_long, and more than five AND, OR or
//   NOT with too_many_operators. Quoted, they are words, but GitHub's documented rule still counts them.
import {TransformError} from '../_shared/error.v1.mjs';
import {validOwner, validRepo} from '../_shared/ownerRepo.v1.mjs';
import {quotable, quote} from './_quote.v1.mjs';

const MAX_TEXT = 256;
const MAX_OPERATORS = 5;
const OPERATOR = new Set(['AND', 'OR', 'NOT']);
const refuse = code => { throw new TransformError(code); };

export const ENTRY = {name: 'text.githubQuery', version: 1, kind: 'map',
  input: {type: 'object', properties: {type: {type: 'string', enum: ['issue', 'pull-request']},
    repo: {type: 'object', properties: {owner: {type: 'string', minLength: 1, maxLength: 100}, name: {type: 'string', minLength: 1, maxLength: 200}}, required: ['owner', 'name'],
      additionalProperties: false},
    scope: {type: 'string', enum: ['author', 'assignee', 'mentions', 'involves', 'review-requested']}, state: {type: 'string', enum: ['open', 'closed']},
    text: {type: 'string', maxLength: 1000}}, required: ['type'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {q: {type: 'string', maxLength: 4096}}, required: ['q'], additionalProperties: false},
  maxInputBytes: 16_384, maxOutputBytes: 16_384, usesClock: false, runtimeFacts: ['unicode'],
  refuses: ['query_value_invalid', 'query_scope_missing', 'query_too_long', 'too_many_operators', 'repo_invalid'], excludes: [],
  example: {input: {type: 'pull-request', scope: 'author', state: 'open', text: 'fix login'}, output: {q: 'is:pull-request author:@me is:open "fix" "login"'}},
  run(input) {
    const text = input.text ?? '';
    if (!quotable(text)) refuse('query_value_invalid');
    if ([...text].length > MAX_TEXT) refuse('query_too_long');
    const words = text.split(' ').filter(word => word !== '');
    if (words.filter(word => OPERATOR.has(word)).length > MAX_OPERATORS) refuse('too_many_operators');
    const repo = input.repo;
    if (repo !== undefined && !(validOwner(repo.owner) && validRepo(repo.name))) refuse('repo_invalid');
    if (repo === undefined && input.scope === undefined) refuse('query_scope_missing');
    const parts = [`is:${input.type}`];
    if (repo !== undefined) parts.push(`repo:${repo.owner}/${repo.name}`);
    if (input.scope !== undefined) parts.push(`${input.scope}:@me`);
    if (input.state !== undefined) parts.push(`is:${input.state}`);
    return {q: [...parts, ...words.map(quote)].join(' ')};
  }};

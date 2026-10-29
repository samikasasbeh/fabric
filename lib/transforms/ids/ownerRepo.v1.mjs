// F10.8 part i (docs/F10.8-BUILD-MAP.md): ids.ownerRepo@1. In: {value}, 'owner/repo'. Out: {owner, repo}. The rule lives in
// _shared/ownerRepo.v1.mjs, which text.githubQuery@1 uses too: an owner of 1 to 39 letters, digits or single inner hyphens, and a
// repository of 1 to 100 letters, digits, '-', '_' or '.', never '.' or '..'. Anything else refuses with repo_invalid.
import {TransformError} from '../_shared/error.v1.mjs';
import {splitOwnerRepo} from '../_shared/ownerRepo.v1.mjs';

export const ENTRY = {name: 'ids.ownerRepo', version: 1, kind: 'map',
  input: {type: 'object', properties: {value: {type: 'string', maxLength: 512}}, required: ['value'], additionalProperties: false},
  pointerArgs: [], stepData: {}, resolvedValues: {},
  output: {type: 'object', properties: {owner: {type: 'string', minLength: 1, maxLength: 39}, repo: {type: 'string', minLength: 1, maxLength: 100}}, required: ['owner', 'repo'],
    additionalProperties: false},
  maxInputBytes: 1024, maxOutputBytes: 512, usesClock: false, runtimeFacts: [], refuses: ['repo_invalid'], excludes: [],
  example: {input: {value: 'octo/hello-world'}, output: {owner: 'octo', repo: 'hello-world'}},
  run(input) {
    const split = splitOwnerRepo(input.value);
    if (split === null) throw new TransformError('repo_invalid');
    return {owner: split.owner, repo: split.repo};
  }};

// F10.17 part 1 (docs/F10.17-BUILD-MAP.md part 1, F10.8 map parts b and k): the codes step 17 adds, in the next error file, so
// error.v1.mjs and every step 8 pin stay as they were. It re-exports TransformError from v1 and lists codes only; lib/transforms/index.mjs
// reads it with v1, and the version modules whose codes it names import TransformError from here, so their pins cover this list.
// - ids gains path_invalid (ids.repoPath@1).
// - collections gains name_invalid and name_repeated (collections.stringValues@1).
// text.mentions@1 only flags, so it adds no code. ids.linkPage@1 and its link_invalid were cut (one page per job, open question 2).
export {TransformError} from './error.v1.mjs';

/** The codes each family gains in step 17; the registry's union keeps every v1 code. */
export const FAMILY_CODES = Object.freeze({
  ids: Object.freeze(['path_invalid']),
  collections: Object.freeze(['name_invalid', 'name_repeated']),
});

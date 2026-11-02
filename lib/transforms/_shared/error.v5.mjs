// Iteration 9 step 6 (docs/I07-BUILD-MAP.md section 2.7): step 6's code. It re-exports TransformError from error.v1.mjs and adds lists only, so no
// existing pin moves: ids.linkPage@1 refuses with link_invalid, which F10.17 cut with the transform (error.v2.mjs) and this step brings back.
export {TransformError} from './error.v1.mjs';

/** The codes step 6 adds, by family. lib/transforms/index.mjs joins them with every other error file's. */
export const FAMILY_CODES = Object.freeze({
  ids: Object.freeze(['link_invalid']),
});

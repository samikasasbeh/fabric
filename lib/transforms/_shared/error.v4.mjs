// F10.21 part 1 e (docs/F10.21-BUILD-MAP.md part 1 e; docs/F10.8-BUILD-MAP.md lines 433-440): step 21's codes. It re-exports TransformError
// from error.v1.mjs and adds lists only, so no existing pin moves: ids.slackEmoji@1 refuses with emoji_invalid. text.slackQuery@1 uses the
// step 8 codes query_value_invalid and query_too_long, so it needs no code here.
export {TransformError} from './error.v1.mjs';

/** The codes step 21 adds, by family. lib/transforms/index.mjs joins them with every other error file's. */
export const FAMILY_CODES = Object.freeze({
  ids: Object.freeze(['emoji_invalid']),
});

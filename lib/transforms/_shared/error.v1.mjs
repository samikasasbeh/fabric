// F10.8 part b (docs/F10.8-BUILD-MAP.md, R16): the one error type of the transform library, the harness codes and the closed code list
// of each step 8 family. Every code hash and the harness hash cover this file (lib/transform-pins.mjs), so it never changes once step 8's
// pins are written: a later step that needs a family or a code adds _shared/error.v2.mjs (then v3, and on), which re-exports
// TransformError from here and adds lists only.

/** A refusal that carries its fixed code and nothing else: no input text, no cause. */
export class TransformError extends Error {
  constructor(code) {
    super(code);
    this.name = 'TransformError';
    this.code = code;
  }
}

/** The codes lib/transforms/run.mjs refuses with itself. A transform may refuse with them too. */
export const HARNESS_CODES = Object.freeze(['transform_unknown', 'input_invalid', 'input_too_large', 'output_invalid', 'output_too_large', 'transform_failed']);

/** Each step 8 family's codes, exactly the "Codes" lines of parts d to j. An entry's `refuses` names only codes of its own family. */
export const FAMILY_CODES = Object.freeze({
  encoding: Object.freeze(['encoding_invalid', 'utf8_invalid', 'output_too_large']),
  rfc5322: Object.freeze(['header_injection', 'address_invalid', 'too_many_recipients', 'message_too_large', 'message_id_invalid', 'mime_too_deep', 'mime_too_many_parts', 'mime_invalid']),
  html: Object.freeze([]),
  time: Object.freeze(['time_invalid', 'time_nonexistent', 'time_ambiguous', 'zone_invalid', 'ts_invalid', 'window_order', 'window_past', 'window_too_far', 'busy_unknown']),
  text: Object.freeze(['too_many_chunks', 'text_too_long', 'query_value_invalid', 'query_scope_missing', 'query_too_long', 'too_many_operators', 'repo_invalid']),
  ids: Object.freeze(['notion_id_invalid', 'slack_link_invalid', 'repo_invalid', 'ref_invalid']),
  collections: Object.freeze(['match_none', 'match_many', 'attendee_protected', 'label_unknown', 'label_system', 'not_one_of', 'too_many_items']),
});

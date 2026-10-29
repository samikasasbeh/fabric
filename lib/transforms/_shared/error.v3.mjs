// F10.19 part 1 (docs/F10.19-BUILD-MAP.md part 1 item 3; docs/F10.8-BUILD-MAP.md part k): the third error file. It re-exports TransformError
// from error.v1.mjs and adds one family, notion, with its closed list of codes. Step 17 owns error.v2.mjs; the numbers need not be contiguous,
// and lib/transforms/index.mjs takes each family's codes as the union over every error file. Every notion pin covers this file.
export {TransformError} from './error.v1.mjs';

/** The notion family's codes. too_many_chunks repeats the text family's name: a notion transform cuts text by text.chunk@1's rule itself. */
export const FAMILY_CODES = Object.freeze({
  notion: Object.freeze(['property_read_only', 'property_unknown', 'property_ambiguous', 'option_unknown', 'too_many_properties', 'too_many_options', 'too_many_conditions', 'too_many_chunks']),
});

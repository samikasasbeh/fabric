// F10.8 part h (docs/F10.8-BUILD-MAP.md, open point Important 5): the one rule text.gmailQuery@1 and text.githubQuery@1 quote by. A
// value goes inside double quotes only when nothing in it can end the quotes or change how they read: no double quote, no backslash
// (GitHub reads \" as a quote that does not close), no control (tab, line feed and carriage return included), no hidden or direction
// character, and no lone surrogate. So user text can never close its quotes and add its own qualifiers, such as repo: or in:trash. The
// hidden-character rule reads Unicode property tables, so a module that imports this helper declares the `unicode` fact.
import {hasHidden} from '../_shared/hidden.v1.mjs';

const UNQUOTABLE = /["\\\u0000-\u001f\u007f]/;

/** True when the text can sit inside double quotes in a search query and read exactly as written. */
export const quotable = text => typeof text === 'string' && !UNQUOTABLE.test(text) && !hasHidden(text) && text.isWellFormed();

/** The text inside double quotes. Callers check quotable() first. */
export const quote = text => `"${text}"`;

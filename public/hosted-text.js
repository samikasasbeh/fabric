// Shared by the hosted pages, the cards and the protocol: agent-supplied text shown exactly, with
// every invisible or direction-changing character made visible.
// Controls, format characters (direction marks and overrides, U+061C, tag characters), line and
// paragraph separators and every default-ignorable character could make text read differently from
// what it is. Tab, line feed and carriage return are left to each caller.
const HIDDEN = /(?![\t\n\r])[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/gu;
const ONE = new RegExp(HIDDEN.source, 'u');
/** Text exactly as sent, with every invisible or direction-changing character made visible. */
export function visible(text) {
  return String(text).replace(HIDDEN, char => `⟦U+${char.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}⟧`);
}
/** True when text holds a character visible() would mark. */
export function hasHidden(text) {return ONE.test(String(text));}
/** The same text with each such character replaced by a space (for one-line titles). */
export function withoutHidden(text) {return String(text).replace(HIDDEN, ' ');}

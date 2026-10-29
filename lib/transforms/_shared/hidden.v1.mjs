// F10.8 part b (docs/F10.8-BUILD-MAP.md, open point Minor 3): the hidden-character rule of public/hosted-text.js line 6, copied as a
// regex literal so an edit there never moves a pin. Controls, format characters (direction marks and overrides, tag characters), line
// and paragraph separators and every default-ignorable character could make text read differently from what it is; tab, line feed and
// carriage return are left to each caller. The rule reads Unicode property tables, so a module that uses it declares the `unicode` fact.

const HIDDEN = /(?![\t\n\r])[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/u;

/** True when the text holds a character public/hosted-text.js would mark as hidden. */
export const hasHidden = text => HIDDEN.test(text);

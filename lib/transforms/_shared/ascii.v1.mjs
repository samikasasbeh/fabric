// F10.8 part b (docs/F10.8-BUILD-MAP.md, R18): case and space without Unicode tables. toLowerCase, toUpperCase, trim and \s read
// tables that change with Unicode versions, so only a module whose entry declares the `unicode` fact may use them. Everything else
// folds A to Z only, exactly as body routes fold (lib/permission-groups.mjs:19), and knows the five ASCII whitespace characters.

/** The text with A to Z turned into a to z; nothing else changes. */
export const foldAscii = text => text.replace(/[A-Z]/g, char => String.fromCharCode(char.charCodeAt(0) + 32));

/** True when two texts are equal once A to Z are folded. */
export const sameAscii = (a, b) => foldAscii(a) === foldAscii(b);

/** True for tab, line feed, form feed, carriage return and space: ASCII whitespace as WHATWG defines it. */
export const isAsciiSpace = code => code === 0x09 || code === 0x0a || code === 0x0c || code === 0x0d || code === 0x20;

/** The text without ASCII whitespace at either end. */
export function trimAscii(text) {
  let start = 0, end = text.length;
  while (start < end && isAsciiSpace(text.charCodeAt(start))) start++;
  while (end > start && isAsciiSpace(text.charCodeAt(end - 1))) end--;
  return text.slice(start, end);
}

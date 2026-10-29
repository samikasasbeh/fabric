// F10.8 part b (docs/F10.8-BUILD-MAP.md, open question 29): JSON pointers into step data. wellFormedPointer() checks syntax only.
// pointerReader() reads step data at a pointer held in an argument the entry declares in pointerArgs, and throws a plain Error for any
// other name, which the harness turns into transform_failed. So a transform reads step data at an argument-supplied pointer only where
// its entry says, and step 9 can check every such pointer (constants only, no token that secretKey() matches). This file exports these
// two functions and nothing else; fixed paths a transform knows are plain property reads in its own code.
//
// Own properties and canonical array indexes only, as resolvePointer() reads them (lib/permission-groups.mjs:249-258). Copied, not
// imported, so an edit there never moves a pin. Values are read through Object.entries(), so no key is ever used for computed access.

const MAX_TOKENS = 32;
const BAD_ESCAPE = /~(?![01])/;
const INDEX = /^(?:0|[1-9][0-9]*)$/;

/** True for '' or for '/'-separated tokens with only ~0 and ~1 escapes, at most 32 of them. */
export function wellFormedPointer(text) {
  if (typeof text !== 'string') return false;
  if (text === '') return true;
  if (text.charCodeAt(0) !== 0x2f || BAD_ESCAPE.test(text)) return false;
  return text.split('/').length - 1 <= MAX_TOKENS;
}

const unescapeToken = token => token.replace(/~1/g, '/').replace(/~0/g, '~');
const own = (value, token) => new Map(Object.entries(value)).get(token);

/** A reader for one entry and one run's input: at(value, name) is the value at the pointer held in the argument `name`, or undefined. */
export function pointerReader(entry, input) {
  return function at(value, name) {
    if (!entry.pointerArgs.includes(name)) throw new Error('This argument is not declared in pointerArgs.');
    const pointer = own(input, name);
    if (!wellFormedPointer(pointer)) throw new Error('This argument does not hold a well-formed JSON pointer.');
    let current = value;
    for (const token of pointer === '' ? [] : pointer.slice(1).split('/').map(unescapeToken)) {
      if (current === null || typeof current !== 'object' || (Array.isArray(current) && !INDEX.test(token))) return undefined;
      current = own(current, token);
    }
    return current;
  };
}

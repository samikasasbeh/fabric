// F10.8 part b (docs/F10.8-BUILD-MAP.md, R18 and open points Important 6 and Minor 3): the source scan of lib/transforms/. It parses
// every file there with the TypeScript parser (a dev dependency; nothing at run time needs it) and returns each break of these rules:
// - files: only the harness, the registry, family lists, error files, shared and family helpers and version modules, by their names;
// - imports: static named imports by relative path, each kind of file from the kinds the import rule allows, with the names it allows,
//   each written so the fixed reader of lib/transform-pins.mjs reads exactly the imports the parser reads (open point Minor 13);
// - globals: an allowlist, each global with its own list of members; no computed access on a global, no write to a global or to any
//   member of one, no global used as a value, and no binding that reuses a global's name;
// - names: constructor, prototype, __proto__ and the legacy accessors (__lookupGetter__ and the rest) are refused as identifiers,
//   property names and string literals;
// - computed member access only with a string literal or with a key that is a number by construction;
// - Date only in _shared/utc.v1.mjs, as Date.UTC or as new Date(ms) after Number.isSafeInteger(ms) in the same function; the local-time
//   Date methods and locale data nowhere;
// - Unicode tables, zone data and charsets only in a version module whose entry declares the fact, counting every helper it imports;
//   the harness, the registry, the family lists and the error files read none;
// - no regex that repeats a group holding a quantifier, no regex with the g or y flag outside a function (its lastIndex would carry
//   from one call to the next), no sort without a comparator, no import.meta and no with.
// It is a check on reviewed code, not a sandbox: every transform is still a code change a human reviews (spec line 1169).
//
//   node scripts/transform-scan.mjs [--root <dir>]     prints each finding; exit 1 when there is one
import {existsSync, lstatSync, readdirSync, readFileSync} from 'node:fs';
import {builtinModules} from 'node:module';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import ts from 'typescript';
import {importsOf} from '../lib/transform-pins.mjs';

export const ROOT = fileURLToPath(new URL('..', import.meta.url));
const DIR = 'lib/transforms';
const list = names => Object.freeze(names);

/** The only globals a transform file may name, each with the only members it may read. Widening this is a reviewed change. */
export const GLOBALS = Object.freeze({
  Array: list(['from', 'isArray']),
  BigInt: list([]),
  Boolean: list([]),
  Buffer: list(['byteLength', 'from']),
  Error: list([]),
  Infinity: list([]),
  Intl: list(['DateTimeFormat']),
  JSON: list(['stringify']),
  Map: list([]),
  Math: list(['E', 'LN10', 'LN2', 'LOG10E', 'LOG2E', 'PI', 'SQRT1_2', 'SQRT2', 'abs', 'acos', 'acosh', 'asin', 'asinh', 'atan', 'atan2', 'atanh', 'cbrt', 'ceil', 'clz32',
    'cos', 'cosh', 'exp', 'expm1', 'floor', 'fround', 'hypot', 'imul', 'log', 'log10', 'log1p', 'log2', 'max', 'min', 'pow', 'round', 'sign', 'sin', 'sinh', 'sqrt', 'tan',
    'tanh', 'trunc']),
  NaN: list([]),
  Number: list(['EPSILON', 'MAX_SAFE_INTEGER', 'MAX_VALUE', 'MIN_SAFE_INTEGER', 'MIN_VALUE', 'NEGATIVE_INFINITY', 'NaN', 'POSITIVE_INFINITY', 'isFinite', 'isInteger', 'isNaN',
    'isSafeInteger', 'parseFloat', 'parseInt']),
  Object: list(['entries', 'freeze', 'fromEntries', 'hasOwn', 'isFrozen', 'keys']),
  Set: list([]),
  String: list(['fromCharCode', 'fromCodePoint']),
  TextDecoder: list([]),
  TextEncoder: list([]),
  Uint8Array: list([]),
  undefined: list([]),
});
const CALLED = new Set(['BigInt', 'Boolean', 'Number', 'String']);
const CONSTRUCTED = new Set(['Array', 'Error', 'Map', 'Set', 'TextDecoder', 'TextEncoder', 'Uint8Array']);
const VALUES = new Set(['Infinity', 'NaN', 'undefined']);
// A binding may not reuse a global's name, so every reference to a global name is the global. Node's -e mode adds its builtin modules
// (fs, path, url) as globals; they are left out so the scan reads the same in every mode, and the real globals among them are added back.
const MODULE_NAMES = new Set(builtinModules);
const GLOBAL_NAMES = new Set([...Object.getOwnPropertyNames(globalThis).filter(name => !MODULE_NAMES.has(name)), ...Object.keys(GLOBALS), 'Date', 'globalThis', 'console',
  'crypto', 'process', 'require', 'module', 'exports', '__dirname', '__filename', 'global', 'window', 'self', 'document', 'arguments']);
// The legacy accessors reach a prototype by a name built at run time: ({}).__lookupGetter__('__pro' + 'to__').call([]) is Array.prototype.
const BANNED = new Set(['constructor', 'prototype', '__proto__', '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__']);
const UNICODE_MEMBERS = new Set(['toLowerCase', 'toUpperCase', 'trim', 'trimStart', 'trimEnd', 'trimLeft', 'trimRight', 'normalize']);
const LOCAL_TIME = new Set(['getDate', 'getDay', 'getFullYear', 'getHours', 'getMilliseconds', 'getMinutes', 'getMonth', 'getSeconds', 'getTimezoneOffset', 'getYear', 'setDate',
  'setFullYear', 'setHours', 'setMilliseconds', 'setMinutes', 'setMonth', 'setSeconds', 'setTime', 'setYear', 'toDateString', 'toTimeString', 'toGMTString']);
const UTC_FILE = '_shared/utc.v1.mjs';
const COMPILER = 'lib/compiler.mjs', REDACTION = 'lib/redaction.mjs';
// What run.mjs may import, by file, with the names it may take (null: any name).
const RUN_IMPORTS = new Map([[COMPILER, ['canonicalHash', 'checkSchema', 'validateInput']], [`${DIR}/_shared/ascii.v1.mjs`, ['foldAscii']],
  [`${DIR}/_shared/error.v1.mjs`, null], [`${DIR}/_shared/pointer.v1.mjs`, ['wellFormedPointer']]]);
// What index.mjs may import from outside lib/transforms, for its start checks only.
const INDEX_OUTSIDE = new Map([[COMPILER, ['canonicalHash', 'checkSchema', 'credentialName', 'validateInput']], [REDACTION, ['secretKey']]]);
const FIXED_EXPORTS = new Map([['_shared/pointer.v1.mjs', ['pointerReader', 'wellFormedPointer']]]);

/** What a path under lib/transforms is, or null when no file may sit there. */
export function classify(rel) {
  let match;
  if (rel === 'run.mjs') return {kind: 'run'};
  if (rel === 'index.mjs') return {kind: 'index'};
  if (rel === 'pins.json') return {kind: 'pins'};
  if ((match = /^([a-z][a-z0-9]*)(?:-[a-z][a-z0-9]*)?\.mjs$/.exec(rel))) return {kind: 'list', folder: match[1]};
  if ((match = /^_shared\/error\.v([1-9][0-9]*)\.mjs$/.exec(rel))) return {kind: 'error', version: Number(match[1])};
  if (/^_shared\/[a-z][A-Za-z0-9]*\.v[1-9][0-9]*\.mjs$/.test(rel)) return {kind: 'helper'};
  if ((match = /^([a-z][a-z0-9]*)\/_[a-z][A-Za-z0-9]*\.v[1-9][0-9]*\.mjs$/.exec(rel))) return {kind: 'family-helper', family: match[1]};
  if ((match = /^([a-z][a-z0-9]*)\/[a-z][A-Za-z0-9]*\.v[1-9][0-9]*\.mjs$/.exec(rel))) return {kind: 'version', family: match[1]};
  return null;
}

// Dot files (.DS_Store) are skipped, as scripts/check.mjs skips them: no import may name one, so none can reach a transform.
function walk(base, rel = '', out = []) {
  for (const item of readdirSync(path.join(base, rel), {withFileTypes: true})) {
    if (item.name.startsWith('.')) continue;
    const child = rel ? `${rel}/${item.name}` : item.name;
    if (item.isDirectory() && !lstatSync(path.join(base, child)).isSymbolicLink()) walk(base, child, out);
    else out.push({rel: child, plain: item.isFile()});
  }
  return out;
}

const assignment = kind => kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment;
const exported = node => (ts.canHaveModifiers(node) ? ts.getModifiers(node) ?? [] : []).some(modifier => modifier.kind === ts.SyntaxKind.ExportKeyword);
const defaulted = node => (ts.canHaveModifiers(node) ? ts.getModifiers(node) ?? [] : []).some(modifier => modifier.kind === ts.SyntaxKind.DefaultKeyword);
const keyText = name => ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name) || ts.isPrivateIdentifier(name) ? name.text : null;
const isMember = (node, object, member) => ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === object && node.name.text === member;

/** The identifiers a binding name declares. */
function bindingIdentifiers(name, out = []) {
  if (ts.isIdentifier(name)) out.push(name);
  else if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) for (const element of name.elements) if (!ts.isOmittedExpression(element)) bindingIdentifiers(element.name, out);
  return out;
}
/** True when an identifier is read as a value here, not a property name, a key, a label or a declaration. */
function isReference(node) {
  const parent = node.parent;
  if (!parent) return false;
  if (ts.isPropertyAccessExpression(parent)) return parent.expression === node;
  if (ts.isPropertyAssignment(parent) || ts.isMethodDeclaration(parent) || ts.isPropertyDeclaration(parent) || ts.isGetAccessorDeclaration(parent) || ts.isSetAccessorDeclaration(parent)) return parent.name !== node;
  if (ts.isBindingElement(parent)) return parent.initializer === node;
  if ((ts.isVariableDeclaration(parent) || ts.isParameter(parent) || ts.isFunctionDeclaration(parent) || ts.isFunctionExpression(parent) || ts.isClassDeclaration(parent)
    || ts.isClassExpression(parent)) && parent.name === node) return false;
  if (ts.isImportClause(parent) || ts.isImportSpecifier(parent) || ts.isNamespaceImport(parent) || ts.isExportSpecifier(parent)) return false;
  if (ts.isLabeledStatement(parent) || ts.isBreakStatement(parent) || ts.isContinueStatement(parent) || ts.isMetaProperty(parent)) return false;
  return true;
}
/** The expressions an assignment writes to, through destructuring patterns. */
function targetsOf(node, out = []) {
  if (ts.isParenthesizedExpression(node)) return targetsOf(node.expression, out);
  if (ts.isArrayLiteralExpression(node)) { for (const element of node.elements) targetsOf(ts.isSpreadElement(element) ? element.expression : element, out); return out; }
  if (ts.isObjectLiteralExpression(node)) {
    for (const property of node.properties) {
      if (ts.isPropertyAssignment(property)) targetsOf(property.initializer, out);
      else if (ts.isShorthandPropertyAssignment(property)) out.push(property.name);
      else if (ts.isSpreadAssignment(property)) targetsOf(property.expression, out);
    }
    return out;
  }
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) return targetsOf(node.left, out);
  if (!ts.isOmittedExpression(node)) out.push(node);
  return out;
}
/** The identifier a member chain starts from, or the expression itself. */
function rootOf(node) {
  let current = node;
  while (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current) || ts.isParenthesizedExpression(current) || ts.isNonNullExpression(current)) current = current.expression;
  return current;
}

/** A regex literal's flags and source: whether it reads Unicode tables, and whether it repeats a group that holds a quantifier. */
export function regexRisks(literal) {
  const end = literal.lastIndexOf('/'), source = literal.slice(1, end), flags = literal.slice(end + 1);
  let unicode = /[iuv]/.test(flags), nested = false, inClass = false, closed = null, index = 0;
  const groups = [{inner: false}];
  const quantifierAt = at => {
    const char = source[at];
    if (char === '*' || char === '+') return {length: 1, repeats: true, variable: true};
    if (char === '?') return {length: 1, repeats: false, variable: true};
    const braces = char === '{' ? /^\{([0-9]+)(,([0-9]*))?\}/.exec(source.slice(at)) : null;
    if (!braces) return null;
    const low = Number(braces[1]), high = braces[2] === undefined ? low : braces[3] === '' ? Infinity : Number(braces[3]);
    return {length: braces[0].length, repeats: high >= 2, variable: high !== low};
  };
  while (index < source.length) {
    const char = source[index];
    if (char === '\\') {
      const next = source[index + 1];
      if ('sSpP'.includes(next)) unicode = true;
      index += 2;
      if ((next === 'p' || next === 'P') && source[index] === '{') index = source.indexOf('}', index) + 1 || source.length;
      closed = null;
      continue;
    }
    if (inClass) { if (char === ']') inClass = false; index++; continue; }
    if (char === '[') { inClass = true; closed = null; index++; continue; }
    if (char === '(') {
      groups.push({inner: false});
      index++;
      // (?: (?= (?! take two characters, (?<= (?<! three, and a named group (?<name> runs to its >.
      if (source[index] === '?' && source[index + 1] === '<' && !'=!'.includes(source[index + 2])) {
        const close = source.indexOf('>', index);
        index = close === -1 ? source.length : close + 1;
      } else if (source[index] === '?') index += source[index + 1] === '<' ? 3 : 2;
      closed = null;
      continue;
    }
    if (char === ')') {
      const group = groups.length > 1 ? groups.pop() : {inner: false};
      groups.at(-1).inner ||= group.inner;
      closed = group;
      index++;
      continue;
    }
    const quantifier = quantifierAt(index);
    if (quantifier) {
      if (closed && closed.inner && quantifier.repeats) nested = true;
      if (quantifier.variable) groups.at(-1).inner = true;
      index += quantifier.length + (source[index + quantifier.length] === '?' ? 1 : 0);
      closed = null;
      continue;
    }
    closed = null;
    index++;
  }
  return {unicode, nested};
}

/** The literal runtimeFacts of a version module's exported ENTRY, or null when it is not a literal list of strings. */
function declaredFacts(source) {
  for (const statement of source.statements) {
    if (!ts.isVariableStatement(statement) || !exported(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || declaration.name.text !== 'ENTRY') continue;
      let value = declaration.initializer;
      if (value && ts.isCallExpression(value) && isMember(value.expression, 'Object', 'freeze') && value.arguments.length === 1) value = value.arguments[0];
      if (!value || !ts.isObjectLiteralExpression(value)) return null;
      // The value the entry keeps is the last one written: runtimeFacts once, with no spread or computed key after it.
      const at = value.properties.findIndex(item => ts.isPropertyAssignment(item) && keyText(item.name) === 'runtimeFacts'), property = value.properties[at];
      const later = value.properties.slice(at + 1).some(item => ts.isSpreadAssignment(item) || (item.name && (ts.isComputedPropertyName(item.name) || keyText(item.name) === 'runtimeFacts')));
      if (!property || later || !ts.isArrayLiteralExpression(property.initializer) || !property.initializer.elements.every(item => ts.isStringLiteral(item))) return null;
      return property.initializer.elements.map(item => item.text);
    }
  }
  return null;
}

/** Every finding in one parsed file, plus its resolved imports and the runtime facts its own code reads. */
function scanFile(rel, info, text, add) {
  const file = `${DIR}/${rel}`;
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const lineOf = node => source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
  const report = (node, rule, message) => add(file, node ? lineOf(node) : 1, rule, message);
  const facts = new Map(), imports = [], exports = [], specifiers = [];
  const use = (fact, node) => { if (!facts.has(fact)) facts.set(fact, lineOf(node)); };
  for (const diagnostic of source.parseDiagnostics ?? []) add(file, source.getLineAndCharacterOfPosition(diagnostic.start ?? 0).line + 1, 'syntax', ts.flattenDiagnosticMessageText(diagnostic.messageText, ' '));

  // Bindings first: every name the file declares, for the scope-free reading of references, and which of them are numbers.
  const declared = new Set(), definitions = new Map();
  const define = (name, definition) => { if (!definitions.has(name)) definitions.set(name, []); definitions.get(name).push(definition); };
  const declare = (identifier, definition = {never: true}) => {
    declared.add(identifier.text);
    define(identifier.text, definition);
    if (GLOBAL_NAMES.has(identifier.text)) report(identifier, 'shadow', `${identifier.text} is a global's name; a binding may not reuse it.`);
  };
  (function bind(node) {
    if (ts.isVariableDeclaration(node)) {
      const loop = node.parent?.parent && (ts.isForOfStatement(node.parent.parent) || ts.isForInStatement(node.parent.parent));
      if (ts.isIdentifier(node.name)) declare(node.name, !loop && node.initializer ? {expression: node.initializer} : {never: true});
      else for (const identifier of bindingIdentifiers(node.name)) declare(identifier);
    } else if (ts.isParameter(node)) for (const identifier of bindingIdentifiers(node.name)) declare(identifier);
    else if ((ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isClassDeclaration(node) || ts.isClassExpression(node)) && node.name) declare(node.name);
    else if (ts.isImportClause(node) && node.name) declare(node.name);
    else if (ts.isImportSpecifier(node) || ts.isNamespaceImport(node)) declare(node.name);
    else if (ts.isBinaryExpression(node) && assignment(node.operatorToken.kind)) {
      for (const target of targetsOf(node.left)) if (ts.isIdentifier(target)) {
        const kind = node.operatorToken.kind, keeps = [ts.SyntaxKind.EqualsToken, ts.SyntaxKind.PlusEqualsToken, ts.SyntaxKind.BarBarEqualsToken, ts.SyntaxKind.AmpersandAmpersandEqualsToken, ts.SyntaxKind.QuestionQuestionEqualsToken];
        define(target.text, target === node.left ? (keeps.includes(kind) ? {expression: node.right} : {number: true}) : {never: true});
      }
    } else if ((ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) && ts.isIdentifier(node.operand)) define(node.operand.text, {number: true});
    // A for-of or for-in target that is no declaration takes each item or key: never a number by construction.
    else if ((ts.isForOfStatement(node) || ts.isForInStatement(node)) && !ts.isVariableDeclarationList(node.initializer)) {
      for (const target of targetsOf(node.initializer)) if (ts.isIdentifier(target)) define(target.text, {never: true});
    }
    ts.forEachChild(node, bind);
  })(source);
  const numbers = new Set([...definitions].filter(([, list]) => list.every(item => !item.never)).map(([name]) => name));
  const numeric = node => {
    if (ts.isNumericLiteral(node) || ts.isBigIntLiteral(node)) return true;
    if (ts.isParenthesizedExpression(node)) return numeric(node.expression);
    if (ts.isPrefixUnaryExpression(node)) return node.operator !== ts.SyntaxKind.ExclamationToken;
    if (ts.isPostfixUnaryExpression(node)) return true;
    if (ts.isConditionalExpression(node)) return numeric(node.whenTrue) && numeric(node.whenFalse);
    if (ts.isIdentifier(node)) return numbers.has(node.text);
    if (ts.isCallExpression(node)) return ts.isPropertyAccessExpression(node.expression) && ts.isIdentifier(node.expression.expression) && node.expression.expression.text === 'Math';
    if (!ts.isBinaryExpression(node)) return false;
    const kind = node.operatorToken.kind;
    if ([ts.SyntaxKind.MinusToken, ts.SyntaxKind.AsteriskToken, ts.SyntaxKind.SlashToken, ts.SyntaxKind.PercentToken, ts.SyntaxKind.AsteriskAsteriskToken, ts.SyntaxKind.BarToken,
      ts.SyntaxKind.AmpersandToken, ts.SyntaxKind.CaretToken, ts.SyntaxKind.LessThanLessThanToken, ts.SyntaxKind.GreaterThanGreaterThanToken,
      ts.SyntaxKind.GreaterThanGreaterThanGreaterThanToken].includes(kind)) return true;
    if ([ts.SyntaxKind.PlusToken, ts.SyntaxKind.QuestionQuestionToken, ts.SyntaxKind.BarBarToken, ts.SyntaxKind.AmpersandAmpersandToken].includes(kind)) return numeric(node.left) && numeric(node.right);
    // +=, ||=, &&= and ??= keep or build on the old value, so the old value must be a number too: k ||= 1 keeps a string k.
    if ([ts.SyntaxKind.PlusEqualsToken, ts.SyntaxKind.BarBarEqualsToken, ts.SyntaxKind.AmpersandAmpersandEqualsToken, ts.SyntaxKind.QuestionQuestionEqualsToken].includes(kind)) {
      return numeric(node.left) && numeric(node.right);
    }
    if (kind === ts.SyntaxKind.CommaToken || assignment(kind)) return numeric(node.right);
    return false;
  };
  // A name stays a number only while every definition of it is one; drop names until nothing changes.
  for (let changed = true; changed;) {
    changed = false;
    for (const name of [...numbers]) if (!definitions.get(name).every(item => item.number || numeric(item.expression))) { numbers.delete(name); changed = true; }
  }

  const isGlobal = node => ts.isIdentifier(node) && isReference(node) && !declared.has(node.text);
  const memberName = (name, node) => {
    if (BANNED.has(name)) report(node, 'name', `${name} reaches prototypes and Function; it is refused as a name.`);
    if (name === 'localeCompare' || name.startsWith('toLocale')) report(node, 'member', `${name} reads locale data.`);
    if (LOCAL_TIME.has(name)) report(node, 'date', `${name} reads local time.`);
    if (UNICODE_MEMBERS.has(name)) use('unicode', node);
  };
  const guarded = (newDate, name) => {
    let scope = newDate.parent;
    while (scope && !ts.isFunctionLike(scope) && !ts.isSourceFile(scope)) scope = scope.parent;
    let found = false;
    (function look(node) {
      if (found) return;
      if (ts.isCallExpression(node) && isMember(node.expression, 'Number', 'isSafeInteger') && node.arguments.length === 1 && ts.isIdentifier(node.arguments[0])
        && node.arguments[0].text === name && node.end <= newDate.getStart(source)) found = true;
      else ts.forEachChild(node, look);
    })(scope);
    return found;
  };
  const dateUse = node => {
    const parent = node.parent;
    if (rel !== UTC_FILE) return report(node, 'date', 'Date appears only in lib/transforms/_shared/utc.v1.mjs.');
    if (ts.isPropertyAccessExpression(parent) && parent.expression === node) { if (parent.name.text !== 'UTC') report(node, 'date', `Date.${parent.name.text} is refused; only Date.UTC is read.`); return; }
    if (ts.isNewExpression(parent) && parent.expression === node) {
      const [argument, ...more] = parent.arguments ?? [];
      if (argument && !more.length && ts.isIdentifier(argument) && guarded(parent, argument.text)) return;
      return report(node, 'date', 'new Date takes one value that Number.isSafeInteger() checks before it in the same function.');
    }
    report(node, 'date', 'Date is read only as Date.UTC or new Date(ms).');
  };
  const globalUse = node => {
    const name = node.text, parent = node.parent;
    if (name === 'Date') return dateUse(node);
    if (!Object.hasOwn(GLOBALS, name)) return report(node, 'global', `${name} is not an allowed global.`);
    if (VALUES.has(name)) return;
    if (ts.isPropertyAccessExpression(parent) && parent.expression === node) {
      if (!GLOBALS[name].includes(parent.name.text)) report(parent.name, 'member', `${name}.${parent.name.text} is not an allowed member.`);
      else if (name === 'Intl') use('tz', node);
      return;
    }
    if (ts.isElementAccessExpression(parent) && parent.expression === node) return report(node, 'computed', `${name}[...] is computed access on a global.`);
    if (ts.isCallExpression(parent) && parent.expression === node) { if (!CALLED.has(name)) report(node, 'alias', `${name}() is not a call the scan allows.`); return; }
    if (ts.isNewExpression(parent) && parent.expression === node) {
      if (!CONSTRUCTED.has(name)) return report(node, 'alias', `new ${name}() is not allowed.`);
      const [label] = parent.arguments ?? [];
      if (name === 'TextDecoder' && label && !(ts.isStringLiteral(label) && /^utf-?8$/i.test(label.text))) use('charset', node);
      return;
    }
    if (ts.isBinaryExpression(parent) && parent.operatorToken.kind === ts.SyntaxKind.InstanceOfKeyword && parent.right === node) return;
    if (ts.isTypeOfExpression(parent)) return;
    if (ts.isExpressionWithTypeArguments(parent) && ts.isHeritageClause(parent.parent)) return;
    report(node, 'alias', `${name} may only be called, constructed or read through one of its listed members.`);
  };
  const checkWrite = (target, node) => {
    const root = rootOf(target);
    if (ts.isIdentifier(root) && !declared.has(root.text)) report(node, 'write', `a write to ${root.text}${root === target ? '' : ' or one of its members'} changes shared state.`);
  };
  const checkImport = (node, specifier, names) => {
    if (!ts.isStringLiteral(specifier) || !/^\.\.?\//.test(specifier.text)) return report(node, 'import', 'imports are relative paths inside lib/transforms.');
    const target = path.posix.normalize(path.posix.join(path.posix.dirname(file), specifier.text));
    const targetRel = target.startsWith(`${DIR}/`) ? target.slice(DIR.length + 1) : null, targetInfo = targetRel === null ? null : classify(targetRel);
    let allowed;
    if (info.kind === 'run') allowed = RUN_IMPORTS.has(target) ? {names: RUN_IMPORTS.get(target)} : null;
    else if (info.kind === 'index') {
      if (INDEX_OUTSIDE.has(target)) allowed = {names: INDEX_OUTSIDE.get(target)};
      else if (targetInfo?.kind === 'list') allowed = {names: ['ENTRIES']};
      else if (['run', 'error', 'helper'].includes(targetInfo?.kind)) allowed = {names: null};
    } else if (info.kind === 'list') allowed = targetInfo?.kind === 'version' && targetInfo.family === info.folder ? {names: ['ENTRY']} : null;
    else if (info.kind === 'error') allowed = info.version > 1 && targetRel === '_shared/error.v1.mjs' ? {names: null} : null;
    else if (info.kind === 'helper') allowed = ['helper', 'error'].includes(targetInfo?.kind) ? {names: null} : null;
    else allowed = ['helper', 'error'].includes(targetInfo?.kind) || (targetInfo?.kind === 'family-helper' && targetInfo.family === info.family) ? {names: null} : null;
    if (!allowed) return report(node, 'import', `a ${info.kind} file may not import ${specifier.text}.`);
    for (const name of names) if (allowed.names && !allowed.names.includes(name)) report(node, 'import-name', `${specifier.text} gives this file ${allowed.names.join(', ')} only, not ${name}.`);
    if (targetRel !== null) imports.push(targetRel);
  };

  (function visit(node) {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) specifiers.push({node, path: node.moduleSpecifier.text});
    if (ts.isImportDeclaration(node)) {
      const clause = node.importClause, bindings = clause?.namedBindings;
      if (!clause || clause.name || !bindings || !ts.isNamedImports(bindings) || !bindings.elements.length) report(node, 'import', 'imports are named: import {a, b} from \'./file.mjs\'.');
      else checkImport(node, node.moduleSpecifier, bindings.elements.map(element => (element.propertyName ?? element.name).text));
    } else if (ts.isExportDeclaration(node)) {
      const names = node.exportClause && ts.isNamedExports(node.exportClause) ? node.exportClause.elements : null;
      if (!names) report(node, 'export', 'exports are named.');
      else {
        exports.push(...names.map(element => element.name.text));
        if (node.moduleSpecifier) checkImport(node, node.moduleSpecifier, names.map(element => (element.propertyName ?? element.name).text));
      }
    } else if (ts.isExportAssignment(node) || defaulted(node)) report(node, 'export', 'there is no default export.');
    else if (exported(node)) {
      if (ts.isVariableStatement(node)) for (const declaration of node.declarationList.declarations) exports.push(...bindingIdentifiers(declaration.name).map(identifier => identifier.text));
      else if (node.name) exports.push(node.name.text);
    }
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) report(node, 'import', 'there is no dynamic import().');
    if (ts.isMetaProperty(node) && node.keywordToken === ts.SyntaxKind.ImportKeyword) report(node, 'meta', 'import.meta reads where the file lives.');
    if (ts.isWithStatement(node)) report(node, 'syntax', 'with is refused.');
    if (ts.isIdentifier(node)) {
      if (BANNED.has(node.text)) report(node, 'name', `${node.text} reaches prototypes and Function; it is refused as a name.`);
      if (isGlobal(node)) globalUse(node);
    }
    if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && BANNED.has(node.text)) report(node, 'name', `${node.text} is refused as a string too.`);
    if (ts.isPropertyAccessExpression(node) && !ts.isPrivateIdentifier(node.name)) memberName(node.name.text, node.name);
    if (ts.isElementAccessExpression(node) && !isGlobal(node.expression)) {
      const key = node.argumentExpression;
      if (ts.isStringLiteral(key) || ts.isNoSubstitutionTemplateLiteral(key)) memberName(key.text, key);
      else if (!numeric(key)) report(key, 'computed', 'a computed key is a string literal or a number by construction.');
    }
    if (ts.isBindingElement(node) && ts.isObjectBindingPattern(node.parent)) {
      const key = node.propertyName ?? node.name;
      if (key && ts.isComputedPropertyName(key)) { if (!(ts.isStringLiteral(key.expression) || numeric(key.expression))) report(key, 'computed', 'a computed key is a string literal or a number by construction.'); }
      else if (key && keyText(key) !== null) memberName(keyText(key), key);
    }
    if (ts.isBinaryExpression(node) && assignment(node.operatorToken.kind)) for (const target of targetsOf(node.left)) checkWrite(target, node);
    if ((ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) && [ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(node.operator)) checkWrite(node.operand, node);
    if (ts.isDeleteExpression(node)) checkWrite(node.expression, node);
    if ((ts.isForOfStatement(node) || ts.isForInStatement(node)) && !ts.isVariableDeclarationList(node.initializer)) for (const target of targetsOf(node.initializer)) checkWrite(target, node);
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && ['sort', 'toSorted'].includes(node.expression.name.text) && !node.arguments.length) {
      report(node, 'sort', 'sorting names its comparator.');
    }
    if (node.kind === ts.SyntaxKind.RegularExpressionLiteral) {
      const risks = regexRisks(node.text);
      if (risks.unicode) use('unicode', node);
      if (risks.nested) report(node, 'regex', 'a regex repeats a group that holds a quantifier.');
      if (/[gy]/.test(node.text.slice(node.text.lastIndexOf('/') + 1)) && !ts.findAncestor(node.parent, ts.isFunctionLike)) {
        report(node, 'regex', 'a regex with the g or y flag keeps its lastIndex from one call to the next; write it inside the function that uses it.');
      }
    }
    ts.forEachChild(node, visit);
  })(source);

  if (info.kind === 'version' && !(exports.length === 1 && exports[0] === 'ENTRY')) report(null, 'export', 'a version module exports ENTRY and nothing else.');
  if (info.kind === 'list' && !(exports.length === 1 && exports[0] === 'ENTRIES')) report(null, 'export', 'a family list exports ENTRIES and nothing else.');
  if (FIXED_EXPORTS.has(rel) && [...exports].sort((a, b) => a < b ? -1 : a > b ? 1 : 0).join() !== FIXED_EXPORTS.get(rel).join()) report(null, 'export', `${rel} exports ${FIXED_EXPORTS.get(rel).join(' and ')} only.`);
  // The pins follow imports with their own fixed reader, so it must read exactly the imports the parser reads, in order: one import or
  // re-export starting its line, with `from` and the path where the braces close, and no import-like line in a comment or a string.
  const read = importsOf(text), mismatch = specifiers.findIndex((item, index) => read[index] !== item.path);
  if (mismatch !== -1 || read.length !== specifiers.length) {
    report(specifiers[mismatch]?.node ?? null, 'import-form', `lib/transform-pins.mjs reads this file's imports as [${read.join(', ')}], the parser as [${specifiers.map(item => item.path).join(', ')}]; write one import {a, b} from './file.mjs' per line, starting the line, so each pin covers every helper it reaches.`);
  }
  return {file, facts, imports, declaredFacts: info.kind === 'version' ? declaredFacts(source) : null};
}

/** Every finding under <root>/lib/transforms, as {file, line, rule, message}, in file and line order. Empty when the tree is clean. */
export function scanTransforms(root = ROOT) {
  const findings = [], add = (file, line, rule, message) => findings.push({file, line, rule, message});
  const base = path.join(root, DIR);
  if (!existsSync(base)) return [{file: DIR, line: 1, rule: 'file', message: 'lib/transforms is missing.'}];
  const scanned = new Map();
  for (const {rel, plain} of walk(base)) {
    const info = classify(rel);
    if (!plain || !info) { add(`${DIR}/${rel}`, 1, 'file', 'no file may sit here: see the layout in docs/F10.8-BUILD-MAP.md part b.'); continue; }
    if (info.kind === 'pins') continue;
    scanned.set(rel, {info, ...scanFile(rel, info, readFileSync(path.join(base, rel), 'utf8'), add)});
  }
  // Runtime facts: a version module declares every fact its own code and each helper it reaches reads; the harness and the files
  // around it read none.
  const reach = start => {
    const seen = new Set(), queue = [start];
    while (queue.length) { const rel = queue.shift(); if (seen.has(rel) || !scanned.has(rel)) continue; seen.add(rel); queue.push(...scanned.get(rel).imports); }
    return seen;
  };
  const harness = scanned.has('run.mjs') ? reach('run.mjs') : new Set();
  for (const [rel, item] of scanned) {
    if (item.info.kind === 'version') {
      if (item.declaredFacts === null) { add(item.file, 1, 'fact', 'ENTRY lists runtimeFacts as a literal list of strings, so the scan can read it.'); continue; }
      for (const used of reach(rel)) {
        for (const [fact, line] of scanned.get(used).facts) {
          if (!item.declaredFacts.includes(fact)) add(item.file, used === rel ? line : 1, 'fact', `${used === rel ? 'this module' : `lib/transforms/${used}`} reads the ${fact} fact, which ENTRY does not declare.`);
        }
      }
    } else if (harness.has(rel) || ['index', 'list', 'error'].includes(item.info.kind)) {
      for (const [fact, line] of item.facts) add(item.file, line, 'fact', `the harness and the files around it read no runtime fact, but this reads ${fact}.`);
    }
  }
  return findings.sort((a, b) => a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line);
}

export const formatFinding = finding => `${finding.file}:${finding.line}: [${finding.rule}] ${finding.message}`;

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const at = process.argv.indexOf('--root'), root = at > -1 ? path.resolve(process.argv[at + 1] ?? '.') : ROOT;
  const findings = scanTransforms(root);
  for (const finding of findings) console.error(formatFinding(finding));
  if (findings.length) process.exitCode = 1;
  else console.log('The transform library passes the source scan.');
}

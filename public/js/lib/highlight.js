/**
 * Syntax and diff highlighting
 *
 * A hand-rolled regex tokenizer, deliberately not an external highlighting library — the same
 * no-external-dependency choice as the hand-drawn icons. Good enough to make a code snippet
 * readable, and it never has to be kept in sync with a third-party grammar.
 *
 * diffLineHtml lives here rather than with the finding-detail view because it is the same
 * concern: colouring a line of text by inspecting its first character.
 */

import { escapeHtml } from './html.js';

const HL_KEYWORDS = new Set([
  'function', 'const', 'let', 'var', 'return', 'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'break', 'continue',
  'import', 'export', 'from', 'as', 'default', 'class', 'extends', 'implements', 'interface', 'new', 'delete', 'typeof',
  'instanceof', 'try', 'catch', 'finally', 'throw', 'async', 'await', 'yield', 'static', 'public', 'private', 'protected',
  'void', 'null', 'true', 'false', 'undefined', 'this', 'super', 'in', 'of',
  'def', 'elif', 'pass', 'lambda', 'with', 'is', 'not', 'and', 'or', 'None', 'True', 'False', 'self', 'raise', 'except',
  'global', 'nonlocal', 'assert',
  'func', 'package', 'go', 'chan', 'defer', 'select', 'range', 'struct', 'type', 'map', 'nil',
  'namespace', 'using', 'fn', 'impl', 'pub', 'mut', 'match', 'loop', 'enum', 'trait', 'mod',
  'int', 'string', 'bool', 'float', 'double', 'char', 'long', 'short', 'unsigned', 'const', 'include', 'define',
]);

const HL_TOKEN_RE = /(\/\/[^\n]*|#[^\n]*|\/\*[\s\S]*?\*\/)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)|(\b\d+(?:\.\d+)?\b)|(\b[A-Za-z_$][A-Za-z0-9_$]*\b)/g;

export function highlightCode(code) {
  let out = '';
  let lastIndex = 0;
  HL_TOKEN_RE.lastIndex = 0;
  let m;
  while ((m = HL_TOKEN_RE.exec(code))) {
    if (m.index > lastIndex) out += escapeHtml(code.slice(lastIndex, m.index));
    const [full, comment, string, number, word] = m;
    if (comment) out += `<span class="tok-comment">${escapeHtml(comment)}</span>`;
    else if (string) out += `<span class="tok-string">${escapeHtml(string)}</span>`;
    else if (number) out += `<span class="tok-number">${escapeHtml(number)}</span>`;
    else if (word && HL_KEYWORDS.has(word)) out += `<span class="tok-keyword">${escapeHtml(word)}</span>`;
    else out += escapeHtml(full);
    lastIndex = m.index + full.length;
  }
  if (lastIndex < code.length) out += escapeHtml(code.slice(lastIndex));
  return out;
}

// Minimal unified-diff line coloring — no external diff library, consistent with this app's
// no-external-deps aesthetic. Only cares about the leading +/-/@@ marker per line. Used by
// runCardHtml() to render a write-capable remediation run's applied_diff on Finding Detail.
export function diffLineHtml(line) {
  let cls = '';
  if (line.startsWith('+++') || line.startsWith('---')) cls = 'meta';
  else if (line.startsWith('+')) cls = 'add';
  else if (line.startsWith('-')) cls = 'del';
  else if (line.startsWith('@@')) cls = 'hunk';
  else if (line.startsWith('diff --git') || line.startsWith('index ')) cls = 'meta';
  return `<div class="diff-line${cls ? ' ' + cls : ''}">${escapeHtml(line) || '&nbsp;'}</div>`;
}

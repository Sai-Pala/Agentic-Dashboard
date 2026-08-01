'use strict';

/**
 * extract-client-fns.js — Phase 0 test harness for the client-side decision logic.
 *
 * WHY THIS EXISTS
 * ---------------
 * All of this app's browser logic lives in a single ~3,800-line <script> block inside
 * public/index.html. It is not a module, exports nothing, and its top level both declares
 * ~27 mutable globals and immediately touches `document` (element lookups, event wiring).
 * So it cannot simply be `require()`d, nor eval'd wholesale in Node — it throws on the first
 * DOM access long before any of the pure decision functions are reachable.
 *
 * That leaves the genuinely pure logic — the Remediation Loop state machine, the guard
 * classification, the sort comparators — untestable, which is exactly the logic a refactor
 * is most likely to break silently.
 *
 * HOW IT WORKS
 * ------------
 *   1. Read public/index.html and pull out the body of its largest <script> block.
 *   2. Parse that body with @babel/parser (already a dependency of this repo, and
 *      CommonJS-friendly). No transform, no traversal library — just the AST.
 *   3. Walk ONLY the top-level `FunctionDeclaration` / `VariableDeclaration` nodes and pick
 *      out the specific named declarations we want, slicing their exact original source text
 *      out of the script by node.start/node.end. Nothing else comes along.
 *   4. Concatenate those slices and evaluate them together in a fresh `node:vm` context that
 *      has NO `document`, NO `window`, and none of the app's mutable globals.
 *
 * Step 4's bare context is deliberate. If an extracted function secretly reaches for the DOM
 * or a module-level mutable global, it throws a plain ReferenceError the moment a test calls
 * it, naming the global. That is the signal we want — we do not stub `document` to paper over
 * it. A function that needs a stub is a function that isn't pure and should be dropped from
 * the set (and said so in the report), not contorted into passing.
 *
 * LOUD FAILURE IS THE POINT
 * -------------------------
 * `extract()` throws if any requested name is not found. During the Phase 4 refactor, a
 * renamed or relocated function is a real signal about what moved — swallowing it (returning
 * undefined, skipping the test) would let the whole suite silently pass while testing nothing.
 *
 * LIFESPAN
 * --------
 * This file is scaffolding with a known expiry. Once Phase 4 splits index.html into real ES
 * modules, the tests import those modules directly and this harness — along with the
 * `loadClientFns()` indirection in client-logic.test.js — gets deleted outright.
 */

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const parser = require('@babel/parser');

const INDEX_HTML = path.join(__dirname, '..', '..', 'public', 'index.html');

/**
 * The body of the largest <script> block in index.html.
 *
 * index.html has two: a tiny inline theme-bootstrap script in <head> (reads localStorage
 * before first paint) and the real application script. "Largest" picks the latter without
 * hardcoding line numbers, which would rot on the first edit above it.
 */
function readMainScript() {
  if (!fs.existsSync(INDEX_HTML)) {
    throw new Error(`extract-client-fns: cannot find ${INDEX_HTML}`);
  }
  const html = fs.readFileSync(INDEX_HTML, 'utf8');
  const blocks = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)].map((m) => m[1]);
  if (!blocks.length) {
    throw new Error('extract-client-fns: no <script> block found in public/index.html');
  }
  const main = blocks.reduce((a, b) => (b.length > a.length ? b : a));
  // Offset of the chosen block within the file, so we can report real line numbers.
  const offset = html.indexOf(main);
  const startLine = html.slice(0, offset).split('\n').length;
  return { source: main, startLine };
}

/**
 * Index every top-level named declaration in the script by name -> exact source text.
 *
 * Only `FunctionDeclaration` and `VariableDeclaration` at Program level are considered.
 * Anything nested (a function inside a function, a method on an object literal) is invisible
 * here on purpose — nested helpers are not independently addressable and would need their
 * enclosing scope to make sense.
 */
function indexTopLevelDeclarations() {
  const { source, startLine } = readMainScript();
  const ast = parser.parse(source, {
    sourceType: 'script',
    allowReturnOutsideFunction: false,
    errorRecovery: false,
  });

  const decls = new Map(); // name -> { text, line, kind }

  for (const node of ast.program.body) {
    if (node.type === 'FunctionDeclaration' && node.id) {
      decls.set(node.id.name, {
        text: source.slice(node.start, node.end),
        line: startLine + node.loc.start.line - 1,
        kind: 'function',
      });
    } else if (node.type === 'VariableDeclaration') {
      // A `const A = {...}, B = {...}` would share one node; slice the whole declaration and
      // register it under each declared name. Re-including it twice is de-duped by the
      // Set of emitted texts in extract().
      const text = source.slice(node.start, node.end);
      for (const d of node.declarations) {
        if (d.id && d.id.type === 'Identifier') {
          decls.set(d.id.name, {
            text,
            line: startLine + node.loc.start.line - 1,
            kind: node.kind,
          });
        }
      }
    }
  }

  return { decls, source, startLine };
}

/**
 * Extract the named declarations and evaluate them together in a bare vm context.
 *
 * @param {string[]} names - top-level declaration names to lift out of index.html.
 * @returns {object} an object whose keys are `names`, each bound to the live value, plus a
 *                   non-enumerable `__meta` describing what was pulled and from where.
 * @throws if any name is missing — see "LOUD FAILURE IS THE POINT" above.
 */
function extract(names) {
  const { decls } = indexTopLevelDeclarations();

  const missing = names.filter((n) => !decls.has(n));
  if (missing.length) {
    throw new Error(
      'extract-client-fns: the following declarations no longer exist at the top level of ' +
        'public/index.html:\n' +
        missing.map((n) => `  - ${n}`).join('\n') +
        '\n\nThis is a real signal, not a test-harness bug. Either the function was renamed, ' +
        'moved into a nested scope, or (during the Phase 4 module split) relocated into its ' +
        'own module — in which case this harness should be retired in favour of importing it ' +
        'directly. Do not silence this by dropping the name from the list without checking.'
    );
  }

  const seen = new Set();
  const chunks = [];
  const meta = [];
  for (const name of names) {
    const d = decls.get(name);
    meta.push({ name, kind: d.kind, line: d.line });
    if (seen.has(d.text)) continue; // shared multi-declarator statement
    seen.add(d.text);
    chunks.push(d.text);
  }

  // Bare context on purpose: no document, no window, no app globals. See the header comment.
  const context = vm.createContext(Object.create(null));
  const program = chunks.join('\n\n') + '\n\n;({' + names.map((n) => `${n}: ${n}`).join(', ') + '});';

  let exported;
  try {
    exported = vm.runInContext(program, context, { filename: 'index.html:<script>' });
  } catch (err) {
    throw new Error(
      `extract-client-fns: failed to evaluate the extracted declarations in isolation: ${err.message}\n` +
        'This usually means one of the requested declarations closes over something that was ' +
        'not extracted (another helper, a mutable global, or the DOM). Add the missing pure ' +
        'declaration to the list, or drop the impure one from the test set.'
    );
  }

  Object.defineProperty(exported, '__meta', { value: meta, enumerable: false });
  return exported;
}

/** Every top-level declaration name in the script — useful for exploring what is liftable. */
function listTopLevelNames() {
  return [...indexTopLevelDeclarations().decls.keys()];
}

module.exports = { extract, listTopLevelNames, readMainScript };

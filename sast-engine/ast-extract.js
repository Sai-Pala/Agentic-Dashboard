/**
 * AST-based structural extraction
 * ===============================
 *
 * Pulls routes, mounts, sinks, function definitions and identifier references
 * out of a real parse tree rather than out of regex matches over lines.
 *
 * Why this replaced the regex path: every extraction bug found so far was the
 * same category — a regex losing a fight with syntax. Routes were enumerated
 * out of `/* *\/` documentation examples; `__dirname` inside
 * `path.join(__dirname, 'public')` was read as a security guard; `https://` was
 * truncated by comment-stripping; a function's own recursive call counted as a
 * caller; a multi-line `module.exports = { … }` block made every exported name
 * look used. None of those are fixable in general by a better regex, because
 * the information needed to resolve them (is this inside a comment? a string? a
 * nested call? the same function's body?) is structural. A parser has it for
 * free, and the entire class disappears.
 *
 * Parsing can fail — an exotic dialect, a syntax error, a file that is not
 * really JavaScript. `parseFile()` returns null in that case and the caller
 * falls back to the regex path for that one file, so a bad file degrades
 * instead of vanishing from the map.
 */

import path from 'path';
import { parse } from '@babel/parser';

/** Callers of an Express-style router. Deliberately the same list the regex used. */
const ROUTER_OBJECTS = new Set(['app', 'router', 'server', 'api', 'r']);
const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'all']);

/** Operations where untrusted data causes real damage, matched on the callee name. */
const SINK_KINDS = [
  { kind: 'sql', re: /(?:^|\.)(?:query|execute|raw|\$queryRaw|\$executeRaw)$/ },
  { kind: 'command', re: /(?:^|\.)(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)$/ },
  { kind: 'filesystem', re: /(?:^|\.)(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|unlink|unlinkSync|rename|renameSync|rmdir|rmdirSync|rm|rmSync|mkdir|mkdirSync|copyFile|copyFileSync|readdir|readdirSync|open|openSync|truncate|chmod|chmodSync|symlink|sendFile|download)$/ },
  { kind: 'code-eval', re: /(?:^|\.)(?:eval|runInNewContext|runInThisContext)$/ },
  { kind: 'outbound-http', re: /^(?:axios|fetch|got|request|superagent)(?:\.\w+)?$/ },
  { kind: 'response', re: /^res(?:ponse)?\.(?:send|json|write|end|render|redirect|sendFile)$/ },
  { kind: 'crypto', re: /^(?:crypto\.create(?:Cipheriv|Hash|Hmac)|jwt\.(?:sign|verify|decode))$/ },
];

/** Node keys that never contain child nodes worth walking. */
const SKIP_KEYS = new Set(['loc', 'start', 'end', 'range', 'leadingComments', 'trailingComments', 'innerComments', 'extra']);

function pluginsFor(filename) {
  const ext = path.extname(filename).toLowerCase();
  const plugins = ['decorators-legacy', 'classProperties', 'classPrivateProperties', 'dynamicImport', 'importAssertions'];
  if (ext === '.ts' || ext === '.tsx' || ext === '.mts' || ext === '.cts') plugins.push('typescript');
  if (ext === '.jsx' || ext === '.tsx') plugins.push('jsx');
  else if (ext !== '.ts') plugins.push('jsx'); // plain .js commonly contains JSX
  return plugins;
}

/** Parse one file. Returns null when the file cannot be parsed at all. */
export function parseFile(content, filename) {
  try {
    return parse(content, {
      sourceType: 'unambiguous',   // works for both ESM and CommonJS without being told which
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true,
      allowSuperOutsideMethod: true,
      errorRecovery: true,         // a stray syntax error should not cost the whole file
      plugins: pluginsFor(filename),
    });
  } catch {
    return null;
  }
}

/** Depth-first walk over every node, calling visit(node, parent). */
function walk(node, visit, parent = null) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const child of node) walk(child, visit, parent);
    return;
  }
  if (typeof node.type !== 'string') return;
  visit(node, parent);
  for (const key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue;
    walk(node[key], visit, node);
  }
}

/**
 * Reconstruct a dotted name from a callee expression: `crypto.createHash` from
 * the MemberExpression, `exec` from the Identifier. Computed access
 * (`obj[expr]`) yields null, since there is no static name to match on.
 */
function calleeName(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'ThisExpression') return 'this';
  if (node.type === 'MemberExpression') {
    if (node.computed) return null;
    const objectName = calleeName(node.object);
    const propertyName = node.property && node.property.name;
    if (!propertyName) return null;
    return objectName ? `${objectName}.${propertyName}` : propertyName;
  }
  if (node.type === 'CallExpression') return calleeName(node.callee);
  return null;
}

/** The last segment of a dotted name — `use` from `app.use`. */
const lastSegment = (name) => (name ? name.split('.').pop() : null);
/** The root object of a dotted name — `app` from `app.use`. */
const rootSegment = (name) => (name ? name.split('.')[0] : null);

function isFunctionNode(node) {
  return node.type === 'ArrowFunctionExpression'
    || node.type === 'FunctionExpression'
    || node.type === 'FunctionDeclaration';
}

/**
 * Classify a route/use call's arguments into named middleware and inline
 * handlers. Only plain identifiers count as middleware — a call expression like
 * `express.json()` is configuration, and an inline arrow is the handler itself.
 *
 * This is where the regex version reported `__dirname` as a guard: it had no
 * way to tell a top-level argument from one nested inside another call.
 */
function classifyArgs(args) {
  const middleware = [];
  let inlineHandler = false;
  for (const arg of args) {
    if (!arg) continue;
    if (arg.type === 'Identifier') middleware.push(arg.name);
    else if (arg.type === 'MemberExpression' && !arg.computed) {
      const name = calleeName(arg);
      if (name) middleware.push(name);
    } else if (isFunctionNode(arg)) inlineHandler = true;
  }
  return { middleware, inlineHandler };
}

/**
 * Extract everything of interest from one parsed file.
 *
 * `references` carries every identifier *use* — reads only. Definition names,
 * import bindings, export-object keys and object-property keys are all excluded
 * structurally, which is what makes "this function is never called" trustworthy
 * instead of a guess.
 */
export function extractFromAst(ast, relPath) {
  const routes = [];
  const mounts = [];
  const sinks = [];
  const definitions = [];
  const references = [];
  /** local alias -> original exported name, e.g. `guard` -> `requireAdmin` */
  const importAliases = new Map();

  const seenSinkLines = new Set();
  const definitionNodes = new Set();   // Identifier nodes that name a definition
  const bindingNodes = new Set();      // Identifier nodes that are import/export bindings

  walk(ast.program, (node, parent) => {
    const line = node.loc ? node.loc.start.line : null;

    // ── Routes and mounts ────────────────────────────────────────────────
    if (node.type === 'CallExpression') {
      const name = calleeName(node.callee);
      const method = lastSegment(name);
      const object = rootSegment(name);

      if (object && ROUTER_OBJECTS.has(object) && method && HTTP_METHODS.has(method)
          && node.arguments.length && node.arguments[0].type === 'StringLiteral') {
        const { middleware, inlineHandler } = classifyArgs(node.arguments.slice(1));
        routes.push({
          method: method.toUpperCase(),
          path: node.arguments[0].value,
          file: relPath,
          line,
          middleware,
          inlineHandler,
          code: '',
        });
      } else if (object && ROUTER_OBJECTS.has(object) && method === 'use' && node.arguments.length) {
        const hasPrefix = node.arguments[0].type === 'StringLiteral';
        const rest = classifyArgs(node.arguments.slice(hasPrefix ? 1 : 0));
        // In a prefixed use(), the last identifier is the router being mounted
        // and anything before it guards that subtree. With one name there is no
        // guard at all — the case most worth surfacing.
        mounts.push({
          prefix: hasPrefix ? node.arguments[0].value : null,
          file: relPath,
          line,
          middleware: hasPrefix ? rest.middleware.slice(0, -1) : rest.middleware,
          mounted: hasPrefix && rest.middleware.length ? rest.middleware[rest.middleware.length - 1] : null,
          code: '',
        });
      }

      // ── Sinks ────────────────────────────────────────────────────────
      if (name && line != null && !seenSinkLines.has(line)) {
        for (const s of SINK_KINDS) {
          if (s.re.test(name)) {
            sinks.push({ kind: s.kind, file: relPath, line, code: '' });
            seenSinkLines.add(line);
            break;
          }
        }
      }
    }

    // ── Function definitions, with exact body ranges ─────────────────────
    if (node.type === 'FunctionDeclaration' && node.id) {
      definitionNodes.add(node.id);
      definitions.push({
        name: node.id.name,
        file: relPath,
        line,
        exported: parent ? parent.type.startsWith('Export') : false,
        bodyStart: node.loc ? node.loc.start.line : line,
        bodyEnd: node.loc ? node.loc.end.line : line,
      });
    }
    if (node.type === 'VariableDeclarator' && node.id && node.id.type === 'Identifier'
        && node.init && isFunctionNode(node.init)) {
      definitionNodes.add(node.id);
      definitions.push({
        name: node.id.name,
        file: relPath,
        line,
        exported: false,
        bodyStart: node.loc ? node.loc.start.line : line,
        bodyEnd: node.loc ? node.loc.end.line : line,
      });
    }

    // ── Bindings that mention a name without using it ────────────────────
    if (node.type === 'ImportSpecifier' || node.type === 'ImportDefaultSpecifier'
        || node.type === 'ImportNamespaceSpecifier') {
      if (node.local) bindingNodes.add(node.local);
      if (node.imported) {
        bindingNodes.add(node.imported);
        if (node.local && node.local.name !== node.imported.name) {
          importAliases.set(node.local.name, node.imported.name);
        }
      }
    }
    if (node.type === 'ExportSpecifier') {
      if (node.local) bindingNodes.add(node.local);
      if (node.exported) bindingNodes.add(node.exported);
    }
    // `const { requireAdmin: guard } = require('./auth')`
    if (node.type === 'ObjectProperty' && parent && parent.type === 'ObjectPattern') {
      if (node.key && node.key.type === 'Identifier') bindingNodes.add(node.key);
      if (node.key && node.value && node.key.type === 'Identifier'
          && node.value.type === 'Identifier' && node.key.name !== node.value.name) {
        importAliases.set(node.value.name, node.key.name);
      }
    }
    // `module.exports = { requireUser, requireAdmin }` — a manifest of names,
    // not a set of calls. The regex version could only skip the first line of
    // such a block, which made every exported function look used.
    if (node.type === 'ObjectProperty' && node.key && node.key.type === 'Identifier' && !node.computed) {
      bindingNodes.add(node.key);
      if (node.shorthand && node.value && node.value.type === 'Identifier') {
        bindingNodes.add(node.value);
      }
    }
    // NOTE: `.foo` in `a.foo` is deliberately NOT excluded here.
    //
    // It is tempting to call it "a property, not a variable reference", but a
    // module imported as a namespace is used exactly this way —
    // `const db = require('./store'); db.verifyPassword(...)` — and excluding
    // it reports every such function as never called. That is the single most
    // common shape in a CommonJS codebase, so the exclusion turned a useful
    // check into a false-positive generator. Counting the property instead can
    // only over-count when an unrelated object happens to share a name with a
    // defined function, which is both rare and the safer direction to err in.
    if (node.type === 'ObjectMethod' && node.key) bindingNodes.add(node.key);
    if (node.type === 'ClassMethod' && node.key) bindingNodes.add(node.key);
  });

  // Second walk: collect identifier *uses* only, now that we know which
  // identifier nodes are definitions or bindings.
  walk(ast.program, (node, parent) => {
    if (node.type !== 'Identifier') return;
    if (definitionNodes.has(node) || bindingNodes.has(node)) return;
    // A function's own parameters are not references to anything outside it.
    if (parent && isFunctionNode(parent) && parent.params && parent.params.includes(node)) return;
    if (parent && parent.type === 'VariableDeclarator' && parent.id === node) return;
    references.push({
      name: importAliases.get(node.name) || node.name,
      file: relPath,
      line: node.loc ? node.loc.start.line : null,
    });
  });

  return { routes, mounts, sinks, definitions, references, importAliases };
}

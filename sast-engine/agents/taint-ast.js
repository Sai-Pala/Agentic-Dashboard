/**
 * AST-based taint tracking
 * ========================
 *
 * Follows untrusted values from where they enter to where something dangerous
 * happens with them, using a real parse tree instead of line-by-line regex.
 *
 * What the tree buys, concretely — every one of these is invisible to the regex
 * implementation and free here:
 *
 *     const { id } = req.params;              nested destructuring
 *     const [first] = req.body.items;         array destructuring
 *     const opts = { path: req.query.p };     taint into an object property
 *     sink(wrap(req.query.x))                 taint through a nested call
 *     `https://${host}`                       no comment-stripping to get wrong
 *
 * And two things stop being guesses:
 *
 *   - SCOPE. The regex version looks for text that *resembles* a function
 *     opening and clears state. Here a function IS a node, so "taint does not
 *     leak from one route handler into the next" is structural rather than
 *     hopeful.
 *   - SAFE CALL SHAPES. `db.query('… ?', [v])` is safe because the first
 *     argument is a StringLiteral and there is a second argument — a fact about
 *     the call's structure, not a pattern in its text. Same for
 *     `execFile(cmd, [args])`.
 *
 * Deliberate scope limits, unchanged from the regex version: intra-procedural
 * only (a value passed into a helper is not followed across the call), and a
 * finding is only reported when the source is on an EARLIER line than the sink,
 * so this never restates a same-line finding another agent already reports.
 */

/** Where untrusted data enters. Matched on the object of a member expression. */
const REQUEST_OBJECTS = new Set(['req', 'request', 'ctx']);
const REQUEST_PROPERTIES = new Set(['query', 'body', 'params', 'headers', 'cookies']);
const EVENT_PROPERTIES = new Set(['body', 'queryStringParameters', 'pathParameters']);

/** Calls that render a value harmless. */
const SANITIZERS = new Set([
  'parseInt', 'parseFloat', 'Number', 'Boolean', 'encodeURIComponent', 'encodeURI',
  'escape', 'escapeHtml', 'sanitize', 'sanitizeHtml', 'DOMPurify.sanitize',
  'validator.escape', 'validator.toInt', 'z.parse', 'schema.parse', 'schema.safeParse',
]);
const SANITIZER_NAME_RE = /^(?:sanitiz|escape|validate|purif)/i;

/**
 * Guard strength, by kind. Not all validation is equal, and which kinds count
 * depends on what the value is about to be used for:
 *
 *   full.startsWith(DOC_ROOT)      ← correct, complete fix for path containment
 *   target.startsWith('https://')  ← says NOTHING about the host, so worthless
 *                                    against SSRF: https://169.254.169.254/
 *                                    passes it and reaches cloud metadata
 *
 * So a prefix check clears taint for a filesystem sink and does not clear it for
 * an outbound request. Treating all guards as equally strong is how a scanner
 * misses the interesting half of SSRF.
 */
const GUARD_KINDS = [
  { kind: 'anchored-regex', test: (name, node) => isAnchoredRegexTest(node) },
  { kind: 'allowlist', test: (name) => /(?:^|\.)(?:includes|has|every|some|indexOf)$/.test(name) },
  { kind: 'validator-lib', test: (name) => /^(?:validator|Joi|yup|z|ajv)\./.test(name) || /(?:^|\.)(?:isUUID|isEmail|isNumeric|isAlphanumeric|safeParse)$/.test(name) },
  { kind: 'format-test', test: (name, node) => /(?:^|\.)(?:test|match)$/.test(name) && !isAnchoredRegexTest(node) },
  { kind: 'prefix', test: (name) => /(?:^|\.)(?:startsWith|endsWith)$/.test(name) },
];

/** Which guard kinds are strong enough to stand down, per sink. */
const GUARD_ACCEPTS = {
  sql: ['anchored-regex', 'allowlist', 'validator-lib', 'format-test'],
  command: ['anchored-regex', 'allowlist', 'validator-lib', 'format-test'],
  code: ['anchored-regex', 'allowlist', 'validator-lib'],
  // A prefix check IS the documented containment fix for path traversal.
  path: ['anchored-regex', 'allowlist', 'validator-lib', 'format-test', 'prefix'],
  // Deliberately excludes 'prefix' — see the comment above.
  ssrf: ['anchored-regex', 'allowlist', 'validator-lib'],
  xss: ['anchored-regex', 'allowlist', 'validator-lib', 'format-test'],
  redirect: ['anchored-regex', 'allowlist', 'validator-lib'],
};

/** `/^[a-f0-9]{32}$/.test(x)` — anchored at both ends, so the whole value is pinned. */
function isAnchoredRegexTest(node) {
  if (!node || node.type !== 'CallExpression') return false;
  const callee = node.callee;
  if (!callee || callee.type !== 'MemberExpression') return false;
  const obj = callee.object;
  if (!obj || obj.type !== 'RegExpLiteral') return false;
  return obj.pattern.startsWith('^') && obj.pattern.endsWith('$');
}

/**
 * Sinks. `match` runs against the dotted callee name; `safeWhen` inspects the
 * call node itself, which is where the structural checks live.
 */
const AST_SINKS = [
  {
    id: 'sql',
    match: /(?:^|\.)(?:query|execute|raw|\$queryRaw|\$executeRaw)$/,
    severity: 'critical', cwe: 'CWE-89', owasp: 'A03:2021',
    rule: 'TAINT_SQL_INJECTION',
    title: 'SQL Injection via Tracked User Input',
    what: 'reaches a SQL query',
    fix: 'Use a parameterized query — db.query("SELECT ... WHERE id = $1", [value]) — rather than building the statement from the value.',
    // A plain string statement plus at least one more argument means the driver
    // binds the rest. A template literal is the interpolated form — the bug.
    safeWhen: (call) => call.arguments.length >= 2 && call.arguments[0].type === 'StringLiteral',
  },
  {
    id: 'command',
    match: /(?:^|\.)(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)$/,
    severity: 'critical', cwe: 'CWE-78', owasp: 'A03:2021',
    rule: 'TAINT_COMMAND_INJECTION',
    title: 'Command Injection via Tracked User Input',
    what: 'reaches a shell/process call',
    fix: 'Use execFile(cmd, [args]) with an argument array and no shell, and validate the value against an allowlist.',
    // execFile/spawn with an argv array never goes through a shell.
    safeWhen: (call, name) => /(?:^|\.)(?:execFile|execFileSync|spawn|spawnSync)$/.test(name)
      && call.arguments.length >= 2 && call.arguments[1].type === 'ArrayExpression',
  },
  {
    id: 'path',
    match: /(?:^|\.)(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|unlink|unlinkSync|rename|renameSync|rmdir|rmdirSync|mkdir|mkdirSync|readdir|readdirSync|sendFile|copyFile|copyFileSync)$/,
    severity: 'high', cwe: 'CWE-22', owasp: 'A01:2021',
    rule: 'TAINT_PATH_TRAVERSAL',
    title: 'Path Traversal via Tracked User Input',
    what: 'reaches a filesystem call',
    fix: 'Resolve the path and reject it unless it still starts with the intended base directory.',
  },
  {
    id: 'code',
    match: /(?:^|\.)(?:eval|runInNewContext|runInThisContext)$/,
    severity: 'critical', cwe: 'CWE-95', owasp: 'A03:2021',
    rule: 'TAINT_CODE_INJECTION',
    title: 'Code Injection via Tracked User Input',
    what: 'reaches a code-evaluation call',
    fix: 'Do not evaluate request data. Parse it, or dispatch on an allowlist of known operations.',
  },
  {
    id: 'ssrf',
    match: /^(?:axios|fetch|got|superagent|request)(?:\.\w+)?$/,
    severity: 'high', cwe: 'CWE-918', owasp: 'A10:2021',
    rule: 'TAINT_SSRF',
    title: 'SSRF via Tracked User Input',
    what: 'reaches an outbound HTTP request',
    fix: 'Resolve the host and check it against an allowlist before the request, and disable redirect following.',
  },
  {
    id: 'xss',
    match: /^res(?:ponse)?\.(?:send|write|end)$/,
    severity: 'high', cwe: 'CWE-79', owasp: 'A03:2021',
    rule: 'TAINT_XSS_REFLECTED',
    title: 'Reflected XSS via Tracked User Input',
    what: 'is written into an HTTP response body',
    fix: 'Escape the value for HTML context, or return JSON with a correct content type.',
  },
  {
    id: 'redirect',
    match: /^res(?:ponse)?\.redirect$/,
    severity: 'medium', cwe: 'CWE-601', owasp: 'A01:2021',
    rule: 'TAINT_OPEN_REDIRECT',
    title: 'Open Redirect via Tracked User Input',
    what: 'is used as a redirect target',
    fix: 'Redirect only to a relative path, or check the destination against an allowlist.',
  },
];

const MAX_FLOW_DISTANCE = 60;

const isFunctionNode = (n) => n && (n.type === 'ArrowFunctionExpression'
  || n.type === 'FunctionExpression' || n.type === 'FunctionDeclaration'
  || n.type === 'ObjectMethod' || n.type === 'ClassMethod');

/** Dotted name for a callee/member expression, or null when it is computed. */
function dottedName(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'ThisExpression') return 'this';
  if (node.type === 'MemberExpression') {
    if (node.computed) return null;
    const obj = dottedName(node.object);
    const prop = node.property && node.property.name;
    if (!prop) return null;
    return obj ? `${obj}.${prop}` : prop;
  }
  return null;
}

const lineOf = (node) => (node && node.loc ? node.loc.start.line : null);

/** Is this member expression reading request data? `req.query.id`, `ctx.params` */
function isRequestSource(node) {
  if (!node || node.type !== 'MemberExpression') return false;
  const name = dottedName(node);
  if (!name) {
    // Computed access still counts: req.query[key]
    const objName = dottedName(node.object);
    return Boolean(objName && isRequestSource(node.object));
  }
  const parts = name.split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    if (REQUEST_OBJECTS.has(parts[i]) && REQUEST_PROPERTIES.has(parts[i + 1])) return true;
    if (parts[i] === 'event' && EVENT_PROPERTIES.has(parts[i + 1])) return true;
  }
  if (/^process\.argv/.test(name)) return true;
  if (/^location\.(?:search|hash|href)$/.test(name)) return true;
  if (name === 'document.referrer' || name === 'window.name') return true;
  return false;
}

function isSanitizerCall(node) {
  if (!node || node.type !== 'CallExpression') return false;
  const name = dottedName(node.callee);
  if (!name) return false;
  if (SANITIZERS.has(name)) return true;
  const last = name.split('.').pop();
  return SANITIZER_NAME_RE.test(last) || SANITIZER_NAME_RE.test(name);
}

const isLiteral = (n) => n && (n.type === 'StringLiteral' || n.type === 'NumericLiteral'
  || n.type === 'BooleanLiteral' || n.type === 'NullLiteral'
  || (n.type === 'TemplateLiteral' && n.expressions.length === 0));

/**
 * Decide whether an expression carries taint.
 *
 * Returns the origin ({line, via}) when tainted, else null. `state` is the
 * current scope's map of tainted variable names.
 */
function taintOf(node, state) {
  if (!node) return null;

  switch (node.type) {
    case 'Identifier':
      return state.get(node.name) || null;

    case 'MemberExpression': {
      if (isRequestSource(node)) return { line: lineOf(node), via: dottedName(node) || 'request data' };
      // `parsed.hostname` is tainted if `parsed` is.
      return taintOf(node.object, state);
    }

    case 'CallExpression':
      // A sanitizer launders whatever went in.
      if (isSanitizerCall(node)) return null;
      // Otherwise a call's result is tainted if any argument was — conservative,
      // and what makes `String(req.query.x)` stay tainted.
      for (const arg of node.arguments) {
        const t = taintOf(arg, state);
        if (t) return t;
      }
      return taintOf(node.callee && node.callee.object, state);

    case 'BinaryExpression':
      // A comparison yields a boolean; it cannot carry a payload.
      if (node.operator !== '+') return null;
      return taintOf(node.left, state) || taintOf(node.right, state);

    case 'LogicalExpression':
      return taintOf(node.left, state) || taintOf(node.right, state);

    case 'ConditionalExpression':
      // `req.query.r === 'year' ? 'year' : 'month'` collapses attacker input to
      // a fixed set of literals, so the result is not attacker-controlled.
      if (isLiteral(node.consequent) && isLiteral(node.alternate)) return null;
      return taintOf(node.consequent, state) || taintOf(node.alternate, state);

    case 'TemplateLiteral':
      for (const e of node.expressions) {
        const t = taintOf(e, state);
        if (t) return t;
      }
      return null;

    case 'ObjectExpression':
      for (const p of node.properties) {
        const t = taintOf(p.value, state);
        if (t) return t;
      }
      return null;

    case 'ArrayExpression':
      for (const e of node.elements) {
        const t = taintOf(e, state);
        if (t) return t;
      }
      return null;

    case 'AwaitExpression':
    case 'TSNonNullExpression':
    case 'TSAsExpression':
      return taintOf(node.argument || node.expression, state);

    case 'SpreadElement':
      return taintOf(node.argument, state);

    case 'UnaryExpression':
      return null; // !x, typeof x — not a payload

    default:
      return null;
  }
}

/** Bind taint (or clear it) for every name introduced by a declaration pattern. */
function bindPattern(pattern, origin, state) {
  if (!pattern) return;
  switch (pattern.type) {
    case 'Identifier':
      if (origin) state.set(pattern.name, origin);
      else state.delete(pattern.name);
      break;
    case 'ObjectPattern':
      for (const prop of pattern.properties) {
        if (prop.type === 'RestElement') bindPattern(prop.argument, origin, state);
        else bindPattern(prop.value, origin, state);
      }
      break;
    case 'ArrayPattern':
      for (const el of pattern.elements) bindPattern(el, origin, state);
      break;
    case 'AssignmentPattern':
      bindPattern(pattern.left, origin, state);
      break;
    case 'RestElement':
      bindPattern(pattern.argument, origin, state);
      break;
    default:
      break;
  }
}

/** Collect every identifier named anywhere inside a node. */
function namesIn(node, out = new Set()) {
  if (!node || typeof node !== 'object') return out;
  if (Array.isArray(node)) {
    for (const n of node) namesIn(n, out);
    return out;
  }
  if (typeof node.type !== 'string') return out;
  if (node.type === 'Identifier') out.add(node.name);
  for (const k of Object.keys(node)) {
    if (k === 'loc' || k === 'start' || k === 'end') continue;
    namesIn(node[k], out);
  }
  return out;
}

const exitsScope = (stmt) => {
  if (!stmt) return false;
  if (stmt.type === 'ReturnStatement' || stmt.type === 'ThrowStatement') return true;
  if (stmt.type === 'BlockStatement') return stmt.body.some(exitsScope);
  if (stmt.type === 'ExpressionStatement') {
    const name = stmt.expression.type === 'CallExpression' ? dottedName(stmt.expression.callee) : null;
    return name === 'next';
  }
  return false;
};

/**
 * `if (!/^[a-f0-9]{32}$/.test(id)) return …` — everything after only runs for
 * values that passed. Clears taint for the variables named IN THE CONDITION
 * only: a guard on `parsed.hostname` says nothing about a different variable
 * fetched later, which is exactly the SSRF-allowlist-bypass this must keep
 * finding.
 */
function applyGuard(node, state) {
  if (node.type !== 'IfStatement' || !node.test) return;
  if (!exitsScope(node.consequent)) return;

  const kinds = new Set();
  const scan = (n) => {
    if (!n || typeof n !== 'object' || typeof n.type !== 'string') return;
    if (n.type === 'CallExpression') {
      const name = dottedName(n.callee) || '';
      for (const g of GUARD_KINDS) {
        if (g.test(name, n)) { kinds.add(g.kind); break; }
      }
    }
    for (const k of Object.keys(n)) {
      if (k === 'loc' || k === 'start' || k === 'end') continue;
      const v = n[k];
      if (Array.isArray(v)) v.forEach(scan);
      else scan(v);
    }
  };
  scan(node.test);
  if (!kinds.size) return;

  // Mark rather than delete: whether this guard is sufficient depends on the
  // sink the value later reaches, which is not known yet.
  for (const name of namesIn(node.test)) {
    const entry = state.get(name);
    if (!entry) continue;
    const guardedBy = new Set(entry.guardedBy || []);
    for (const k of kinds) guardedBy.add(k);
    state.set(name, { ...entry, guardedBy });
  }
}

/**
 * Analyze one parsed file. Returns raw finding descriptors; the agent turns
 * them into real findings so it keeps ownership of suppression and formatting.
 */
export function analyzeTaintAst(ast, sourceLines) {
  const out = [];
  const reported = new Set();

  /** Walk one function scope's body in source order with its own taint map. */
  const runScope = (bodyNode, state) => {
    const step = (node) => {
      if (!node || typeof node !== 'object' || typeof node.type !== 'string') return;

      // A nested function is its own scope — taint does not leak into it.
      if (isFunctionNode(node)) {
        runScope(node.body, new Map());
        return;
      }

      // Sinks first would miss same-statement assignment; assignments first
      // would wrongly taint the sink's own line. Order matches the regex
      // version: record assignment, apply guards, then test sinks.
      if (node.type === 'VariableDeclaration') {
        for (const d of node.declarations) {
          bindPattern(d.id, taintOf(d.init, state), state);
        }
      } else if (node.type === 'ExpressionStatement'
                 && node.expression.type === 'AssignmentExpression') {
        const a = node.expression;
        if (a.left.type === 'Identifier') {
          const origin = a.operator === '=' ? taintOf(a.right, state)
            : (taintOf(a.left, state) || taintOf(a.right, state));
          bindPattern(a.left, origin, state);
        }
      } else if (node.type === 'IfStatement') {
        applyGuard(node, state);
      }

      // Sink check
      if (node.type === 'CallExpression') {
        const name = dottedName(node.callee);
        if (name) {
          for (const sink of AST_SINKS) {
            if (!sink.match.test(name)) continue;
            if (sink.safeWhen && sink.safeWhen(node, name)) break;
            const sinkLine = lineOf(node);
            const accepts = GUARD_ACCEPTS[sink.id] || [];
            // Only the argument that actually carries the danger. For every sink
            // here that is the first one — the SQL statement, the command, the
            // path, the URL, the response body. Checking all arguments reports
            // `fs.writeFileSync(safePath, userContent)` as path traversal, which
            // is the wrong vulnerability at a correctly-guarded call site.
            const dangerous = (sink.argIndexes || [0])
              .map((i) => node.arguments[i])
              .filter(Boolean);
            for (const arg of dangerous) {
              const origin = taintOf(arg, state);
              if (!origin) continue;
              // A guard already ran on this value — but only stand down if the
              // guard was strong enough for THIS sink.
              if (origin.guardedBy && [...origin.guardedBy].some((k) => accepts.includes(k))) continue;
              // Only cross-line flows: a same-line source is already covered by
              // the line-local agents, and repeating it adds nothing.
              if (origin.line == null || sinkLine == null) continue;
              if (origin.line >= sinkLine) continue;
              if (sinkLine - origin.line > MAX_FLOW_DISTANCE) continue;
              const key = `${sinkLine}:${sink.rule}`;
              if (reported.has(key)) break;
              reported.add(key);
              const varName = arg.type === 'Identifier' ? arg.name : (dottedName(arg) || 'the value');
              out.push({
                line: sinkLine,
                sink,
                varName,
                originLine: origin.line,
                via: origin.via,
                matched: (sourceLines[sinkLine - 1] || '').trim().slice(0, 200),
              });
              break;
            }
            break;
          }
        }
      }

      // Recurse in source order.
      for (const key of Object.keys(node)) {
        if (key === 'loc' || key === 'start' || key === 'end') continue;
        const child = node[key];
        if (Array.isArray(child)) child.forEach(step);
        else step(child);
      }
    };

    if (Array.isArray(bodyNode)) bodyNode.forEach(step);
    else step(bodyNode);
  };

  runScope(ast.program.body, new Map());
  return out;
}

/**
 * TaintFlowAgent — Cross-Line Data Flow
 * ======================================
 *
 * Follows user-controlled values through local variables to dangerous sinks,
 * covering the case every other agent here structurally cannot see.
 *
 * BaseAgent.scanFileWithPatterns() tests each regex against one physical line,
 * so every pattern-based agent requires the taint source and the sink to appear
 * on the same line. Ordinary code does not look like that:
 *
 *     const term = req.query.term;                                    // source
 *     const clause = "SELECT * FROM products WHERE sku = '" + term;   // propagation
 *     const rows = await db.query(clause);                            // sink
 *
 * Cross-line SQL injection, path traversal and command injection are all
 * invisible to every line-local pattern agent for this reason, and an LLM pass
 * is not a reliable substitute — AST-based tools catch them precisely because
 * they do not care about line boundaries. This agent closes that gap without
 * adding a parser dependency.
 *
 * Deliberate scope limits — this is a heuristic, not sound dataflow analysis:
 *   - Intra-procedural only. A value tainted in one function and passed to
 *     another is not tracked; that needs a call graph this engine doesn't have.
 *   - Taint resets at each apparent function/handler boundary, so a variable
 *     in one route handler can't leak taint into the next.
 *   - Only fires when the source is on an EARLIER line than the sink. Same-line
 *     cases are already covered by InjectionTester and friends, and reporting
 *     them here would duplicate those findings rather than add anything.
 *   - Assignment through a recognized sanitizer/caster clears taint.
 */

import path from 'path';
import { BaseAgent, createFinding } from '../core/base-agent.js';
import { parseFile } from '../../ast-extract.js';
import { analyzeTaintAst } from '../core/taint-ast.js';

// ── Where untrusted data enters ───────────────────────────────────────────────
const TAINT_SOURCE = /\b(?:req|request)\s*\.\s*(?:query|body|params|headers|cookies)\b|\bctx\s*\.\s*(?:query|params|request)\b|\bevent\s*\.\s*(?:body|queryStringParameters|pathParameters)\b|\bprocess\.argv\b|\blocation\s*\.\s*(?:search|hash|href)\b|\bwindow\.name\b|\bdocument\.referrer\b|\bnew\s+URLSearchParams\b/;

// A value that has been through one of these is no longer attacker-shaped.
const SANITIZER = /\b(?:parseInt|parseFloat|Number|Boolean|encodeURIComponent|encodeURI|escape|sanitize|sanitizeHtml|DOMPurify|validator|escapeHtml|zod|z\s*\.\s*\w+|schema\s*\.\s*(?:parse|safeParse)|Joi\s*\.|yup\s*\.|allowlist|whitelist)\b|\.(?:test|match|includes|startsWith|endsWith)\s*\(/;

// A new scope starts here, clearing tracked taint.
const SCOPE_BOUNDARY = /\bfunction\s|=>\s*\{|\b(?:router|app|server)\s*\.\s*(?:get|post|put|patch|delete|all|use)\s*\(|\bclass\s+\w+|^\s*(?:async\s+)?\w+\s*\([^)]*\)\s*\{/;

// ── Shapes that mean a value is no longer attacker-controlled ────────────────

/**
 * A query whose statement is a plain quoted string literal followed by another
 * argument is parameterized: the driver binds the remaining arguments, so user
 * data in them cannot change the statement's structure. A template literal is
 * deliberately excluded — that is the interpolated form, which is the bug.
 * This is the single largest source of false positives in SQL taint analysis.
 */
const PARAMETERIZED_QUERY =
  /\.\s*(?:query|execute|raw|\$queryRaw|\$executeRaw)\s*\(\s*(['"])(?:\\.|(?!\1)[^\\])*\1\s*,/;

/** execFile/spawn with an argv array and no shell never goes through a shell. */
const ARGV_ARRAY_CALL = /\b(?:execFile|execFileSync|spawn|spawnSync)\s*\(\s*[^,]+,\s*\[/;

/**
 * `x === 'a' ? 'a' : 'b'` collapses attacker input to a fixed set of literals,
 * and a bare comparison yields a boolean. Neither can carry an injection
 * payload, however tainted the operand was.
 */
const LITERAL_TERNARY = /\?\s*(?:'[^']*'|"[^"]*"|`[^`${]*`|\d+|true|false|null)\s*:\s*(?:'[^']*'|"[^"]*"|`[^`${]*`|\d+|true|false|null)\s*;?\s*$/;
const BARE_COMPARISON = /^[^?]*(?:===|!==|==|!=)[^?]*$/;

/**
 * An early-return guard that validates a value and bails out — the classic
 * `if (!/^[a-f0-9]{32}$/.test(id)) return res.status(400)...`. Code after such
 * a guard only runs for values that passed it.
 */
const GUARD_STATEMENT = /^\s*if\s*\(([^]*)\)\s*(?:\{\s*)?(?:return|throw|next\s*\()/;
const GUARD_VALIDATOR = /\.(?:test|match|includes|indexOf|startsWith|endsWith|every|some)\s*\(|\b(?:validator|Joi|yup|z)\s*\.|\b(?:isUUID|isEmail|isNumeric|isAlphanumeric)\s*\(/;

// ── Dangerous sinks, grouped by what reaching them means ─────────────────────
const SINKS = [
  {
    id: 'sql',
    regex: /\b(?:db|conn|connection|client|pool|sequelize|knex|prisma)?\s*\.?\s*(?:query|execute|raw|\$queryRaw|\$executeRaw)\s*\(/,
    severity: 'critical',
    cwe: 'CWE-89',
    owasp: 'A03:2021',
    rule: 'TAINT_SQL_INJECTION',
    title: 'SQL Injection via Tracked User Input',
    what: 'reaches a SQL query',
    fix: 'Use a parameterized query — db.query("SELECT ... WHERE id = $1", [value]) — rather than building the statement from the value.',
    safeWhen: PARAMETERIZED_QUERY,
  },
  {
    id: 'command',
    regex: /\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(/,
    severity: 'critical',
    cwe: 'CWE-78',
    owasp: 'A03:2021',
    rule: 'TAINT_COMMAND_INJECTION',
    title: 'Command Injection via Tracked User Input',
    what: 'reaches a shell/process call',
    fix: 'Use execFile(cmd, [args]) with an argument array and no shell, and validate the value against an allowlist.',
    safeWhen: ARGV_ARRAY_CALL,
  },
  {
    id: 'path',
    regex: /\b(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|unlink|unlinkSync|rename|renameSync|rmdir|readdir|readdirSync|sendFile)\s*\(/,
    severity: 'high',
    cwe: 'CWE-22',
    owasp: 'A01:2021',
    rule: 'TAINT_PATH_TRAVERSAL',
    title: 'Path Traversal via Tracked User Input',
    what: 'reaches a filesystem call',
    fix: 'Resolve the path and confirm it stays inside the intended directory: const p = path.resolve(base, name); if (!p.startsWith(base)) throw new Error("invalid path").',
  },
  {
    id: 'code',
    regex: /\beval\s*\(|\bnew\s+Function\s*\(|\bvm\s*\.\s*(?:runInNewContext|runInThisContext|compileFunction)\s*\(|\bsetTimeout\s*\(\s*[a-zA-Z_$]/,
    severity: 'critical',
    cwe: 'CWE-94',
    owasp: 'A03:2021',
    rule: 'TAINT_CODE_INJECTION',
    title: 'Code Injection via Tracked User Input',
    what: 'reaches a dynamic code evaluation',
    fix: 'Do not evaluate user input. Use JSON.parse() for data, or a domain-specific parser.',
  },
  {
    id: 'ssrf',
    regex: /\b(?:axios|fetch|got|superagent|needle)\s*(?:\.\s*(?:get|post|put|patch|delete|head|request))?\s*\(|\b(?:http|https)\s*\.\s*(?:get|request)\s*\(/,
    severity: 'high',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    rule: 'TAINT_SSRF',
    title: 'SSRF via Tracked User Input',
    what: 'reaches an outbound HTTP request',
    fix: 'Validate the URL against an allowlist of permitted hosts and reject internal/link-local addresses before requesting it.',
  },
  {
    id: 'xss',
    regex: /\.\s*innerHTML\s*=|\.\s*outerHTML\s*=|\bdocument\s*\.\s*write(?:ln)?\s*\(|\bres\s*\.\s*(?:send|write|end)\s*\(/,
    severity: 'high',
    cwe: 'CWE-79',
    owasp: 'A03:2021',
    rule: 'TAINT_XSS',
    title: 'Cross-Site Scripting via Tracked User Input',
    what: 'reaches an HTML response or DOM sink',
    fix: 'Escape the value for its output context, or use textContent / a templating engine with automatic escaping.',
  },
  {
    id: 'redirect',
    regex: /\bres\s*\.\s*redirect\s*\(|\blocation\s*\.\s*(?:href|assign|replace)\s*[=(]/,
    severity: 'medium',
    cwe: 'CWE-601',
    owasp: 'A01:2021',
    rule: 'TAINT_OPEN_REDIRECT',
    title: 'Open Redirect via Tracked User Input',
    what: 'reaches a redirect',
    fix: 'Only redirect to relative paths, or check the destination against an allowlist of trusted hosts.',
  },
];

/**
 * Strip a trailing `//` comment without breaking string contents.
 *
 * A plain /\/\/.*$/ replace looks correct and silently corrupts any line
 * containing a URL: `const full = \`https://${target}/api\`` gets truncated at
 * the protocol slashes, so the tainted variable inside the template is never
 * seen and a real SSRF flow goes unreported. Tracking quote state costs almost
 * nothing and removes that whole class of mistake.
 */
function stripLineComment(line) {
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === '\\') { i++; continue; }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
    if (ch === '/' && line[i + 1] === '/') return line.slice(0, i);
  }
  return line;
}

const CODE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);
// How far a tainted assignment stays interesting. Beyond this the connection is
// too weak to report with confidence.
const MAX_FLOW_DISTANCE = 60;

export class TaintFlowAgent extends BaseAgent {
  constructor() {
    super('TaintFlowAgent', 'Track user input across lines to dangerous sinks', 'dataflow');
  }

  shouldRun() {
    return true;
  }

  async analyze(context) {
    const files = this.getFilesToScan(context).filter((f) =>
      CODE_EXTENSIONS.has(path.extname(f).toLowerCase()));
    const forceRegex = Boolean(context.options && context.options.forceRegexTaint);
    const findings = [];
    for (const file of files) {
      findings.push(...(forceRegex ? this._scanFile(file) : this._scanFileAst(file)));
    }
    return findings;
  }

  /**
   * Preferred path: track taint over a real parse tree. Falls back to the regex
   * scanner for any single file that will not parse, so an exotic dialect or a
   * syntax error costs that one file rather than silently blanking it.
   */
  _scanFileAst(filePath) {
    const content = this.readFile(filePath);
    if (!content) return [];
    const ast = parseFile(content, filePath);
    if (!ast) return this._scanFile(filePath);

    const sourceLines = content.split('\n');
    const findings = [];
    for (const hit of analyzeTaintAst(ast, sourceLines)) {
      const rawLine = sourceLines[hit.line - 1] || '';
      if (this.isSuppressed(rawLine, hit.sink.severity)) continue;
      const f = createFinding({
        file: filePath,
        line: hit.line,
        column: Math.max(1, rawLine.indexOf(hit.varName) + 1),
        severity: hit.sink.severity,
        category: 'dataflow',
        rule: hit.sink.rule,
        title: hit.sink.title,
        description: `User input from \`${hit.via}\` (line ${hit.originLine}) flows into \`${hit.varName}\` and ${hit.sink.what} here on line ${hit.line} with no validation or escaping in between.`,
        matched: hit.matched,
        confidence: 'high',
        cwe: hit.sink.cwe,
        owasp: hit.sink.owasp,
        fix: hit.sink.fix,
      });
      f.taintSourceLine = hit.originLine;
      findings.push(f);
    }
    return findings;
  }

  _scanFile(filePath) {
    const content = this.readFile(filePath);
    if (!content) return [];
    const lines = content.split('\n');
    const findings = [];

    /** @type {Map<string, {line: number, via: string}>} name -> where it became tainted */
    let tainted = new Map();
    const reported = new Set();

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const stripped = stripLineComment(line);
      if (!stripped.trim() || /^\s*(?:\*|\/\*)/.test(line)) continue;

      // A new function/handler starts: previously tracked locals are out of scope.
      if (SCOPE_BOUNDARY.test(stripped) && tainted.size) tainted = new Map();

      this._trackAssignment(stripped, i, tainted);
      this._applyGuard(stripped, tainted);

      // Does this line pass anything tainted into a sink?
      for (const sink of SINKS) {
        if (!sink.regex.test(stripped)) continue;
        // The call is structurally safe for this sink (bound parameters, argv
        // array), so reaching it with tainted data is not a vulnerability.
        if (sink.safeWhen && sink.safeWhen.test(stripped)) continue;
        for (const [name, origin] of tainted) {
          if (origin.line === i) continue; // same line — existing agents already cover this
          if (i - origin.line > MAX_FLOW_DISTANCE) continue;
          if (!this._usesVariable(stripped, name)) continue;

          const key = `${i}:${sink.rule}`;
          if (reported.has(key)) continue;
          if (this.isSuppressed(line, sink.severity)) continue;
          reported.add(key);

          const f = createFinding({
            file: filePath,
            line: i + 1,
            column: stripped.indexOf(name) + 1,
            severity: sink.severity,
            category: 'dataflow',
            rule: sink.rule,
            title: sink.title,
            description: `User input from \`${origin.via}\` (line ${origin.line + 1}) flows into \`${name}\` and ${sink.what} here on line ${i + 1} with no validation or escaping in between.`,
            matched: stripped.trim().slice(0, 200),
            confidence: 'high',
            cwe: sink.cwe,
            owasp: sink.owasp,
            fix: sink.fix,
          });
          f.taintSourceLine = origin.line + 1;
          findings.push(f);
          break; // one finding per sink per line, regardless of how many tainted vars reach it
        }
      }
    }

    return findings;
  }

  /**
   * Clear taint for any variable an early-return guard validates on this line.
   *
   * `if (!/^[a-f0-9]{32}$/.test(id)) return res.status(400)...` means every line
   * below it only runs for values matching that pattern. Without this, a
   * correctly validated input keeps its taint all the way to the sink and gets
   * reported — one of the most common false positives in taint analysis, and
   * exactly the shape developers are told to write.
   *
   * Only the variables actually named in the condition are cleared: a guard on
   * `parsed.hostname` says nothing about a different variable used later, which
   * is precisely the SSRF-allowlist-bypass bug this engine needs to keep finding.
   */
  _applyGuard(line, tainted) {
    if (!tainted.size) return;
    const guard = line.match(GUARD_STATEMENT);
    if (!guard) return;
    const condition = guard[1];
    if (!GUARD_VALIDATOR.test(condition)) return;
    for (const name of [...tainted.keys()]) {
      if (this._usesVariable(condition, name)) tainted.delete(name);
    }
  }

  /**
   * Record or clear taint for a variable assigned on this line.
   * Covers `const x = <expr>`, plain reassignment `x = <expr>`, and destructuring
   * `const { a, b } = req.query`.
   */
  _trackAssignment(line, index, tainted) {
    // Destructuring straight off a source: const { term, page } = req.query
    const destructure = line.match(/(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(.+)$/);
    if (destructure && TAINT_SOURCE.test(destructure[2])) {
      for (const raw of destructure[1].split(',')) {
        const name = raw.split(':').pop().trim().replace(/=.*$/, '').trim();
        if (/^[A-Za-z_$][\w$]*$/.test(name)) {
          tainted.set(name, { line: index, via: destructure[2].trim().slice(0, 60) });
        }
      }
      return;
    }

    const assign = line.match(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)$/)
      || line.match(/^\s*([A-Za-z_$][\w$]*)\s*=\s*(.+)$/);
    if (!assign) return;

    const [, name, rhsRaw] = assign;
    const rhs = rhsRaw.trim();

    // Direct source, or propagation from an already-tainted variable.
    const fromSource = TAINT_SOURCE.test(rhs);
    let fromVar = null;
    if (!fromSource) {
      for (const [tname, origin] of tainted) {
        if (tname !== name && this._usesVariable(rhs, tname)) { fromVar = origin; break; }
      }
    }
    if (!fromSource && !fromVar) {
      // Reassigned to something clean — it is no longer attacker-controlled.
      if (tainted.has(name)) tainted.delete(name);
      return;
    }

    // Passed through validation/casting on the way in, or collapsed to a fixed
    // set of literals / a boolean, which cannot carry a payload either way.
    if (SANITIZER.test(rhs) || LITERAL_TERNARY.test(rhs) || (!rhs.includes('?') && BARE_COMPARISON.test(rhs))) {
      tainted.delete(name);
      return;
    }

    tainted.set(name, fromSource
      ? { line: index, via: (rhs.match(TAINT_SOURCE) || [rhs])[0] }
      : { line: fromVar.line, via: fromVar.via });
  }

  /** Whether `line` references `name` as an identifier rather than a substring. */
  _usesVariable(line, name) {
    return new RegExp(`(?:^|[^\\w$.])${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w$])`).test(line);
  }
}

export default TaintFlowAgent;

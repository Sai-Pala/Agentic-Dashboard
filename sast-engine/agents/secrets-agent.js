/**
 * SecretsAgent — Hardcoded Secrets in the Working Tree
 * =====================================================
 *
 * Runs SECRET_PATTERNS over the files that are actually checked out, which is
 * the case a user means when they say "scan my repo for hardcoded secrets".
 *
 * Before this agent existed, SECRET_PATTERNS had exactly one consumer —
 * GitHistoryScanner — which greps `git log --max-count=50`. That means secret
 * detection used to depend entirely on git: a non-git directory returned
 * nothing at all, a secret committed 51 commits ago was invisible, and a secret
 * that was never committed (the most urgent case, since it is still live and
 * unreviewed) could not be found by construction. Findings also came back with
 * `line: 0` and were labelled "Historical Secret" even when the value was
 * sitting in the current working tree.
 *
 * This agent is the working-tree half. GitHistoryScanner still covers the
 * genuinely historical case — a secret that was committed and later removed
 * from the tree but is still recoverable from history — which this agent cannot
 * see. They overlap on "committed and still present", which the orchestrator's
 * own dedup does not collapse (different rule ids), so this agent marks its
 * findings with rule HARDCODED_SECRET and GitHistoryScanner keeps
 * GIT_HISTORY_SECRET; a value present in both is genuinely worth both notes,
 * because remediation differs (delete + rotate vs. rotate + rewrite history).
 *
 * False-positive control:
 *   - Specific-prefix patterns (AKIA…, sk_live_…, ghp_…) are reported as-is.
 *     The pattern file's own maintenance rule is that these only match real
 *     secret formats, so a prefix match is high-signal on its own.
 *   - Generic patterns (`requiresEntropyCheck: true` — api_key/secret/password
 *     assignments, connection strings) are scored before reporting. That flag
 *     has been in the data model all along with nothing implementing it, so
 *     those patterns were previously reported with no filtering whatsoever.
 *   - Values that are obviously not secrets — env-var references, template
 *     placeholders, and known dummy strings — are dropped regardless of pattern.
 */

import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';
import { SECRET_PATTERNS } from '../utils/patterns.js';

// Files where a "secret" is nearly always illustrative rather than live.
const EXAMPLE_FILE = /(?:\.example$|\.sample$|\.template$|\.dist$|(?:^|[\\/])(?:examples?|samples?|fixtures?|__mocks__)[\\/])/i;

// Values that match a secret shape but carry no secret.
const PLACEHOLDER_VALUE = [
  /^(?:x{3,}|y{3,}|z{3,}|a{3,}|0{3,}|1{3,}|\.{3,})$/i,
  /^(?:your|my|the)[_-]?(?:api[_-]?)?(?:key|secret|token|password)/i,
  /(?:change[_-]?me|replace[_-]?me|insert[_-]?here|placeholder|dummy|redacted|todo|fixme)/i,
  /^(?:test|example|sample|foo|bar|baz|abc|password|secret|token)[0-9]{0,4}$/i,
  /^\**$/,          // fully masked, e.g. "********"
  /^<.*>$/,         // <YOUR_KEY>
  /^\{\{.*\}\}$/,   // {{ secret }} templating
  /^\$\{.*\}$/,     // ${ENV_VAR} interpolation
];

// The value is read from configuration rather than hardcoded.
const ENV_REFERENCE = /process\.env|import\.meta\.env|os\.environ|os\.getenv|getenv\(|ENV\[|Deno\.env|System\.getenv|config\.get\(/i;

/** Shannon entropy in bits per character. */
function shannonEntropy(str) {
  if (!str) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Pull the candidate secret value out of a match.
 *
 * Capture group 1 is NOT reliably the value: 'Database URL with Credentials'
 * uses group 1 for the scheme alternation (`postgres`), so scoring group 1
 * there would measure the entropy of the word "postgres" and discard every
 * connection string. Preferring the quoted literal inside the match handles the
 * assignment-style patterns correctly and falls back to the whole match for
 * URL-style ones.
 */
function extractValue(matchText) {
  const quoted = matchText.match(/["']([^"']{6,})["']/);
  return quoted ? quoted[1] : matchText;
}

// Below this, a generic match is far more likely to be prose or an identifier
// than key material. Only applied to patterns carrying `requiresEntropyCheck`;
// specific-prefix patterns (AKIA…, sk_live_…) report regardless of entropy.
const MIN_ENTROPY = 3.0;

export class SecretsAgent extends BaseAgent {
  constructor() {
    super('SecretsAgent', 'Detect hardcoded secrets in working-tree files', 'secrets');
  }

  shouldRun() {
    return true; // hardcoded secrets are possible in any codebase
  }

  async analyze(context) {
    const { rootPath } = context;
    const files = this.getFilesToScan(context);
    const findings = [];

    for (const file of files) {
      findings.push(...this._scanFile(file, rootPath));
    }
    return findings;
  }

  _scanFile(filePath, rootPath) {
    const content = this.readFile(filePath);
    if (!content) return [];

    const isExample = EXAMPLE_FILE.test(path.relative(rootPath || '', filePath));
    const lines = content.split('\n');
    const findings = [];
    // One finding per (line, pattern) — a pattern with the /g flag can match the
    // same line repeatedly, and reporting the same secret several times reads as
    // several secrets.
    const seen = new Set();

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > 2000) continue; // minified/bundled payload, not source

      for (const p of SECRET_PATTERNS) {
        p.pattern.lastIndex = 0;
        const match = p.pattern.exec(line);
        if (!match) continue;

        const key = `${i}:${p.name}`;
        if (seen.has(key)) continue;

        const value = extractValue(match[0]);
        // An `insecureDefault` pattern targets the `process.env.X || 'literal'`
        // shape specifically. Both filters below would reject it by construction:
        // the line mentions process.env, and the literal is usually a
        // placeholder-looking string. For this class those are the finding, not
        // reasons to dismiss it — a guessable default that goes live whenever
        // the variable is unset is worse than a high-entropy one, not better.
        if (!p.insecureDefault) {
          if (ENV_REFERENCE.test(line)) continue;
          if (PLACEHOLDER_VALUE.some((re) => re.test(value))) continue;
        }
        if (p.requiresEntropyCheck && shannonEntropy(value) < MIN_ENTROPY) continue;

        const severity = isExample ? 'low' : (p.severity || 'high');
        if (this.isSuppressed(line, severity)) continue;
        seen.add(key);

        findings.push(createFinding({
          file: filePath,
          line: i + 1,
          column: match.index + 1,
          severity,
          category: 'secrets',
          rule: 'HARDCODED_SECRET',
          title: `Hardcoded Secret: ${p.name}`,
          description: `${p.description} Detected in the current working tree${isExample ? ' (in an example/sample file, so it may be illustrative)' : ''}.`,
          matched: this._mask(match[0]),
          confidence: p.requiresEntropyCheck ? 'medium' : 'high',
          cwe: 'CWE-798',
          owasp: 'A07:2021',
          fix: 'Remove the value from source and load it from an environment variable or secret manager, then rotate the credential — it must be treated as compromised once committed.',
        }));
      }
    }

    return findings;
  }

  /** Never echo a live credential back into a report. */
  _mask(text) {
    const t = String(text);
    if (t.length <= 12) return `${t.slice(0, 3)}***`;
    return `${t.slice(0, 8)}***${t.slice(-4)}`;
  }
}

export default SecretsAgent;

/**
 * The deterministic half of a hybrid scan, run by Opengrep.
 *
 * Replaces the vendored pattern engine's 491 regex rules. Measured on DVNA, against that repo's
 * own documentation: the regex engine found 3 of the 10 vulnerabilities a fixed rule should be
 * able to find; Opengrep found 6, in 5 seconds instead of 210, having written no rules.
 *
 * WHY OPENGREP RATHER THAN SEMGREP. They are the same engine — a fork, same LGPL-2.1, and on the
 * benchmark they produced byte-identical output (23 findings, none unique to either). The one
 * difference that matters is `--taint-intrafile`: inter-procedural taint tracking within a file,
 * which Semgrep keeps behind its paid tier. Verified on a purpose-built case where `req.body`
 * enters in one function and reaches `exec()` in another — Semgrep and plain Opengrep find
 * nothing, Opengrep with the flag finds it.
 *
 * That is the entire point of moving off regex. `/exec\(.*\+/` cannot know whether the thing
 * being concatenated is attacker-controlled; a taint rule only fires when it actually is. The
 * false positives the adjudication pass currently pays to close are mostly this.
 *
 * WHAT THIS DOES NOT REPLACE. Route enumeration (`enumerate.js`), the dependency audit, and the
 * fix applier are separate concerns that were never Semgrep's job, and the reasoning pass is
 * steered by the route manifest. Those stay.
 */

const { spawn } = require('child_process');
const path = require('path');

const {
  OPENGREP_BIN, OPENGREP_CONFIG, OPENGREP_TIMEOUT_MS,
} = require('../../config');
const { normalizeSeverity } = require('../taxonomy');
const { toRepoRelative } = require('../paths');
const { sendScanText } = require('./emit');

/**
 * Opengrep severity plus impact, mapped onto this app's five-level scale.
 *
 * `impact` is used only to separate critical from high: an ERROR-level rule for a class the
 * ruleset itself rates HIGH impact (injection, RCE) should not land at the same level as an
 * ERROR-level configuration nit. Everything below ERROR maps straight across — inventing
 * gradations there would be dressing up a three-level signal as a five-level one.
 */
function mapSeverity(result) {
  const sev = String(result.extra && result.extra.severity || '').toUpperCase();
  const impact = String(result.extra && result.extra.metadata && result.extra.metadata.impact || '').toUpperCase();
  if (sev === 'ERROR') return impact === 'HIGH' ? 'critical' : 'high';
  if (sev === 'WARNING') return 'medium';
  if (sev === 'INFO') return 'low';
  return 'medium';
}

/**
 * `javascript.express.security.audit.express-sequelize-injection.express-sequelize-injection`
 * → `express-sequelize-injection`.
 *
 * The last dot-segment, which is the rule's own name. This becomes `finding.rule`, which the
 * triage table groups by, so it needs to be stable and human-readable rather than a full path.
 */
function ruleIdOf(checkId) {
  const parts = String(checkId || '').split('.');
  return parts[parts.length - 1] || String(checkId || 'opengrep');
}

/** `express-sequelize-injection` → `Express Sequelize Injection`. */
function titleOf(ruleId) {
  return ruleId.split(/[-_]/).filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

/** Prefer the current OWASP edition when a rule lists several. */
function owaspOf(metadata) {
  const list = (metadata && Array.isArray(metadata.owasp)) ? metadata.owasp : [];
  if (!list.length) return null;
  return list.find((o) => /2021/.test(o)) || list[list.length - 1];
}

/**
 * Where untrusted input entered, when the rule ran in taint mode.
 *
 * Opengrep reports it under `dataflow_trace.taint_source` in a nested tuple shape
 * (`["CliLoc", [location, matched_text]]`). Extracting it is what lets `readFlowSpan()` render
 * the real source→sink span rather than a single line, and it only exists because these rules
 * track dataflow — the regex engine had nothing to put here.
 */
function taintSourceLineOf(result) {
  const trace = result.extra && result.extra.dataflow_trace;
  const src = trace && trace.taint_source;
  if (!Array.isArray(src) || src.length < 2 || !Array.isArray(src[1])) return null;
  const loc = src[1][0];
  const line = loc && loc.start && loc.start.line;
  return typeof line === 'number' ? line : null;
}

/**
 * One Opengrep result in the shape `findingFromSastEngine()` already consumes.
 *
 * Deliberately reuses that factory rather than adding a parallel one: the merge, dedupe,
 * corroboration and adjudication steps downstream are engine-agnostic, and giving them a second
 * finding shape to understand is how those paths grow subtle divergences.
 */
function toEngineFinding(result, targetPath) {
  const meta = (result.extra && result.extra.metadata) || {};
  const ruleId = ruleIdOf(result.check_id);
  const rel = String(result.path || '');
  const abs = path.isAbsolute(rel) ? rel : path.join(targetPath, rel);
  const snippet = String((result.extra && result.extra.lines) || '');

  return {
    rule: ruleId,
    title: titleOf(ruleId),
    severity: normalizeSeverity(mapSeverity(result)),
    confidence: String(meta.confidence || 'medium').toLowerCase(),
    file: abs,
    line: (result.start && result.start.line) || null,
    description: String((result.extra && result.extra.message) || '').trim(),
    cwe: Array.isArray(meta.cwe) && meta.cwe.length ? meta.cwe[0] : null,
    owasp: owaspOf(meta),
    codeContext: snippet ? snippet.split(/\r?\n/).map((text) => ({ text })) : [],
    // No second-pass verifier exists here, and `null` means "not checked" rather than
    // "unverified" — which is what lands these at needs_review instead of treating them as
    // suspect. Claiming otherwise would fabricate a verification step that never ran.
    verified: null,
    verifierNote: meta.confidence
      ? `Opengrep rule ${ruleId}, rated ${String(meta.confidence).toLowerCase()} confidence by its own author. Not independently re-checked against surrounding code.`
      : `Opengrep rule ${ruleId}. Not independently re-checked against surrounding code.`,
    taintSourceLine: taintSourceLineOf(result),
  };
}

/**
 * Run Opengrep over the target and return findings in the engine's shape.
 *
 * Signature and return shape match runDeterministicPatternScan() so scanner.js does not care
 * which engine produced the list.
 */
function runOpengrepScan(scan, targetPath, diffFiles, { children, send }) {
  return new Promise((resolve) => {
    if (scan.status === 'cancelled') { resolve({ findings: [], error: null }); return; }

    const args = ['scan', '--config', OPENGREP_CONFIG, '--taint-intrafile', '--json', '--quiet'];
    // A diff-scoped scan passes explicit targets; a full scan passes the directory.
    if (diffFiles && diffFiles.length) args.push(...diffFiles);
    else args.push('.');

    const runId = `${scan.runId}::opengrep`;
    const child = spawn(OPENGREP_BIN, args, {
      cwd: targetPath,
      shell: false,
      // Opengrep aborts with a UnicodeDecodeError on any rule file containing a non-ASCII
      // character (an em dash in a `message:` field is enough) when the inherited locale is
      // ASCII. Forcing UTF-8 here rather than relying on the parent environment.
      env: { ...process.env, LC_ALL: 'en_US.UTF-8', LANG: 'en_US.UTF-8', PYTHONUTF8: '1' },
    });
    children.set(runId, child);
    scan.moduleRunIds = scan.moduleRunIds || [];
    scan.moduleRunIds.push(runId);

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c.toString(); });
    child.stderr.on('data', (c) => {
      stderr += c.toString();
      send({ type: 'scan-stderr', runId: scan.runId, scanId: scan.id, data: c.toString() });
    });

    const timer = setTimeout(() => {
      child.kill('SIGKILL');
    }, OPENGREP_TIMEOUT_MS);

    let settled = false;
    const settle = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      children.delete(runId);
      resolve(error ? { findings: [], error } : parse());
    };

    const parse = () => {
      let report;
      try {
        report = JSON.parse(stdout);
      } catch {
        return {
          findings: [],
          error: `Opengrep produced output that could not be parsed as JSON${stderr ? `: ${stderr.trim().slice(0, 300)}` : ''}`,
        };
      }

      const results = Array.isArray(report.results) ? report.results : [];
      const findings = results.map((r) => toEngineFinding(r, targetPath));

      // Opengrep reports the files it actually parsed. That is ground truth for coverage — far
      // better than re-deriving it — so it is handed back for the scan record.
      const scanned = (report.paths && Array.isArray(report.paths.scanned)) ? report.paths.scanned : [];
      const skipped = (report.paths && Array.isArray(report.paths.skipped)) ? report.paths.skipped : [];

      // A rule that failed to run is a coverage hole, not a clean result — the same invariant the
      // pattern engine's failed-agent reporting exists for.
      const engineErrors = Array.isArray(report.errors) ? report.errors : [];
      if (engineErrors.length && scan.status !== 'cancelled') {
        send({
          type: 'scan-warning',
          runId: scan.runId,
          scanId: scan.id,
          message: `Opengrep reported ${engineErrors.length} error${engineErrors.length === 1 ? '' : 's'} while scanning, so some files or rules were NOT checked: `
            + engineErrors.slice(0, 3).map((e) => String(e.message || e.type || 'unknown').split('\n')[0]).join('; '),
        });
      }

      if (findings.length && scan.status !== 'cancelled') {
        sendScanText(send, scan, findings.map((f) => {
          const rel = toRepoRelative(targetPath, f.file) || 'unknown file';
          return `[${f.severity}] \`${rel}${f.line ? ':' + f.line : ''}\` — ${f.title}`;
        }));
      }

      return {
        findings,
        scannedFiles: scanned.map((p) => (path.isAbsolute(p) ? p : path.join(targetPath, p))),
        skippedFiles: skipped,
        engineErrors,
        error: null,
      };
    };

    child.on('error', (err) => {
      settle(err.code === 'ENOENT'
        ? `Opengrep is not installed or not on PATH (looked for "${OPENGREP_BIN}"). Install it from https://github.com/opengrep/opengrep/releases, or set OPENGREP_BIN.`
        : `Opengrep could not be started: ${err.message}`);
    });

    child.on('close', (code) => {
      if (scan.status === 'cancelled') { settle(null); return; }
      // Exit 1 means "findings were reported", which is success here — this app decides what
      // blocks, not the scanner. Anything above that is a real failure.
      if (code === 0 || code === 1) settle(null);
      else settle(`Opengrep exited with code ${code}${stderr ? `: ${stderr.trim().slice(0, 300)}` : ''}`);
    });
  });
}

module.exports = { runOpengrepScan, toEngineFinding, mapSeverity, ruleIdOf, titleOf, owaspOf, taintSourceLineOf };

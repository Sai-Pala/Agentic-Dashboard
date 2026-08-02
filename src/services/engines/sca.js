/**
 * The dependency-audit half of a hybrid scan: sast-engine's runDepsAudit, which wraps the
 * project's own package-manager audit tool. No LLM, and it ignores scope entirely — an audit
 * always reads the whole manifest/lockfile.
 */

const { normalizeSeverity } = require('../taxonomy');

async function runDeterministicScaScan(engine, scan, targetPath, { send }) {
  let result;
  try {
    result = await engine.runDepsAudit(targetPath);
  } catch (err) {
    return { findings: [], error: `Dependency audit failed: ${err.message}` };
  }

  if (scan.status === 'cancelled') return { findings: [], error: null };

  // No supported manifest is a valid "nothing to report", not a failure.
  if (!result.pm) return { findings: [], error: null };
  if (result.error) return { findings: [], error: result.error };

  if (result.vulns.length) {
    const lines = result.vulns.map((v) => `[${normalizeSeverity(v.severity)}] \`${v.name}@${v.range}\` — ${v.title}`);
    send({
      type: 'scan-event',
      runId: scan.runId,
      scanId: scan.id,
      event: { type: 'assistant', message: { content: [{ type: 'text', text: lines.join('\n') }] } },
    });
  }

  return { findings: result.vulns, error: null };
}

module.exports = { runDeterministicScaScan };

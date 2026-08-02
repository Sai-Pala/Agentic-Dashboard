/**
 * Reading a finding's run history: each stage's own latest run, and the single derived status
 * every stage funnels through.
 */

/**
 * Last run of a given agent type, or null. The client's Remediation Loop track needs each
 * stage's status independently — a later Verify run would otherwise hide whether Triage ran.
 */
function latestRunByAgent(runs, agentName) {
  for (let i = runs.length - 1; i >= 0; i--) {
    if (runs[i].agent === agentName) return { status: runs[i].status, verdict: runs[i].verdict };
  }
  return null;
}

function deriveStatus(finding) {
  const latest = finding.runs[finding.runs.length - 1];
  if (!latest) return 'new';
  if (latest.status === 'running') return 'in_review';
  if (latest.status === 'error' || latest.status === 'cancelled') return 'in_review';
  const v = latest.verdict && latest.verdict.verdict;
  if (v === 'false_positive' || v === 'duplicate') return 'closed';
  // Verify's vocabulary doesn't overlap with anything below, so only verified_fixed needs a
  // branch; still_vulnerable/partially_fixed/inconclusive fall through to in_review, which is
  // the right outcome for both "needs more work" and "couldn't be confirmed either way".
  if (latest.agent === 'verify' && v === 'verified_fixed') return 'verified_fixed';
  if (latest.agent === 'remediation' && latest.verdict && latest.verdict.corrected_code && (v === 'confirmed' || v === 'needs_review')) return 'remediation_generated';
  if (v === 'confirmed' && !latest.verdict.next_agent) return 'remediation_ready';
  if (v === 'confirmed' || v === 'needs_review') return 'in_review';
  return 'in_review';
}

module.exports = { latestRunByAgent, deriveStatus };

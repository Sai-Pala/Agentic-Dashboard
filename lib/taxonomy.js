/**
 * Severity / confidence / priority vocabulary
 * ===========================================
 *
 * The shared scale every agent's `.md` prompt also defines in prose. Those prompt definitions
 * must stay byte-identical across agents (see CLAUDE.md's "Taxonomy convention"); this module
 * is the executable half — the parts the server itself decides rather than the model.
 *
 * Extracted from server.js unchanged. Pure: no I/O, no module state, no app state, so it is
 * directly unit-testable and safe for anything to require.
 */

const crypto = require('crypto');

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];

// 'moderate' is included because npm/pip audit emit it where this app uses 'medium'.
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, moderate: 2, low: 3, informational: 4 };

/** Sort key for a severity. Unrecognized sorts last rather than throwing. */
function severityRank(sev) {
  const r = SEVERITY_RANK[String(sev || '').toLowerCase()];
  return r == null ? 5 : r;
}

/**
 * Deterministic severity+confidence -> priority table, replacing what agents/triage.md (an
 * LLM call) used to decide case by case. Mirrors triage.md's p0-p3 definitions: p0 same-day,
 * p1 this sprint, p2 normal backlog, p3 track only.
 *
 * Note this does NOT validate its inputs: an unrecognized confidence takes the more urgent
 * branch for 'critical' and the less urgent for 'high', and matching is case-sensitive, so
 * callers must normalize first. Recorded in the tests as a CONCERN rather than changed here,
 * since changing it would move real findings' priorities.
 */
function priorityFromSeverityConfidence(severity, confidence) {
  if (severity === 'critical') return confidence === 'low' ? 'p1' : 'p0';
  if (severity === 'high') return confidence === 'high' ? 'p0' : 'p1';
  if (severity === 'medium') return confidence === 'low' ? 'p3' : 'p2';
  return 'p3'; // low, informational, or unrecognized
}

/**
 * npm/pip audit tools use "moderate" where this app's SEVERITIES uses "medium" — normalize so
 * SCA findings sort/filter/display the same as reasoning findings.
 *
 * Unknown input defaults to 'medium', not 'low', so an unparseable advisory severity is
 * promoted into the middle of the scale rather than quietly buried.
 */
function normalizeSeverity(raw) {
  const s = String(raw || '').toLowerCase();
  if (s === 'moderate') return 'medium';
  return SEVERITIES.includes(s) ? s : 'medium';
}

/**
 * Synthetic 'triage' run for a reasoning finding with no source directory to check against —
 * today that means one added manually via "+ Add". Triage is not a live agent stage anymore
 * (its .md file is gone), so every reasoning finding needs *some* triage run at creation time
 * or the Remediation Loop's first stage is permanently stuck pointing at a stage that can't run.
 */
function placeholderTriageRun(severity) {
  return {
    runId: crypto.randomUUID(),
    agent: 'triage',
    status: 'done',
    startedAt: Date.now(),
    finishedAt: Date.now(),
    verdict: {
      verdict: 'needs_review',
      severity_confirmed: severity,
      confidence: 'low',
      priority: priorityFromSeverityConfidence(severity, 'low'),
      reasoning: 'No scan or source directory to verify against.',
      owasp: null,
      asvs: null,
      cwe: null,
      nist_800_53: [],
      next_agent: null,
      source: 'manual-placeholder',
    },
    fullText: '',
  };
}

module.exports = {
  SEVERITIES,
  SEVERITY_RANK,
  severityRank,
  priorityFromSeverityConfidence,
  normalizeSeverity,
  placeholderTriageRun,
};

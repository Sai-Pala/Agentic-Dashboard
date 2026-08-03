/**
 * Severity / confidence / priority vocabulary — the executable half of the taxonomy every
 * agent prompt also defines in prose. Pure: no I/O, no state.
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
 * p0 same-day, p1 this sprint, p2 normal backlog, p3 track only.
 * Inputs are NOT validated and matching is case-sensitive — callers must normalize first.
 */
function priorityFromSeverityConfidence(severity, confidence) {
  if (severity === 'critical') return confidence === 'low' ? 'p1' : 'p0';
  if (severity === 'high') return confidence === 'high' ? 'p0' : 'p1';
  if (severity === 'medium') return confidence === 'low' ? 'p3' : 'p2';
  return 'p3'; // low, informational, or unrecognized
}

/**
 * Unknown input defaults to 'medium', not 'low', so an unparseable advisory severity is
 * promoted into the middle of the scale rather than quietly buried.
 */
function normalizeSeverity(raw) {
  const s = String(raw || '').toLowerCase();
  if (s === 'moderate') return 'medium';
  return SEVERITIES.includes(s) ? s : 'medium';
}

/**
 * Synthetic 'triage' run for a reasoning finding with no source directory to check against
 * (one added manually). Triage is not a live agent stage, so every reasoning finding needs
 * *some* triage run at creation time or the Remediation Loop's first stage can never advance.
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
  severityRank,
  priorityFromSeverityConfidence,
  normalizeSeverity,
  placeholderTriageRun,
};

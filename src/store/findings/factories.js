/**
 * Builds Finding records from each engine's raw output.
 *
 * Every reasoning finding is born already triaged — Triage is not a live agent stage, so
 * without a synthetic run here the pipeline's first step would point at something that cannot
 * run. The two reasoning factories differ in where that verdict comes from: the adjudication
 * pass re-reading a deterministic hit, or the reasoning pass's own assessment of its own finding.
 */

const crypto = require('crypto');

const { PRIORITIES } = require('../../config');
const { SEVERITIES, normalizeSeverity, priorityFromSeverityConfidence } = require('../../services/taxonomy');
const { parseFileLine } = require('../../services/merge');
const { deriveStatus } = require('./status');
const { readFlowSpan } = require('./flow');
const { toRepoRelative } = require('../../services/paths');

/** @typedef {import('../../types').Finding} Finding */
/** @typedef {import('../../types').Run} Run */

const CONFIDENCES = ['high', 'medium', 'low'];

/** Shared skeleton — every finding carries the same fields, engine-specific ones default null. */
function baseFinding(over) {
  return {
    id: crypto.randomUUID(),
    severity: 'medium',
    rule: null,
    file: null,
    description: '',
    code: null,
    packageName: null,
    packageVersion: null,
    fixedVersion: null,
    endpoint: null,
    method: null,
    status: 'new',
    createdAt: Date.now(),
    runs: [],
    ...over,
  };
}

function triageRun(verdict) {
  return {
    runId: crypto.randomUUID(),
    agent: 'triage',
    status: 'done',
    startedAt: Date.now(),
    finishedAt: Date.now(),
    verdict,
    fullText: '',
  };
}

/**
 * A deterministic finding, today always from Opengrep.
 *
 * `f.verified` is ALWAYS null on that path — Opengrep has no second-pass verifier, and null
 * means "not checked" rather than "unverified", which is why these land at needs_review instead
 * of being treated as suspect. The `verified === true` branch below is reachable only from the
 * dormant pattern engine, whose VerifierAgent re-checked critical/high hits; it is kept because
 * that engine is parked rather than deleted (see services/engines/deterministic.js).
 *
 * An adjudication verdict wins when present: it read the surrounding code with far more context
 * than a regex plus a heuristic has. A finding it calls a false positive is still created —
 * deriveStatus maps that to 'closed' so it stays inspectable. A wrong adjudication should cost
 * visibility, not evidence.
 *
 * `corroboration` is a reasoning-pass finding at the same location. When present the two are one
 * finding, not two: the pattern engine supplies rule, CWE, code context and taint span, and the
 * reasoning pass supplies the title and description, which is the half that explains why the
 * match matters. Independent agreement raises the verdict to confirmed — but never over an
 * adjudicator that explicitly called it a false positive, since that pass read the code with
 * more context than either.
 */
function findingFromSastEngine(f, scan, targetPath, adjudication = null, corroboration = null, collapsed = 0) {
  const relFile = toRepoRelative(targetPath, f.file);
  const severity = normalizeSeverity(f.severity);
  const confidence = CONFIDENCES.includes(f.confidence) ? f.confidence : 'medium';

  const adjVerdict = adjudication && ['confirmed', 'needs_review', 'false_positive'].includes(adjudication.verdict)
    ? adjudication.verdict
    : null;
  const adjSeverity = adjudication && adjudication.severity ? normalizeSeverity(adjudication.severity) : null;
  const finalSeverity = adjSeverity || severity;
  const finalConfidence = adjudication && CONFIDENCES.includes(adjudication.confidence)
    ? adjudication.confidence
    : confidence;
  const verdictLabel = adjVerdict
    || (corroboration ? 'confirmed' : (f.verified === true ? 'confirmed' : 'needs_review'));

  const finding = baseFinding({
    title: (corroboration && String(corroboration.title || '').trim())
      || f.title || f.rule || 'Untitled finding',
    severity: finalSeverity,
    scanType: 'reasoning',
    rule: f.rule || null,
    file: relFile ? `${relFile}${f.line ? ':' + f.line : ''}` : null,
    description: (corroboration && String(corroboration.description || '').trim())
      || f.description || '',
    code: Array.isArray(f.codeContext) && f.codeContext.length
      ? f.codeContext.map((c) => c.text).join('\n')
      : null,
    sourceScanId: scan.id,
    flow: readFlowSpan(f),
  });

  finding.runs.push(triageRun({
    verdict: verdictLabel,
    severity_confirmed: finalSeverity,
    confidence: finalConfidence,
    priority: priorityFromSeverityConfidence(finalSeverity, finalConfidence),
    reasoning: (adjudication && adjudication.reasoning)
      || (corroboration && 'Independently reported by both the pattern engine and the reasoning '
        + `pass at this location. Pattern rule: ${f.rule || 'n/a'}. Reasoning: `
        + `${String(corroboration.description || '').trim()}`)
      || f.verifierNote
      // Fallback only. Opengrep always supplies a verifierNote, so this is reached from the
      // dormant pattern engine's sub-floor findings, or a hand-built one.
      || 'Deterministic pattern match, not independently re-checked against surrounding code.',
    owasp: f.owasp || null,
    asvs: null, // sast-engine has no ASVS or NIST mapping — see docs/agents.md
    cwe: f.cwe || null,
    nist_800_53: [],
    next_agent: verdictLabel === 'confirmed' ? 'remediation' : null,
    // Which pass decided this — Finding Detail badges them differently, and it matters
    // which one closed a finding.
    source: adjVerdict ? 'reasoning-adjudication'
      : corroboration ? 'both-engines'
        : 'sast-engine-verifier',
    // Recorded separately from `source` because the two answer different questions: `source` is
    // which pass produced the VERDICT, `corroborated` is whether both engines independently
    // reported the finding. A merged finding that is then adjudicated has source
    // 'reasoning-adjudication', which silently hid every merge from any consumer keying off
    // source alone — including the check written to verify the merge worked.
    corroborated: Boolean(corroboration),
  }));
  finding.disposition = buildDisposition({
    severityBefore: severity,
    severityAfter: finalSeverity,
    changedBy: adjSeverity ? 'the adjudicator' : null,
    applied: true,
    verdict: verdictLabel,
    // The right-hand side is unreachable on the Opengrep path and names a component that no
    // longer runs: `closedAs` is set only for a false_positive/duplicate verdict, and without
    // an adjudication `verdictLabel` can only be confirmed or needs_review. It survives for the
    // dormant pattern engine, whose verifier could close a finding on its own.
    closedBy: adjVerdict ? 'the adjudicator' : 'the pattern engine’s verifier',
    corroborated: Boolean(corroboration),
    collapsed,
  });
  finding.status = deriveStatus(finding);
  return finding;
}

/**
 * What happened to this finding between the engine emitting it and the list showing it.
 *
 * Every field here records a decision the app made on the user's behalf, each of which changes
 * whether you should trust the row: a severity downgrade that would otherwise discard the
 * original, a rule firing six times on one condition collapsing to a single row, a finding closed
 * as a false positive without saying whether a regex heuristic or a pass that read the
 * surrounding code made that call.
 *
 * Returns null when nothing happened, so the common case adds no weight to the wire shape.
 */
function buildDisposition({ severityBefore, severityAfter, changedBy, applied, verdict, closedBy, corroborated, collapsed }) {
  const d = {};
  if (severityAfter !== severityBefore) {
    d.severityFrom = severityBefore;
    d.severityTo = severityAfter;
    // Direction matters more than the pair: a downgrade is the app quietly de-prioritising
    // something the engine flagged, which is the one worth a second look.
    d.severityDirection = SEVERITIES.indexOf(severityAfter) > SEVERITIES.indexOf(severityBefore)
      ? 'down' : 'up';
    d.severityChangedBy = changedBy;
    // Whether the row you are looking at shows the NEW severity or the old one. The adjudicator's
    // call is applied to the finding; the reasoning pass's `severity_confirmed` is not, it sits
    // in the verdict beside a `severity` that still disagrees with it. Labelling both "downgraded"
    // would assert a change to the row that in the second case never happened.
    d.severityApplied = Boolean(applied);
  }
  if (verdict === 'false_positive' || verdict === 'duplicate') {
    d.closedAs = verdict;
    d.closedBy = closedBy;
  }
  if (corroborated) d.corroborated = true;
  if (collapsed > 0) d.collapsed = collapsed;
  return Object.keys(d).length ? d : null;
}

/** A dependency-audit finding. No triage run — SCA never enters the Remediation Loop. */
function findingFromDepVuln(v, scan) {
  return baseFinding({
    title: `${v.name}@${v.range} — ${v.title}`,
    severity: normalizeSeverity(v.severity),
    scanType: 'sca',
    rule: v.cve || null,
    description: [v.title, v.cve ? `CVE: ${v.cve}` : null, v.url || null].filter(Boolean).join('\n'),
    packageName: v.name,
    packageVersion: v.range,
    fixedVersion: v.fix || null,
    sourceScanId: scan.id,
  });
}

/**
 * A reasoning-pass finding. Its triage verdict is real, not synthesized: the same call that
 * found the issue also assigned the full taxonomy, including the ASVS and NIST mapping the
 * deterministic half has no data for.
 */
function findingFromLLMScan(rf, scan) {
  const severity = normalizeSeverity(rf.severity);
  const loc = parseFileLine(rf.file);

  const finding = baseFinding({
    title: String(rf.title).trim(),
    severity,
    scanType: 'reasoning',
    rule: rf.rule ? String(rf.rule).trim() : null,
    file: loc.file ? `${loc.file}${loc.line ? ':' + loc.line : ''}` : null,
    description: String(rf.description).trim(),
    code: rf.code ? String(rf.code) : null,
    packageName: rf.package_name ? String(rf.package_name).trim() : null,
    packageVersion: rf.package_version ? String(rf.package_version).trim() : null,
    fixedVersion: rf.fixed_version ? String(rf.fixed_version).trim() : null,
    endpoint: rf.endpoint ? String(rf.endpoint).trim() : null,
    method: rf.method ? String(rf.method).trim() : null,
    sourceScanId: scan.id,
  });

  const verdict = ['confirmed', 'needs_review', 'false_positive', 'duplicate'].includes(rf.verdict)
    ? rf.verdict
    : 'needs_review';
  const confidence = CONFIDENCES.includes(rf.confidence) ? rf.confidence : 'medium';
  const severityConfirmed = SEVERITIES.includes(rf.severity_confirmed) ? rf.severity_confirmed : severity;

  finding.runs.push(triageRun({
    verdict,
    severity_confirmed: severityConfirmed,
    confidence,
    priority: PRIORITIES.includes(rf.priority)
      ? rf.priority
      : priorityFromSeverityConfidence(severityConfirmed, confidence),
    reasoning: rf.reasoning ? String(rf.reasoning).trim() : '',
    owasp: rf.owasp || null,
    asvs: rf.asvs || null,
    cwe: rf.cwe || null,
    nist_800_53: Array.isArray(rf.nist_800_53) ? rf.nist_800_53 : [],
    next_agent: verdict === 'confirmed' ? 'remediation' : null,
    source: 'reasoning-scan',
  }));
  // The reasoning pass can revise its own severity in the same breath as reporting it — the
  // finding carries `severity`, the verdict carries `severity_confirmed`, and they can disagree.
  finding.disposition = buildDisposition({
    severityBefore: severity,
    severityAfter: severityConfirmed,
    changedBy: 'the reasoning pass',
    applied: false,
    verdict,
    closedBy: 'the reasoning pass',
    corroborated: false,
    collapsed: 0,
  });
  finding.status = deriveStatus(finding);
  return finding;
}

module.exports = { findingFromSastEngine, findingFromDepVuln, findingFromLLMScan };

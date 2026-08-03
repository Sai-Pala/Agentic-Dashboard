/**
 * The Remediation Loop state machine
 *
 * Reduces a finding to where it stands in Triaged -> Remediated -> Fixed -> Verified, and to
 * the single next automatable step. Pure: no DOM, no app state, no rendering.
 */

/**
 * Each stage's own latest run. A list-item finding (GET /api/findings) carries this
 * precomputed as `.stageRuns`; a full finding (GET /api/findings/:id) has only `.runs`.
 */
export function findingStageRuns(f) {
  if (f.stageRuns) return f.stageRuns;
  const runs = Array.isArray(f.runs) ? f.runs : [];
  const latestByAgent = (agentName) => {
    for (let i = runs.length - 1; i >= 0; i--) {
      if (runs[i].agent === agentName) return { status: runs[i].status, verdict: runs[i].verdict };
    }
    return null;
  };
  return {
    triage: latestByAgent('triage'),
    remediation: latestByAgent('remediation'),
    fix: latestByAgent('fix'),
    verify: latestByAgent('verify'),
  };
}

/**
 * 'fixed' carries one state beyond pending/running/attention/done: 'unavailable', for when
 * Remediate finished without proposing an edit — there is nothing to apply, which is not the
 * same as "not started yet".
 */
export function findingLoopState(f) {
  const stageRuns = findingStageRuns(f);
  let triaged = 'pending';
  let remediated = 'pending';
  let fixed = 'pending';
  let verified = 'pending';

  if (stageRuns.triage) {
    if (stageRuns.triage.status === 'running') triaged = 'running';
    else if (stageRuns.triage.status === 'error' || stageRuns.triage.status === 'cancelled') triaged = 'attention';
    else triaged = 'done';
  }

  if (stageRuns.remediation) {
    if (stageRuns.remediation.status === 'running') remediated = 'running';
    else if (stageRuns.remediation.status === 'error' || stageRuns.remediation.status === 'cancelled') remediated = 'attention';
    else remediated = 'done';
  }

  const plan = stageRuns.remediation && stageRuns.remediation.verdict && stageRuns.remediation.verdict.edit_plan;
  const hasPlan = !!(plan && Array.isArray(plan.files) && plan.files.length);
  if (remediated === 'done' && !hasPlan) fixed = 'unavailable';

  if (stageRuns.fix) {
    if (stageRuns.fix.status === 'running') fixed = 'running';
    // "Fixed" requires real evidence of a write. A completed fix run with no applied_diff means
    // nothing landed — showing "Fixed" and offering Verify there would be actively misleading.
    else if (stageRuns.fix.verdict && stageRuns.fix.verdict.applied_diff) fixed = 'done';
    else fixed = 'attention';
  }

  if (stageRuns.verify) {
    if (stageRuns.verify.status === 'running') verified = 'running';
    else if (stageRuns.verify.status === 'error' || stageRuns.verify.status === 'cancelled') verified = 'attention';
    // Read the verify run's OWN verdict, not the finding's overall status: any later unrelated
    // run changes f.status and would silently regress an already-verified finding.
    else if (stageRuns.verify.verdict && stageRuns.verify.verdict.verdict === 'verified_fixed') verified = 'done';
    else verified = 'attention'; // still_vulnerable / partially_fixed / inconclusive
  }

  return { triaged, remediated, fixed, verified, hasPlan };
}

/**
 * The single next automatable step. A failed Verify or Fix both map back to 'remediate' — the
 * fix didn't hold or the plan went stale, so repeating the same attempt would fail the same way.
 */
export function findingLoopNextAction(f) {
  const { triaged, remediated, fixed, verified } = findingLoopState(f);
  if (triaged === 'running' || remediated === 'running' || fixed === 'running' || verified === 'running') return null;
  if (triaged === 'pending' || triaged === 'attention') return 'triage';
  if (verified === 'attention') return 'remediate';
  if (fixed === 'attention') return 'remediate';
  if (remediated === 'pending' || remediated === 'attention') return 'remediate';
  if (fixed === 'unavailable') return null;
  if (fixed === 'pending') return 'fix';
  if (verified === 'pending') return 'verify';
  return null; // verified === 'done' — nothing left
}

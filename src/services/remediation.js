/**
 * The write path — the only code in this app that touches a user's files.
 *
 * Remediate proposes, Fix applies. No `claude` call ever reaches disk, not even indirectly:
 * applyRemediationPlan() is a plain function run from a separate, later step a human triggers
 * after reading what was proposed. checkCleanGitTarget() is what makes every landed edit
 * inspectable (git diff) and revertible (git checkout) entirely outside this app.
 *
 * Treat this module as the highest-trust code in the repository.
 */

const fs = require('fs');
const { execFileSync } = require('child_process');

const { loadSastEngine } = require('./sast-engine');

/** Refuse to write unless the target is a git repo with a clean working tree. */
function checkCleanGitTarget(targetPath) {
  let stat;
  try {
    stat = fs.statSync(targetPath);
  } catch (err) {
    return { ok: false, message: `Path not found: ${targetPath}` };
  }
  if (!stat.isDirectory()) return { ok: false, message: `Not a directory: ${targetPath}` };

  let gitStatus;
  try {
    gitStatus = execFileSync('git', ['status', '--porcelain'], { cwd: targetPath, encoding: 'utf8' });
  } catch (err) {
    return { ok: false, message: `Applying a fix requires a git repository — "${targetPath}" doesn't look like one: ${String(err.message).split('\n')[0]}` };
  }
  if (gitStatus.trim()) {
    return { ok: false, message: 'Target directory has uncommitted changes. Commit or stash them first so the fix stays cleanly revertible.' };
  }
  return { ok: true };
}

/**
 * Validates a Remediation verdict's `edit_plan` against the live files and, only then, writes
 * it. Returns { applied, diff, error }:
 *   - no plan      -> { applied: false, error: null }. The model declining to guess at an exact
 *                     edit is a legitimate outcome, not a failure.
 *   - plan invalid -> { applied: false, error: <reason> }. Surfaced as the run erroring.
 *   - plan valid   -> written, { applied: true, diff }.
 */
async function applyRemediationPlan(targetPath, verdict) {
  const plan = verdict && verdict.edit_plan;
  if (!plan || !Array.isArray(plan.files) || plan.files.length === 0) {
    return { applied: false, diff: null, error: null };
  }

  const engine = await loadSastEngine();
  let validation;
  try {
    validation = engine.validatePlan(targetPath, plan);
  } catch (err) {
    // e.g. a proposed path resolving to a directory. This function's only callers are
    // fire-and-forget IIFEs with no .catch(), so a throw here becomes an unhandled rejection.
    return { applied: false, diff: null, error: `Proposed edit could not be validated: ${err.message}` };
  }
  if (!validation.ok) {
    return { applied: false, diff: null, error: `Proposed edit could not be applied: ${validation.reason}` };
  }

  try {
    engine.applyPlan(targetPath, plan);
  } catch (err) {
    return { applied: false, diff: null, error: `Failed to apply edit: ${err.message}` };
  }

  let diff;
  try {
    diff = execFileSync('git', ['diff'], { cwd: targetPath, encoding: 'utf8' });
  } catch (err) {
    diff = `(failed to capture git diff: ${String(err.message).split('\n')[0]})`;
  }
  return { applied: true, diff: diff || null, error: null };
}

module.exports = { checkCleanGitTarget, applyRemediationPlan };

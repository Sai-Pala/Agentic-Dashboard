/**
 * The Remediate / Fix / Verify WebSocket handlers.
 *
 * Remediate proposes read-only, Fix applies without any model call, Verify re-checks. All three
 * relay the same started/event/done shapes as the generic `run` path, so the client needed no
 * new message handling. See services/remediation.js for the write-path guarantees.
 */

const fs = require('fs');

const { RUN_ID_RE, agentFilePath } = require('../config');
const { spawnAgentStage } = require('../services/claude');
const { checkCleanGitTarget, applyRemediationPlan } = require('../services/remediation');
const { findings, runIndex, deriveStatus } = require('../store/findings');

/**
 * The entry checks every fix-flow handler runs before doing anything.
 *
 * Written out three times previously, once per handler, differing only in how many run ids the
 * message carries and one sentence of wording. Validation that is copied is validation that
 * drifts — and this is the gate in front of the only code path in the app that writes to a
 * user's files, so drift here is the expensive kind.
 *
 * @param {object} msg                      the raw client message
 * @param {{children: Map, send: Function}} ctx
 * @param {{runIdKeys: string[], pathPurpose: string}} spec
 *   runIdKeys   — message fields holding run ids; the first is the one errors are reported against
 *   pathPurpose — completes "A target directory is required to ___."
 * @returns {{findingId: string|null, finding: object, runIds: string[], runId: string,
 *            targetPath: string}|null} null when a check failed — the error has already been
 *            sent, so the caller only needs to return.
 */
function validateFixRequest(msg, { children, send }, { runIdKeys, pathPurpose }) {
  const findingId = msg.findingId ? String(msg.findingId) : null;
  const runIds = runIdKeys.map((key) => String(msg[key] || '').trim());
  const runId = runIds[0];

  if (!runIds.every((id) => RUN_ID_RE.test(id))) {
    // No runId echoed back: it is the thing that failed validation, and echoing an unvalidated
    // value is how it ends up keyed into a Map.
    send({ type: 'error', message: `Invalid or missing run id${runIds.length > 1 ? '(s)' : ''}.` });
    return null;
  }
  if (runIds.some((id) => children.has(id))) {
    send({ type: 'error', runId, findingId, message: 'This run is already active.' });
    return null;
  }
  const finding = findingId ? findings.get(findingId) : null;
  if (!finding) {
    send({ type: 'error', runId, findingId, message: 'Unknown finding.' });
    return null;
  }
  const targetPath = String(msg.path || '').trim();
  if (!targetPath) {
    send({ type: 'error', runId, findingId, message: `A target directory is required to ${pathPurpose}.` });
    return null;
  }
  return { findingId, finding, runIds, runId, targetPath };
}

/**
 * Runs Remediation read-only against the finding's target directory and stops — no apply, no
 * automatic chain into Fix, so a human always sees the proposal before anything is written.
 */
function handleRemediatePreviewMessage(msg, { children, send }) {
  const valid = validateFixRequest(msg, { children, send }, {
    runIdKeys: ['runId'], pathPurpose: 'propose a fix',
  });
  if (!valid) return;
  const { findingId, finding, runId, targetPath } = valid;
  const context = String(msg.context || '');
  const instruction = String(msg.instruction || '');
  // No git-clean gate here: this handler never writes.
  try {
    if (!fs.statSync(targetPath).isDirectory()) {
      send({ type: 'error', runId, findingId, message: `Not a directory: ${targetPath}` });
      return;
    }
  } catch (err) {
    send({ type: 'error', runId, findingId, message: `Path not found: ${targetPath}` });
    return;
  }

  const remediationAgentPath = agentFilePath('remediation');
  if (!fs.existsSync(remediationAgentPath)) {
    send({ type: 'error', runId, findingId, message: 'Remediation agent file is missing.' });
    return;
  }
  let remediationPrompt;
  try {
    remediationPrompt = fs.readFileSync(remediationAgentPath, 'utf8');
  } catch (err) {
    send({ type: 'error', runId, findingId, message: `Failed to read agent prompt: ${err.message}` });
    return;
  }

  (async () => {
    const userPrompt = `${instruction}\n\nFinding context:\n${context}\n\nApply mode: propose the fix as an \`edit_plan\` in your verdict (see your instructions) if you're confident in an exact edit — you do not have Edit/Write access. A human reviews your proposal before a separate Fix step applies it.`;
    const rem = await spawnAgentStage({
      runId, findingId, finding, agentName: 'remediation',
      systemPrompt: remediationPrompt, userPrompt, allowedTools: 'Read,Grep,Glob',
      cwd: targetPath, instruction, children, send,
    });
    finding.status = deriveStatus(finding);
    send({ type: 'done', runId, findingId, code: rem.code, verdict: rem.verdict, fullText: '' });
  })();
}

/**
 * Applies the most recent Remediate proposal's `edit_plan`. Makes no `claude` call at all.
 * Fails loudly when there is nothing to apply rather than silently generating something new —
 * Fix must write exactly what the human just reviewed.
 */
function handleRemediateFixMessage(msg, { children, send }) {
  const valid = validateFixRequest(msg, { children, send }, {
    runIdKeys: ['runId'], pathPurpose: 'apply a fix',
  });
  if (!valid) return;
  const { findingId, finding, runId, targetPath } = valid;

  const remRun = [...finding.runs].reverse().find((r) => r.agent === 'remediation');
  const plan = remRun && remRun.verdict && remRun.verdict.edit_plan;
  if (!plan || !Array.isArray(plan.files) || !plan.files.length) {
    send({ type: 'error', runId, findingId, message: 'No proposed fix to apply yet — run Remediate first.' });
    return;
  }

  const gate = checkCleanGitTarget(targetPath);
  if (!gate.ok) {
    send({ type: 'error', runId, findingId, message: gate.message });
    return;
  }

  const runRecord = {
    runId, agent: 'fix', instruction: '', context: '',
    status: 'running', verdict: null, fullText: '',
    startedAt: Date.now(), finishedAt: null,
  };
  finding.runs.push(runRecord);
  runIndex.set(runId, { findingId: finding.id, run: runRecord });
  send({ type: 'started', runId, findingId, agent: 'fix' });

  (async () => {
    const result = await applyRemediationPlan(targetPath, { edit_plan: plan });
    const verdict = { verdict: result.applied ? 'applied' : 'not_applied', applied_diff: result.diff };
    runRecord.status = result.error ? 'error' : 'done';
    runRecord.verdict = verdict;
    runRecord.finishedAt = Date.now();
    runIndex.delete(runId);
    if (result.error) send({ type: 'stderr', runId, findingId, data: result.error });
    finding.status = deriveStatus(finding);
    send({ type: 'done', runId, findingId, code: result.error ? 1 : 0, verdict, fullText: '' });
  })();
}

/**
 * Chains Remediate -> Fix -> Verify for the "run all stages" button. The git-clean gate is
 * checked once up front so the chain fails fast rather than spending an LLM call proposing a
 * fix it then cannot apply.
 */
function handleRemediateAllMessage(msg, { children, send }) {
  const valid = validateFixRequest(msg, { children, send }, {
    runIdKeys: ['remediationRunId', 'fixRunId', 'verifyRunId'],
    pathPurpose: 'run the full pipeline',
  });
  if (!valid) return;
  const { findingId, finding, targetPath } = valid;
  const [remediationRunId, fixRunId, verifyRunId] = valid.runIds;
  const context = String(msg.context || '');
  const instruction = String(msg.instruction || '');

  const gate = checkCleanGitTarget(targetPath);
  if (!gate.ok) {
    send({ type: 'error', runId: remediationRunId, findingId, message: gate.message });
    return;
  }

  const remediationAgentPath = agentFilePath('remediation');
  const verifyAgentPath = agentFilePath('verify');
  if (!fs.existsSync(remediationAgentPath) || !fs.existsSync(verifyAgentPath)) {
    send({ type: 'error', runId: remediationRunId, findingId, message: 'Remediation or Verify agent file is missing.' });
    return;
  }

  let remediationPrompt, verifyPrompt;
  try {
    remediationPrompt = fs.readFileSync(remediationAgentPath, 'utf8');
    verifyPrompt = fs.readFileSync(verifyAgentPath, 'utf8');
  } catch (err) {
    send({ type: 'error', runId: remediationRunId, findingId, message: `Failed to read agent prompt: ${err.message}` });
    return;
  }

  (async () => {
    const remediationUserPrompt = `${instruction}\n\nFinding context:\n${context}\n\nApply mode: propose the fix as an \`edit_plan\` in your verdict (see your instructions) if you're confident in an exact edit — you do not have Edit/Write access; the next stage applies it automatically.`;
    const rem = await spawnAgentStage({
      runId: remediationRunId, findingId, finding, agentName: 'remediation',
      systemPrompt: remediationPrompt, userPrompt: remediationUserPrompt,
      allowedTools: 'Read,Grep,Glob', cwd: targetPath, instruction, children, send,
    });
    finding.status = deriveStatus(finding);
    send({ type: 'done', runId: remediationRunId, findingId, code: rem.code, verdict: rem.verdict, fullText: '' });

    const plan = rem.verdict && rem.verdict.edit_plan;
    if (rem.cancelled || rem.code !== 0 || !plan || !Array.isArray(plan.files) || !plan.files.length) {
      return; // nothing confident enough to apply — chain stops after the proposal
    }

    const fixRunRecord = {
      runId: fixRunId, agent: 'fix', instruction: '', context: '',
      status: 'running', verdict: null, fullText: '',
      startedAt: Date.now(), finishedAt: null,
    };
    finding.runs.push(fixRunRecord);
    runIndex.set(fixRunId, { findingId: finding.id, run: fixRunRecord });
    send({ type: 'started', runId: fixRunId, findingId, agent: 'fix' });

    const result = await applyRemediationPlan(targetPath, { edit_plan: plan });
    const fixVerdict = { verdict: result.applied ? 'applied' : 'not_applied', applied_diff: result.diff };
    fixRunRecord.status = result.error ? 'error' : 'done';
    fixRunRecord.verdict = fixVerdict;
    fixRunRecord.finishedAt = Date.now();
    runIndex.delete(fixRunId);
    if (result.error) send({ type: 'stderr', runId: fixRunId, findingId, data: result.error });
    finding.status = deriveStatus(finding);
    send({ type: 'done', runId: fixRunId, findingId, code: result.error ? 1 : 0, verdict: fixVerdict, fullText: '' });

    if (result.error || !result.applied) return; // nothing written — don't chain into Verify

    const verifyUserPrompt = `${instruction}\n\nFinding context:\n${context}\n\nThe Remediation agent proposed this fix and it was just applied to this exact directory:\n${JSON.stringify(fixVerdict, null, 2)}\n\nConfirm whether the fix actually landed and resolves the finding.`;
    const ver = await spawnAgentStage({
      runId: verifyRunId, findingId, finding, agentName: 'verify',
      systemPrompt: verifyPrompt, userPrompt: verifyUserPrompt,
      allowedTools: 'Read,Grep,Glob', cwd: targetPath, instruction, children, send,
    });
    finding.status = deriveStatus(finding);
    send({ type: 'done', runId: verifyRunId, findingId, code: ver.code, verdict: ver.verdict, fullText: '' });
  })();
}

module.exports = {
  handleRemediatePreviewMessage,
  handleRemediateFixMessage,
  handleRemediateAllMessage,
};

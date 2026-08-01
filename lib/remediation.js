/**
 * The fix flow — the only path in this app that writes to a user's files
 * =====================================================================
 *
 * Remediate proposes, Fix applies, Verify re-checks. The split matters: no `claude` call ever
 * reaches disk, not even indirectly. Remediate runs fully read-only and returns an `edit_plan`
 * in its verdict; Fix makes NO model call at all — it is a deterministic function that applies
 * whatever plan the previous Remediate already proposed, after validating it against the live
 * file (sast-engine/remediation-apply.js). So the one function that touches disk is not
 * reached from inside a model invocation; it is a separate, later step a human triggers after
 * reading what was proposed.
 *
 * The guardrail that makes all of it recoverable is checkCleanGitTarget(): Fix refuses to run
 * unless `git status --porcelain` comes back git-tracked and clean, so every edit that lands
 * is trivially inspectable (git diff, surfaced back to the user) and revertible (git checkout)
 * entirely outside this app.
 *
 * Treat this module as the highest-trust code in the repository.
 *
 * Extracted from server.js unchanged. Dependencies are injected rather than required, both to
 * keep this module free of opinions about app wiring and because everything here is worth
 * being able to exercise without booting a server.
 *
 * Covered by test/ws-fix-flow.test.js (43 tests over the error and git-gate paths) and
 * test/remediation-apply.test.js (31 tests over plan validation itself).
 */

module.exports = function createRemediationHandlers(deps) {
  const {
    fs, path, execFileSync, spawn,
    RUN_ID_RE, findings, runIndex,
    agentFilePath, extractVerdict, deriveStatus, loadSastEngine,
  } = deps;

  // Safety gate for the one flow that lets an agent write to a finding's real target directory:
  // refuse unless it's a clean git working tree, so every change is trivially inspectable
  // (git diff) and revertible (git checkout) entirely outside this app.
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
  
  // Validates and applies a Remediation verdict's `edit_plan` (see sast-engine/
  // remediation-apply.js) against the real target directory, then captures a git diff of
  // whatever actually changed. This is the ONE place any agent's output can touch disk in this
  // app — the model that produced `verdict` never gets Edit/Write tools itself (see CLAUDE.md's
  // Security posture); it only proposes edits, which get validated against the live file before
  // anything is written.
  //
  // Returns { applied, diff, error }:
  //   - no edit_plan / empty files array -> { applied: false, diff: null, error: null } — the
  //     model chose not to propose an edit (matches remediation.md's own "don't guess" guidance,
  //     e.g. an architectural fix). Not a failure.
  //   - edit_plan present but invalid (ambiguous/missing find string, protected path, no-op) ->
  //     { applied: false, diff: null, error: <reason> } — a real failure, surfaced as the run
  //     erroring so the Remediation Loop shows "Fix failed" / offers a retry.
  //   - edit_plan valid -> written to disk, { applied: true, diff, error: null }.
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
      // e.g. a proposed path resolving to a directory (fs.readFileSync throws EISDIR) — an
      // unlikely but real LLM slip. Report it the same way an invalid plan is reported, rather
      // than letting it propagate as an unhandled rejection (this function's only callers are
      // fire-and-forget IIFEs with no .catch()).
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
  
    let diff = '';
    try {
      diff = execFileSync('git', ['diff'], { cwd: targetPath, encoding: 'utf8' });
    } catch (err) {
      diff = `(failed to capture git diff: ${String(err.message).split('\n')[0]})`;
    }
    return { applied: true, diff: diff || null, error: null };
  }
  
  // Spawns a real per-finding agent stage against a specific cwd (used by
  // handleRemediatePreviewMessage/handleRemediateAllMessage below, kept separate from those
  // functions just to keep them readable). Pushes/updates the run record and relays
  // started/event/stderr/done exactly like
  // the generic per-finding `run` path, registered in the same `runIndex`/`children` maps, so
  // cancellation and the client's existing run-rendering code both work unmodified.
  function spawnAgentStage({ runId, findingId, finding, agentName, systemPrompt, userPrompt, allowedTools, cwd, instruction, children, send }) {
    return new Promise((resolve) => {
      const runRecord = {
        runId, agent: agentName, instruction, context: userPrompt,
        status: 'running', verdict: null, fullText: '',
        startedAt: Date.now(), finishedAt: null,
      };
      finding.runs.push(runRecord);
      runIndex.set(runId, { findingId: finding.id, run: runRecord });
  
      send({ type: 'started', runId, findingId, agent: agentName });
  
      const args = [
        '-p', userPrompt,
        '--append-system-prompt', systemPrompt,
        '--output-format', 'stream-json',
        '--verbose',
        '--allowedTools', allowedTools,
        '--permission-mode', 'acceptEdits',
      ];
      const child = spawn('claude', args, { cwd, shell: false });
      children.set(runId, child);
  
      let stdoutBuffer = '';
      let fullText = '';
  
      child.stdout.on('data', (chunk) => {
        stdoutBuffer += chunk.toString();
        const lines = stdoutBuffer.split('\n');
        stdoutBuffer = lines.pop();
        for (const line of lines) {
          if (!line.trim()) continue;
          let event;
          try {
            event = JSON.parse(line);
          } catch (err) {
            continue;
          }
          if (event.type === 'assistant' && event.message && Array.isArray(event.message.content)) {
            for (const block of event.message.content) {
              if (block.type === 'text' && typeof block.text === 'string') fullText += block.text;
            }
          }
          send({ type: 'event', runId, findingId, event });
        }
      });
  
      child.stderr.on('data', (chunk) => {
        send({ type: 'stderr', runId, findingId, data: chunk.toString() });
      });
  
      child.on('close', (code) => {
        const cancelled = runRecord.status === 'cancelled';
        const verdict = extractVerdict(fullText);
        if (runRecord.status === 'running') runRecord.status = code === 0 ? 'done' : 'error';
        runRecord.verdict = verdict;
        runRecord.fullText = fullText;
        runRecord.finishedAt = Date.now();
        children.delete(runId);
        runIndex.delete(runId);
        resolve({ code, verdict, cancelled });
      });
  
      child.on('error', (err) => {
        runRecord.status = 'error';
        runRecord.finishedAt = Date.now();
        children.delete(runId);
        runIndex.delete(runId);
        send({ type: 'error', runId, findingId, message: `Failed to spawn claude: ${err.message}` });
        resolve({ code: 1, verdict: null, cancelled: false });
      });
    });
  }
  
  // Runs Remediation read-only against the finding's real target directory and stops — no apply,
  // no automatic chain into Fix. This is the "Remediate" stage: a human-reviewable proposal
  // (fix guidance, corrected_code, and — if the model is confident in an exact edit — an
  // `edit_plan`) with nothing written to disk. The Fix stage below is a separate, later step that
  // actually applies whatever this run proposed — splitting "propose" from "write" means a human
  // always sees the suggested fix before anything touches their files (see CLAUDE.md's
  // Remediation Loop). Remediation itself never gets Edit/Write tools (Read,Grep,Glob only).
  function handleRemediatePreviewMessage(msg, { children, send }) {
    const findingId = msg.findingId ? String(msg.findingId) : null;
    const runId = String(msg.runId || '').trim();
    const context = String(msg.context || '');
    const instruction = String(msg.instruction || '');
    const targetPath = String(msg.path || '').trim();
  
    if (!RUN_ID_RE.test(runId)) {
      send({ type: 'error', message: 'Invalid or missing run id.' });
      return;
    }
    if (children.has(runId)) {
      send({ type: 'error', runId, findingId, message: 'This run is already active.' });
      return;
    }
    const finding = findingId ? findings.get(findingId) : null;
    if (!finding) {
      send({ type: 'error', runId, findingId, message: 'Unknown finding.' });
      return;
    }
    if (!targetPath) {
      send({ type: 'error', runId, findingId, message: 'A target directory is required to propose a fix.' });
      return;
    }
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
  
  // Applies the most recent Remediate proposal's `edit_plan` to the finding's real target
  // directory — this is the "Fix" stage. Deliberately makes no `claude` call at all: the plan was
  // already produced by Remediate, so this step is purely deterministic (validate the plan
  // against the live file, write it, capture a diff — see applyRemediationPlan()). Fails loudly
  // if there's no usable proposal to apply yet, rather than silently generating a fresh one — Fix
  // is meant to write exactly what a human just reviewed in the Remediate box, not something new.
  function handleRemediateFixMessage(msg, { children, send }) {
    const findingId = msg.findingId ? String(msg.findingId) : null;
    const runId = String(msg.runId || '').trim();
    const targetPath = String(msg.path || '').trim();
  
    if (!RUN_ID_RE.test(runId)) {
      send({ type: 'error', message: 'Invalid or missing run id.' });
      return;
    }
    if (children.has(runId)) {
      send({ type: 'error', runId, findingId, message: 'This run is already active.' });
      return;
    }
    const finding = findingId ? findings.get(findingId) : null;
    if (!finding) {
      send({ type: 'error', runId, findingId, message: 'Unknown finding.' });
      return;
    }
    if (!targetPath) {
      send({ type: 'error', runId, findingId, message: 'A target directory is required to apply a fix.' });
      return;
    }
  
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
  
  // Chains Remediate (propose) -> Fix (apply, no LLM call) -> Verify for the loop's "run all
  // stages" button. This used to run Triage first too, but Triage is no longer a live agent stage
  // (see CLAUDE.md) — every finding reaching this handler already carries a triage verdict from
  // when it was created, and buildBaseContext() on the client already folds that prior verdict
  // into `context` below, so Remediate sees it without a fresh live call. The git-clean gate is
  // checked once up front (Fix, further down the chain, is the step that will actually write) so
  // the whole chain fails fast rather than spending an LLM call proposing a fix it then can't
  // apply.
  function handleRemediateAllMessage(msg, { children, send }) {
    const findingId = msg.findingId ? String(msg.findingId) : null;
    const remediationRunId = String(msg.remediationRunId || '').trim();
    const fixRunId = String(msg.fixRunId || '').trim();
    const verifyRunId = String(msg.verifyRunId || '').trim();
    const context = String(msg.context || '');
    const instruction = String(msg.instruction || '');
    const targetPath = String(msg.path || '').trim();
  
    if (!RUN_ID_RE.test(remediationRunId) || !RUN_ID_RE.test(fixRunId) || !RUN_ID_RE.test(verifyRunId)) {
      send({ type: 'error', message: 'Invalid or missing run id(s).' });
      return;
    }
    if (children.has(remediationRunId) || children.has(fixRunId) || children.has(verifyRunId)) {
      send({ type: 'error', runId: remediationRunId, findingId, message: 'This run is already active.' });
      return;
    }
    const finding = findingId ? findings.get(findingId) : null;
    if (!finding) {
      send({ type: 'error', runId: remediationRunId, findingId, message: 'Unknown finding.' });
      return;
    }
    if (!targetPath) {
      send({ type: 'error', runId: remediationRunId, findingId, message: 'A target directory is required to run the full pipeline.' });
      return;
    }
  
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
  
      if (result.error || !result.applied) return; // apply failed or nothing written — don't chain into Verify
  
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
  return {
    checkCleanGitTarget,
    applyRemediationPlan,
    spawnAgentStage,
    handleRemediatePreviewMessage,
    handleRemediateFixMessage,
    handleRemediateAllMessage,
  };
};

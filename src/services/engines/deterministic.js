/**
 * The deterministic half of a hybrid scan: sast-engine's pattern agents plus VerifierAgent.
 * No LLM anywhere. Returns results rather than finishing the scan, since the merge step needs
 * every engine's output together.
 *
 * DORMANT — nothing imports this. services/scanner.js calls engines/opengrep.js instead, which
 * scored better on the benchmark (see docs/Engine-Rework.md). It is parked rather than deleted
 * because the 11 AI/agentic pattern agents have no Opengrep equivalent and the overlap between
 * the two engines has not been measured. Do not delete until it has been.
 *
 * Two things are dormant with it, and are dead code for as long as this file is unwired:
 *   services/scan-report.js            — only this file calls summarizeRecon/buildAgentRoster
 *   plan.js buildCoverageSummary()     — reached only when scan.agentRoster is set, i.e. here
 * Both still have characterization tests; those tests pass over parked code, not live code.
 */


const { DETERMINISTIC_AGENT_TIMEOUT_MS } = require('../../config');
const { normalizeSeverity } = require('../taxonomy');
const { toRepoRelative } = require('../paths');
const { summarizeRecon, buildAgentRoster } = require('../scan-report');
const { sendScanText } = require('./emit');

async function runDeterministicPatternScan(engine, scan, targetPath, diffFiles, { send }) {
  let orchestrator;
  try {
    orchestrator = await engine.buildOrchestratorAsync(targetPath);
  } catch (err) {
    return { findings: [], error: `Failed to initialize scan engine: ${err.message}` };
  }

  let done = 0;
  // Placeholder only: many agents are gated behind shouldRun(recon) and never run on a given
  // repo, and a skipped agent's slot can never be filled by onAgentDone. onScopeReady corrects
  // this before any onAgentDone fires, or the progress bar stalls below 100% forever.
  let total = orchestrator.agents.length;

  // The orchestrator records an errored/timed-out agent as success: false. Reporting it is what
  // separates "this class is clean" from "this class was never checked" — the one confusion a
  // security tool cannot afford.
  const failedAgents = [];
  let skipped = [];

  try {
    const result = await orchestrator.runAll(targetPath, {
      quiet: true,
      onlyFiles: diffFiles || undefined,
      timeout: DETERMINISTIC_AGENT_TIMEOUT_MS,
      onScopeReady: (realTotal, skippedNames) => {
        total = realTotal;
        skipped = Array.isArray(skippedNames) ? skippedNames : [];
        scan.agentsRun = realTotal;
        scan.agentsSkipped = skipped;
        if (scan.status === 'cancelled') return;
        send({ type: 'scan-progress', runId: scan.runId, scanId: scan.id, engine: 'deterministic', done, total, skipped });
      },
      onAgentDone: (agentResult, agentFindings) => {
        done++;
        if (agentResult && agentResult.success === false) {
          failedAgents.push(`${agentResult.agent} (${agentResult.error || 'unknown error'})`);
        }
        if (scan.status === 'cancelled') return;
        // Sent every time, unlike the scan-event below, which is narration and only sent when
        // there is something to narrate.
        send({ type: 'scan-progress', runId: scan.runId, scanId: scan.id, engine: 'deterministic', done, total });
        if (!agentFindings.length) return;
        sendScanText(send, scan, agentFindings.map((f) => {
          const rel = toRepoRelative(targetPath, f.file) || 'unknown file';
          const loc = f.line ? `${rel}:${f.line}` : rel;
          return `[${normalizeSeverity(f.severity)}] \`${loc}\` — ${f.title}`;
        }));
      },
    });
    // Recorded on the scan for the same reason agentsSkipped is: the reasoning pass needs to
    // know which classes went unchecked so it does not treat them as already covered.
    scan.agentsFailed = failedAgents;

    // runAll() returns the whole record of how it decided, not just `findings` and `surface`.
    // These three are what make a scan auditable rather than only a result.
    scan.agentRoster = buildAgentRoster(orchestrator.agents, result.agentResults, skipped);
    scan.engineRecon = summarizeRecon(result.recon);
    scan.suppression = result.suppression || null;
    if (failedAgents.length && scan.status !== 'cancelled') {
      send({
        type: 'scan-warning',
        runId: scan.runId,
        scanId: scan.id,
        message: `${failedAgents.length} of ${total} pattern agents did not complete, so the vulnerability classes they cover were NOT checked — this is incomplete coverage, not a clean result: ${failedAgents.join(', ')}`,
      });
    }
    return {
      findings: result.findings,
      surface: result.surface || null,
      failedAgents,
      error: null,
    };
  } catch (err) {
    return { findings: [], failedAgents, error: err.message };
  }
}

module.exports = { runDeterministicPatternScan };

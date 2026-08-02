/**
 * Spawning `claude -p` and relaying its stream-json output: the line framing every caller
 * shares, the per-finding agent stage, and one reasoning-scan call.
 */

const { spawn } = require('child_process');

/** @typedef {import('../types').Run} Run */
/** @typedef {import('../types').Verdict} Verdict */

const { extractVerdict } = require('./verdict');
const { runIndex } = require('../store/findings');

/**
 * Frame a stream-json stdout into whole parsed events. Chunks split mid-line, so the trailing
 * partial must be carried over rather than parsed; an unparseable line is skipped, not fatal.
 */
function onStreamJson(stream, handle) {
  let buffer = '';
  stream.on('data', (chunk) => {
    buffer += chunk.toString();
    const lines = buffer.split('\n');
    buffer = lines.pop();
    for (const line of lines) {
      if (!line.trim()) continue;
      let event;
      try {
        event = JSON.parse(line);
      } catch (err) {
        continue;
      }
      handle(event);
    }
  });
}

/** The assistant text carried by one stream-json event, or '' for any other event type. */
function assistantText(event) {
  if (event.type !== 'assistant' || !event.message || !Array.isArray(event.message.content)) return '';
  let out = '';
  for (const block of event.message.content) {
    if (block.type === 'text' && typeof block.text === 'string') out += block.text;
  }
  return out;
}

function claudeArgs({ userPrompt, systemPrompt, allowedTools }) {
  return [
    '-p', userPrompt,
    '--append-system-prompt', systemPrompt,
    '--output-format', 'stream-json',
    '--verbose',
    '--allowedTools', allowedTools,
    '--permission-mode', 'acceptEdits',
  ];
}

/**
 * Runs one per-finding agent stage against a specific cwd. Pushes/updates the run record and
 * relays started/event/stderr exactly like the generic `run` path, registered in the same
 * runIndex/children maps, so cancellation and the client's run rendering work unmodified.
 */
function spawnAgentStage({ runId, findingId, finding, agentName, systemPrompt, userPrompt, allowedTools, cwd, instruction, children, send }) {
  return new Promise((resolve) => {
    const runRecord = {
      runId, agent: agentName, instruction, context: userPrompt,
      status: 'running', verdict: null, fullText: '',
      startedAt: Date.now(), finishedAt: null,
    };
    // `finding` is optional: the generic `run` message accepts a null findingId, in which case
    // there is no history to append to and nothing to look up on done/cancel.
    if (finding) {
      finding.runs.push(runRecord);
      runIndex.set(runId, { findingId: finding.id, run: runRecord });
    }

    send({ type: 'started', runId, findingId, agent: agentName });

    const child = spawn('claude', claudeArgs({ userPrompt, systemPrompt, allowedTools }), { cwd, shell: false });
    children.set(runId, child);

    let fullText = '';

    onStreamJson(child.stdout, (event) => {
      fullText += assistantText(event);
      send({ type: 'event', runId, findingId, event });
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

/**
 * One `claude -p` reasoning call for a scan, relaying stream-json as scan-events and resolving
 * with the parsed verdict plus real spend.
 *
 * Registered in `children` under a synthetic `${scan.runId}::mod${index}` key (tracked on
 * scan.moduleRunIds) rather than the scan's own runId, so the WS cancel handler can kill every
 * in-flight reasoning call for a scan and not just one child.
 */
function runReasoningCall({ scan, targetPath, children, send, index, label, systemPrompt, userPrompt, budgetUsd }) {
  return new Promise((resolve) => {
    if (scan.status === 'cancelled') { resolve({ parsed: null, error: null, costUsd: 0 }); return; }

    const args = claudeArgs({ userPrompt, systemPrompt, allowedTools: 'Read,Grep,Glob' });
    if (scan.budgetEnabled) args.push('--max-budget-usd', String(budgetUsd));

    const callRunId = `${scan.runId}::mod${index}`;
    const child = spawn('claude', args, { cwd: targetPath, shell: false });
    children.set(callRunId, child);
    scan.moduleRunIds.push(callRunId);

    let fullText = '';
    // The final stream-json `result` event carries real `total_cost_usd` and, when the call hit
    // its cap rather than finishing, `subtype: 'error_max_budget_usd'` — which is how budget
    // exhaustion is told apart from a generic crash below.
    let resultEvent = null;

    onStreamJson(child.stdout, (event) => {
      fullText += assistantText(event);
      if (event.type === 'result') resultEvent = event;
      send({ type: 'scan-event', runId: scan.runId, scanId: scan.id, event });
    });

    child.stderr.on('data', (chunk) => {
      send({ type: 'scan-stderr', runId: scan.runId, scanId: scan.id, data: chunk.toString() });
    });

    const settle = (error) => {
      children.delete(callRunId);
      const costUsd = resultEvent && typeof resultEvent.total_cost_usd === 'number'
        ? resultEvent.total_cost_usd
        : 0;
      // Parse even on a non-zero exit: a call that hit its cap mid-way often still emitted a
      // complete JSON block first, and discarding it throws away work already paid for.
      resolve({ parsed: extractVerdict(fullText), error, costUsd });
    };

    child.on('close', (code) => {
      if (scan.status === 'cancelled') { settle(null); return; }
      if (code === 0) { settle(null); return; }
      if (resultEvent && resultEvent.subtype === 'error_max_budget_usd') {
        settle(`${label} hit its $${budgetUsd} budget cap before finishing — its coverage is incomplete, not a clean "nothing found"`);
        return;
      }
      settle(`${label}: claude exited with code ${code}`);
    });

    child.on('error', (err) => settle(`${label}: failed to spawn claude — ${err.message}`));
  });
}

module.exports = { onStreamJson, assistantText, claudeArgs, spawnAgentStage, runReasoningCall };

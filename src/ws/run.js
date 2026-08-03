/**
 * The generic per-finding `run` message: spawn an arbitrary agent prompt against a finding and
 * relay its stream-json live.
 */

const fs = require('fs');

const { RUN_ID_RE, AGENT_NAME_RE, agentFilePath } = require('../config');
const { spawnAgentStage } = require('../services/claude');
const { findings, deriveStatus } = require('../store/findings');

function handleRunMessage(msg, { children, send }) {
  const runId = String(msg.runId || '').trim();
  if (!RUN_ID_RE.test(runId)) {
    send({ type: 'error', message: 'Invalid or missing runId.' });
    return;
  }

  if (children.has(runId)) {
    send({ type: 'error', runId, message: 'This runId is already active.' });
    return;
  }

  const agentName = String(msg.agent || '').trim();
  const context = String(msg.context || '');
  const instruction = String(msg.instruction || '');
  const findingId = msg.findingId ? String(msg.findingId) : null;

  if (!AGENT_NAME_RE.test(agentName)) {
    send({ type: 'error', runId, message: `Invalid agent name: ${agentName}` });
    return;
  }

  const agentPath = agentFilePath(agentName);
  if (!fs.existsSync(agentPath)) {
    send({ type: 'error', runId, message: `Unknown agent: ${agentName}` });
    return;
  }

  let systemPrompt;
  try {
    systemPrompt = fs.readFileSync(agentPath, 'utf8');
  } catch (err) {
    send({ type: 'error', runId, message: `Failed to read agent prompt: ${err.message}` });
    return;
  }

  const finding = findingId ? findings.get(findingId) : null;
  const userPrompt = `${instruction}\n\nFinding context:\n${context}`;

  // Per-finding agents normally reason over the `code` snippet already in context, so they run
  // with this app's own cwd and no Glob. Verify is the exception: confirming a fix landed means
  // reading the finding's real target codebase. If the client resolved a source path and it is
  // still a directory, spawn there with Glob added; otherwise fall back silently — verify.md is
  // written to return `inconclusive` rather than reason over the wrong repository.
  let runCwd = process.cwd();
  let allowedTools = 'Read,Grep';
  const requestedPath = String(msg.path || '').trim();
  if (requestedPath) {
    try {
      if (fs.statSync(requestedPath).isDirectory()) {
        runCwd = requestedPath;
        allowedTools = 'Read,Grep,Glob';
      }
    } catch (err) {
      // Path no longer exists (e.g. a temp checkout was cleaned up).
    }
  }

  // Same spawn/relay/close path every other stage uses. It was duplicated here, and the two
  // copies had already drifted on what `done` carries.
  spawnAgentStage({
    runId, findingId, finding, agentName, systemPrompt, userPrompt,
    allowedTools, cwd: runCwd, instruction, children, send,
  }).then((res) => {
    if (finding) finding.status = deriveStatus(finding);
    // fullText stays on the run record; no client reads it off the wire, and a whole model
    // transcript per run is a lot of socket traffic for nothing.
    send({ type: 'done', runId, findingId, code: res.code, verdict: res.verdict, fullText: '' });
  });
}

module.exports = { handleRunMessage };

/**
 * The generic per-finding `run` message: spawn an arbitrary agent prompt against a finding and
 * relay its stream-json live.
 */

const fs = require('fs');
const { spawn } = require('child_process');

const { RUN_ID_RE, AGENT_NAME_RE, agentFilePath } = require('../config');
const { extractVerdict } = require('../services/verdict');
const { onStreamJson, assistantText, claudeArgs } = require('../services/claude');
const { findings, runIndex, deriveStatus } = require('../store/findings');

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
  let runRecord = null;
  if (finding) {
    runRecord = {
      runId,
      agent: agentName,
      instruction,
      context,
      status: 'running',
      verdict: null,
      fullText: '',
      startedAt: Date.now(),
      finishedAt: null,
    };
    finding.runs.push(runRecord);
    runIndex.set(runId, { findingId: finding.id, run: runRecord });
  }

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

  send({ type: 'started', runId, findingId, agent: agentName });

  const child = spawn('claude', claudeArgs({ userPrompt, systemPrompt, allowedTools }), { cwd: runCwd, shell: false });
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
    const verdict = extractVerdict(fullText);
    if (runRecord && runRecord.status === 'running') {
      runRecord.status = code === 0 ? 'done' : 'error';
    }
    if (runRecord) {
      runRecord.verdict = verdict;
      runRecord.fullText = fullText;
      runRecord.finishedAt = Date.now();
    }
    if (finding) finding.status = deriveStatus(finding);
    // fullText stays on the run record; no client reads it off the wire, and a whole
    // model transcript per run is a lot of socket traffic for nothing.
    send({ type: 'done', runId, findingId, code, verdict, fullText: '' });
    children.delete(runId);
    runIndex.delete(runId);
  });

  child.on('error', (err) => {
    if (runRecord) {
      runRecord.status = 'error';
      runRecord.finishedAt = Date.now();
    }
    if (finding) finding.status = deriveStatus(finding);
    send({ type: 'error', runId, findingId, message: `Failed to spawn claude: ${err.message}` });
    children.delete(runId);
    runIndex.delete(runId);
  });
}

module.exports = { handleRunMessage };

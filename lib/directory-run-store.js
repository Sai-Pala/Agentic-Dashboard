/**
 * Whole-directory run stores
 * ==========================
 *
 * App-level threat models and control assessments are the same KIND of thing: one holistic
 * `claude -p` run against an entire directory, producing a single report object, tied to no
 * finding and no scan. Only three things actually differ between them — which agent .md is
 * loaded, how the agent is named in an error message, and the opening line of the prompt.
 *
 * They used to be written out twice: two stores, two runIndexes, two byte-identical list-item
 * mappers, two pairs of REST routes, and two 134-line WebSocket handlers differing in three
 * strings. That is what this factory replaces. Everything is derived from `kind` rather than
 * hardcoded, so adding a third whole-directory agent is a config entry rather than another
 * ~170 lines to keep in sync.
 *
 * What is deliberately NOT collapsed into this shape:
 *   - The `scans` store. It carries a dozen extra fields (scope, budget, cost, agent counts)
 *     and a three-engine pipeline; forcing it through here would mean a config object with
 *     more exceptions than shared behaviour.
 *   - The `findings` store. A finding is a different domain object entirely — it owns a `runs`
 *     chain and a status machine, where these own exactly one run.
 *
 * The per-family WebSocket message names (`app-threat-model-*` vs `controls-assist-*`) are
 * preserved exactly. They are not incidental duplication: the client keys its handlers on
 * them, and distinct names are what stop a runId collision between families routing one
 * family's message into another's handler. test/ws-scan-protocol.test.js pins all fifteen.
 *
 * Dependencies are injected rather than required directly, so this module holds no opinion
 * about how the app is wired and can be exercised without booting a server.
 */

module.exports = function createDirectoryRunStores({ app, fs, crypto, spawn, RUN_ID_RE, agentFilePath, extractVerdict }) {

  const DIRECTORY_RUN_KINDS = {
    appThreatModel: {
      routeBase: '/api/app-threat-models',
      wsPrefix: 'app-threat-model',
      agentName: 'app_threat_model',
      agentLabel: 'App Threat Model',
      openingLine: 'Analyze this codebase and produce a whole-app, architecture-level threat model.',
    },
    controlAssessment: {
      routeBase: '/api/control-assessments',
      wsPrefix: 'controls-assist',
      agentName: 'controls_assist',
      agentLabel: 'Controls Assist',
      openingLine:
        'Analyze this codebase and identify which NIST 800-53 controls the application layer provides evidence for, drafting SSP-ready narratives for each.',
    },
  };
  
  /**
   * Build one whole-directory run store: its records, its runId index, its list-item mapper,
   * its two REST routes and its WebSocket handler.
   */
  function createDirectoryRunStore(kind) {
    const records = new Map();   // id -> record
    const runIndex = new Map();  // runId -> record, for O(1) lookup on done/error/cancel
  
    const toListItem = (record) => ({
      id: record.id,
      runId: record.runId,
      path: record.path,
      app: record.app,
      branch: record.branch,
      instruction: record.instruction,
      status: record.status,
      verdict: record.verdict,
      error: record.error,
      startedAt: record.startedAt,
      finishedAt: record.finishedAt,
    });
  
    app.get(kind.routeBase, (req, res) => {
      res.json([...records.values()].sort((a, b) => b.startedAt - a.startedAt).map(toListItem));
    });
  
    app.get(`${kind.routeBase}/:id`, (req, res) => {
      const record = records.get(req.params.id);
      if (!record) {
        res.status(404).json({ error: 'not found' });
        return;
      }
      res.json(toListItem(record));
    });
  
    // Every error from this handler carries the family's own type name, so a client listening
    // for one family never sees another's failures.
    const fail = (send, runId, message, extra) =>
      send({ type: `${kind.wsPrefix}-error`, ...(runId ? { runId } : {}), ...extra, message });
  
    function handleMessage(msg, { children, send }) {
      const runId = String(msg.runId || '').trim();
      if (!RUN_ID_RE.test(runId)) {
        fail(send, null, 'Invalid or missing runId.');
        return;
      }
      if (children.has(runId)) {
        fail(send, runId, 'This runId is already active.');
        return;
      }
  
      const targetPath = String(msg.path || '').trim();
      const instruction = String(msg.instruction || '').trim();
      const branch = String(msg.branch || '').trim();
      const appLabel = String(msg.app || '').trim();
  
      if (!targetPath) {
        fail(send, runId, 'A target directory path is required.');
        return;
      }
  
      let stat;
      try {
        stat = fs.statSync(targetPath);
      } catch (err) {
        fail(send, runId, `Path not found: ${targetPath}`);
        return;
      }
      if (!stat.isDirectory()) {
        fail(send, runId, `Not a directory: ${targetPath}`);
        return;
      }
  
      const agentPath = agentFilePath(kind.agentName);
      if (!fs.existsSync(agentPath)) {
        fail(send, runId, `${kind.agentLabel} agent (agents/${kind.agentName}.md) is not available.`);
        return;
      }
  
      let systemPrompt;
      try {
        systemPrompt = fs.readFileSync(agentPath, 'utf8');
      } catch (err) {
        fail(send, runId, `Failed to read agent prompt: ${err.message}`);
        return;
      }
  
      const record = {
        id: crypto.randomUUID(),
        runId,
        path: targetPath,
        app: appLabel || null,
        branch: branch || null,
        instruction,
        status: 'running',
        verdict: null,
        error: null,
        startedAt: Date.now(),
        finishedAt: null,
      };
      records.set(record.id, record);
      runIndex.set(runId, record);
  
      const userPrompt = [kind.openingLine, instruction, `Target directory: ${targetPath}`]
        .filter(Boolean)
        .join('\n\n');
  
      const args = [
        '-p', userPrompt,
        '--append-system-prompt', systemPrompt,
        '--output-format', 'stream-json',
        '--verbose',
        '--allowedTools', 'Read,Grep,Glob',
        '--permission-mode', 'acceptEdits',
      ];
  
      send({ type: `${kind.wsPrefix}-started`, runId, id: record.id, path: targetPath });
  
      const child = spawn('claude', args, { cwd: targetPath, shell: false });
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
          send({ type: `${kind.wsPrefix}-event`, runId, id: record.id, event });
        }
      });
  
      child.stderr.on('data', (chunk) => {
        send({ type: `${kind.wsPrefix}-stderr`, runId, id: record.id, data: chunk.toString() });
      });
  
      child.on('close', (code) => {
        const verdict = extractVerdict(fullText);
        if (record.status === 'running') {
          record.status = code === 0 && verdict ? 'done' : 'error';
          record.error = code === 0 && verdict ? null : `claude exited with code ${code}`;
        }
        record.verdict = verdict;
        record.finishedAt = Date.now();
        send({ type: `${kind.wsPrefix}-done`, runId, id: record.id, code, verdict });
        children.delete(runId);
        runIndex.delete(runId);
      });
  
      child.on('error', (err) => {
        record.status = 'error';
        record.error = err.message;
        record.finishedAt = Date.now();
        fail(send, runId, `Failed to spawn claude: ${err.message}`, { id: record.id });
        children.delete(runId);
        runIndex.delete(runId);
      });
    }
  
    return { records, runIndex, toListItem, handleMessage };
  }
  return {
    appThreatModelStore: createDirectoryRunStore(DIRECTORY_RUN_KINDS.appThreatModel),
    controlAssessmentStore: createDirectoryRunStore(DIRECTORY_RUN_KINDS.controlAssessment),
  };
};

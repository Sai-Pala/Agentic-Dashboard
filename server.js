const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 4500;
const AGENTS_DIR = path.join(__dirname, 'agents');
const AGENT_NAME_RE = /^[a-zA-Z0-9_-]+$/;
const RUN_ID_RE = /^[a-zA-Z0-9_-]+$/;
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
// Shipped with the app and load-bearing for other hardcoded UI (the scan flow,
// the Dashboard's pipeline health panel) — editable, but not deletable via the
// Agents screen.
const BUILTIN_AGENTS = ['triage', 'threat_model', 'remediation', 'scan'];

function agentFilePath(name) {
  return path.join(AGENTS_DIR, `${name}.md`);
}

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/agents', (req, res) => {
  const files = fs.readdirSync(AGENTS_DIR).filter((f) => f.endsWith('.md'));
  // 'scan' is an agent .md file but not a per-finding pipeline agent — it runs
  // against a directory via the dedicated Scans flow, not the stage/branch UI.
  const names = files.map((f) => f.replace(/\.md$/, '')).filter((n) => n !== 'scan');
  res.json(names);
});

app.get('/api/agents/:name', (req, res) => {
  const { name } = req.params;
  if (!AGENT_NAME_RE.test(name)) return res.status(400).json({ error: 'Invalid agent name.' });
  const filePath = agentFilePath(name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Agent not found.' });
  const content = fs.readFileSync(filePath, 'utf8');
  res.json({ name, content, isBuiltIn: BUILTIN_AGENTS.includes(name) });
});

app.post('/api/agents', (req, res) => {
  const { name, content } = req.body || {};
  if (typeof name !== 'string' || !AGENT_NAME_RE.test(name)) {
    return res.status(400).json({ error: 'Agent name must match ^[a-zA-Z0-9_-]+$.' });
  }
  if (typeof content !== 'string' || !content.trim()) {
    return res.status(400).json({ error: 'Agent content must not be empty.' });
  }
  const filePath = agentFilePath(name);
  if (fs.existsSync(filePath)) return res.status(409).json({ error: 'An agent with this name already exists.' });
  fs.writeFileSync(filePath, content, 'utf8');
  res.status(201).json({ name });
});

app.put('/api/agents/:name', (req, res) => {
  const { name } = req.params;
  const { content } = req.body || {};
  if (!AGENT_NAME_RE.test(name)) return res.status(400).json({ error: 'Invalid agent name.' });
  if (typeof content !== 'string' || !content.trim()) {
    return res.status(400).json({ error: 'Agent content must not be empty.' });
  }
  const filePath = agentFilePath(name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Agent not found.' });
  fs.writeFileSync(filePath, content, 'utf8');
  res.json({ name });
});

app.delete('/api/agents/:name', (req, res) => {
  const { name } = req.params;
  if (!AGENT_NAME_RE.test(name)) return res.status(400).json({ error: 'Invalid agent name.' });
  if (BUILTIN_AGENTS.includes(name)) {
    return res.status(403).json({ error: 'Built-in pipeline agents cannot be deleted.' });
  }
  const filePath = agentFilePath(name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Agent not found.' });
  fs.unlinkSync(filePath);
  res.json({ ok: true });
});

// ---------- in-memory findings store ----------
// Session-lifetime only — lost on restart. No CSV ingestion/persistence yet
// (see CLAUDE.md "Not yet built"). Each finding owns a list of agent runs,
// which is how the pipeline chains (triage -> threat_model -> remediation).

const findings = new Map(); // id -> finding record
const runIndex = new Map(); // runId -> { findingId, run } for O(1) lookup on done/error/cancel

function toListItem(finding) {
  const runs = finding.runs;
  const latest = runs.length ? runs[runs.length - 1] : null;
  return {
    id: finding.id,
    title: finding.title,
    severity: finding.severity,
    rule: finding.rule,
    file: finding.file,
    description: finding.description,
    status: finding.status,
    createdAt: finding.createdAt,
    runCount: runs.length,
    latestRun: latest ? { agent: latest.agent, status: latest.status, verdict: latest.verdict } : null,
    sourceScanId: finding.sourceScanId || null,
  };
}

function deriveStatus(finding) {
  const latest = finding.runs[finding.runs.length - 1];
  if (!latest) return 'new';
  if (latest.status === 'running') return 'in_review';
  if (latest.status === 'error' || latest.status === 'cancelled') return 'in_review';
  const v = latest.verdict && latest.verdict.verdict;
  if (v === 'false_positive' || v === 'duplicate') return 'closed';
  if (v === 'confirmed' && !latest.verdict.next_agent) return 'remediation_ready';
  if (v === 'confirmed' || v === 'needs_review') return 'in_review';
  return 'in_review';
}

function seedFindings() {
  const samples = [
    {
      title: 'SQL Injection via title search parameter',
      severity: 'high',
      rule: 'CWE-89 SQL Injection',
      file: 'findings-dashboard.jsx (example legacy endpoint, hypothetical Node/Express backend)',
      description:
        "Scanner: Veracode SAST\nRule: CWE-89 SQL Injection\n\nSnippet:\n\n  app.get('/api/findings/search', (req, res) => {\n    const q = req.query.title;\n    const sql = `SELECT * FROM findings WHERE title LIKE '%${q}%'`;\n    db.query(sql, (err, rows) => {\n      if (err) return res.status(500).send('error');\n      res.json(rows);\n    });\n  });\n\nDescription: user-controlled query parameter `title` is concatenated directly into a SQL string and executed without parameterization.",
    },
    {
      title: 'Reflected XSS in finding title render',
      severity: 'medium',
      rule: 'CWE-79 Cross-Site Scripting',
      file: 'findings-dashboard.jsx (hypothetical detail pane)',
      description:
        "Scanner: manual review\nRule: CWE-79 Reflected XSS\n\nSnippet:\n\n  detailPane.innerHTML = `<h2>${finding.title}</h2>`;\n\nDescription: finding.title comes from an uploaded CSV and is interpolated directly into innerHTML with no escaping. A crafted title in the CSV would execute in the analyst's browser session.",
    },
    {
      title: 'Hardcoded Azure DevOps PAT in ticket-creation helper',
      severity: 'critical',
      rule: 'CWE-798 Use of Hard-coded Credentials',
      file: 'findings-dashboard.jsx (ticket creation helper, hypothetical)',
      description:
        "Scanner: gitleaks\nRule: CWE-798 Hardcoded credentials\n\nSnippet:\n\n  const ADO_PAT = 'ado_pat_9f2a...redacted...';\n  fetch(`https://dev.azure.com/org/_apis/wit/workitems?api-version=6.0`, {\n    headers: { Authorization: `Basic ${btoa(':' + ADO_PAT)}` }\n  });\n\nDescription: a personal access token is committed directly in client-side JS, shipped to every browser that loads the dashboard.",
    },
    {
      title: 'Missing authorization check on /api/findings/:id/status',
      severity: 'low',
      rule: 'CWE-862 Missing Authorization',
      file: 'server.js (hypothetical future endpoint, not yet built here)',
      description:
        "Scanner: manual review (design note)\nRule: CWE-862 Missing Authorization\n\nDescription: the planned PATCH /api/findings/:id/status endpoint (for marking findings triaged/closed from the dashboard) has no auth model defined yet in this local single-user tool. Flagging now so it's not forgotten if this app is ever exposed beyond localhost.",
    },
  ];

  for (const s of samples) {
    const id = crypto.randomUUID();
    findings.set(id, {
      id,
      title: s.title,
      severity: s.severity,
      rule: s.rule,
      file: s.file,
      description: s.description,
      status: 'new',
      createdAt: Date.now(),
      runs: [],
    });
  }
}
seedFindings();

// ---------- in-memory scans store ----------
// A scan is one "scan this directory" invocation of the Scan agent (agents/scan.md).
// It doesn't chain like a per-finding run does — on completion it creates zero or
// more new Finding records (tagged with sourceScanId) and remembers their ids, so
// the Scans view can show "this scan produced N findings" and link through to them.

const scans = new Map(); // id -> scan record
const scanRunIndex = new Map(); // runId -> scan record, for O(1) lookup on done/error/cancel

function toScanListItem(scan) {
  return {
    id: scan.id,
    runId: scan.runId,
    path: scan.path,
    instruction: scan.instruction,
    status: scan.status,
    error: scan.error,
    findingIds: scan.findingIds,
    startedAt: scan.startedAt,
    finishedAt: scan.finishedAt,
  };
}

app.get('/api/scans', (req, res) => {
  const list = [...scans.values()].sort((a, b) => b.startedAt - a.startedAt).map(toScanListItem);
  res.json(list);
});

app.get('/api/scans/:id', (req, res) => {
  const scan = scans.get(req.params.id);
  if (!scan) {
    res.status(404).json({ error: 'not found' });
    return;
  }
  res.json({
    ...toScanListItem(scan),
    findings: scan.findingIds.map((id) => findings.get(id)).filter(Boolean).map(toListItem),
  });
});

app.delete('/api/scans/:id', (req, res) => {
  const scan = scans.get(req.params.id);
  if (!scan) {
    res.status(404).json({ error: 'not found' });
    return;
  }
  if (scan.status === 'running') {
    res.status(409).json({ error: 'Cancel the scan before deleting it.' });
    return;
  }
  scans.delete(req.params.id);
  res.json({ ok: true });
});

app.get('/api/findings', (req, res) => {
  const list = [...findings.values()]
    .sort((a, b) => b.createdAt - a.createdAt)
    .map(toListItem);
  res.json(list);
});

app.post('/api/findings', (req, res) => {
  const body = req.body || {};
  const title = String(body.title || '').trim();
  const description = String(body.description || '').trim();
  if (!title || !description) {
    res.status(400).json({ error: 'title and description are required' });
    return;
  }

  const id = crypto.randomUUID();
  const finding = {
    id,
    title,
    severity: SEVERITIES.includes(body.severity) ? body.severity : 'medium',
    rule: body.rule ? String(body.rule).trim() : null,
    file: body.file ? String(body.file).trim() : null,
    description,
    status: 'new',
    createdAt: Date.now(),
    runs: [],
  };
  findings.set(id, finding);
  res.status(201).json(finding);
});

function csvEscape(value) {
  const s = value === null || value === undefined ? '' : String(value);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

// Must be registered before `/api/findings/:id` — otherwise Express matches
// this request as that route with id="export.csv" and 404s.
app.get('/api/findings/export.csv', (req, res) => {
  const columns = [
    'id', 'title', 'status', 'severity', 'rule', 'file',
    'verdict', 'severity_confirmed', 'confidence', 'priority',
    'owasp', 'cwe', 'nist_800_53',
    'root_cause', 'fix_guidance', 'effort',
    'run_count', 'latest_agent', 'source_scan_path', 'created_at',
  ];
  const rows = [columns.join(',')];

  for (const finding of [...findings.values()].sort((a, b) => a.createdAt - b.createdAt)) {
    const latest = finding.runs[finding.runs.length - 1];
    const v = (latest && latest.verdict) || {};
    const scan = finding.sourceScanId ? scans.get(finding.sourceScanId) : null;
    rows.push([
      finding.id, finding.title, finding.status, finding.severity, finding.rule || '', finding.file || '',
      v.verdict || '', v.severity_confirmed || '', v.confidence || '', v.priority || '',
      v.owasp || '', v.cwe || '', Array.isArray(v.nist_800_53) ? v.nist_800_53.join('; ') : '',
      v.root_cause || '', v.fix_guidance || '', v.effort || '',
      finding.runs.length, latest ? latest.agent : '', scan ? scan.path : '',
      new Date(finding.createdAt).toISOString(),
    ].map(csvEscape).join(','));
  }

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="findings-export-${Date.now()}.csv"`);
  res.send(rows.join('\r\n'));
});

app.get('/api/findings/:id', (req, res) => {
  const finding = findings.get(req.params.id);
  if (!finding) {
    res.status(404).json({ error: 'not found' });
    return;
  }
  res.json(finding);
});

app.get('/api/timeline', (req, res) => {
  const entries = [];
  for (const finding of findings.values()) {
    for (const run of finding.runs) {
      entries.push({
        kind: run.agent, // 'triage' | 'threat_model' | 'remediation'
        runId: run.runId,
        findingId: finding.id,
        findingTitle: finding.title,
        agent: run.agent,
        status: run.status,
        instruction: run.instruction,
        verdict: run.verdict,
        startedAt: run.startedAt,
        finishedAt: run.finishedAt,
      });
    }
  }
  for (const scan of scans.values()) {
    entries.push({
      kind: 'scan',
      runId: scan.runId,
      scanId: scan.id,
      path: scan.path,
      status: scan.status,
      instruction: scan.instruction,
      findingCount: scan.findingIds.length,
      error: scan.error,
      startedAt: scan.startedAt,
      finishedAt: scan.finishedAt,
    });
  }
  entries.sort((a, b) => b.startedAt - a.startedAt);
  res.json(entries);
});

// ---------- websocket: agent invocation ----------

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

function extractVerdict(text) {
  const match = text.match(/```json\s*([\s\S]*?)```/);
  if (!match) return null;
  try {
    return JSON.parse(match[1]);
  } catch (err) {
    return null;
  }
}

wss.on('connection', (ws) => {
  const children = new Map(); // runId -> ChildProcess

  const send = (payload) => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(payload));
  };

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch (err) {
      send({ type: 'error', message: 'Malformed message.' });
      return;
    }

    if (msg.type === 'cancel') {
      const runId = String(msg.runId || '');
      const child = children.get(runId);
      const indexed = runIndex.get(runId);
      if (indexed && indexed.run.status === 'running') {
        indexed.run.status = 'cancelled';
        indexed.run.finishedAt = Date.now();
      }
      const scanIndexed = scanRunIndex.get(runId);
      if (scanIndexed && scanIndexed.status === 'running') {
        scanIndexed.status = 'cancelled';
        scanIndexed.finishedAt = Date.now();
      }
      if (child) child.kill();
      return;
    }

    if (msg.type === 'scan') {
      handleScanMessage(msg, { children, send });
      return;
    }

    if (msg.type !== 'run') return;

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

    if (agentName === 'scan') {
      send({ type: 'error', runId, message: 'Use a "scan" message to run the Scan agent against a directory.' });
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

    const args = [
      '-p', userPrompt,
      '--append-system-prompt', systemPrompt,
      '--output-format', 'stream-json',
      '--verbose',
      '--allowedTools', 'Read,Grep',
      '--permission-mode', 'acceptEdits',
    ];

    send({ type: 'started', runId, findingId, agent: agentName });

    const child = spawn('claude', args, { cwd: process.cwd(), shell: false });
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
            if (block.type === 'text' && typeof block.text === 'string') {
              fullText += block.text;
            }
          }
        }

        send({ type: 'event', runId, findingId, event });
      }
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
      send({ type: 'done', runId, findingId, code, verdict, fullText });
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
  });

  ws.on('close', () => {
    for (const [runId, child] of children.entries()) {
      const indexed = runIndex.get(runId);
      if (indexed && indexed.run.status === 'running') {
        indexed.run.status = 'cancelled';
        indexed.run.finishedAt = Date.now();
      }
      const scanIndexed = scanRunIndex.get(runId);
      if (scanIndexed && scanIndexed.status === 'running') {
        scanIndexed.status = 'cancelled';
        scanIndexed.finishedAt = Date.now();
      }
      child.kill();
    }
    children.clear();
  });
});

function handleScanMessage(msg, { children, send }) {
  const runId = String(msg.runId || '').trim();
  if (!RUN_ID_RE.test(runId)) {
    send({ type: 'error', message: 'Invalid or missing runId.' });
    return;
  }
  if (children.has(runId)) {
    send({ type: 'error', runId, message: 'This runId is already active.' });
    return;
  }

  const targetPath = String(msg.path || '').trim();
  const instruction = String(msg.instruction || '').trim();

  if (!targetPath) {
    send({ type: 'scan-error', runId, message: 'A target directory path is required.' });
    return;
  }

  let stat;
  try {
    stat = fs.statSync(targetPath);
  } catch (err) {
    send({ type: 'scan-error', runId, message: `Path not found: ${targetPath}` });
    return;
  }
  if (!stat.isDirectory()) {
    send({ type: 'scan-error', runId, message: `Not a directory: ${targetPath}` });
    return;
  }

  const scanAgentPath = path.join(AGENTS_DIR, 'scan.md');
  if (!fs.existsSync(scanAgentPath)) {
    send({ type: 'scan-error', runId, message: 'Scan agent (agents/scan.md) is not available.' });
    return;
  }

  let systemPrompt;
  try {
    systemPrompt = fs.readFileSync(scanAgentPath, 'utf8');
  } catch (err) {
    send({ type: 'scan-error', runId, message: `Failed to read scan agent prompt: ${err.message}` });
    return;
  }

  const scan = {
    id: crypto.randomUUID(),
    runId,
    path: targetPath,
    instruction,
    status: 'running',
    error: null,
    findingIds: [],
    startedAt: Date.now(),
    finishedAt: null,
  };
  scans.set(scan.id, scan);
  scanRunIndex.set(runId, scan);

  const userPrompt = `${instruction || 'Scan this directory for real, concrete security vulnerabilities.'}\n\nTarget directory: ${targetPath}`;

  const args = [
    '-p', userPrompt,
    '--append-system-prompt', systemPrompt,
    '--output-format', 'stream-json',
    '--verbose',
    '--allowedTools', 'Read,Grep,Glob',
    '--permission-mode', 'acceptEdits',
  ];

  send({ type: 'scan-started', runId, scanId: scan.id, path: targetPath });

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
      send({ type: 'scan-event', runId, scanId: scan.id, event });
    }
  });

  child.stderr.on('data', (chunk) => {
    send({ type: 'scan-stderr', runId, scanId: scan.id, data: chunk.toString() });
  });

  child.on('close', (code) => {
    const parsed = extractVerdict(fullText);
    const rawFindings = parsed && Array.isArray(parsed.findings) ? parsed.findings : [];
    const created = [];

    for (const rf of rawFindings) {
      const title = String(rf.title || '').trim();
      const description = String(rf.description || '').trim();
      if (!title || !description) continue; // skip malformed entries rather than fail the whole scan

      const id = crypto.randomUUID();
      const finding = {
        id,
        title,
        severity: SEVERITIES.includes(rf.severity) ? rf.severity : 'medium',
        rule: rf.rule ? String(rf.rule).trim() : null,
        file: rf.file ? String(rf.file).trim() : null,
        description,
        status: 'new',
        createdAt: Date.now(),
        runs: [],
        sourceScanId: scan.id,
      };
      findings.set(id, finding);
      scan.findingIds.push(id);
      created.push(toListItem(finding));
    }

    if (scan.status !== 'cancelled') {
      scan.status = code === 0 ? 'done' : 'error';
      scan.error = code === 0 ? null : `claude exited with code ${code}`;
    }
    scan.finishedAt = Date.now();
    send({ type: 'scan-done', runId, scanId: scan.id, code, findings: created });
    children.delete(runId);
    scanRunIndex.delete(runId);
  });

  child.on('error', (err) => {
    scan.status = 'error';
    scan.error = err.message;
    scan.finishedAt = Date.now();
    send({ type: 'scan-error', runId, scanId: scan.id, message: `Failed to spawn claude: ${err.message}` });
    children.delete(runId);
    scanRunIndex.delete(runId);
  });
}

server.listen(PORT, () => {
  console.log(`Findings Agent App listening on http://localhost:${PORT}`);
});
